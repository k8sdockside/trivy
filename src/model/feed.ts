// Keeps every report fresh through the bridge's `watch`.
//
// Only the kinds the cluster serves are watched: `summary()` says which of the
// manifest's `requires` are there, so an operator installed without, say,
// the compliance reports costs nothing and draws no error. Reports change only
// when a scan finishes, so they are polled slowly; the ReplicaSets and Jobs
// that lift a report to its Deployment or CronJob even more slowly.

import { emptyData, fingerprint, type TrivyData } from './posture';
import { KINDS, type ReportKey } from './trivy';

export interface FeedState {
    data: TrivyData;
    /** Which report kinds this cluster serves; filled once `summary()` has answered. */
    served: Set<ReportKey>;
    /** Why a kind could not be read, by kind. */
    errors: Partial<Record<ReportKey | 'replicasets' | 'jobs', string>>;
    /**
     * Whether every served report kind -- and the ReplicaSets and Jobs, when
     * asked for -- has answered once: until then the totals are partial, and
     * a Deployment would be drawn as its ReplicaSet for a moment.
     */
    ready: boolean;
    summary: K8sDockside.Summary | null;
}

export interface FeedOptions {
    namespace?: string;
    /** Milliseconds between polls of the reports. */
    interval?: number;
    /** Leave out the kinds a page does not draw. */
    only?: ReportKey[];
    /** Read ReplicaSets and Jobs too, to name Deployments and CronJobs. */
    owners?: boolean;
    onChange: (state: FeedState) => void;
}

const BY_KIND = new Map<string, ReportKey>(Object.entries(KINDS).map(([k, v]) => [v, k as ReportKey]));

function listPrint(items: K8sDockside.KubeObject[]): string {
    return fingerprint(items.map((o) => `${o.metadata.uid ?? o.metadata.namespace + '/' + o.metadata.name}@${o.metadata.resourceVersion ?? ''}`).join('|'));
}

export function startFeed(bridge: K8sDockside.Bridge, opts: FeedOptions): () => void {
    const state: FeedState = { data: emptyData(), served: new Set(), errors: {}, ready: false, summary: null };
    const prints = new Map<string, string>();
    const answered = new Set<string>();
    const stops: (() => void)[] = [];
    let stopped = false;

    const settle = (): void => {
        const wanted: string[] = [...state.served];
        if (opts.owners !== false) wanted.push('replicasets', 'jobs');
        state.ready = wanted.every((k) => answered.has(k) || k in state.errors);
    };

    function accept(key: ReportKey | 'replicasets' | 'jobs', items: K8sDockside.KubeObject[]): void {
        const print = listPrint(items);
        const hadError = key in state.errors;
        delete state.errors[key];
        const first = !answered.has(key);
        answered.add(key);
        if (prints.get(key) === print && !hadError && !first) return;
        prints.set(key, print);
        (state.data as unknown as Record<string, unknown>)[key] = items;
        settle();
        opts.onChange(state);
    }

    function refuse(key: ReportKey | 'replicasets' | 'jobs', err: Error): void {
        if (state.errors[key] === err.message) return;
        state.errors[key] = err.message;
        settle();
        opts.onChange(state);
    }

    const watch = (key: ReportKey | 'replicasets' | 'jobs', kind: string, interval: number): void => {
        stops.push(
            bridge.watch(
                { kind, namespace: opts.namespace ?? '', interval },
                (items) => accept(key, items),
                (err) => refuse(key, err),
            ),
        );
    };

    bridge
        .summary()
        .then((summary) => {
            if (stopped) return;
            state.summary = summary;
            for (const r of summary.requirements) {
                const key = BY_KIND.get(r.kind);
                // "Could not tell" is watched anyway: the watch says what is wrong.
                if (key && (r.served || r.error) && (!opts.only || opts.only.includes(key))) state.served.add(key);
            }
            if (!summary.checked) {
                // The cluster did not answer: try the main report kind, so the
                // page says why as soon as it can rather than waiting forever.
                state.served.add('vulnerability');
            }
            settle();
            opts.onChange(state);
            for (const key of state.served) watch(key, KINDS[key], opts.interval ?? 30_000);
            if (opts.owners !== false) {
                watch('replicasets', 'replicasets', 60_000);
                watch('jobs', 'jobs', 60_000);
            }
        })
        .catch((err: unknown) => {
            state.errors.vulnerability = err instanceof Error ? err.message : String(err);
            opts.onChange(state);
        });

    return () => {
        stopped = true;
        stops.forEach((stop) => stop());
    };
}
