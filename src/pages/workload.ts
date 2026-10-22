// The Trivy panel in the detail view of a Deployment, StatefulSet,
// DaemonSet, ReplicaSet, CronJob, Job or Pod: its vulnerabilities by
// severity and per container, its failed configuration checks and any
// secrets in its images, with Rescan.
//
// trivy-operator scans a Deployment through its ReplicaSets and a CronJob
// through its Jobs, and a pod through whatever owns it, so the panel first
// works out which object's reports are this one's.
//
// Bridge calls used here: ready, object, list, run, openView (through go).

import { buildPosture, emptyData, type Posture, type TrivyData } from '../model/posture';
import { KINDS, SEVERITIES, rank, severity, subjectOf, total, type AuditReport, type ExposedSecretReport, type KubeObject, type VulnerabilityReport } from '../model/trivy';
import { compact, severityBar, severityRing } from '../ui/charts';
import { add, button, byId, el, icon } from '../ui/dom';
import { plural } from '../ui/format';
import { banner, declined, every, sdk } from '../ui/page';
import { fail, go } from '../ui/shell';
import { age, countCells, dateTime, sevChip } from '../ui/widgets';

const EVERY = 30_000;

/** The Kubernetes kind of the app kinds a panel is drawn for. */
const KIND: Record<string, string> = {
    deployments: 'Deployment',
    statefulsets: 'StatefulSet',
    daemonsets: 'DaemonSet',
    replicasets: 'ReplicaSet',
    cronjobs: 'CronJob',
    jobs: 'Job',
    pods: 'Pod',
};

interface Target {
    namespace: string;
    /** The objects trivy-operator reports this one through, as `Kind/name`. */
    subjects: Set<string>;
    /** The one it names in a sentence when it is not the object itself. */
    via: string;
}

/** Which objects' reports are this object's. */
async function resolve(ctx: K8sDockside.Context, obj: KubeObject): Promise<Target> {
    const ref = ctx.object!;
    const kind = KIND[ref.kind] ?? '';
    const ns = ref.namespace;
    const subjects = new Set<string>([`${kind}/${ref.name}`]);
    let via = '';
    const owned = async (listKind: string, ownerKind: string): Promise<KubeObject[]> => {
        try {
            const all = await sdk.list({ kind: listKind, namespace: ns });
            return all.filter((o) => o.metadata.ownerReferences?.some((r) => r.kind === ownerKind && r.name === ref.name));
        } catch {
            return [];
        }
    };
    if (kind === 'Deployment') {
        // Newest first: the ReplicaSet running now is the one that matters.
        const rs = (await owned('replicasets', 'Deployment')).sort((a, b) => (b.metadata.creationTimestamp ?? '').localeCompare(a.metadata.creationTimestamp ?? ''));
        for (const r of rs) subjects.add(`ReplicaSet/${r.metadata.name}`);
        if (rs[0]) via = `ReplicaSet ${rs[0].metadata.name}`;
    } else if (kind === 'CronJob') {
        for (const j of await owned('jobs', 'CronJob')) subjects.add(`Job/${j.metadata.name}`);
        via = 'its Jobs';
    } else if (kind === 'Pod') {
        const owner = obj.metadata.ownerReferences?.find((r) => r.controller);
        if (owner) {
            subjects.add(`${owner.kind}/${owner.name}`);
            via = `${owner.kind} ${owner.name}`;
        }
    }
    return { namespace: ns, subjects, via };
}

function ofTarget<T extends KubeObject>(list: T[], t: Target): T[] {
    return list.filter((r) => {
        const s = subjectOf(r);
        return t.subjects.has(`${s.kind}/${s.name}`);
    });
}

async function read<T extends KubeObject>(kind: string, ns: string): Promise<T[]> {
    try {
        return await sdk.list<T>({ kind, namespace: ns });
    } catch {
        // Not served, or not allowed: the panel draws what it can.
        return [];
    }
}

let sig = '';

async function refresh(ctx: K8sDockside.Context, target: Target): Promise<void> {
    const [vulns, configs, secrets] = await Promise.all([
        read<VulnerabilityReport>(KINDS.vulnerability, target.namespace),
        read<AuditReport>(KINDS.configAudit, target.namespace),
        read<ExposedSecretReport>(KINDS.exposedSecret, target.namespace),
    ]);
    const data: TrivyData = { ...emptyData(), vulnerability: ofTarget(vulns, target), configAudit: ofTarget(configs, target), exposedSecret: ofTarget(secrets, target) };
    const p = buildPosture(data);
    const next = p.signature + data.vulnerability.length + data.configAudit.length;
    if (next === sig) return;
    sig = next;
    banner.clear();
    draw(ctx, target, data, p);
}

function draw(ctx: K8sDockside.Context, target: Target, data: TrivyData, p: Posture): void {
    const root = byId('panel');
    root.textContent = '';
    if (!data.vulnerability.length && !data.configAudit.length && !data.exposedSecret.length) {
        const none = el('div', 'panel-empty');
        add(
            none,
            icon('clock'),
            el(
                'span',
                '',
                ctx.object?.kind === 'replicasets' || ctx.object?.kind === 'jobs' || ctx.object?.kind === 'pods'
                    ? 'trivy-operator has no reports for this object. It scans each workload once, through the object that owns its pods; a report appears a few minutes after a new workload starts.'
                    : 'No trivy-operator reports for this workload yet. It is scanned a few minutes after it starts; if it never is, check that trivy-operator watches this namespace.',
            ),
        );
        root.appendChild(none);
        return;
    }

    const t = p.totals;
    const top = el('div', 'panel-top');
    const centre = el('div', 'ring-text');
    const n = total(t.findings);
    add(centre, el('div', 'ring-mid', compact(n)), el('div', 'ring-small', n === 1 ? 'finding' : 'findings'));
    top.appendChild(severityRing(t.findings, centre, { size: 104, thickness: 12, noun: 'vulnerabilities' }));

    const facts = el('div', 'panel-facts');
    const sevs = el('div', 'panel-sevs');
    for (const s of SEVERITIES) if (t.findings[s] || s !== 'UNKNOWN') sevs.appendChild(sevChip(s, t.findings[s]));
    facts.appendChild(sevs);
    const line = el('p', 'panel-line');
    add(
        line,
        el('strong', t.fixable ? 'ok' : '', compact(t.fixable)),
        ` of ${compact(n)} have a fix`,
        ' · ',
        el('strong', total(t.misconfig) ? 'warnish' : 'ok', compact(total(t.misconfig))),
        ` failed config ${total(t.misconfig) === 1 ? 'check' : 'checks'}`,
        ' · ',
        el('strong', total(t.secrets) ? 'bad' : 'ok', String(total(t.secrets))),
        ` exposed ${total(t.secrets) === 1 ? 'secret' : 'secrets'}`,
    );
    facts.appendChild(line);
    const when = el('p', 'faint small');
    when.textContent = `Scanned ${age(t.newest)}` + (target.via ? ` · through ${target.via}` : '');
    when.title = dateTime(t.newest);
    facts.appendChild(when);
    const actions = el('div', 'cta');
    add(
        actions,
        button('All vulnerabilities', 'ghost small', 'bug', () => go('vulnerabilities', { group: 'workload', q: ctx.object?.name ?? '', ns: target.namespace })),
        total(t.misconfig) ? button('Misconfigurations', 'ghost small', 'policy', () => go('misconfigurations', { group: 'resource', q: ctx.object?.name ?? '', ns: target.namespace })) : null,
    );
    facts.appendChild(actions);
    top.appendChild(facts);
    root.appendChild(top);

    // Per container: its image, its counts, its worst CVEs.
    const containers = el('div', 'panel-containers');
    const byImage = new Map(p.images.map((i) => [i.name, i]));
    const seen = new Set<string>();
    for (const w of p.workloads) {
        for (const c of w.containers) {
            const key = `${c.name}/${c.image}`;
            if (seen.has(key)) continue;
            seen.add(key);
            const row = el('div', 'panel-container');
            const head = el('div', 'container-head');
            const rescan = button('Rescan', 'ghost small', 'rescan', () => {
                sdk.run('rescan-vulnerabilities', { namespace: c.report.namespace, name: c.report.name }).catch((err: unknown) => {
                    if (!declined(err)) fail(err);
                });
            });
            rescan.title = `Delete ${c.report.name} so trivy-operator scans the image again`;
            add(head, icon('container'), el('span', 'strong', c.name || 'container'), el('span', 'iname small', c.image), countCells(c.counts), rescan);
            row.appendChild(head);
            row.appendChild(severityBar(c.counts, { className: 'thin' }));
            const img = byImage.get(c.image);
            const worst = (img?.findings ?? [])
                .filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH')
                .sort((a, b) => rank(a.severity) - rank(b.severity) || Number(Boolean(b.fixed)) - Number(Boolean(a.fixed)) || (b.score ?? 0) - (a.score ?? 0))
                .slice(0, 5);
            if (worst.length) {
                const list = el('ul', 'panel-cves');
                for (const f of worst) {
                    const li = el('li');
                    add(li, sevChip(severity(f.severity)), el('span', 'mono', f.id), el('span', 'faint mono small', `${f.pkg} ${f.installed}`), f.fixed ? el('span', 'fixed mono small', '→ ' + f.fixed) : el('span', 'faint small', 'no fix yet'));
                    li.title = f.title;
                    list.appendChild(li);
                }
                row.appendChild(list);
            }
            containers.appendChild(row);
        }
    }
    root.appendChild(containers);

    // Failed config checks, worst first.
    const checks = p.resources.flatMap((r) => r.findings).sort((a, b) => rank(a.severity) - rank(b.severity));
    if (checks.length) {
        const box = el('div', 'panel-checks');
        box.appendChild(el('div', 'mini-title', `Failed configuration checks (${checks.length})`));
        for (const c of checks.slice(0, 6)) {
            const row = el('div', 'panel-check');
            add(row, sevChip(c.severity), el('span', 'mono small', c.checkID), el('span', '', c.title));
            row.title = c.messages.join('\n') || c.description;
            box.appendChild(row);
        }
        if (checks.length > 6) box.appendChild(el('p', 'faint small', `and ${plural(checks.length - 6, 'more')}`));
        root.appendChild(box);
    }

    if (p.secrets.length) {
        const box = el('div', 'panel-checks alarm');
        box.appendChild(el('div', 'mini-title', `Exposed secrets (${p.secrets.length})`));
        for (const s of p.secrets.slice(0, 4)) {
            const row = el('div', 'panel-check');
            add(row, sevChip(s.severity), el('span', '', s.title), el('span', 'mono small faint', s.target));
            box.appendChild(row);
        }
        root.appendChild(box);
    }
}

sdk.ready()
    .then(async (ctx) => {
        if (!ctx.object) return;
        const obj = await sdk.object();
        const target = await resolve(ctx, obj);
        every(EVERY, () => refresh(ctx, target));
    })
    .catch(fail);
