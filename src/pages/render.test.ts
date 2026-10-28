// @vitest-environment happy-dom
//
// Does each page actually draw? It runs each page module against a stub of
// the bridge, with no cluster and no app, against reports shaped the way
// trivy-operator writes them, and reads the text that comes out.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { complianceReports, configAuditReports, exposedSecretReports, rbacReports, replicasets, vulnerabilityReports } from '../fixtures';
import { KINDS } from '../model/trivy';

type Lists = Record<string, unknown[]>;

const FULL: Lists = {
    [KINDS.vulnerability]: vulnerabilityReports,
    [KINDS.configAudit]: configAuditReports,
    [KINDS.rbac]: rbacReports,
    [KINDS.exposedSecret]: exposedSecretReports,
    [KINDS.compliance]: complianceReports,
    replicasets,
    jobs: [],
};

let ran: { id: string; ref: unknown }[] = [];

function bridge(lists: Lists, opts: { installed?: boolean; object?: { kind: string; namespace: string; name: string }; obj?: unknown } = {}) {
    const inNs = (list: unknown[], namespace?: string) => (namespace ? list.filter((o) => (o as { metadata: { namespace?: string } }).metadata.namespace === namespace) : list);
    const requirements = Object.values(KINDS).map((kind) => ({ kind, label: kind, optional: kind !== KINDS.vulnerability, served: kind in lists, error: '' }));
    return {
        ready: async () => ({
            pluginId: 'trivy',
            viewId: '',
            sectionId: '',
            object: opts.object ?? null,
            contextId: 'test',
            contextName: 'test-cluster',
            readable: [],
            write: false,
            actions: [],
            theme: { id: 'k8sdockside-dark', base: 'dark' as const, tokens: {} },
        }),
        object: async () => opts.obj,
        list: async ({ kind, namespace }: { kind: string; namespace?: string }) => {
            if (!(kind in lists)) throw new Error(`the cluster does not serve ${kind}`);
            return inNs(lists[kind]!, namespace);
        },
        watch: ({ kind, namespace }: { kind: string; namespace?: string }, onItems: (items: unknown[]) => void, onError: (err: Error) => void) => {
            if (kind in lists) onItems(inNs(lists[kind]!, namespace));
            else onError(new Error(`the cluster does not serve ${kind}`));
            return () => {};
        },
        summary: async () => ({ pluginId: 'trivy', installed: opts.installed ?? true, checked: true, requirements: opts.installed === false ? requirements.map((r) => ({ ...r, served: false })) : requirements, cards: [], error: '' }),
        charts: async () => ({ attached: true, range: 1440, source: { available: false, error: '', describe: '' }, charts: [] }),
        storage: { get: async () => null, set: async () => null, remove: async () => null, keys: async () => [] },
        run: async (id: string, ref: unknown) => {
            ran.push({ id, ref });
            return { created: '' };
        },
        open: async () => null,
        openView: async () => null,
        openUrl: async () => null,
        edit: async () => null,
        resize: async () => null,
        on: () => () => {},
        ui: { section },
    };
}

/** The bridge's ui.section, as plain elements: a heading and a body. */
function section(opts: K8sDockside.SectionOptions): K8sDockside.Section {
    const root = document.createElement('section');
    const title = document.createElement('h3');
    title.textContent = opts.title;
    const actions = document.createElement('div');
    const body = document.createElement('div');
    root.append(title, actions, body);
    opts.parent?.append(root);
    return {
        root,
        body,
        actions,
        setTitle: (text) => void (title.textContent = text),
        setCount: () => {},
        isFolded: () => false,
        setFolded: () => {},
        onToggle: () => () => {},
    };
}

const PAGE = '<div id="nav"></div><p id="error" hidden></p><div id="toolbar" hidden></div><main id="main"></main><section id="history" hidden></section><div id="foot"></div>';
const PANEL = '<p id="error" hidden></p><div id="panel"></div>';

async function run(module: string, html: string, hash = ''): Promise<string> {
    document.body.innerHTML = html;
    location.hash = hash;
    vi.resetModules();
    await import(module);
    for (let i = 0; i < 60; i++) await Promise.resolve();
    await new Promise((resolve) => setTimeout(resolve, 20));
    for (let i = 0; i < 20; i++) await Promise.resolve();
    return document.body.textContent ?? '';
}

beforeEach(() => {
    ran = [];
});

afterEach(() => {
    vi.unstubAllGlobals();
});

describe('the overview', () => {
    it('draws the score, the severities, the heatmap and the lists', async () => {
        vi.stubGlobal('k8sdockside', bridge(FULL));
        const text = await run('./overview.js', PAGE);
        expect(text).toContain('vulnerabilities across 4 images');
        expect(text).toContain('Security score');
        expect(text).toContain('CVE-2024-6387');
        expect(text).toContain('Most vulnerable images');
        expect(text).toContain('nginx:1.25.3');
        expect(text).toContain('AWS Access Key ID');
        expect(text).toContain('National Security Agency');
        expect(text).toContain('No Prometheus was found');
        expect(document.querySelectorAll('.heat-cell').length).toBeGreaterThan(0);
        expect(document.querySelectorAll('.gauge')).toHaveLength(3);
    });

    it('says trivy-operator is not installed', async () => {
        vi.stubGlobal('k8sdockside', bridge({}, { installed: false }));
        const text = await run('./overview.js', PAGE);
        expect(text).toContain('trivy-operator is not installed');
        expect(text).toContain('helm install trivy-operator');
    });

    it('puts names on the page as text', async () => {
        const evil = { ...vulnerabilityReports[0]!, metadata: { ...vulnerabilityReports[0]!.metadata, ownerReferences: [{ apiVersion: 'apps/v1', kind: 'StatefulSet', name: '<img src=x onerror=alert(1)>', uid: 'x', controller: true }] } };
        vi.stubGlobal('k8sdockside', bridge({ ...FULL, [KINDS.vulnerability]: [evil] }));
        await run('./overview.js', PAGE);
        expect(document.querySelector('img[src="x"]')).toBe(null);
    });
});

describe('the working pages', () => {
    it('lists CVEs, and images and workloads on request', async () => {
        vi.stubGlobal('k8sdockside', bridge(FULL));
        let text = await run('./vulnerabilities.js', PAGE);
        expect(text).toContain('CVE-2023-44487');
        expect(document.querySelectorAll('tr.tbl-row')).toHaveLength(5);
        text = await run('./vulnerabilities.js', PAGE, '#group=workload&sev=CRITICAL');
        expect(text).toContain('shop');
        expect(text).not.toContain('agent');
        text = await run('./vulnerabilities.js', PAGE, '#group=image&fix=1');
        expect(text).toContain('payments-api');
        expect(text).not.toContain('alloy');
    });

    it('opens the workload of a report the app focused', async () => {
        vi.stubGlobal('k8sdockside', bridge(FULL));
        const text = await run('./vulnerabilities.js', PAGE, '#group=workload&report=shop/replicaset-shop-7d9f8c-nginx');
        expect(text).toContain('scanned this Deployment through its ReplicaSet shop-7d9f8c');
    });

    it('lists failing checks and resources', async () => {
        vi.stubGlobal('k8sdockside', bridge(FULL));
        let text = await run('./misconfigurations.js', PAGE);
        expect(text).toContain('KSV017');
        expect(text).toContain('Manage secrets');
        text = await run('./misconfigurations.js', PAGE, '#group=resource&audit=rbac');
        expect(text).toContain('pod-reader');
        expect(text).not.toContain('KSV017');
    });

    it('lists exposed secrets', async () => {
        vi.stubGlobal('k8sdockside', bridge(FULL));
        const text = await run('./secrets.js', PAGE);
        expect(text).toContain('1 secret exposed in 1 image');
        expect(text).toContain('/app/.env');
    });

    it('shows a compliance report with its failing controls', async () => {
        vi.stubGlobal('k8sdockside', bridge(FULL));
        const text = await run('./compliance.js', PAGE);
        expect(text).toContain('Preventing privileged containers');
        expect(text).not.toContain('Immutable container file systems');
    });
});

describe('the panel', () => {
    it('finds a Deployment’s reports through its ReplicaSets', async () => {
        const deployment = { metadata: { name: 'shop', namespace: 'shop' } };
        vi.stubGlobal('k8sdockside', bridge(FULL, { object: { kind: 'deployments', namespace: 'shop', name: 'shop' }, obj: deployment }));
        const text = await run('./workload.js', PANEL);
        expect(text).toContain('CVE-2024-6387');
        expect(text).toContain('through ReplicaSet shop-7d9f8c');
        expect(text).toContain('Root file system is not read-only');
        expect(text).toContain('Failed configuration checks');
        (document.querySelector('.container-head button') as HTMLButtonElement).click();
        expect(ran[0]).toEqual({ id: 'rescan-vulnerabilities', ref: { namespace: 'shop', name: 'replicaset-shop-7d9f8c-nginx' } });
    });

    it('says when there are no reports', async () => {
        vi.stubGlobal('k8sdockside', bridge(FULL, { object: { kind: 'statefulsets', namespace: 'x', name: 'none' }, obj: { metadata: { name: 'none', namespace: 'x' } } }));
        const text = await run('./workload.js', PANEL);
        expect(text).toContain('No trivy-operator reports');
    });
});
