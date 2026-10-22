// Renders every page of the plugin to standalone HTML, with no cluster and no
// app: the same fixtures the render test uses, the plugin's real stylesheet,
// and the app's real theme tokens written onto :root the way the SDK does.
//
//   node scripts/preview.mjs [out-dir]
//
// It is a way to look at the pages, not a test -- the test is `npm test`.
// The app's themes are read from a checkout of K8s Dockside beside this one
// (../k8sdockside); set K8SDOCKSIDE to point somewhere else.

import { copyFileSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Window } from 'happy-dom';
import * as esbuild from 'esbuild';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = process.argv[2] ?? path.join(ROOT, 'preview');
const APP = process.env.K8SDOCKSIDE ?? path.resolve(ROOT, '../k8sdockside');

const PAGE = '<div id="nav"></div><p id="error" class="banner error" hidden></p><div id="toolbar" class="toolbar" hidden></div><main id="main"></main><section id="history" class="history" hidden></section><div id="foot"></div>';
const PANEL = '<p id="error" class="banner error" hidden></p><div id="panel" class="panel"></div>';

// [file name, page module, title, body class, address hash, the panel's object]
const PAGES = [
    ['overview', 'overview', 'Overview', 'page page-overview', ''],
    ['vulnerabilities', 'vulnerabilities', 'Vulnerabilities by CVE', 'page page-list', 'open=CVE-2023-44487'],
    ['vulnerabilities-image', 'vulnerabilities', 'Vulnerabilities by image', 'page page-list', 'group=image&open=index.docker.io/library/nginx@sha256:aaa111'],
    ['vulnerabilities-workload', 'vulnerabilities', 'Vulnerabilities by workload', 'page page-list', 'group=workload'],
    ['misconfigurations', 'misconfigurations', 'Misconfigurations by check', 'page page-list', 'open=config/KSV014'],
    ['misconfigurations-resource', 'misconfigurations', 'Misconfigurations by resource', 'page page-list', 'group=resource'],
    ['secrets', 'secrets', 'Exposed secrets', 'page page-list', ''],
    ['compliance', 'compliance', 'Compliance', 'page page-list', 'all=1'],
    ['panel', 'workload', 'Panel: Deployment shop', 'page page-section', '', { kind: 'deployments', namespace: 'shop', name: 'shop' }],
];

let imports = 0;
async function load(entry) {
    const built = await esbuild.build({ entryPoints: [entry], bundle: true, write: false, format: 'esm', platform: 'browser', target: ['es2022'] });
    return import(`data:text/javascript;base64,${Buffer.from(built.outputFiles[0].text).toString('base64')}#${imports++}`);
}

const themes = ['k8sdockside-light', 'k8sdockside-dark'].map((id) => JSON.parse(readFileSync(path.join(APP, 'internal/themes/builtin', `${id}.json`), 'utf8')));
const f = await load(path.join(ROOT, 'src/fixtures.ts'));
const { KINDS } = await load(path.join(ROOT, 'src/model/trivy.ts'));
const css = readFileSync(path.join(ROOT, 'ui/trivy.css'), 'utf8');

const LISTS = {
    [KINDS.vulnerability]: f.vulnerabilityReports,
    [KINDS.configAudit]: f.configAuditReports,
    [KINDS.rbac]: f.rbacReports,
    [KINDS.exposedSecret]: f.exposedSecretReports,
    [KINDS.compliance]: f.complianceReports,
    replicasets: f.replicasets,
    jobs: [],
};

// A day of history for the charts, so their drawing can be looked at too.
const series = (name, base) => ({ name, points: Array.from({ length: 96 }, (_, i) => ({ t: 1_761_000_000 + i * 900, v: Math.max(0, Math.round(base + Math.sin(i / 9) * base * 0.15 - i * base * 0.002)) })) });
const charts = {
    attached: true,
    range: 1440,
    source: { available: true, describe: 'monitoring/prometheus-operated:9090', error: '' },
    charts: [
        { id: 'vulnerabilities', label: 'Vulnerabilities', unit: 'count', description: 'Vulnerabilities by severity.', error: '', series: [series('Critical', 12), series('High', 60), series('Medium', 140), series('Low', 90)] },
        { id: 'misconfigurations', label: 'Misconfigurations', unit: 'count', description: 'Failed checks by severity.', error: '', series: [series('Critical', 3), series('High', 22), series('Medium', 40)] },
    ],
};

const pad = (n) => String(n).padStart(2, '0');
const format = {
    settings: () => ({ clock: '24h', dates: 'iso', zone: 'local', ages: 'relative' }),
    date: (w) => { const d = new Date(w); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`; },
    day: (w) => { const d = new Date(w); return `${pad(d.getMonth() + 1)}-${pad(d.getDate())}`; },
    time: (w) => { const d = new Date(w); return `${pad(d.getHours())}:${pad(d.getMinutes())}`; },
    dateTime: (w) => `${format.date(w)} ${format.time(w)}`,
    age: (w) => { const h = Math.round((f.NOW - new Date(w).getTime()) / 3_600_000); return h < 48 ? `${h}h` : `${Math.round(h / 24)}d`; },
    moment: (w) => ({ text: format.dateTime(w), title: '' }),
};

function stub(theme, object) {
    const inNs = (list, namespace) => (namespace ? list.filter((o) => (o.metadata.namespace ?? '') === namespace) : list);
    const requirements = Object.values(KINDS).map((kind) => ({ kind, label: kind.replace(/^crd:|\..*$/g, ''), optional: kind !== KINDS.vulnerability, served: kind in LISTS, error: '' }));
    return {
        ready: async () => ({ pluginId: 'trivy', viewId: '', sectionId: '', object, contextId: 'preview', contextName: 'kind-trivy-dev', readable: [], write: false, actions: [], theme, plugin: { id: 'trivy', name: 'Trivy', version: '1.0.0', docs: '', links: [{ label: 'trivy-operator', url: 'https://aquasecurity.github.io/trivy-operator/latest/' }] } }),
        object: async () => ({ metadata: { name: object?.name, namespace: object?.namespace } }),
        list: async ({ kind, namespace }) => { if (!(kind in LISTS)) throw new Error(`the cluster does not serve ${kind}`); return inNs(LISTS[kind], namespace); },
        watch: ({ kind, namespace }, onItems, onError) => { if (kind in LISTS) onItems(inNs(LISTS[kind], namespace)); else onError(new Error(`the cluster does not serve ${kind}`)); return () => {}; },
        summary: async () => ({ pluginId: 'trivy', installed: true, checked: true, requirements, cards: [], error: '' }),
        charts: async () => charts,
        storage: { get: async () => null, set: async () => null, remove: async () => null, keys: async () => [] },
        run: async () => ({ created: '' }), open: async () => null, openView: async () => null, openUrl: async () => null, edit: async () => null, resize: async () => null,
        on: () => () => {},
        format,
    };
}

async function render(page, theme) {
    const [, module, , , hash, object] = page;
    const win = new Window({ url: `https://preview.local/${hash ? `#${hash}` : ''}` });
    const { document } = win;
    document.body.innerHTML = module === 'workload' ? PANEL : PAGE;
    const root = document.documentElement;
    for (const [name, value] of Object.entries(theme.tokens)) root.style.setProperty(`--${name}`, value);
    root.setAttribute('data-theme-base', theme.base);
    const globals = ['window', 'document', 'navigator', 'location', 'history', 'getComputedStyle', 'Node', 'Element', 'HTMLElement', 'SVGElement', 'Event', 'addEventListener', 'setTimeout', 'clearTimeout'];
    for (const key of globals) {
        if (win[key] === undefined) continue;
        const value = typeof win[key] === 'function' && /EventListener|getComputedStyle/.test(key) ? win[key].bind(win) : win[key];
        Object.defineProperty(globalThis, key, { value, configurable: true, writable: true });
    }
    Object.defineProperty(globalThis, 'k8sdockside', { value: stub(theme, object ?? null), configurable: true, writable: true });
    await load(path.join(ROOT, 'src/pages', `${module}.ts`));
    for (let i = 0; i < 60; i++) await new Promise((r) => setTimeout(r, 1));
    const html = document.body.innerHTML;
    await win.happyDOM.close();
    return html;
}

mkdirSync(OUT, { recursive: true });
for (const file of ['logo.png', 'aqua.png']) copyFileSync(path.join(ROOT, 'ui', file), path.join(OUT, file));
const index = [];
for (const page of PAGES) {
    for (const theme of themes) {
        const html = await render(page, theme);
        const file = `${page[0]}.${theme.base}.html`;
        writeFileSync(
            path.join(OUT, file),
            `<!doctype html><html lang="en" data-theme-base="${theme.base}" style="${Object.entries(theme.tokens).map(([k, v]) => `--${k}:${v}`).join(';')}">
<head><meta charset="utf-8"><title>${page[2]} — ${theme.base}</title><style>${css}</style>${page[1] === 'workload' ? '<style>body{max-width:760px}</style>' : ''}</head>
<body class="${page[3]}">${html}</body></html>`,
        );
        if (theme.base === 'light') index.push([page[2], page[0]]);
    }
}
writeFileSync(
    path.join(OUT, 'index.html'),
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Trivy plugin preview</title>
<style>body{font:14px/1.6 system-ui;margin:40px auto;max-width:680px;color:#1a1d21}h1{font-size:20px}li{margin:4px 0}a{color:#0b6bcb}</style></head>
<body><h1>Trivy plugin — page preview</h1>
<ul>${index.map(([label, id]) => `<li>${label} — <a href="${id}.light.html">light</a> · <a href="${id}.dark.html">dark</a></li>`).join('')}</ul>
<p style="color:#5c636b">Static HTML drawn from the fixtures. Buttons do nothing: there is no app behind them.</p></body></html>`,
);
console.log(`wrote ${PAGES.length * 2 + 1} files to ${OUT}`);
process.exit(0);
