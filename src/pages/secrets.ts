// Secrets trivy-operator found inside container images: a key, a token, a
// password written into a file of the image. Trivy writes the match with
// the secret itself masked, so this page shows what it shows -- never more.
//
// Bridge calls used here: ready, summary and watch (through the feed), open,
// run (Rescan), storage (arriving on a filter).

import { startFeed, type FeedState } from '../model/feed';
import { buildPosture, type Posture, type SecretFinding } from '../model/posture';
import { KINDS, rank, zero, type Severity } from '../model/trivy';
import { severityBar, severityRing } from '../ui/charts';
import { add, button, byId, el, icon } from '../ui/dom';
import { matches, mountToolbar, namespaceSelect, nsMatch, readSeverities, searchBox, severityToggles, writeSeverities } from '../ui/filters';
import { plural } from '../ui/format';
import { banner, declined, keepFocus, politely, sdk, writeHash } from '../ui/page';
import { absent, arrival, drawAbsence, fail, loading, nav } from '../ui/shell';
import { byText, drawTable, tableState, type Column } from '../ui/table';
import { countCells, fact, sevChip, workloadButton } from '../ui/widgets';

interface Filters {
    q: string;
    sev: Set<Severity>;
    ns: string;
}

const state = {
    ctx: null as K8sDockside.Context | null,
    feed: null as FeedState | null,
    posture: null as Posture | null,
    sig: '',
    filters: { q: '', sev: new Set(), ns: '' } as Filters,
    table: tableState('severity'),
};

function keyOf(s: SecretFinding): string {
    return `${s.report.namespace}/${s.report.name}/${s.target}/${s.ruleID}/${s.match}`;
}

function remember(): void {
    const f = state.filters;
    writeHash({ q: f.q, sev: writeSeverities(f.sev), ns: f.ns, sort: state.table.sort === 'severity' ? '' : state.table.sort, dir: state.table.dir === -1 ? 'desc' : '' });
}

function rows(p: Posture, f: Filters, opts: { sev?: boolean } = {}): SecretFinding[] {
    return p.secrets.filter(
        (s) =>
            (opts.sev === false || !f.sev.size || f.sev.has(s.severity)) &&
            nsMatch(f.ns, s.workload.namespace) &&
            matches(f.q, s.title, s.ruleID, s.category, s.target, s.image, s.workload.name, s.workload.namespace, s.container),
    );
}

function columns(): Column<SecretFinding>[] {
    return [
        { id: 'severity', label: 'Severity', sort: (a, b) => rank(a.severity) - rank(b.severity), cell: (s) => sevChip(s.severity) },
        {
            id: 'title',
            label: 'Secret',
            className: 'grow',
            sort: (a, b) => byText(a.title, b.title),
            cell: (s) => {
                const node = el('div', 'cve-id');
                add(node, el('span', 'strong', s.title), el('div', 'cve-title', [s.category, s.ruleID].filter(Boolean).join(' · ')));
                return node;
            },
        },
        { id: 'target', label: 'File in the image', sort: (a, b) => byText(a.target, b.target), cell: (s) => el('span', 'mono small', s.target || '—') },
        { id: 'image', label: 'Image', sort: (a, b) => byText(a.image, b.image), cell: (s) => el('span', 'iname small', s.image) },
        { id: 'workload', label: 'Workload', sort: (a, b) => byText(a.workload.name, b.workload.name), cell: (s) => workloadButton(s.workload, { onFail: fail }) },
    ];
}

function detail(s: SecretFinding): HTMLElement {
    const box = el('div', 'detail');
    if (s.match) {
        const m = el('div', 'match');
        add(m, el('span', 'mini-title', 'What Trivy matched (masked)'), el('code', 'match-code', s.match));
        box.appendChild(m);
    }
    const facts = el('div', 'facts');
    add(facts, fact('Rule', s.ruleID || '—'), fact('Category', s.category || '—'), fact('File', s.target || '—'), fact('Container', s.container || '—'), fact('Image', s.image));
    box.appendChild(facts);
    const advice = el('div', 'remedy');
    add(
        advice,
        el('span', 'mini-title', 'What to do'),
        el('p', '', 'Treat the secret as leaked: anyone who can pull the image can read it. Revoke or rotate it first, then rebuild the image without it — pass it at run time from a Secret instead — and push the new build.'),
    );
    box.appendChild(advice);
    if (s.report.kind === KINDS.exposedSecret) {
        const actions = el('div', 'detail-actions');
        actions.appendChild(
            button('Rescan', 'ghost small', 'rescan', () => {
                sdk.run('rescan-secrets', { namespace: s.report.namespace, name: s.report.name }).catch((err: unknown) => {
                    if (!declined(err)) fail(err);
                });
            }),
        );
        box.appendChild(actions);
    }
    return box;
}

function setFilters(next: Partial<Filters>): void {
    Object.assign(state.filters, next);
    state.table.limit = 100;
    remember();
    keepFocus(document.body, render);
}

let search: HTMLElement | null = null;

function render(): void {
    byId('nav').replaceChildren(nav('secrets', state.ctx));
    const main = byId('main');
    const bar = byId('toolbar');
    if (drawAbsence(main, state.feed)) {
        bar.hidden = true;
        return;
    }
    const p = state.posture;
    if (!p) return;
    main.textContent = '';
    if (!p.secrets.length) {
        bar.hidden = true;
        const ok = el('section', 'absent calm');
        const art = el('div', 'empty-art ok');
        art.appendChild(icon('check'));
        add(
            ok,
            art,
            el('h1', 'absent-title', 'No exposed secrets'),
            el('p', 'absent-text', p.totals.images ? `trivy-operator looked through ${plural(p.totals.images, 'image')} and found no keys, tokens or passwords written into any of them.` : 'No exposed secret reports yet: trivy-operator writes them alongside each image’s vulnerability report.'),
        );
        main.appendChild(ok);
        return;
    }
    const f = state.filters;
    bar.hidden = false;
    search ??= searchBox(f.q, 'Search secret, file, image, workload…', (q) => setFilters({ q }));
    const counts = zero();
    for (const s of rows(p, f, { sev: false })) counts[s.severity]++;
    const row1 = el('div', 'toolbar-row');
    row1.appendChild(
        namespaceSelect(
            p.secrets.map((s) => s.workload.namespace),
            f.ns,
            (ns) => setFilters({ ns }),
        ),
    );
    const row2 = el('div', 'toolbar-row');
    row2.appendChild(severityToggles(f.sev, counts, (sev) => setFilters({ sev })));
    mountToolbar(bar, search, [row1], [row2]);

    const list = rows(p, f);
    const shown = zero();
    for (const s of list) shown[s.severity]++;

    const hero = el('section', 'secret-hero');
    const centre = el('div', 'ring-text');
    add(centre, el('div', 'ring-big', String(p.secrets.length)), el('div', 'ring-small', p.secrets.length === 1 ? 'secret' : 'secrets'));
    const all = zero();
    for (const s of p.secrets) all[s.severity]++;
    const text = el('div', 'secret-hero-text');
    add(
        text,
        el('h1', 'verdict', `${plural(p.secrets.length, 'secret')} exposed in ${plural(p.totals.imagesWithSecrets, 'image')}`),
        el('p', 'story', 'Anything written into an image can be read by anyone who can pull it. Rotate each one, then rebuild the image without it.'),
    );
    add(hero, severityRing(all, centre, { size: 120, thickness: 13, noun: 'secrets' }), text);
    main.appendChild(hero);

    const result = el('div', 'result');
    add(result, el('strong', '', String(list.length)), el('span', 'faint', list.length === 1 ? ' finding' : ' findings'), severityBar(shown, { className: 'result-bar' }), countCells(shown));
    const box = el('div', 'table-box');
    add(main, result, box);
    drawTable(box, { columns: columns(), rows: list, key: keyOf, expand: detail, state: state.table, onState: remember, tone: (s) => s.severity.toLowerCase(), empty: 'No secret matches these filters.' });
}

const redraw = politely(document.body, render);

function onFeed(feed: FeedState): void {
    state.feed = feed;
    // Half the lists would draw a page that changes under the user a moment later.
    if (!feed.ready && !absent(feed)) return;
    const posture = buildPosture(feed.data);
    const sig = posture.signature + JSON.stringify(feed.errors) + (feed.summary ? 's' : '') + (feed.ready ? 'r' : '');
    if (sig === state.sig) return;
    state.posture = posture;
    state.sig = sig;
    banner.clear();
    redraw();
}

loading(byId('main'));
sdk.ready()
    .then(async (ctx) => {
        state.ctx = ctx;
        byId('nav').replaceChildren(nav('secrets', ctx));
        const h = await arrival('secrets');
        state.filters = { q: h.q ?? '', sev: readSeverities(h.sev), ns: h.ns ?? '' };
        if (h.sort) state.table.sort = h.sort;
        if (h.dir === 'desc') state.table.dir = -1;
        remember();
        startFeed(sdk, { onChange: onFeed, only: ['vulnerability', 'exposedSecret'] });
    })
    .catch(fail);
