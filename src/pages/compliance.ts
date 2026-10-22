// The compliance reports trivy-operator keeps -- the CIS Kubernetes Benchmark,
// the NSA and CISA hardening guide, the Pod Security Standards -- each as a
// pass rate and its controls, the failing ones first.
//
// Bridge calls used here: ready, summary and watch (through the feed), open,
// edit, storage (arriving on a filter).

import { startFeed, type FeedState } from '../model/feed';
import { buildPosture, type ComplianceEntry, type Posture } from '../model/posture';
import { KINDS, SEVERITIES, rank, zero, type Severity } from '../model/trivy';
import { gaugeTone, ring, severityBar } from '../ui/charts';
import { add, button, byId, el, icon } from '../ui/dom';
import { matches, mountToolbar, readSeverities, searchBox, severityToggles, toggle, writeSeverities } from '../ui/filters';
import { plural } from '../ui/format';
import { banner, keepFocus, politely, sdk, writeHash } from '../ui/page';
import { INSTALL_DOCS, absent, arrival, drawAbsence, fail, loading, nav } from '../ui/shell';
import { byText, drawTable, tableState, type Column } from '../ui/table';
import { age, dateTime, externalLink, sevChip } from '../ui/widgets';

type Control = ComplianceEntry['controls'][number];

interface Filters {
    report: string;
    q: string;
    sev: Set<Severity>;
    failing: boolean;
}

const state = {
    ctx: null as K8sDockside.Context | null,
    feed: null as FeedState | null,
    posture: null as Posture | null,
    sig: '',
    filters: { report: '', q: '', sev: new Set(), failing: true } as Filters,
    table: tableState('status'),
};

function remember(): void {
    const f = state.filters;
    writeHash({ report: f.report, q: f.q, sev: writeSeverities(f.sev), all: f.failing ? '' : '1' });
}

function setFilters(next: Partial<Filters>): void {
    Object.assign(state.filters, next);
    state.table.limit = 100;
    if ('report' in next) state.table.open.clear();
    remember();
    keepFocus(document.body, render);
}

function rateRing(c: ComplianceEntry, size: number, thickness: number): HTMLElement {
    const tone = gaugeTone(c.rate);
    const centre = el('div', 'ring-text');
    add(centre, el('div', size > 100 ? 'ring-big' : 'ring-mid', c.rate === null ? '—' : `${Math.round(c.rate * 100)}%`), size > 100 ? el('div', 'ring-small', 'passing') : null);
    return ring(
        [
            { value: c.pass, colour: `var(--tone-${tone})`, title: `${c.pass} passing` },
            { value: c.fail, colour: 'var(--c-line)', title: `${c.fail} failing` },
        ],
        centre,
        { size, thickness, label: `${c.title}: ${c.pass} of ${c.pass + c.fail} controls passing` },
    );
}

function columns(): Column<Control>[] {
    return [
        {
            id: 'status',
            label: 'Result',
            sort: (a, b) => Number(b.fail > 0) - Number(a.fail > 0) || rank(a.severity) - rank(b.severity) || b.fail - a.fail,
            cell: (c) => {
                const n = el('span', 'result-chip ' + (c.fail ? 'fail' : 'pass'));
                add(n, icon(c.fail ? 'close' : 'check'), el('span', '', c.fail ? 'Fail' : 'Pass'));
                return n;
            },
        },
        { id: 'severity', label: 'Severity', sort: (a, b) => rank(a.severity) - rank(b.severity), cell: (c) => sevChip(c.severity) },
        { id: 'id', label: 'Control', sort: (a, b) => byText(a.id, b.id), cell: (c) => el('span', 'mono strong', c.id) },
        { id: 'name', label: 'What it requires', className: 'grow', sort: (a, b) => byText(a.name, b.name), cell: (c) => el('span', '', c.name) },
        { id: 'fail', label: 'Failing', className: 'num', title: 'Resources failing the control', sort: (a, b) => b.fail - a.fail, cell: (c) => el('span', c.fail ? 'num-strong bad-text' : 'faint', String(c.fail)) },
    ];
}

function controlDetail(c: Control): HTMLElement {
    const box = el('div', 'detail');
    box.appendChild(el('p', 'detail-text', c.description || 'The report carries no description of this control.'));
    if (c.fail) box.appendChild(el('p', 'faint small', `${plural(c.fail, 'resource fails', 'resources fail')} it. The checks behind the control are the Misconfigurations page's: search there for the check IDs of the control.`));
    return box;
}

function drawList(p: Posture, current: ComplianceEntry): HTMLElement {
    const list = el('div', 'comp-list');
    for (const c of p.compliance) {
        const b = el('button', 'comp-card' + (c.name === current.name ? ' on' : ''));
        b.type = 'button';
        b.dataset.focus = 'comp:' + c.name;
        b.addEventListener('click', () => setFilters({ report: c.name }));
        const text = el('div', 'comp-text');
        add(text, el('div', 'comp-title', c.title), el('div', 'faint small', `${c.pass} passing · ${c.fail} failing`));
        add(b, rateRing(c, 64, 8), text);
        list.appendChild(b);
    }
    return list;
}

let search: HTMLElement | null = null;

function render(): void {
    byId('nav').replaceChildren(nav('compliance', state.ctx));
    const main = byId('main');
    const bar = byId('toolbar');
    if (drawAbsence(main, state.feed)) {
        bar.hidden = true;
        return;
    }
    const p = state.posture;
    if (!p) return;
    main.textContent = '';
    if (!p.compliance.length) {
        bar.hidden = true;
        const box = el('section', 'absent');
        const art = el('div', 'empty-art');
        art.appendChild(icon('certificate'));
        add(
            box,
            art,
            el('h1', 'absent-title', 'No compliance reports'),
            el('p', 'absent-text', state.feed?.served.has('compliance') ? 'trivy-operator has not written a ClusterComplianceReport yet. The Helm chart installs the CIS, NSA and Pod Security Standards specs and runs them on a schedule (compliance.cron); the first results appear after the first run.' : 'This cluster does not serve the ClusterComplianceReport kind. It comes with trivy-operator’s Helm chart.'),
        );
        const cta = el('div', 'cta');
        cta.appendChild(button('Installation guide', 'ghost', 'book', () => void sdk.openUrl(INSTALL_DOCS).catch(fail)));
        box.appendChild(cta);
        main.appendChild(box);
        return;
    }
    const f = state.filters;
    const current = p.compliance.find((c) => c.name === f.report) ?? p.compliance[0]!;

    bar.hidden = false;
    search ??= searchBox(f.q, 'Search control ID or requirement…', (q) => setFilters({ q }));
    const sevCounts = zero();
    for (const c of current.controls) if (!f.failing || c.fail) sevCounts[c.severity]++;
    const row1 = el('div', 'toolbar-row');
    row1.appendChild(toggle('Failing only', f.failing, 'filter', (failing) => setFilters({ failing })));
    const row2 = el('div', 'toolbar-row');
    row2.appendChild(severityToggles(f.sev, sevCounts, (sev) => setFilters({ sev })));
    mountToolbar(bar, search, [row1], [row2]);

    const layout = el('div', 'comp-layout');
    layout.appendChild(drawList(p, current));

    const side = el('div', 'comp-main');
    const head = el('section', 'comp-head');
    const text = el('div', 'comp-head-text');
    add(text, el('h1', 'verdict', current.title), el('p', 'story', current.description || ''));
    const meta = el('div', 'comp-meta');
    add(
        meta,
        current.version ? el('span', 'tag', 'Version ' + current.version) : null,
        current.cron ? el('span', 'tag', 'Runs ' + current.cron) : null,
        current.updated ? el('span', 'faint small', 'Last run ' + age(current.updated) + ' · ' + dateTime(current.updated)) : el('span', 'faint small', 'Not run yet'),
    );
    text.appendChild(meta);
    const failing = zero();
    for (const c of current.controls) if (c.fail) failing[c.severity]++;
    const sevLine = el('div', 'comp-sevline');
    add(sevLine, el('span', 'mini-title', 'Failing controls by severity'), severityBar(failing, { className: 'result-bar' }));
    for (const s of SEVERITIES) if (failing[s]) sevLine.appendChild(sevChip(s, failing[s]));
    text.appendChild(sevLine);
    const actions = el('div', 'cta');
    add(
        actions,
        button('Open the report', 'ghost small', 'file', () => void sdk.open({ kind: KINDS.compliance, name: current.name }).catch(fail)),
        button('YAML', 'ghost small', 'edit', () => void sdk.edit({ kind: KINDS.compliance, name: current.name }).catch(fail)),
        externalLink('About compliance reports', 'https://aquasecurity.github.io/trivy-operator/latest/docs/crds/clustercompliance-report/', fail),
    );
    text.appendChild(actions);
    add(head, rateRing(current, 150, 16), text);
    side.appendChild(head);

    const controls = current.controls.filter((c) => (!f.failing || c.fail > 0) && (!f.sev.size || f.sev.has(c.severity)) && matches(f.q, c.id, c.name, c.description));
    const box = el('div', 'table-box');
    side.appendChild(box);
    drawTable(box, {
        columns: columns(),
        rows: controls,
        key: (c) => c.id,
        expand: controlDetail,
        state: state.table,
        tone: (c) => (c.fail ? c.severity.toLowerCase() : 'none'),
        empty: f.failing ? 'Every control matching these filters passes.' : 'No control matches these filters.',
    });
    layout.appendChild(side);
    main.appendChild(layout);
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
        byId('nav').replaceChildren(nav('compliance', ctx));
        const h = await arrival('compliance');
        state.filters = { report: h.report ?? '', q: h.q ?? '', sev: readSeverities(h.sev), failing: h.all !== '1' };
        remember();
        startFeed(sdk, { onChange: onFeed, only: ['compliance'], owners: false });
    })
    .catch(fail);
