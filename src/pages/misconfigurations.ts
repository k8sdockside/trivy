// The checks trivy-operator's config audit, RBAC assessment and infra
// assessment failed: by check (what to change in the templates) and by
// resource (what to change on one object). Each opened row says what the
// check looks for, what Trivy saw, and how to fix it.
//
// Bridge calls used here: ready, summary and watch (through the feed), open,
// run (Rescan), storage (arriving on a filter).

import { startFeed, type FeedState } from '../model/feed';
import { AUDIT_LABEL, buildPosture, type AuditKind, type CheckEntry, type Posture, type ResourceEntry } from '../model/posture';
import { KINDS, SEVERITIES, rank, total, zero, type Counts, type Severity } from '../model/trivy';
import { compact, severityBar } from '../ui/charts';
import { add, button, byId, el } from '../ui/dom';
import { matches, mountToolbar, namespaceSelect, nsMatch, readSeverities, searchBox, segmented, severityToggles, writeSeverities } from '../ui/filters';
import { plural } from '../ui/format';
import { banner, declined, keepFocus, politely, sdk, writeHash } from '../ui/page';
import { absent, arrival, drawAbsence, fail, loading, nav } from '../ui/shell';
import { byText, drawTable, tableState, type Column, type TableState } from '../ui/table';
import { age, countCells, dateTime, sevChip, workloadButton, worstChip } from '../ui/widgets';

type Group = 'check' | 'resource';
type Audit = AuditKind | '';

interface Filters {
    group: Group;
    audit: Audit;
    q: string;
    sev: Set<Severity>;
    ns: string;
}

const state = {
    ctx: null as K8sDockside.Context | null,
    feed: null as FeedState | null,
    posture: null as Posture | null,
    sig: '',
    filters: { group: 'check', audit: '', q: '', sev: new Set(), ns: '' } as Filters,
    tables: { check: tableState('severity'), resource: tableState('severity') } as Record<Group, TableState>,
    focusReport: '',
};

function remember(): void {
    const f = state.filters;
    const t = state.tables[f.group];
    writeHash({
        group: f.group === 'check' ? '' : f.group,
        audit: f.audit,
        q: f.q,
        sev: writeSeverities(f.sev),
        ns: f.ns,
        sort: t.sort === 'severity' ? '' : t.sort,
        dir: t.dir === -1 ? 'desc' : '',
        open: [...t.open].slice(0, 5).join('|'),
    });
}

// ----- filtering ---------------------------------------------------------------------

interface CheckRow {
    check: CheckEntry;
    resources: CheckEntry['resources'];
}

function checkRows(p: Posture, f: Filters): CheckRow[] {
    const out: CheckRow[] = [];
    for (const c of p.checks) {
        if (f.audit && c.audit !== f.audit) continue;
        if (f.sev.size && !f.sev.has(c.severity)) continue;
        const resources = c.resources.filter((r) => nsMatch(f.ns, r.workload.namespace));
        if (!resources.length) continue;
        if (!matches(f.q, c.checkID, c.title, c.category, c.description, resources.map((r) => r.workload.name).join(' '))) continue;
        out.push({ check: c, resources });
    }
    return out;
}

interface ResourceRow {
    entry: ResourceEntry;
    counts: Counts;
}

function resourceRows(p: Posture, f: Filters): ResourceRow[] {
    const out: ResourceRow[] = [];
    for (const r of p.resources) {
        if (f.audit && r.audit !== f.audit) continue;
        if (!nsMatch(f.ns, r.workload.namespace)) continue;
        if (!matches(f.q, r.workload.name, r.workload.kind, r.workload.namespace, r.findings.map((x) => `${x.checkID} ${x.title}`).join(' '))) continue;
        let counts = r.counts;
        if (f.sev.size) {
            counts = zero();
            for (const s of SEVERITIES) if (f.sev.has(s)) counts[s] = r.counts[s];
        }
        if (!total(counts)) continue;
        out.push({ entry: r, counts });
    }
    return out;
}

// ----- the columns ---------------------------------------------------------------------

const AUDIT_ICON = { config: 'policy', rbac: 'rbac', infra: 'server' } as const;

function auditTag(a: AuditKind): HTMLElement {
    return el('span', 'tag audit-' + a, AUDIT_LABEL[a]);
}

function checkColumns(): Column<CheckRow>[] {
    return [
        { id: 'severity', label: 'Severity', sort: (a, b) => rank(a.check.severity) - rank(b.check.severity) || b.resources.length - a.resources.length, cell: (r) => sevChip(r.check.severity) },
        { id: 'id', label: 'Check', sort: (a, b) => byText(a.check.checkID, b.check.checkID), cell: (r) => el('span', 'mono strong', r.check.checkID) },
        {
            id: 'title',
            label: 'What it checks',
            className: 'grow',
            sort: (a, b) => byText(a.check.title, b.check.title),
            cell: (r) => {
                const node = el('div', 'cve-id');
                add(node, el('span', 'strong', r.check.title), r.check.category ? el('div', 'cve-title', r.check.category) : null);
                return node;
            },
        },
        { id: 'audit', label: 'Audit', sort: (a, b) => byText(a.check.audit, b.check.audit), cell: (r) => auditTag(r.check.audit) },
        { id: 'resources', label: 'Resources', className: 'num', sort: (a, b) => b.resources.length - a.resources.length, cell: (r) => el('span', 'num-strong', String(r.resources.length)) },
    ];
}

function checkDetail(r: CheckRow): HTMLElement {
    const c = r.check;
    const box = el('div', 'detail');
    if (c.description) box.appendChild(el('p', 'detail-text', c.description));
    if (c.remediation) {
        const fix = el('div', 'remedy');
        add(fix, el('span', 'mini-title', 'How to fix it'), el('p', '', c.remediation));
        box.appendChild(fix);
    }
    const list = el('div', 'res-list');
    list.appendChild(el('span', 'mini-title', `Failing on ${plural(r.resources.length, 'resource')}`));
    for (const res of r.resources.slice(0, 60)) {
        const row = el('div', 'res-row');
        add(row, workloadButton(res.workload, { onFail: fail }));
        if (res.messages.length) {
            const msgs = el('ul', 'messages');
            for (const m of res.messages.slice(0, 4)) msgs.appendChild(el('li', '', m));
            if (res.messages.length > 4) msgs.appendChild(el('li', 'faint', `+${res.messages.length - 4} more`));
            row.appendChild(msgs);
        }
        list.appendChild(row);
    }
    if (r.resources.length > 60) list.appendChild(el('p', 'faint small', `and ${r.resources.length - 60} more`));
    box.appendChild(list);
    return box;
}

function resourceColumns(): Column<ResourceRow>[] {
    return [
        { id: 'severity', label: 'Worst', sort: (a, b) => cmp(a.counts, b.counts), cell: (r) => worstChip(r.counts) },
        { id: 'resource', label: 'Resource', className: 'grow', sort: (a, b) => byText(a.entry.workload.name, b.entry.workload.name), cell: (r) => workloadButton(r.entry.workload, { namespace: false, onFail: fail }) },
        { id: 'namespace', label: 'Namespace', sort: (a, b) => byText(a.entry.workload.namespace, b.entry.workload.namespace), cell: (r) => el('span', 'small', r.entry.workload.namespace || '(cluster)') },
        { id: 'audit', label: 'Audit', sort: (a, b) => byText(a.entry.audit, b.entry.audit), cell: (r) => auditTag(r.entry.audit) },
        { id: 'counts', label: 'C · H · M · L', cell: (r) => countCells(r.counts) },
        { id: 'bar', label: '', className: 'barcol', cell: (r) => severityBar(r.counts) },
        { id: 'total', label: 'Failed', className: 'num', sort: (a, b) => total(b.counts) - total(a.counts), cell: (r) => el('span', 'num-strong', compact(total(r.counts))) },
        {
            id: 'scanned',
            label: 'Audited',
            sort: (a, b) => b.entry.updated - a.entry.updated,
            cell: (r) => {
                const n = el('span', 'small faint', age(r.entry.updated));
                n.title = dateTime(r.entry.updated);
                return n;
            },
        },
    ];
}

function cmp(a: Counts, b: Counts): number {
    for (const s of SEVERITIES) if (a[s] !== b[s]) return b[s] - a[s];
    return 0;
}

function resourceDetail(r: ResourceRow): HTMLElement {
    const e = r.entry;
    const box = el('div', 'detail');
    if (e.workload.via) box.appendChild(el('p', 'faint small', `Audited through its ${e.workload.via.kind} ${e.workload.via.name}.`));
    if (!e.detailed) box.appendChild(el('p', 'quiet', 'The report holds only its counts: the checks themselves were not recorded.'));
    const f = state.filters;
    const list = e.findings.filter((x) => !f.sev.size || f.sev.has(x.severity)).sort((a, b) => rank(a.severity) - rank(b.severity) || byText(a.checkID, b.checkID));
    const checks = el('div', 'check-cards');
    for (const c of list) {
        const card = el('div', 'check-card');
        card.dataset.tone = c.severity.toLowerCase();
        const head = el('div', 'check-card-head');
        add(head, sevChip(c.severity), el('span', 'mono strong', c.checkID), el('span', 'strong', c.title), c.category ? el('span', 'faint small', c.category) : null);
        card.appendChild(head);
        if (c.messages.length) {
            const msgs = el('ul', 'messages');
            for (const m of c.messages) msgs.appendChild(el('li', '', m));
            card.appendChild(msgs);
        } else if (c.description) {
            card.appendChild(el('p', 'detail-text small', c.description));
        }
        if (c.remediation) {
            const fix = el('p', 'remedy-line');
            add(fix, el('strong', '', 'Fix: '), c.remediation);
            card.appendChild(fix);
        }
        checks.appendChild(card);
    }
    box.appendChild(checks);
    if (e.report.kind === KINDS.configAudit) {
        const actions = el('div', 'detail-actions');
        const b = button('Audit again', 'ghost small', 'rescan', () => {
            sdk.run('rescan-config', { namespace: e.report.namespace, name: e.report.name }).catch((err: unknown) => {
                if (!declined(err)) fail(err);
            });
        });
        b.title = `Delete ${e.report.name} so trivy-operator audits it again`;
        actions.appendChild(b);
        box.appendChild(actions);
    }
    return box;
}

// ----- drawing ------------------------------------------------------------------------------

function setFilters(next: Partial<Filters>): void {
    Object.assign(state.filters, next);
    state.tables[state.filters.group].limit = 100;
    remember();
    keepFocus(document.body, render);
}

let search: HTMLElement | null = null;

function drawToolbar(p: Posture): void {
    const f = state.filters;
    const bar = byId('toolbar');
    bar.hidden = false;
    search ??= searchBox(f.q, 'Search check, title, resource…', (q) => setFilters({ q }));
    const by = p.totals.misconfigBy;
    const row1 = el('div', 'toolbar-row');
    add(
        row1,
        segmented<Group>(
            [
                { id: 'check', label: 'By check', icon: 'policy' },
                { id: 'resource', label: 'By resource', icon: 'deployment' },
            ],
            f.group,
            (group) => setFilters({ group }),
        ),
        segmented<Audit>(
            [
                { id: '', label: `All ${compact(total(p.totals.misconfig))}` },
                { id: 'config', label: `Workloads ${compact(total(by.config))}`, icon: AUDIT_ICON.config },
                { id: 'rbac', label: `RBAC ${compact(total(by.rbac))}`, icon: AUDIT_ICON.rbac },
                { id: 'infra', label: `Infra ${compact(total(by.infra))}`, icon: AUDIT_ICON.infra },
            ],
            f.audit,
            (audit) => setFilters({ audit }),
        ),
        namespaceSelect(
            p.namespaces.map((n) => n.namespace),
            f.ns,
            (ns) => setFilters({ ns }),
        ),
    );
    const counts = zero();
    for (const r of resourceRows(p, { ...f, sev: new Set() })) for (const s of SEVERITIES) counts[s] += r.counts[s];
    const row2 = el('div', 'toolbar-row');
    row2.appendChild(severityToggles(f.sev, counts, (sev) => setFilters({ sev })));
    mountToolbar(bar, search, [row1], [row2]);
}

function render(): void {
    byId('nav').replaceChildren(nav('misconfigurations', state.ctx));
    const main = byId('main');
    if (drawAbsence(main, state.feed)) {
        byId('toolbar').hidden = true;
        return;
    }
    const p = state.posture;
    if (!p) return;
    main.textContent = '';
    if (!p.resources.length) {
        main.appendChild(el('p', 'quiet big', state.feed?.ready ? 'No config audit, RBAC or infra assessment reports yet.' : 'Reading the reports…'));
        return;
    }
    applyFocus(p);
    drawToolbar(p);
    const f = state.filters;
    const box = el('div', 'table-box');
    const result = el('div', 'result');
    if (f.group === 'check') {
        const rows = checkRows(p, f);
        const counts = zero();
        for (const r of rows) counts[r.check.severity]++;
        add(result, el('strong', '', String(rows.length)), el('span', 'faint', rows.length === 1 ? ' failing check' : ' failing checks'), severityBar(counts, { className: 'result-bar' }), countCells(counts));
        add(main, result, box);
        drawTable(box, { columns: checkColumns(), rows, key: (r) => `${r.check.audit}/${r.check.checkID}`, expand: checkDetail, state: state.tables.check, onState: remember, tone: (r) => r.check.severity.toLowerCase(), empty: 'No failing check matches these filters.' });
    } else {
        const rows = resourceRows(p, f);
        const counts = zero();
        for (const r of rows) for (const s of SEVERITIES) counts[s] += r.counts[s];
        add(result, el('strong', '', String(rows.length)), el('span', 'faint', rows.length === 1 ? ' resource' : ' resources'), severityBar(counts, { className: 'result-bar' }), countCells(counts));
        add(main, result, box);
        drawTable(box, {
            columns: resourceColumns(),
            rows,
            key: (r) => `${r.entry.audit}/${r.entry.report.namespace}/${r.entry.report.name}`,
            expand: resourceDetail,
            state: state.tables.resource,
            onState: remember,
            tone: (r) => (SEVERITIES.find((s) => r.counts[s]) ?? 'none').toLowerCase(),
            empty: 'No resource matches these filters.',
        });
    }
}

function applyFocus(p: Posture): void {
    if (!state.focusReport) return;
    const [ns, name] = state.focusReport.split('/');
    const r = p.resources.find((x) => x.report.namespace === ns && x.report.name === name);
    if (!r) return;
    state.focusReport = '';
    state.filters.group = 'resource';
    state.filters.ns = ns ?? '';
    state.tables.resource.open.add(`${r.audit}/${r.report.namespace}/${r.report.name}`);
    remember();
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
        byId('nav').replaceChildren(nav('misconfigurations', ctx));
        const h = await arrival('misconfigurations');
        const group: Group = h.group === 'resource' ? 'resource' : 'check';
        const audit: Audit = h.audit === 'config' || h.audit === 'rbac' || h.audit === 'infra' ? h.audit : '';
        state.filters = { group, audit, q: h.q ?? '', sev: readSeverities(h.sev), ns: h.ns ?? '' };
        const t = state.tables[group];
        if (h.sort) t.sort = h.sort;
        if (h.dir === 'desc') t.dir = -1;
        for (const k of (h.open ?? '').split('|').filter(Boolean)) t.open.add(k);
        state.focusReport = h.report ?? '';
        remember();
        startFeed(sdk, { onChange: onFeed, only: ['configAudit', 'clusterConfigAudit', 'rbac', 'clusterRbac', 'infra', 'clusterInfra'] });
    })
    .catch(fail);
