// Every vulnerability trivy-operator found, three ways round: by CVE (what
// to patch), by image (what to rebuild) and by workload (who to tell).
// Search, severity, namespace and "has a fix" filter all three; the choice,
// the sort and the open rows are kept in the page's address.
//
// Bridge calls used here: ready, summary and watch (through the feed), open,
// openUrl, run (Rescan), storage (arriving on a filter).

import { startFeed, type FeedState } from '../model/feed';
import { buildPosture, type CveEntry, type Finding, type ImageEntry, type Posture, type ReportRef, type WorkloadEntry } from '../model/posture';
import { KINDS, SEVERITIES, rank, total, zero, type Counts, type Severity } from '../model/trivy';
import { compact, severityBar } from '../ui/charts';
import { add, button, byId, el, icon } from '../ui/dom';
import { matches, mountToolbar, namespaceSelect, nsMatch, readSeverities, searchBox, segmented, severityToggles, toggle, writeSeverities } from '../ui/filters';
import { plural } from '../ui/format';
import { banner, declined, keepFocus, politely, sdk, writeHash } from '../ui/page';
import { absent, arrival, drawAbsence, fail, go, loading, nav } from '../ui/shell';
import { byText, drawTable, tableState, type Column, type TableState } from '../ui/table';
import { age, countCells, date, dateTime, externalLink, fact, sevChip, workloadButton, worstChip } from '../ui/widgets';

type Group = 'cve' | 'image' | 'workload';

interface Filters {
    group: Group;
    q: string;
    sev: Set<Severity>;
    ns: string;
    fix: boolean;
}

const state = {
    ctx: null as K8sDockside.Context | null,
    feed: null as FeedState | null,
    posture: null as Posture | null,
    sig: '',
    filters: { group: 'cve', q: '', sev: new Set(), ns: '', fix: false } as Filters,
    tables: { cve: tableState('severity'), image: tableState('severity'), workload: tableState('severity') } as Record<Group, TableState>,
    /** A report the app opened the page on, to open its workload once the reports are in. */
    focusReport: '',
};

function remember(): void {
    const f = state.filters;
    const t = state.tables[f.group];
    writeHash({
        group: f.group === 'cve' ? '' : f.group,
        q: f.q,
        sev: writeSeverities(f.sev),
        ns: f.ns,
        fix: f.fix ? '1' : '',
        sort: t.sort === 'severity' ? '' : t.sort,
        dir: t.dir === -1 ? 'desc' : '',
        open: [...t.open].slice(0, 5).join('|'),
    });
}

// ----- filtering -------------------------------------------------------------------

function findingMatches(f: Finding, filters: Filters): boolean {
    if (filters.sev.size && !filters.sev.has(f.severity)) return false;
    if (filters.fix && !f.fixed) return false;
    return true;
}

/** Counts of an image's findings that pass the severity and fix filters. */
function filteredCounts(findings: Finding[], fallback: Counts, filters: Filters, detailed: boolean): Counts {
    if (!detailed) {
        // Only a summary: the severity filter can still apply, "has a fix" cannot.
        if (filters.fix) return zero();
        const c = zero();
        for (const s of SEVERITIES) if (!filters.sev.size || filters.sev.has(s)) c[s] = fallback[s];
        return c;
    }
    const c = zero();
    for (const f of findings) if (findingMatches(f, filters)) c[f.severity]++;
    return c;
}

function cveRows(p: Posture, f: Filters): CveEntry[] {
    return p.cves.filter(
        (c) =>
            (!f.sev.size || f.sev.has(c.severity)) &&
            (!f.fix || c.fixable) &&
            (!f.ns || c.namespaces.some((n) => nsMatch(f.ns, n))) &&
            matches(f.q, c.id, c.title, c.packages.join(' '), c.images.join(' '), c.workloads.map((w) => w.name).join(' ')),
    );
}

interface ImageRow {
    entry: ImageEntry;
    counts: Counts;
}

function imageRows(p: Posture, f: Filters): ImageRow[] {
    const out: ImageRow[] = [];
    for (const entry of p.images) {
        if (f.ns && !entry.namespaces.some((n) => nsMatch(f.ns, n))) continue;
        if (!matches(f.q, entry.name, entry.os, entry.workloads.map((w) => w.name).join(' '), entry.findings.map((x) => x.id + ' ' + x.pkg).join(' '))) continue;
        const counts = filteredCounts(entry.findings, entry.counts, f, entry.detailed);
        if ((f.sev.size || f.fix) && !total(counts)) continue;
        out.push({ entry, counts: f.sev.size || f.fix ? counts : entry.counts });
    }
    return out;
}

interface WorkloadRow {
    entry: WorkloadEntry;
    counts: Counts;
}

function workloadRows(p: Posture, f: Filters): WorkloadRow[] {
    const byImage = new Map(p.images.map((i) => [i.key, i]));
    const out: WorkloadRow[] = [];
    for (const entry of p.workloads) {
        if (!nsMatch(f.ns, entry.workload.namespace)) continue;
        const images = entry.images.map((k) => byImage.get(k)).filter((x): x is ImageEntry => Boolean(x));
        if (!matches(f.q, entry.workload.name, entry.workload.namespace, entry.workload.kind, images.map((i) => i.name).join(' '), images.flatMap((i) => i.findings.map((x) => x.id)).join(' '))) continue;
        let counts = entry.counts;
        if (f.sev.size || f.fix) {
            counts = zero();
            for (const c of entry.containers) {
                const img = images.find((i) => i.name === c.image);
                const part = img ? filteredCounts(img.findings, c.counts, f, img.detailed) : zero();
                for (const s of SEVERITIES) counts[s] += part[s];
            }
            if (!total(counts)) continue;
        }
        out.push({ entry, counts });
    }
    return out;
}

// ----- the columns ---------------------------------------------------------------------

const bySev = (a: Counts, b: Counts): number => {
    for (const s of SEVERITIES) if (a[s] !== b[s]) return b[s] - a[s];
    return 0;
};

function cveColumns(): Column<CveEntry>[] {
    return [
        { id: 'severity', label: 'Severity', sort: (a, b) => rank(a.severity) - rank(b.severity) || (b.score ?? 0) - (a.score ?? 0) || b.images.length - a.images.length, cell: (c) => sevChip(c.severity) },
        {
            id: 'id',
            label: 'Vulnerability',
            className: 'grow',
            sort: (a, b) => byText(a.id, b.id),
            cell: (c) => {
                const node = el('div', 'cve-id');
                add(node, el('span', 'mono strong', c.id), c.title ? el('div', 'cve-title', c.title) : null);
                return node;
            },
        },
        { id: 'score', label: 'Score', className: 'num', title: 'The CVSS score Trivy reports', sort: (a, b) => (b.score ?? -1) - (a.score ?? -1), cell: (c) => scoreBadge(c.score) },
        { id: 'pkg', label: 'Package', sort: (a, b) => byText(a.packages[0] ?? '', b.packages[0] ?? ''), cell: (c) => el('span', 'mono small', c.packages.slice(0, 2).join(', ') + (c.packages.length > 2 ? ` +${c.packages.length - 2}` : '')) },
        { id: 'installed', label: 'Installed', cell: (c) => el('span', 'mono small faint', c.installed.slice(0, 2).join(', ') + (c.installed.length > 2 ? ' …' : '')) },
        { id: 'fixed', label: 'Fixed in', sort: (a, b) => Number(b.fixable) - Number(a.fixable), cell: (c) => (c.fixable ? el('span', 'fixed mono small', c.fixed.slice(0, 2).join(', ') + (c.fixed.length > 2 ? ' …' : '')) : el('span', 'faint small', 'no fix yet')) },
        { id: 'images', label: 'Images', className: 'num', sort: (a, b) => b.images.length - a.images.length, cell: (c) => el('span', 'num-strong', String(c.images.length)) },
        { id: 'workloads', label: 'Workloads', className: 'num', sort: (a, b) => b.workloads.length - a.workloads.length, cell: (c) => el('span', 'num-strong', String(c.workloads.length)) },
        { id: 'published', label: 'Published', sort: (a, b) => (a.published || Infinity) - (b.published || Infinity), cell: (c) => el('span', 'small faint', c.published ? date(c.published) : '—') },
    ];
}

function scoreBadge(score: number | null): HTMLElement {
    if (score === null) return el('span', 'faint', '—');
    const tone = score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low';
    return el('span', 'score sev-' + tone, score.toFixed(1));
}

function cveDetail(c: CveEntry, p: Posture): HTMLElement {
    const box = el('div', 'detail');
    if (c.description) box.appendChild(el('p', 'detail-text', c.description));
    const facts = el('div', 'facts');
    add(
        facts,
        fact('Packages', c.packages.join(', ') || '—'),
        fact('Installed', c.installed.join(', ') || '—'),
        fact('Fixed in', c.fixed.join(', ') || 'no fixed version yet'),
        fact('Published', c.published ? date(c.published) : '—'),
        fact('Namespaces', c.namespaces.map((n) => n || '(cluster)').join(', ')),
    );
    box.appendChild(facts);
    const links = el('div', 'detail-links');
    const urls = [...new Set([c.link, ...c.links].filter(Boolean))].slice(0, 6);
    if (urls.length) {
        links.appendChild(el('span', 'mini-title', 'Read more'));
        urls.forEach((u, i) => links.appendChild(externalLink(i === 0 ? c.id : hostOf(u), u, fail)));
        box.appendChild(links);
    }
    const imgs = el('div', 'detail-list');
    imgs.appendChild(el('span', 'mini-title', `In ${plural(c.images.length, 'image')}`));
    const byKey = new Map(p.images.map((i) => [i.key, i]));
    for (const k of c.images.slice(0, 12)) {
        const img = byKey.get(k);
        const b = button(img?.name ?? k, 'pill', 'image', () => setFilters({ group: 'image', q: img?.name ?? k }));
        b.title = 'Show this image';
        imgs.appendChild(b);
    }
    if (c.images.length > 12) imgs.appendChild(el('span', 'faint small', `+${c.images.length - 12} more`));
    box.appendChild(imgs);
    const wls = el('div', 'detail-list');
    wls.appendChild(el('span', 'mini-title', `Running in ${plural(c.workloads.length, 'workload')}`));
    for (const w of c.workloads.slice(0, 16)) wls.appendChild(workloadButton(w, { onFail: fail }));
    if (c.workloads.length > 16) wls.appendChild(el('span', 'faint small', `+${c.workloads.length - 16} more`));
    box.appendChild(wls);
    return box;
}

function hostOf(url: string): string {
    const m = /^https?:\/\/([^/]+)/i.exec(url);
    return m ? m[1]! : url;
}

function imageColumns(): Column<ImageRow>[] {
    return [
        { id: 'severity', label: 'Worst', sort: (a, b) => bySev(a.counts, b.counts), cell: (r) => worstChip(r.counts) },
        {
            id: 'image',
            label: 'Image',
            className: 'grow',
            sort: (a, b) => byText(a.entry.name, b.entry.name),
            cell: (r) => {
                const node = el('div', 'img-cell');
                add(node, el('span', 'iname', r.entry.name), el('div', 'faint small', [r.entry.os, r.entry.components !== null ? `${r.entry.components} components` : ''].filter(Boolean).join(' · ')));
                if (r.entry.eosl) node.appendChild(el('span', 'tag warn', 'OS end of support'));
                return node;
            },
        },
        { id: 'counts', label: 'C · H · M · L', cell: (r) => countCells(r.counts) },
        { id: 'bar', label: '', className: 'barcol', cell: (r) => severityBar(r.counts) },
        { id: 'total', label: 'Total', className: 'num', sort: (a, b) => total(b.counts) - total(a.counts), cell: (r) => el('span', 'num-strong', compact(total(r.counts))) },
        { id: 'fixable', label: 'Fixable', className: 'num', sort: (a, b) => b.entry.fixable - a.entry.fixable, cell: (r) => el('span', r.entry.fixable ? 'fixed' : 'faint', compact(r.entry.fixable)) },
        { id: 'workloads', label: 'Workloads', className: 'num', sort: (a, b) => b.entry.workloads.length - a.entry.workloads.length, cell: (r) => String(r.entry.workloads.length) },
        { id: 'scanned', label: 'Scanned', sort: (a, b) => b.entry.updated - a.entry.updated, cell: (r) => scanned(r.entry.updated) },
    ];
}

function scanned(ms: number): HTMLElement {
    const node = el('span', 'small' + (ms && Date.now() - ms > 86_400_000 ? ' warn-text' : ' faint'), age(ms));
    node.title = dateTime(ms);
    return node;
}

function findingsTable(findings: Finding[], filters: Filters): HTMLElement {
    const list = findings.filter((f) => findingMatches(f, filters)).sort((a, b) => rank(a.severity) - rank(b.severity) || (b.score ?? 0) - (a.score ?? 0) || byText(a.id, b.id));
    const box = el('div', 'inner-table');
    const table = el('table', 'tbl compact');
    const hr = el('tr');
    for (const h of ['Severity', 'Vulnerability', 'Package', 'Installed', 'Fixed in', 'Score']) hr.appendChild(el('th', '', h));
    const head = el('thead');
    head.appendChild(hr);
    table.appendChild(head);
    const body = el('tbody');
    const LIMIT = 150;
    for (const f of list.slice(0, LIMIT)) {
        const tr = el('tr');
        tr.dataset.tone = f.severity.toLowerCase();
        const s = el('td');
        s.appendChild(sevChip(f.severity));
        const id = el('td', 'cve-id');
        add(id, f.link ? externalLink(f.id, f.link, fail) : el('span', 'mono', f.id), f.title ? el('div', 'cve-title', f.title) : null);
        const fixed = el('td');
        fixed.appendChild(f.fixed ? el('span', 'fixed mono small', f.fixed) : el('span', 'faint small', 'no fix yet'));
        const sc = el('td', 'num');
        sc.appendChild(scoreBadge(f.score));
        add(tr, s, id, el('td', 'mono small', f.pkg), el('td', 'mono small faint', f.installed), fixed, sc);
        body.appendChild(tr);
    }
    table.appendChild(body);
    box.appendChild(table);
    if (list.length > LIMIT) box.appendChild(el('p', 'faint small', `Showing the worst ${LIMIT} of ${list.length}. Group by CVE to see them all.`));
    if (!list.length) box.appendChild(el('p', 'quiet', 'No findings match the filters.'));
    return box;
}

function imageDetail(r: ImageRow): HTMLElement {
    const e = r.entry;
    const box = el('div', 'detail');
    const facts = el('div', 'facts');
    add(
        facts,
        fact('Registry', e.ref.registry || '—'),
        fact('Repository', e.ref.repository || '—'),
        fact('Tag', e.ref.tag || '—'),
        fact('Digest', el('span', 'mono small', e.ref.digest || '—')),
        fact('OS', (e.os || '—') + (e.eosl ? ' (end of support: no more fixes)' : '')),
        fact('Scanned', dateTime(e.updated) || '—'),
    );
    box.appendChild(facts);
    const wls = el('div', 'detail-list');
    wls.appendChild(el('span', 'mini-title', `Used by ${plural(e.workloads.length, 'workload')}`));
    for (const w of e.workloads) wls.appendChild(workloadButton(w, { onFail: fail }));
    box.appendChild(wls);
    if (!e.detailed) box.appendChild(el('p', 'quiet', 'trivy-operator recorded only the counts for this image, not the vulnerabilities themselves (its vulnerabilityReports.scanner.reportRecordFailedChecksOnly or a summary-only setting).'));
    else box.appendChild(findingsTable(e.findings, state.filters));
    const actions = el('div', 'detail-actions');
    actions.appendChild(rescanButton(e.reports[0]));
    box.appendChild(actions);
    return box;
}

function workloadColumns(): Column<WorkloadRow>[] {
    return [
        { id: 'severity', label: 'Worst', sort: (a, b) => bySev(a.counts, b.counts), cell: (r) => worstChip(r.counts) },
        { id: 'workload', label: 'Workload', className: 'grow', sort: (a, b) => byText(a.entry.workload.name, b.entry.workload.name), cell: (r) => workloadButton(r.entry.workload, { namespace: false, onFail: fail }) },
        { id: 'namespace', label: 'Namespace', sort: (a, b) => byText(a.entry.workload.namespace, b.entry.workload.namespace), cell: (r) => el('span', 'small', r.entry.workload.namespace || '(cluster)') },
        { id: 'counts', label: 'C · H · M · L', cell: (r) => countCells(r.counts) },
        { id: 'bar', label: '', className: 'barcol', cell: (r) => severityBar(r.counts) },
        { id: 'images', label: 'Images', className: 'num', sort: (a, b) => b.entry.images.length - a.entry.images.length, cell: (r) => String(r.entry.images.length) },
        { id: 'fixable', label: 'Fixable', className: 'num', sort: (a, b) => b.entry.fixable - a.entry.fixable, cell: (r) => el('span', r.entry.fixable ? 'fixed' : 'faint', compact(r.entry.fixable)) },
        { id: 'config', label: 'Config', className: 'num', title: 'Failed configuration checks', sort: (a, b) => total(b.entry.misconfig) - total(a.entry.misconfig), cell: (r) => el('span', total(r.entry.misconfig) ? '' : 'faint', compact(total(r.entry.misconfig))) },
        { id: 'secrets', label: 'Secrets', className: 'num', sort: (a, b) => b.entry.secrets - a.entry.secrets, cell: (r) => (r.entry.secrets ? sevChip('CRITICAL', r.entry.secrets) : el('span', 'faint', '0')) },
        { id: 'scanned', label: 'Scanned', sort: (a, b) => b.entry.updated - a.entry.updated, cell: (r) => scanned(r.entry.updated) },
    ];
}

function workloadDetail(r: WorkloadRow, p: Posture): HTMLElement {
    const e = r.entry;
    const box = el('div', 'detail');
    if (e.workload.via) box.appendChild(el('p', 'faint small', `trivy-operator scanned this ${e.workload.kind} through its ${e.workload.via.kind} ${e.workload.via.name}.`));
    const list = el('div', 'containers');
    const byName = new Map(p.images.map((i) => [i.name, i]));
    for (const c of e.containers) {
        const row = el('div', 'container');
        const head = el('div', 'container-head');
        add(head, icon('container'), el('span', 'strong', c.name || 'container'), el('span', 'iname small', c.image), countCells(c.counts), rescanButton(c.report));
        row.appendChild(head);
        const img = byName.get(c.image);
        if (img && img.detailed && total(c.counts)) row.appendChild(findingsTable(img.findings, state.filters));
        list.appendChild(row);
    }
    box.appendChild(list);
    const actions = el('div', 'detail-actions');
    if (total(e.misconfig)) actions.appendChild(button(`${compact(total(e.misconfig))} misconfigurations`, 'ghost small', 'policy', () => go('misconfigurations', { group: 'resource', q: e.workload.name, ns: e.workload.namespace })));
    if (e.secrets) actions.appendChild(button(`${e.secrets} exposed secrets`, 'ghost small', 'key', () => go('secrets', { q: e.workload.name, ns: e.workload.namespace })));
    box.appendChild(actions);
    return box;
}

function rescanButton(report: ReportRef | undefined): HTMLElement {
    if (!report || report.kind !== KINDS.vulnerability) return el('span');
    const b = button('Rescan', 'ghost small', 'rescan', () => {
        sdk.run('rescan-vulnerabilities', { namespace: report.namespace, name: report.name }).catch((err: unknown) => {
            if (!declined(err)) fail(err);
        });
    });
    b.title = `Delete ${report.name} so trivy-operator scans again`;
    return b;
}

// ----- drawing ------------------------------------------------------------------------------

function setFilters(next: Partial<Filters>): void {
    Object.assign(state.filters, next);
    // A new filter starts the list from the top.
    state.tables[state.filters.group].limit = 100;
    remember();
    // The user's own change is drawn now; only polls wait for them.
    keepFocus(document.body, render);
}

// The toolbar lives outside the redrawn part of the page, and its search
// field is made once: redrawing it would take the caret away mid-word.
let search: HTMLElement | null = null;

function drawToolbar(p: Posture): void {
    const f = state.filters;
    const bar = byId('toolbar');
    bar.hidden = false;
    search ??= searchBox(f.q, 'Search CVE, package, image, workload, namespace…', (q) => setFilters({ q }));
    const row1 = el('div', 'toolbar-row');
    add(
        row1,
        segmented<Group>(
            [
                { id: 'cve', label: 'By CVE', icon: 'bug' },
                { id: 'image', label: 'By image', icon: 'image' },
                { id: 'workload', label: 'By workload', icon: 'deployment' },
            ],
            f.group,
            (group) => setFilters({ group }),
        ),
        namespaceSelect(
            p.namespaces.map((n) => n.namespace),
            f.ns,
            (ns) => setFilters({ ns }),
        ),
        toggle('Has a fix', f.fix, 'wrench', (fix) => setFilters({ fix }), 'Only vulnerabilities with a fixed version'),
    );
    // The counts beside each severity are what the other filters leave.
    const counts = zero();
    const other = { ...f, sev: new Set<Severity>() };
    for (const c of cveRows(p, other)) counts[c.severity]++;
    const row2 = el('div', 'toolbar-row');
    row2.appendChild(severityToggles(f.sev, counts, (sev) => setFilters({ sev })));
    mountToolbar(bar, search, [row1], [row2]);
}

function drawSummary(n: number, noun: string, counts: Counts): HTMLElement {
    const node = el('div', 'result');
    add(node, el('strong', '', compact(n)), el('span', 'faint', ' ' + noun), severityBar(counts, { className: 'result-bar' }), countCells(counts));
    return node;
}

function render(): void {
    byId('nav').replaceChildren(nav('vulnerabilities', state.ctx));
    const main = byId('main');
    if (drawAbsence(main, state.feed)) {
        byId('toolbar').hidden = true;
        return;
    }
    const p = state.posture;
    if (!p) return;
    main.textContent = '';
    if (!p.images.length) {
        main.appendChild(el('p', 'quiet big', state.feed?.ready ? 'No vulnerability reports yet. trivy-operator writes one for every container as soon as it has scanned its image.' : 'Reading the reports…'));
        return;
    }
    applyFocus(p);
    drawToolbar(p);
    const f = state.filters;
    const box = el('div', 'table-box');
    if (f.group === 'cve') {
        const rows = cveRows(p, f);
        const counts = zero();
        for (const c of rows) counts[c.severity]++;
        main.appendChild(drawSummary(rows.length, rows.length === 1 ? 'CVE' : 'CVEs', counts));
        main.appendChild(box);
        drawTable(box, { columns: cveColumns(), rows, key: (c) => c.id, expand: (c) => cveDetail(c, p), state: state.tables.cve, onState: remember, tone: (c) => c.severity.toLowerCase(), empty: 'No CVE matches these filters.' });
    } else if (f.group === 'image') {
        const rows = imageRows(p, f);
        const counts = zero();
        for (const r of rows) for (const s of SEVERITIES) counts[s] += r.counts[s];
        main.appendChild(drawSummary(rows.length, rows.length === 1 ? 'image' : 'images', counts));
        main.appendChild(box);
        drawTable(box, { columns: imageColumns(), rows, key: (r) => r.entry.key, expand: imageDetail, state: state.tables.image, onState: remember, tone: (r) => (worstOf(r.counts) ?? 'none').toLowerCase(), empty: 'No image matches these filters.' });
    } else {
        const rows = workloadRows(p, f);
        const counts = zero();
        for (const r of rows) for (const s of SEVERITIES) counts[s] += r.counts[s];
        main.appendChild(drawSummary(rows.length, rows.length === 1 ? 'workload' : 'workloads', counts));
        main.appendChild(box);
        drawTable(box, { columns: workloadColumns(), rows, key: (r) => r.entry.workload.key, expand: (r) => workloadDetail(r, p), state: state.tables.workload, onState: remember, tone: (r) => (worstOf(r.counts) ?? 'none').toLowerCase(), empty: 'No workload matches these filters.' });
    }
}

function worstOf(c: Counts): Severity | null {
    return SEVERITIES.find((s) => c[s] > 0) ?? null;
}

/** Opens the workload of the report the app opened this page on, once. */
function applyFocus(p: Posture): void {
    if (!state.focusReport) return;
    const [ns, name] = state.focusReport.split('/');
    const w = p.workloads.find((x) => x.containers.some((c) => c.report.namespace === ns && c.report.name === name));
    if (!w) return;
    state.focusReport = '';
    state.filters.group = 'workload';
    state.filters.ns = ns ?? '';
    state.tables.workload.open.add(w.workload.key);
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
        byId('nav').replaceChildren(nav('vulnerabilities', ctx));
        const h = await arrival('vulnerabilities');
        const group = (['cve', 'image', 'workload'] as Group[]).includes(h.group as Group) ? (h.group as Group) : 'cve';
        state.filters = { group, q: h.q ?? '', sev: readSeverities(h.sev), ns: h.ns ?? '', fix: h.fix === '1' };
        const t = state.tables[group];
        if (h.sort) t.sort = h.sort;
        if (h.dir === 'desc') t.dir = -1;
        for (const k of (h.open ?? '').split('|').filter(Boolean)) t.open.add(k);
        state.focusReport = h.report ?? '';
        remember();
        startFeed(sdk, { onChange: onFeed, only: ['vulnerability', 'clusterVulnerability', 'configAudit', 'exposedSecret', 'sbom'] });
    })
    .catch(fail);
