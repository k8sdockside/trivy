// Trivy's own overview, in place of the page the app generates.
//
// One picture of everything trivy-operator found: a score and the three
// gauges it is made of, the vulnerabilities by severity and how many have a
// fix, the namespaces as a heatmap, the images and workloads worst off, the
// CVEs that reach the most workloads, the misconfigurations and exposed
// secrets, each compliance report's pass rate, when the CVEs were published,
// and -- from Prometheus, when there is one -- how the counts moved over the
// last day.
//
// Bridge calls used here: ready, summary and watch (through the feed),
// charts, open, openView (through go), openUrl, storage.

import { startFeed, type FeedState } from '../model/feed';
import { AUDIT_LABEL, buildPosture, type AuditKind, type CveEntry, type Posture } from '../model/posture';
import { SEVERITIES, SEVERITY_LABEL, severity, total, zero, type Severity } from '../model/trivy';
import { compact, gauge, heatmap, lineChart, ring, severityBar, severityColumns, severityRing, sevColour } from '../ui/charts';
import { add, button, byId, clear, el, icon } from '../ui/dom';
import { percent, plural, words } from '../ui/format';
import type { IconName } from '../ui/icons';
import { banner, every, politely, sdk } from '../ui/page';
import { absent, aquaMark, drawAbsence, fail, go, loading, mark, nav } from '../ui/shell';
import { age, countCells, externalLink, sevChip, severityLegend, workloadButton } from '../ui/widgets';

const CHARTS_EVERY = 60_000;
const HISTORY_MINUTES = 24 * 60;

interface State {
    ctx: K8sDockside.Context | null;
    feed: FeedState | null;
    posture: Posture | null;
    panel: K8sDockside.ChartsPanel | null;
    sig: string;
}

const state: State = { ctx: null, feed: null, posture: null, panel: null, sig: '' };

function strong(text: string | number, className = ''): HTMLElement {
    return el('strong', className, String(text));
}

function card(id: string, title: string, iconName: IconName, sub?: string, action?: HTMLElement): HTMLElement {
    const box = el('section', 'card ' + id);
    const head = el('div', 'card-head');
    add(head, icon(iconName), el('h2', '', title));
    if (sub) head.appendChild(el('span', 'card-sub', sub));
    if (action) {
        action.classList.add('push');
        head.appendChild(action);
    }
    box.appendChild(head);
    return box;
}

// ----- the hero ---------------------------------------------------------------------

type Tone = 'ok' | 'warn' | 'error' | 'info';

function verdict(p: Posture): { tone: Tone; icon: IconName; status: string } {
    const t = p.totals;
    if (!t.images && !t.resources) return { tone: 'info', icon: 'clock', status: 'trivy-operator has not written any reports yet' };
    if (t.cves.CRITICAL) {
        const fix = t.fixableCritical ? ` — ${plural(t.fixableCritical, 'fix is', 'fixes are')} waiting` : '';
        return { tone: 'error', icon: 'alert', status: `${plural(t.cves.CRITICAL, 'critical vulnerability', 'critical vulnerabilities')} in the running images${fix}` };
    }
    if (t.secrets.CRITICAL || t.secrets.HIGH) return { tone: 'error', icon: 'key', status: `${plural(t.secrets.CRITICAL + t.secrets.HIGH, 'secret is', 'secrets are')} exposed inside images` };
    if (t.cves.HIGH || t.misconfig.CRITICAL) {
        const parts: string[] = [];
        if (t.cves.HIGH) parts.push(plural(t.cves.HIGH, 'high vulnerability', 'high vulnerabilities'));
        if (t.misconfig.CRITICAL) parts.push(plural(t.misconfig.CRITICAL, 'critical misconfiguration', 'critical misconfigurations'));
        return { tone: 'warn', icon: 'alert', status: `No critical vulnerabilities — ${words(parts)} to look at` };
    }
    return { tone: 'ok', icon: 'check', status: 'No critical or high vulnerabilities in any running image' };
}

function headline(p: Posture): string {
    const t = p.totals;
    const cves = total(t.cves);
    if (!t.images) return t.resources ? `${plural(t.resources, 'resource')} audited` : 'Waiting for the first scans';
    return `${compact(cves)} ${cves === 1 ? 'vulnerability' : 'vulnerabilities'} across ${plural(t.images, 'image')}`;
}

function story(p: Posture): HTMLElement {
    const t = p.totals;
    const node = el('p', 'story');
    if (t.images) {
        add(node, strong(plural(t.workloads, 'workload')), ' run ', strong(plural(t.images, 'scanned image')), '; ', strong(`${t.cleanImages}`, t.cleanImages === t.images ? 'ok' : ''), ` ${t.cleanImages === 1 ? 'is' : 'are'} free of critical and high vulnerabilities. `);
        const findings = total(t.findings);
        if (findings) add(node, strong(percent(t.fixable, findings), t.fixable ? 'ok' : ''), ' of the findings have a fixed version available. ');
        if (t.eoslImages) add(node, strong(t.eoslImages, 'warnish'), ` ${t.eoslImages === 1 ? 'image runs' : 'images run'} an operating system past its end of support. `);
    }
    const mis = total(t.misconfig);
    if (t.resources) add(node, strong(compact(mis), t.misconfig.CRITICAL || t.misconfig.HIGH ? 'warnish' : ''), ` failed ${mis === 1 ? 'check' : 'checks'} on ${plural(t.resources, 'audited resource')}`);
    const sec = total(t.secrets);
    if (sec) add(node, t.resources ? ', and ' : '', strong(sec, 'bad'), ` exposed ${sec === 1 ? 'secret' : 'secrets'} in ${plural(t.imagesWithSecrets, 'image')}`);
    if (t.resources || sec) add(node, '.');
    return node;
}

function drawHero(p: Posture): HTMLElement {
    const v = verdict(p);
    const hero = el('section', 'hero ' + v.tone);
    const main = el('div', 'hero-main');
    const h1 = el('h1', 'verdict');
    add(h1, icon(v.icon), el('span', '', headline(p)));
    const status = el('p', 'status ' + v.tone);
    add(status, el('i', 'sdot ' + v.tone), el('span', '', v.status));
    const cta = el('div', 'cta');
    add(
        cta,
        button('Vulnerabilities', 'primary', 'bug', () => go('vulnerabilities')),
        button('Fixable critical & high', 'ghost', 'wrench', () => go('vulnerabilities', { sev: 'CRITICAL,HIGH', fix: '1' })),
        button('Misconfigurations', 'ghost', 'policy', () => go('misconfigurations')),
        button('Compliance', 'ghost', 'certificate', () => go('compliance')),
    );
    add(main, h1, status, story(p), cta);
    hero.appendChild(main);
    hero.appendChild(scoreDial(p));
    return hero;
}

const GRADE_TONE: Record<string, string> = { A: 'ok', B: 'ok', C: 'fair', D: 'warn', E: 'bad', F: 'bad', '–': 'none' };

function scoreDial(p: Posture): HTMLElement {
    const s = p.score;
    const side = el('div', 'hero-side');
    const tone = GRADE_TONE[s.grade] ?? 'none';
    const centre = el('div', 'ring-text');
    add(centre, el('div', 'grade grade-' + tone, s.grade), el('div', 'ring-small', s.value === null ? 'not scored yet' : `${s.value} / 100`));
    const fill = s.value ?? 0;
    const dial = ring(
        [
            { value: fill, colour: `var(--tone-${tone})`, title: `Security score ${s.value ?? '—'} of 100` },
            { value: 100 - fill, colour: 'transparent', title: '' },
        ],
        centre,
        { size: 170, thickness: 16, label: `Security score ${s.value ?? 'not measured'} of 100, grade ${s.grade}` },
    );
    dial.classList.add('score-ring');
    const caption = el('div', 'score-caption');
    add(caption, el('span', 'mini-title', 'Security score'), el('span', 'faint small', 'The average of the gauges below, less a little for every critical fix left waiting.'));
    add(side, dial, caption);
    return side;
}

// ----- score parts and severity ------------------------------------------------------------

function drawGauges(p: Posture): HTMLElement {
    const box = card('gauges', 'What the score is made of', 'gauge');
    const row = el('div', 'gauge-row');
    const target: Record<string, () => void> = {
        images: () => go('vulnerabilities', { group: 'image' }),
        resources: () => go('misconfigurations'),
        compliance: () => go('compliance'),
    };
    for (const g of p.score.gauges) {
        const gnode = gauge(g.value, g.label, g.detail);
        const b = el('button', 'gauge-button');
        b.type = 'button';
        b.dataset.focus = 'gauge:' + g.id;
        b.appendChild(gnode);
        b.addEventListener('click', target[g.id] ?? (() => undefined));
        row.appendChild(b);
    }
    box.appendChild(row);
    return box;
}

function drawSeverity(p: Posture): HTMLElement {
    const t = p.totals;
    const box = card('severity', 'Vulnerabilities by severity', 'bug', 'Each CVE counted once, at its worst.');
    const body = el('div', 'sev-body');
    const centre = el('div', 'ring-text');
    const cves = total(t.cves);
    add(centre, el('div', 'ring-big', compact(cves)), el('div', 'ring-small', cves === 1 ? 'CVE' : 'CVEs'));
    body.appendChild(severityRing(t.cves, centre, { size: 168, thickness: 18, noun: 'CVEs' }));
    const side = el('div', 'sev-side');
    side.appendChild(severityLegend(t.cves, { onPick: (s) => go('vulnerabilities', { sev: s }) }));

    const findings = total(t.findings);
    const fix = el('div', 'fixmeter');
    const bar = el('div', 'meter-bar big');
    const fill = el('i', 'meter-fill ok');
    fill.style.width = findings ? `${(t.fixable / findings) * 100}%` : '0';
    bar.appendChild(fill);
    const fixLine = el('div', 'fixmeter-line');
    add(fixLine, icon('wrench'), el('span', '', 'Fix available'), strong(findings ? percent(t.fixable, findings) : '—'));
    add(fix, fixLine, bar, el('div', 'faint small', `${compact(t.fixable)} of ${compact(findings)} findings · ${t.fixableCritical} critical, ${t.fixableHigh} high`));
    side.appendChild(fix);
    body.appendChild(side);
    box.appendChild(body);
    return box;
}

// ----- the numbers -------------------------------------------------------------------------

function tile(label: string, value: string, sub: string, tone: string, iconName: IconName, onClick?: () => void, extra?: HTMLElement): HTMLElement {
    const node = onClick ? el('button', 'stat' + (tone ? ' ' + tone : '')) : el('div', 'stat' + (tone ? ' ' + tone : ''));
    if (onClick) {
        (node as HTMLButtonElement).type = 'button';
        node.addEventListener('click', onClick);
        node.dataset.focus = 'tile:' + label;
    }
    const top = el('div', 'stat-top');
    add(top, icon(iconName), el('span', '', label));
    add(node, top, el('div', 'stat-value', value), extra ?? null, el('div', 'stat-sub', sub));
    return node;
}

function drawStats(p: Posture): HTMLElement {
    const t = p.totals;
    const box = el('section', 'stats');
    const mis = total(t.misconfig);
    const sec = total(t.secrets);
    const clean = el('div', 'stat-meter');
    const cf = el('i');
    cf.style.width = percent(t.cleanImages, t.images);
    clean.appendChild(cf);
    add(
        box,
        tile('Critical', compact(t.cves.CRITICAL), t.cves.CRITICAL ? `${t.fixableCritical} with a fix` : 'none found', t.cves.CRITICAL ? 'critical' : 'ok', 'alert', () => go('vulnerabilities', { sev: 'CRITICAL' })),
        tile('High', compact(t.cves.HIGH), t.cves.HIGH ? `${t.fixableHigh} with a fix` : 'none found', t.cves.HIGH ? 'high' : 'ok', 'alert', () => go('vulnerabilities', { sev: 'HIGH' })),
        tile('Images scanned', String(t.images), `${t.cleanImages} clean of critical and high`, '', 'image', () => go('vulnerabilities', { group: 'image' }), clean),
        tile('Misconfigurations', compact(mis), mis ? `${t.misconfig.CRITICAL} critical · ${t.misconfig.HIGH} high` : t.resources ? 'every check passes' : 'no audits yet', t.misconfig.CRITICAL ? 'critical' : t.misconfig.HIGH ? 'high' : mis ? '' : 'ok', 'policy', () => go('misconfigurations')),
        tile('Exposed secrets', String(sec), sec ? `in ${plural(t.imagesWithSecrets, 'image')}` : 'none found', sec ? 'critical' : 'ok', 'key', () => go('secrets')),
        tile('Last scan', t.newest ? age(t.newest) : '—', t.stale ? `${plural(t.stale, 'report')} older than a day` : `${plural(t.reports, 'report')}, all fresh`, t.stale ? 'warn' : '', 'clock'),
    );
    return box;
}

// ----- namespaces, images, workloads ----------------------------------------------------------

function drawHeatmap(p: Posture): HTMLElement {
    const box = card('heatmap', 'Namespaces', 'heat', 'Darker is more, compared within each column.');
    const rows = p.namespaces.filter((n) => total(n.vulns) + total(n.misconfig) + total(n.secrets) > 0).slice(0, 14);
    if (!rows.length) {
        box.appendChild(el('p', 'quiet', 'No namespace has any findings.'));
        return box;
    }
    const cols = [
        ...(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Severity[]).map((s) => ({ label: SEVERITY_LABEL[s], colour: sevColour(s), title: `${SEVERITY_LABEL[s]} vulnerability findings` })),
        { label: 'Config', colour: 'var(--c-accent)', title: 'Failed configuration, RBAC and infra checks' },
        { label: 'Secrets', colour: sevColour('CRITICAL'), title: 'Exposed secrets in images' },
    ];
    box.appendChild(
        heatmap(
            cols,
            rows.map((n) => ({
                label: n.namespace || '(cluster)',
                values: [n.vulns.CRITICAL, n.vulns.HIGH, n.vulns.MEDIUM, n.vulns.LOW, total(n.misconfig), total(n.secrets)],
                title: `${n.namespace || 'cluster-scoped'}: ${plural(n.images, 'image')}, ${plural(n.workloads, 'workload')} — open its vulnerabilities`,
                onClick: () => go('vulnerabilities', { ns: n.namespace, group: 'workload' }),
            })),
        ),
    );
    if (p.namespaces.length > rows.length) box.appendChild(el('p', 'faint small more-note', `and ${plural(p.namespaces.length - rows.length, 'more namespace')}`));
    return box;
}

function drawImages(p: Posture): HTMLElement {
    const box = card('top-images', 'Most vulnerable images', 'image', '', button('All images', 'ghost small', 'grid', () => go('vulnerabilities', { group: 'image' })));
    const top = p.images.filter((i) => total(i.counts) > 0).slice(0, 8);
    if (!top.length) {
        box.appendChild(el('p', 'quiet', p.images.length ? 'No scanned image has a known vulnerability.' : 'No images scanned yet.'));
        return box;
    }
    const max = Math.max(...top.map((i) => total(i.counts)));
    const list = el('ol', 'bars');
    for (const img of top) {
        const li = el('li');
        const row = el('button', 'bar-row');
        row.type = 'button';
        row.dataset.focus = 'img:' + img.key;
        row.title = `${img.name}\n${img.os}${img.eosl ? ' (end of support)' : ''}\nUsed by ${plural(img.workloads.length, 'workload')}`;
        row.addEventListener('click', () => go('vulnerabilities', { group: 'image', q: img.name }));
        const label = el('div', 'bar-label');
        add(label, el('span', 'iname', img.name), img.eosl ? el('span', 'tag warn', 'EOSL') : null, el('span', 'bar-note', `${plural(img.workloads.length, 'workload')} · ${compact(total(img.counts))}`));
        add(row, label, severityBar(img.counts, { max }), countCells(img.counts));
        li.appendChild(row);
        list.appendChild(li);
    }
    box.appendChild(list);
    return box;
}

function drawWorkloads(p: Posture): HTMLElement {
    const box = card('top-workloads', 'Workloads at risk', 'deployment', '', button('All workloads', 'ghost small', 'grid', () => go('vulnerabilities', { group: 'workload' })));
    const top = p.workloads.filter((w) => w.counts.CRITICAL || w.counts.HIGH).slice(0, 8);
    if (!top.length) {
        box.appendChild(el('p', 'quiet', 'No workload runs an image with a critical or high vulnerability.'));
        return box;
    }
    const list = el('ol', 'wl-list');
    for (const w of top) {
        const li = el('li', 'wl-row');
        const right = el('div', 'wl-right');
        add(right, countCells(w.counts), w.secrets ? sevChip('CRITICAL', w.secrets, 'Exposed secrets') : null);
        add(li, workloadButton(w.workload, { onFail: fail, detail: plural(w.images.length, 'image') }), right);
        list.appendChild(li);
    }
    box.appendChild(list);
    return box;
}

// ----- CVEs ---------------------------------------------------------------------------------

function drawCves(p: Posture): HTMLElement {
    const box = card('top-cves', 'CVEs that reach the furthest', 'bug', 'Critical and high first, then by how many images carry them.', button('All vulnerabilities', 'ghost small', 'grid', () => go('vulnerabilities')));
    const top = p.cves.filter((c) => c.severity === 'CRITICAL' || c.severity === 'HIGH').slice(0, 10);
    const list = top.length ? top : p.cves.slice(0, 10);
    if (!list.length) {
        box.appendChild(el('p', 'quiet', 'No vulnerabilities found.'));
        return box;
    }
    const maxImages = Math.max(...list.map((c) => c.images.length));
    const table = el('table', 'tbl compact');
    const hr = el('tr');
    for (const h of ['Severity', 'CVE', 'Package', 'Fixed in', 'Score', 'Images', 'Workloads']) hr.appendChild(el('th', h === 'Images' ? 'reach' : '', h));
    const head = el('thead');
    head.appendChild(hr);
    table.appendChild(head);
    const body = el('tbody');
    for (const c of list) body.appendChild(cveRow(c, maxImages));
    table.appendChild(body);
    const scroll = el('div', 'tbl-scroll');
    scroll.appendChild(table);
    box.appendChild(scroll);
    return box;
}

function cveRow(c: CveEntry, maxImages: number): HTMLElement {
    const tr = el('tr', 'tbl-row clickable');
    tr.dataset.tone = c.severity.toLowerCase();
    tr.title = c.title || c.id;
    tr.addEventListener('click', (e) => {
        if ((e.target as HTMLElement).closest('button')) return;
        go('vulnerabilities', { group: 'cve', q: c.id, open: c.id });
    });
    const id = el('td', 'cve-id');
    add(id, c.link ? externalLink(c.id, c.link, fail) : el('span', 'mono', c.id), c.title ? el('div', 'cve-title', c.title) : null);
    const pkg = el('td', 'mono small', c.packages.slice(0, 2).join(', ') + (c.packages.length > 2 ? ` +${c.packages.length - 2}` : ''));
    const fixed = el('td');
    fixed.appendChild(c.fixable ? el('span', 'fixed mono', c.fixed.slice(0, 2).join(', ')) : el('span', 'faint', 'no fix yet'));
    const reach = el('td', 'reach');
    const bar = el('span', 'reach-bar');
    const fill = el('i');
    fill.style.width = `${(c.images.length / maxImages) * 100}%`;
    fill.style.background = sevColour(c.severity);
    bar.appendChild(fill);
    add(reach, bar, el('span', 'reach-n', String(c.images.length)));
    const sevTd = el('td');
    sevTd.appendChild(sevChip(c.severity));
    add(tr, sevTd, id, pkg, fixed, el('td', 'num', c.score === null ? '—' : c.score.toFixed(1)), reach, el('td', 'num', String(c.workloads.length)));
    return tr;
}

function drawYears(p: Posture): HTMLElement {
    const box = card('years', 'When the CVEs were published', 'calendar', 'Old CVEs still running are the easiest wins: their fixes have been out for a while.');
    if (!p.byYear.length) {
        box.appendChild(el('p', 'quiet', 'The reports carry no publication dates.'));
        return box;
    }
    // At most the last twelve years, the rest folded into the first column.
    const years = p.byYear;
    const shown = years.slice(-12);
    const older = years.slice(0, -12);
    const data = shown.map((y) => ({ label: String(y.year), counts: y.counts }));
    if (older.length) {
        const c = zero();
        for (const y of older) for (const s of SEVERITIES) c[s] += y.counts[s];
        data.unshift({ label: `≤${older[older.length - 1]!.year}`, counts: c });
    }
    box.appendChild(severityColumns(data, { noun: 'CVEs' }));
    return box;
}

// ----- misconfigurations, secrets, compliance -------------------------------------------------

function drawMisconfig(p: Posture): HTMLElement {
    const t = p.totals;
    const box = card('misconfig', 'Misconfigurations', 'policy', '', button('Open', 'ghost small', 'grid', () => go('misconfigurations')));
    if (!t.resources) {
        box.appendChild(el('p', 'quiet', 'No config audit reports yet. trivy-operator writes them when its config audit scanner is on, as it is by default.'));
        return box;
    }
    const body = el('div', 'sev-body');
    const centre = el('div', 'ring-text');
    const n = total(t.misconfig);
    add(centre, el('div', 'ring-big', compact(n)), el('div', 'ring-small', n === 1 ? 'failed check' : 'failed checks'));
    body.appendChild(severityRing(t.misconfig, centre, { size: 140, thickness: 15, noun: 'failed checks' }));
    const side = el('div', 'sev-side');
    const kinds = el('div', 'audit-kinds');
    const max = Math.max(1, ...(Object.keys(t.misconfigBy) as AuditKind[]).map((k) => total(t.misconfigBy[k])));
    for (const k of Object.keys(t.misconfigBy) as AuditKind[]) {
        const c = t.misconfigBy[k];
        const row = el('button', 'audit-kind');
        row.type = 'button';
        row.addEventListener('click', () => go('misconfigurations', { audit: k }));
        add(row, el('span', 'audit-label', AUDIT_LABEL[k]), severityBar(c, { max }), el('strong', '', compact(total(c))));
        kinds.appendChild(row);
    }
    side.appendChild(kinds);
    body.appendChild(side);
    box.appendChild(body);

    const checks = p.checks.slice(0, 5);
    if (checks.length) {
        const list = el('ol', 'check-list');
        list.appendChild(el('div', 'mini-title', 'Failing most often'));
        for (const c of checks) {
            const li = el('li');
            const b = el('button', 'check-row');
            b.type = 'button';
            b.title = c.description || c.title;
            b.addEventListener('click', () => go('misconfigurations', { group: 'check', q: c.checkID, audit: c.audit }));
            add(b, sevChip(c.severity), el('span', 'check-id mono', c.checkID), el('span', 'check-title', c.title), el('span', 'check-n', plural(c.resources.length, 'resource')));
            li.appendChild(b);
            list.appendChild(li);
        }
        box.appendChild(list);
    }
    return box;
}

function drawSecrets(p: Posture): HTMLElement {
    const box = card('secrets', 'Exposed secrets', 'key', '', p.secrets.length ? button('Open', 'ghost small', 'grid', () => go('secrets')) : undefined);
    if (!p.secrets.length) {
        const ok = el('div', 'all-clear');
        add(ok, icon('check'), el('span', '', p.totals.images ? 'No secrets found inside any scanned image.' : 'No exposed secret reports yet.'));
        box.appendChild(ok);
        return box;
    }
    box.classList.add('alarm');
    const list = el('ol', 'secret-list');
    for (const s of p.secrets.slice(0, 6)) {
        const li = el('li', 'secret-row');
        const what = el('div', 'secret-what');
        add(what, sevChip(s.severity), el('span', 'secret-title', s.title), el('span', 'faint mono small', s.target));
        add(li, what, workloadButton(s.workload, { onFail: fail }));
        list.appendChild(li);
    }
    box.appendChild(list);
    if (p.secrets.length > 6) box.appendChild(el('p', 'faint small more-note', `and ${plural(p.secrets.length - 6, 'more')}`));
    return box;
}

function drawCompliance(p: Posture): HTMLElement | null {
    if (!p.compliance.length) return null;
    const box = card('compliance', 'Compliance', 'certificate', 'Controls passing in each report trivy-operator keeps.', button('Open', 'ghost small', 'grid', () => go('compliance')));
    const grid = el('div', 'comp-grid');
    for (const c of p.compliance) {
        const b = el('button', 'comp-card');
        b.type = 'button';
        b.dataset.focus = 'comp:' + c.name;
        b.addEventListener('click', () => go('compliance', { report: c.name }));
        const rate = c.rate;
        const tone = rate === null ? 'none' : rate >= 0.9 ? 'ok' : rate >= 0.7 ? 'fair' : rate >= 0.5 ? 'warn' : 'bad';
        const centre = el('div', 'ring-text');
        add(centre, el('div', 'ring-mid', rate === null ? '—' : `${Math.round(rate * 100)}%`));
        const r = ring(
            [
                { value: c.pass, colour: `var(--tone-${tone})`, title: `${c.pass} passing` },
                { value: c.fail, colour: 'var(--c-line)', title: `${c.fail} failing` },
            ],
            centre,
            { size: 92, thickness: 10, label: `${c.title}: ${c.pass} of ${c.pass + c.fail} controls passing` },
        );
        const text = el('div', 'comp-text');
        const worstControls = c.controls.filter((x) => x.fail > 0).slice(0, 2);
        add(text, el('div', 'comp-title', c.title), el('div', 'faint small', `${c.pass} passing · ${c.fail} failing` + (c.updated ? ` · ${age(c.updated)}` : '')));
        for (const w of worstControls) {
            const line = el('div', 'comp-control');
            add(line, el('i', 'sdot sev-bg-' + w.severity.toLowerCase()), el('span', '', `${w.id} ${w.name}`));
            text.appendChild(line);
        }
        add(b, r, text);
        grid.appendChild(b);
    }
    box.appendChild(grid);
    return box;
}

// ----- history, from Prometheus -------------------------------------------------------------

function seriesColour(name: string): string {
    const s = severity(name);
    return sevColour(s);
}

function seriesOrder(a: string, b: string): number {
    return SEVERITIES.indexOf(severity(a)) - SEVERITIES.indexOf(severity(b));
}

function drawHistory(): void {
    const box = byId('history');
    clear(box);
    const panel = state.panel;
    box.hidden = !panel || !panel.attached || !state.posture || !state.posture.totals.reports;
    if (box.hidden || !panel) return;
    const head = el('div', 'section-head');
    add(head, icon('chart'), el('h2', '', `Over the last ${Math.round(panel.range / 60) || 24} hours`));
    if (panel.source.available && panel.source.describe) head.appendChild(el('span', 'card-sub', 'From Prometheus at ' + panel.source.describe));
    box.appendChild(head);
    if (!panel.source.available) {
        box.appendChild(el('p', 'quiet', 'No Prometheus was found in this cluster, so there is no history to draw — everything above comes from the reports themselves. ' + (panel.source.error || 'If yours lives somewhere the app did not look, set its address in the cluster’s settings.')));
        return;
    }
    const row = el('div', 'chart-row');
    for (const chart of panel.charts) row.appendChild(lineChart(chart, seriesColour, seriesOrder));
    box.appendChild(row);
}

// ----- the foot -----------------------------------------------------------------------------

function drawFoot(): HTMLElement {
    const box = el('footer', 'foot');
    const summary = state.feed?.summary;
    if (summary && summary.requirements.length) {
        const reqs = el('div', 'reqs');
        reqs.appendChild(el('span', 'reqs-label', 'Reports this cluster serves'));
        for (const r of summary.requirements) {
            const tone = r.error ? 'warn' : r.served ? 'ok' : r.optional ? 'muted' : 'error';
            const chip = el('span', 'chip ' + tone);
            add(chip, icon(r.error ? 'alert' : r.served ? 'check' : 'close'), el('span', '', r.label));
            chip.title = r.error || r.kind;
            reqs.appendChild(chip);
        }
        box.appendChild(reqs);
    }
    const errors = Object.entries(state.feed?.errors ?? {});
    if (errors.length) {
        const note = el('p', 'foot-note');
        add(note, icon('info'), el('span', '', 'Could not read: ' + errors.map(([k, m]) => `${k} (${m})`).join(' · ')));
        box.appendChild(note);
    }
    const plugin = state.ctx?.plugin;
    const about = el('div', 'about');
    const who = el('span', 'about-name');
    add(who, mark(), el('span', '', plugin?.name || 'Trivy'), plugin?.version ? el('span', 'about-version', 'v' + plugin.version) : null);
    about.appendChild(who);
    const credit = el('span', 'about-credit');
    add(credit, aquaMark(), el('span', '', 'Reports by trivy-operator, from Aqua Security'));
    about.appendChild(credit);
    const go2 = el('div', 'go');
    add(
        go2,
        button('Operator', 'ghost small', 'rocket', () => go('operator')),
        button('Scan jobs', 'ghost small', 'play', () => go('scan-jobs')),
    );
    about.appendChild(go2);
    for (const l of plugin?.links ?? []) about.appendChild(externalLink(l.label || l.url, l.url, fail));
    box.appendChild(about);
    return box;
}

// ----- putting it together ---------------------------------------------------------------------

function render(): void {
    const main = byId('main');
    byId('nav').replaceChildren(nav('overview', state.ctx));
    const foot = byId('foot');
    if (drawAbsence(main, state.feed)) {
        byId('history').hidden = true;
        foot.replaceChildren(drawFoot());
        return;
    }
    const p = state.posture;
    if (!p) return;
    clear(main);
    foot.replaceChildren(drawFoot());
    if (!p.totals.reports) {
        const wait = el('section', 'absent');
        const art = el('div', 'empty-art brand');
        art.appendChild(mark('mark big'));
        add(
            wait,
            art,
            el('h1', 'absent-title', 'No reports yet'),
            el('p', 'absent-text', 'trivy-operator is installed but has not written a report yet. Its first scan jobs run as soon as it starts — each pulls a vulnerability database and then one image, so the first reports take a few minutes. They appear here on their own.'),
        );
        const cta = el('div', 'cta');
        add(cta, button('Scan jobs', 'primary', 'play', () => go('scan-jobs')), button('Operator pods', 'ghost', 'rocket', () => go('operator')));
        wait.appendChild(cta);
        main.appendChild(wait);
        return;
    }
    const top = el('div', 'grid two wide-left');
    add(top, drawSeverity(p), drawGauges(p));
    const mid = el('div', 'grid two');
    add(mid, drawHeatmap(p), drawImages(p));
    const low = el('div', 'grid two');
    add(low, drawMisconfig(p), drawSecrets(p));
    const last = el('div', 'grid two');
    add(last, drawWorkloads(p), drawYears(p));
    add(main, drawHero(p), drawStats(p), top, mid, drawCves(p), low, drawCompliance(p), last);
    drawHistory();
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
    .then((ctx) => {
        state.ctx = ctx;
        byId('nav').replaceChildren(nav('overview', ctx));
        startFeed(sdk, { onChange: onFeed });
        every(CHARTS_EVERY, async () => {
            state.panel = await sdk.charts({ minutes: HISTORY_MINUTES });
            if (state.posture) drawHistory();
        });
    })
    .catch(fail);

