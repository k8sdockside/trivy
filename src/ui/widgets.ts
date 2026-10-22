// The pieces every page draws a finding with: its severity, its counts, the
// workload it is on, how old the scan is.

import type { Workload } from '../model/posture';
import { SEVERITIES, SEVERITY_LABEL, total, worst, type Counts, type Severity } from '../model/trivy';
import { add, button, el, icon } from './dom';
import { compact } from './charts';
import { kindIcon } from './icons';
import { sdk } from './page';

/** A severity as a coloured pill: `CRITICAL`, or `CRITICAL 12` with a count. */
export function sevChip(s: Severity, count?: number, title?: string): HTMLElement {
    const node = el('span', 'sev sev-' + s.toLowerCase());
    node.appendChild(el('span', 'sev-name', SEVERITY_LABEL[s]));
    if (count !== undefined) node.appendChild(el('strong', 'sev-count', compact(count)));
    if (title) node.title = title;
    return node;
}

/**
 * The counts as a row of small squares, one per severity -- `3 12 40 5` in
 * their colours -- with the zeroes faint, so rows line up and compare.
 */
export function countCells(c: Counts, opts: { unknown?: boolean } = {}): HTMLElement {
    const node = el('span', 'cells');
    for (const s of SEVERITIES) {
        if (s === 'UNKNOWN' && !opts.unknown && !c.UNKNOWN) continue;
        const cell = el('span', 'cell sev-' + s.toLowerCase() + (c[s] ? '' : ' zero'), c[s] ? compact(c[s]) : '0');
        cell.title = `${SEVERITY_LABEL[s]}: ${c[s]}`;
        node.appendChild(cell);
    }
    return node;
}

/** The worst severity of the counts as a chip, or a calm "clean". */
export function worstChip(c: Counts): HTMLElement {
    const w = worst(c);
    if (!w) {
        const ok = el('span', 'sev sev-none');
        add(ok, icon('check'), el('span', 'sev-name', 'Clean'));
        return ok;
    }
    return sevChip(w, c[w]);
}

/** A workload as a button that opens it in the app. */
export function workloadButton(w: Workload, opts: { namespace?: boolean; detail?: string; onFail?: (err: unknown) => void } = {}): HTMLButtonElement {
    const node = button('', 'wl', kindIcon(w.kind), () => openWorkload(w, opts.onFail));
    node.dataset.focus = 'wl:' + w.key;
    add(
        node,
        el('span', 'wl-kind', w.kind || 'Object'),
        el('span', 'wl-name', w.name),
        opts.namespace !== false && w.namespace ? el('span', 'wl-ns', w.namespace) : null,
        opts.detail ? el('span', 'wl-detail', opts.detail) : null,
    );
    node.title = w.appKind ? `Open ${w.kind} ${w.namespace ? w.namespace + '/' : ''}${w.name}` + (w.via ? ` (scanned through ${w.via.kind} ${w.via.name})` : '') : `${w.kind} ${w.name}: the app has no tab for this kind`;
    if (!w.appKind) node.disabled = true;
    return node;
}

export function openWorkload(w: Workload, onFail?: (err: unknown) => void): void {
    if (!w.appKind) return;
    sdk.open({ kind: w.appKind, namespace: w.namespace, name: w.name }).catch((err: unknown) => onFail?.(err));
}

/** Opens an http(s) link in the user's browser; anything else is left alone. */
export function externalLink(text: string, url: string, onFail?: (err: unknown) => void): HTMLElement {
    if (!/^https?:\/\//i.test(url)) return el('span', '', text);
    const b = el('button', 'link ext');
    b.type = 'button';
    add(b, el('span', '', text), icon('open'));
    b.title = url;
    b.addEventListener('click', (e) => {
        e.stopPropagation();
        sdk.openUrl(url).catch((err: unknown) => onFail?.(err));
    });
    return b;
}

/** "3h ago", written as the app writes ages when it can. */
export function age(ms: number): string {
    if (!ms) return 'never';
    const f = sdk.format;
    if (f) return f.age(ms) + ' ago';
    const d = Math.max(0, Date.now() - ms);
    if (d < 60_000) return 'just now';
    if (d < 3_600_000) return `${Math.round(d / 60_000)}m ago`;
    if (d < 172_800_000) return `${Math.round(d / 3_600_000)}h ago`;
    return `${Math.round(d / 86_400_000)}d ago`;
}

export function dateTime(ms: number): string {
    if (!ms) return '';
    return sdk.format ? sdk.format.dateTime(ms) : new Date(ms).toLocaleString();
}

export function date(ms: number): string {
    if (!ms) return '';
    return sdk.format ? sdk.format.date(ms) : new Date(ms).toLocaleDateString();
}

/** The legend under a severity drawing: each severity's colour, name and count. */
export function severityLegend(c: Counts, opts: { onPick?: (s: Severity) => void; unknown?: boolean } = {}): HTMLElement {
    const node = el('div', 'sev-legend');
    const sum = total(c);
    for (const s of SEVERITIES) {
        if (s === 'UNKNOWN' && !c.UNKNOWN && !opts.unknown) continue;
        const row = opts.onPick ? el('button', 'sev-legend-row') : el('div', 'sev-legend-row');
        if (opts.onPick) {
            (row as HTMLButtonElement).type = 'button';
            row.addEventListener('click', () => opts.onPick!(s));
            row.title = `Show only ${SEVERITY_LABEL[s].toLowerCase()}`;
        }
        const dot = el('i', 'swatch sev-bg-' + s.toLowerCase());
        const share = el('span', 'sev-legend-share');
        const fill = el('i');
        fill.style.width = sum ? `${(c[s] / sum) * 100}%` : '0';
        fill.className = 'sev-bg-' + s.toLowerCase();
        share.appendChild(fill);
        add(row, dot, el('span', 'sev-legend-name', SEVERITY_LABEL[s]), share, el('strong', 'sev-legend-count', compact(c[s])));
        node.appendChild(row);
    }
    return node;
}

/** A labelled fact, for the details under an opened row. */
export function fact(label: string, value: Node | string): HTMLElement {
    const node = el('div', 'fact');
    const v = el('div', 'fact-value');
    add(v, value);
    add(node, el('div', 'fact-label', label), v);
    return node;
}
