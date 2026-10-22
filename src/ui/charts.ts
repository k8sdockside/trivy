// The drawings: a ring of shares, a gauge, bars split by severity, columns,
// a heatmap and line charts for the Prometheus history. Plain SVG and HTML,
// no library -- the page cannot load one from the network anyway.
//
// Colours are set as styles, never as presentation attributes: a style can
// hold var(--sev-high), so the drawings follow the theme without being drawn
// again.

import { SEVERITIES, SEVERITY_LABEL, total, type Counts, type Severity } from '../model/trivy';
import { add, el, svg } from './dom';

export function sevColour(s: Severity | 'NONE'): string {
    return `var(--sev-${s.toLowerCase()})`;
}

// ----- the ring ---------------------------------------------------------------------

export interface Slice {
    value: number;
    colour: string;
    title: string;
}

/**
 * A ring with one arc per slice, in the order given, a hairline gap between
 * them, and whatever `centre` holds written in the middle.
 */
export function ring(slices: Slice[], centre: Node, opts: { size?: number; thickness?: number; label?: string } = {}): HTMLElement {
    const size = opts.size ?? 184;
    const thickness = opts.thickness ?? 20;
    const r = (size - thickness) / 2;
    const c = 2 * Math.PI * r;
    const mid = size / 2;
    const wrap = el('div', 'ring');
    wrap.style.width = wrap.style.height = size + 'px';
    const drawing = svg('svg', { viewBox: `0 0 ${size} ${size}`, class: 'ring-svg', role: 'img' });
    if (opts.label) drawing.setAttribute('aria-label', opts.label);
    drawing.appendChild(svg('circle', { cx: mid, cy: mid, r, class: 'ring-track', 'stroke-width': thickness }));

    const sum = slices.reduce((n, s) => n + s.value, 0);
    const shown = slices.filter((s) => s.value > 0);
    const gap = shown.length > 1 ? Math.min(3, c / shown.length / 4) : 0;
    let offset = 0;
    for (const s of shown) {
        const length = (s.value / sum) * c;
        const arc = svg('circle', {
            cx: mid,
            cy: mid,
            r,
            class: 'ring-arc',
            'stroke-width': thickness,
            'stroke-dasharray': `${Math.max(0.8, length - gap)} ${c}`,
            'stroke-dashoffset': String(-offset),
            transform: `rotate(-90 ${mid} ${mid})`,
        });
        arc.style.stroke = s.colour;
        const title = svg('title');
        title.textContent = s.title;
        arc.appendChild(title);
        drawing.appendChild(arc);
        offset += length;
    }
    const inner = el('div', 'ring-centre');
    inner.appendChild(centre);
    add(wrap, drawing, inner);
    return wrap;
}

/** A ring of counts by severity, worst first. */
export function severityRing(counts: Counts, centre: Node, opts: { size?: number; thickness?: number; noun?: string } = {}): HTMLElement {
    const noun = opts.noun ?? 'findings';
    const slices = SEVERITIES.map((s) => ({ value: counts[s], colour: sevColour(s), title: `${SEVERITY_LABEL[s]}: ${counts[s]} ${noun}` }));
    if (!total(counts)) slices.push({ value: 1, colour: sevColour('NONE'), title: `No ${noun}` });
    return ring(slices, centre, { ...opts, label: `${noun} by severity: ` + SEVERITIES.map((s) => `${SEVERITY_LABEL[s]} ${counts[s]}`).join(', ') });
}

// ----- the gauge ----------------------------------------------------------------------

/** Half a ring filled to `value` (0..1), the percentage in the middle. */
export function gauge(value: number | null, label: string, detail: string): HTMLElement {
    const node = el('div', 'gauge ' + gaugeTone(value));
    const W = 140;
    const r = 56;
    const cx = W / 2;
    const cy = 66;
    const len = Math.PI * r;
    const arcPath = `M${cx - r} ${cy} A${r} ${r} 0 0 1 ${cx + r} ${cy}`;
    const drawing = svg('svg', { viewBox: `0 0 ${W} 76`, class: 'gauge-svg', role: 'img', 'aria-label': `${label}: ${value === null ? 'not measured' : Math.round(value * 100) + '%'}` });
    drawing.appendChild(svg('path', { d: arcPath, class: 'gauge-track' }));
    if (value !== null) {
        const fill = svg('path', { d: arcPath, class: 'gauge-fill', 'stroke-dasharray': `${Math.max(0.01, value) * len} ${len}` });
        drawing.appendChild(fill);
    }
    const text = el('div', 'gauge-value', value === null ? '—' : `${Math.round(value * 100)}%`);
    add(node, drawing, text, el('div', 'gauge-label', label), el('div', 'gauge-detail', detail));
    node.title = detail;
    return node;
}

export function gaugeTone(value: number | null): string {
    if (value === null) return 'none';
    return value >= 0.9 ? 'ok' : value >= 0.7 ? 'fair' : value >= 0.5 ? 'warn' : 'bad';
}

// ----- bars ------------------------------------------------------------------------------

/**
 * One bar split by severity. With `max`, the bar is as long as its total is
 * of `max` -- so a list of bars compares -- otherwise it fills its track.
 */
export function severityBar(counts: Counts, opts: { max?: number; className?: string; noun?: string } = {}): HTMLElement {
    const sum = total(counts);
    const track = el('div', 'sevbar' + (opts.className ? ' ' + opts.className : ''));
    const inner = el('div', 'sevbar-fill');
    inner.style.width = opts.max ? `${Math.max(sum ? 2 : 0, (sum / opts.max) * 100)}%` : '100%';
    for (const s of SEVERITIES) {
        if (!counts[s]) continue;
        const seg = el('i', 'sevbar-seg');
        seg.style.flexGrow = String(counts[s]);
        seg.style.background = sevColour(s);
        seg.title = `${SEVERITY_LABEL[s]}: ${counts[s]}`;
        inner.appendChild(seg);
    }
    track.appendChild(inner);
    track.title = sum ? SEVERITIES.filter((s) => counts[s]).map((s) => `${SEVERITY_LABEL[s]} ${counts[s]}`).join(' · ') + (opts.noun ? ' ' + opts.noun : '') : 'none';
    return track;
}

// ----- columns ---------------------------------------------------------------------------

/** Columns stacked by severity: one per label, the worst at the top. */
export function severityColumns(data: { label: string; counts: Counts; title?: string }[], opts: { height?: number; noun?: string } = {}): HTMLElement {
    const height = opts.height ?? 140;
    const wrap = el('div', 'cols');
    const max = Math.max(1, ...data.map((d) => total(d.counts)));
    const plot = el('div', 'cols-plot');
    plot.style.height = height + 'px';
    for (const d of data) {
        const col = el('div', 'col');
        const stack = el('div', 'col-stack');
        const sum = total(d.counts);
        stack.style.height = `${(sum / max) * 100}%`;
        // Lowest severity at the bottom, so the critical sits on top.
        for (const s of [...SEVERITIES].reverse()) {
            if (!d.counts[s]) continue;
            const seg = el('i', 'col-seg');
            seg.style.flexGrow = String(d.counts[s]);
            seg.style.background = sevColour(s);
            stack.appendChild(seg);
        }
        col.title = d.title ?? `${d.label}: ${sum} ${opts.noun ?? ''}`.trim() + (sum ? ' — ' + SEVERITIES.filter((s) => d.counts[s]).map((s) => `${SEVERITY_LABEL[s]} ${d.counts[s]}`).join(', ') : '');
        add(col, el('span', 'col-num', sum ? String(sum) : ''), stack);
        plot.appendChild(col);
    }
    const axis = el('div', 'cols-axis');
    for (const d of data) axis.appendChild(el('span', '', d.label));
    add(wrap, plot, axis);
    return wrap;
}

// ----- the heatmap ------------------------------------------------------------------------

export interface HeatColumn {
    label: string;
    /** A CSS colour the cells mix towards as their value grows. */
    colour: string;
    title?: string;
}

export interface HeatRow {
    label: string;
    values: number[];
    onClick?: () => void;
    title?: string;
}

/**
 * Rows against columns, each cell tinted by how its value compares with the
 * largest in its column -- a namespace with 3 criticals still shows when
 * another has 900 lows -- and its number written in it.
 */
export function heatmap(columns: HeatColumn[], rows: HeatRow[]): HTMLElement {
    const grid = el('div', 'heat');
    grid.style.gridTemplateColumns = `minmax(110px, 1.6fr) repeat(${columns.length}, minmax(52px, 1fr))`;
    grid.appendChild(el('span', 'heat-corner'));
    for (const c of columns) {
        const h = el('span', 'heat-col', c.label);
        if (c.title) h.title = c.title;
        grid.appendChild(h);
    }
    const max = columns.map((_, i) => Math.max(0, ...rows.map((r) => r.values[i] ?? 0)));
    for (const r of rows) {
        const label = r.onClick ? el('button', 'heat-row link') : el('span', 'heat-row');
        label.textContent = r.label;
        if (r.onClick) {
            (label as HTMLButtonElement).type = 'button';
            label.addEventListener('click', r.onClick);
        }
        if (r.title) label.title = r.title;
        grid.appendChild(label);
        r.values.forEach((v, i) => {
            const cell = el('span', 'heat-cell' + (v ? '' : ' empty'), v ? compact(v) : '·');
            const m = max[i] ?? 0;
            if (v && m) {
                // Never fainter than a quarter, so a single finding is visible.
                const strength = 25 + Math.round((Math.sqrt(v) / Math.sqrt(m)) * 70);
                cell.style.setProperty('--heat', columns[i]!.colour);
                cell.style.setProperty('--strength', `${strength}%`);
                if (strength > 60) cell.classList.add('strong');
            }
            cell.title = `${r.label} · ${columns[i]!.label}: ${v}`;
            grid.appendChild(cell);
        });
    }
    return grid;
}

/** 1234 as "1.2k". */
export function compact(n: number): string {
    if (n < 1000) return String(n);
    if (n < 10_000) return (n / 1000).toFixed(1).replace(/\.0$/, '') + 'k';
    if (n < 1_000_000) return Math.round(n / 1000) + 'k';
    return (n / 1_000_000).toFixed(1).replace(/\.0$/, '') + 'M';
}

// ----- line charts -------------------------------------------------------------------

/** Writes a value the way its unit reads. */
export function formatValue(v: number, unit: string): string {
    if (!Number.isFinite(v)) return '—';
    const round = (n: number): string => (Math.abs(n) >= 100 ? String(Math.round(n)) : Math.abs(n) >= 10 ? n.toFixed(1).replace(/\.0$/, '') : n.toFixed(2).replace(/\.?0+$/, '') || '0');
    switch (unit) {
        case 'count':
            return compact(Math.round(v));
        case 'percent':
            return `${round(v * 100)}%`;
        case 'ops/s':
            return `${round(v)}/s`;
        case 'seconds':
            return v < 120 ? `${round(v)}s` : v < 7200 ? `${round(v / 60)}m` : `${round(v / 3600)}h`;
        default:
            return round(v);
    }
}

let gradients = 0;

/**
 * One chart: a line per series from zero, a soft fill under it, a gap where
 * Prometheus had no sample, the top of the scale in the corner and each
 * series' latest value in the legend. Series are ordered and coloured by
 * `colourOf`, which for Trivy's metrics is by severity.
 */
export function lineChart(chart: K8sDockside.Chart, colourOf: (name: string, index: number) => string, order: (a: string, b: string) => number = () => 0): HTMLElement {
    const card = el('article', 'chart');
    const head = el('div', 'chart-head');
    head.appendChild(el('h3', '', chart.label));
    card.appendChild(head);
    if (chart.description) card.appendChild(el('p', 'chart-desc', chart.description));

    const series = chart.series.filter((s) => s.points.length > 0).sort((a, b) => order(a.name, b.name));
    if (chart.error || !series.length) {
        card.appendChild(el('p', 'quiet', chart.error ? chart.error : 'No data in this window.'));
        return card;
    }

    let minT = Infinity;
    let maxT = -Infinity;
    let maxV = 0;
    for (const s of series) {
        for (const p of s.points) {
            minT = Math.min(minT, p.t);
            maxT = Math.max(maxT, p.t);
            if (Number.isFinite(p.v)) maxV = Math.max(maxV, p.v);
        }
    }
    if (maxT === minT) maxT = minT + 1;
    const top = maxV > 0 ? maxV * 1.15 : 1;
    const W = 600;
    const H = 120;
    const x = (t: number): number => ((t - minT) / (maxT - minT)) * W;
    const y = (v: number): number => H - (Math.max(0, v) / top) * H;
    const step = (maxT - minT) / 60;

    const plot = el('div', 'chart-plot');
    const drawing = svg('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none', class: 'chart-svg', role: 'img' });
    drawing.setAttribute('aria-label', `${chart.label}: ${series.map((s) => `${s.name || chart.label} ${formatValue(s.points[s.points.length - 1]!.v, chart.unit)}`).join(', ')}`);
    const defs = svg('defs');
    drawing.appendChild(defs);
    for (const f of [0.25, 0.5, 0.75, 1]) {
        const gy = H * (1 - f / 1.15);
        drawing.appendChild(svg('line', { x1: 0, x2: W, y1: gy, y2: gy, class: 'chart-grid' }));
    }

    const legend = el('div', 'chart-legend');
    series.forEach((s, i) => {
        const colour = colourOf(s.name, i);
        const id = `fill-${++gradients}`;
        const gradient = svg('linearGradient', { id, x1: 0, y1: 0, x2: 0, y2: 1 });
        const a = svg('stop', { offset: '0%', 'stop-opacity': 0.3 });
        const b = svg('stop', { offset: '100%', 'stop-opacity': 0 });
        a.style.stopColor = colour;
        b.style.stopColor = colour;
        add(gradient, a, b);
        defs.appendChild(gradient);

        // Runs of points with no gap longer than three steps between them.
        const runs: K8sDockside.ChartPoint[][] = [];
        let run: K8sDockside.ChartPoint[] = [];
        s.points.forEach((p, j) => {
            const prev = s.points[j - 1];
            if (!Number.isFinite(p.v) || (prev && p.t - prev.t > step * 3)) {
                if (run.length) runs.push(run);
                run = [];
                if (!Number.isFinite(p.v)) return;
            }
            run.push(p);
        });
        if (run.length) runs.push(run);

        for (const r of runs) {
            const d = r.map((p, j) => `${j ? 'L' : 'M'}${x(p.t).toFixed(1)} ${y(p.v).toFixed(1)}`).join(' ');
            const first = r[0]!;
            const last = r[r.length - 1]!;
            drawing.appendChild(svg('path', { d: `${d} L${x(last.t).toFixed(1)} ${H} L${x(first.t).toFixed(1)} ${H} Z`, fill: `url(#${id})`, class: 'chart-area' }));
            const line = svg('path', { d, class: 'chart-line' });
            line.style.stroke = colour;
            drawing.appendChild(line);
        }

        const latest = s.points[s.points.length - 1]!;
        const key = el('span', 'chart-key');
        const dot = el('i', 'dot');
        dot.style.background = colour;
        add(key, dot, el('span', '', s.name || chart.label), el('strong', '', formatValue(latest.v, chart.unit)));
        legend.appendChild(key);
    });

    add(plot, drawing, el('span', 'chart-top', formatValue(maxV, chart.unit)));
    add(card, plot, legend);
    return card;
}
