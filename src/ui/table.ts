// A table that sorts by any column, opens a row for its details, and shows a
// page of rows at a time -- the same on every page. It redraws only itself:
// sorting a thousand CVEs should not rebuild the rest of the page.

import { add, el, icon, type Child } from './dom';

export interface Column<T> {
    id: string;
    label: string;
    className?: string;
    /** Header tooltip. */
    title?: string;
    /** How rows order by this column; left out, the column does not sort. */
    sort?: (a: T, b: T) => number;
    cell: (row: T) => Child | Child[];
}

export interface TableState {
    sort: string;
    /** 1 ascending, -1 descending. */
    dir: 1 | -1;
    open: Set<string>;
    limit: number;
}

export interface TableOptions<T> {
    columns: Column<T>[];
    rows: T[];
    key: (row: T) => string;
    expand?: (row: T) => HTMLElement;
    state: TableState;
    empty?: string;
    /** Called after the user sorts, opens or pages, to keep it in the address. */
    onState?: (state: TableState) => void;
    /** The rows' tone, for a coloured edge. */
    tone?: (row: T) => string;
    page?: number;
}

export function tableState(sort = '', dir: 1 | -1 = 1, page = 100): TableState {
    return { sort, dir, open: new Set(), limit: page };
}

export function drawTable<T>(box: HTMLElement, opts: TableOptions<T>): void {
    const { columns, state } = opts;
    const page = opts.page ?? 100;
    box.textContent = '';
    if (!opts.rows.length) {
        box.appendChild(el('p', 'quiet table-empty', opts.empty ?? 'Nothing to show.'));
        return;
    }
    const col = columns.find((c) => c.id === state.sort && c.sort);
    const rows = col ? [...opts.rows].sort((a, b) => col.sort!(a, b) * state.dir) : opts.rows;
    const redraw = (): void => {
        drawTable(box, opts);
        opts.onState?.(state);
    };

    const table = el('table', 'tbl');
    const head = el('thead');
    const hr = el('tr');
    if (opts.expand) hr.appendChild(el('th', 'tbl-toggle'));
    for (const c of columns) {
        const th = el('th', c.className ?? '');
        if (c.title) th.title = c.title;
        if (c.sort) {
            const b = el('button', 'tbl-sort' + (state.sort === c.id ? ' on' : ''));
            b.type = 'button';
            b.dataset.focus = 'sort:' + c.id;
            add(b, el('span', '', c.label), icon(state.sort === c.id ? (state.dir === 1 ? 'chevron-up' : 'chevron-down') : 'sort'));
            b.addEventListener('click', () => {
                if (state.sort === c.id) state.dir = state.dir === 1 ? -1 : 1;
                else {
                    state.sort = c.id;
                    state.dir = 1;
                }
                redraw();
            });
            th.appendChild(b);
            th.setAttribute('aria-sort', state.sort === c.id ? (state.dir === 1 ? 'ascending' : 'descending') : 'none');
        } else {
            th.textContent = c.label;
        }
        hr.appendChild(th);
    }
    head.appendChild(hr);
    table.appendChild(head);

    const body = el('tbody');
    const shown = rows.slice(0, state.limit);
    for (const row of shown) {
        const key = opts.key(row);
        const open = state.open.has(key);
        const tr = el('tr', 'tbl-row' + (open ? ' open' : '') + (opts.expand ? ' expandable' : ''));
        const tone = opts.tone?.(row);
        if (tone) tr.dataset.tone = tone;
        if (opts.expand) {
            const td = el('td', 'tbl-toggle');
            const b = el('button', 'tbl-open');
            b.type = 'button';
            b.dataset.focus = 'open:' + key;
            b.setAttribute('aria-expanded', String(open));
            b.setAttribute('aria-label', open ? 'Close details' : 'Open details');
            b.appendChild(icon(open ? 'chevron-down' : 'chevron'));
            td.appendChild(b);
            tr.appendChild(td);
            const toggle = (): void => {
                if (state.open.has(key)) state.open.delete(key);
                else state.open.add(key);
                redraw();
            };
            b.addEventListener('click', (e) => {
                e.stopPropagation();
                toggle();
            });
            // A click anywhere on the row opens it -- except on a button or link inside it.
            tr.addEventListener('click', (e) => {
                const t = e.target as HTMLElement;
                if (t.closest('button, a, input, select') || document.getSelection()?.toString()) return;
                toggle();
            });
        }
        for (const c of columns) {
            const td = el('td', c.className ?? '');
            const content = c.cell(row);
            add(td, ...(Array.isArray(content) ? content : [content]));
            tr.appendChild(td);
        }
        body.appendChild(tr);
        if (open && opts.expand) {
            const dr = el('tr', 'tbl-detail');
            if (tone) dr.dataset.tone = tone;
            const td = el('td');
            td.colSpan = columns.length + 1;
            td.appendChild(opts.expand(row));
            dr.appendChild(td);
            body.appendChild(dr);
        }
    }
    table.appendChild(body);
    const scroll = el('div', 'tbl-scroll');
    scroll.appendChild(table);
    box.appendChild(scroll);

    const foot = el('div', 'tbl-foot');
    foot.appendChild(el('span', 'faint', rows.length > shown.length ? `Showing ${shown.length} of ${rows.length}` : `${rows.length} ${rows.length === 1 ? 'row' : 'rows'}`));
    if (rows.length > shown.length) {
        const more = el('button', 'ghost small');
        more.type = 'button';
        more.dataset.focus = 'more';
        add(more, icon('chevron-down'), el('span', '', `Show ${Math.min(page, rows.length - shown.length)} more`));
        more.addEventListener('click', () => {
            state.limit += page;
            redraw();
        });
        const all = el('button', 'ghost small');
        all.type = 'button';
        all.textContent = 'Show all';
        all.addEventListener('click', () => {
            state.limit = rows.length;
            redraw();
        });
        add(foot, more, all);
    }
    box.appendChild(foot);
}

/** Compares two strings as a person sorts them: numbers inside them in order. */
export function byText(a: string, b: string): number {
    return a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' });
}
