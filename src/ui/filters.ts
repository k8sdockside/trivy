// The controls along the top of every working page: group by, search,
// severities, namespace, and the odd on/off filter.

import { SEVERITIES, SEVERITY_LABEL, type Counts, type Severity } from '../model/trivy';
import { add, el, icon } from './dom';
import { compact } from './charts';
import type { IconName } from './icons';

/** Buttons of which one is on. */
export function segmented<T extends string>(options: { id: T; label: string; icon?: IconName }[], current: T, onPick: (id: T) => void): HTMLElement {
    const node = el('div', 'seg');
    node.setAttribute('role', 'tablist');
    for (const o of options) {
        const b = el('button', 'seg-btn' + (o.id === current ? ' on' : ''));
        b.type = 'button';
        b.setAttribute('role', 'tab');
        b.setAttribute('aria-selected', String(o.id === current));
        b.dataset.focus = 'seg:' + o.id;
        if (o.icon) b.appendChild(icon(o.icon));
        b.appendChild(el('span', '', o.label));
        b.addEventListener('click', () => onPick(o.id));
        node.appendChild(b);
    }
    return node;
}

/** A search field that tells the page after each keystroke, a moment later. */
export function searchBox(value: string, placeholder: string, onInput: (text: string) => void): HTMLElement {
    const wrap = el('label', 'search');
    wrap.appendChild(icon('search'));
    const input = el('input');
    input.type = 'search';
    input.value = value;
    input.placeholder = placeholder;
    input.dataset.focus = 'search';
    input.setAttribute('aria-label', placeholder);
    let timer: ReturnType<typeof setTimeout> | undefined;
    input.addEventListener('input', () => {
        clearTimeout(timer);
        timer = setTimeout(() => onInput(input.value), 160);
    });
    wrap.appendChild(input);
    return wrap;
}

/**
 * One toggle per severity with its count. None on means all: the first click
 * picks one severity, further clicks add or remove.
 */
export function severityToggles(on: Set<Severity>, counts: Counts, onChange: (next: Set<Severity>) => void): HTMLElement {
    const node = el('div', 'sev-toggles');
    for (const s of SEVERITIES) {
        if (s === 'UNKNOWN' && !counts.UNKNOWN && !on.has(s)) continue;
        const active = on.has(s);
        const b = el('button', 'sev-toggle sev-' + s.toLowerCase() + (active ? ' on' : '') + (on.size && !active ? ' off' : ''));
        b.type = 'button';
        b.dataset.focus = 'sev:' + s;
        b.setAttribute('aria-pressed', String(active));
        add(b, el('span', '', SEVERITY_LABEL[s]), el('strong', '', compact(counts[s])));
        b.addEventListener('click', () => {
            const next = new Set(on);
            if (next.has(s)) next.delete(s);
            else next.add(s);
            onChange(next);
        });
        node.appendChild(b);
    }
    if (on.size) {
        const clear = el('button', 'ghost small');
        clear.type = 'button';
        clear.textContent = 'All';
        clear.addEventListener('click', () => onChange(new Set()));
        node.appendChild(clear);
    }
    return node;
}

/** A namespace picker: every namespace that has something, and "all". */
export function namespaceSelect(namespaces: string[], value: string, onPick: (ns: string) => void): HTMLElement {
    const wrap = el('label', 'ns-pick');
    wrap.appendChild(icon('namespace'));
    const select = el('select');
    select.dataset.focus = 'ns';
    select.setAttribute('aria-label', 'Namespace');
    const all = el('option', '', 'All namespaces');
    all.value = '';
    select.appendChild(all);
    const list = [...new Set(namespaces)].sort();
    if (value && !list.includes(value)) list.unshift(value);
    for (const ns of list) {
        const o = el('option', '', ns || '(cluster-scoped)');
        o.value = ns || '-';
        select.appendChild(o);
    }
    select.value = value;
    select.addEventListener('change', () => onPick(select.value));
    wrap.appendChild(select);
    return wrap;
}

/** A filter that is on or off. */
export function toggle(label: string, on: boolean, iconName: IconName, onChange: (on: boolean) => void, title?: string): HTMLElement {
    const b = el('button', 'toggle' + (on ? ' on' : ''));
    b.type = 'button';
    b.dataset.focus = 'toggle:' + label;
    b.setAttribute('aria-pressed', String(on));
    add(b, icon(on ? 'check' : iconName), el('span', '', label));
    if (title) b.title = title;
    b.addEventListener('click', () => onChange(!on));
    return b;
}

/** The severities in an address, `CRITICAL,HIGH`. */
export function readSeverities(text: string | undefined): Set<Severity> {
    const out = new Set<Severity>();
    for (const part of (text ?? '').split(',')) {
        const s = part.trim().toUpperCase();
        if ((SEVERITIES as readonly string[]).includes(s)) out.add(s as Severity);
    }
    return out;
}

export function writeSeverities(set: Set<Severity>): string {
    return SEVERITIES.filter((s) => set.has(s)).join(',');
}

/** The namespace picker's value as a namespace: `-` is the cluster-scoped ones. */
export function nsMatch(filter: string, ns: string): boolean {
    if (!filter) return true;
    return filter === '-' ? ns === '' : ns === filter;
}

/** Whether every word of the search is somewhere in the texts. */
export function matches(q: string, ...texts: (string | undefined)[]): boolean {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean);
    if (!words.length) return true;
    const hay = texts.filter(Boolean).join(' ').toLowerCase();
    return words.every((w) => hay.includes(w));
}

/**
 * Puts a toolbar together around its search field without remaking it:
 * everything else is replaced, the field is kept -- with its caret, its
 * selection and its focus.
 */
export function mountToolbar(bar: HTMLElement, search: HTMLElement, before: HTMLElement[], after: HTMLElement[]): void {
    for (const child of [...bar.children]) if (child !== search) child.remove();
    if (search.parentElement !== bar) bar.appendChild(search);
    for (const node of before) bar.insertBefore(node, search);
    for (const node of after) bar.appendChild(node);
}
