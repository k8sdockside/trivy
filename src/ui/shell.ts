// What every tab has around its own content: a strip to move between the
// plugin's pages, the "trivy-operator is not here" page, and a way to open
// another page on a filter.

import type { FeedState } from '../model/feed';
import { add, button, el } from './dom';
import type { IconName } from './icons';
import { banner, readHash, sdk } from './page';

export const INSTALL_DOCS = 'https://aquasecurity.github.io/trivy-operator/latest/getting-started/installation/helm/';

const PAGES: { id: string; label: string; icon: IconName }[] = [
    { id: 'overview', label: 'Overview', icon: 'logo' },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: 'bug' },
    { id: 'misconfigurations', label: 'Misconfigurations', icon: 'policy' },
    { id: 'secrets', label: 'Exposed secrets', icon: 'key' },
    { id: 'compliance', label: 'Compliance', icon: 'certificate' },
];

export function fail(err: unknown): void {
    banner.show(err);
}

/** trivy-operator's mark, from the plugin's own files. */
export function mark(className = 'mark'): HTMLImageElement {
    const img = el('img', className);
    img.src = 'logo.png';
    img.alt = '';
    return img;
}

/** Aqua Security's mark, for crediting the operator. */
export function aquaMark(className = 'mark small'): HTMLImageElement {
    const img = el('img', className);
    img.src = 'aqua.png';
    img.alt = '';
    return img;
}

/** The strip of the plugin's pages, with this one marked. */
export function nav(current: string, ctx: K8sDockside.Context | null): HTMLElement {
    const node = el('nav', 'nav');
    const brand = el('span', 'nav-brand');
    add(brand, mark(), el('span', '', 'Trivy'), ctx?.contextName ? el('span', 'faint', '· ' + ctx.contextName) : null);
    node.appendChild(brand);
    const tabs = el('div', 'nav-tabs');
    for (const p of PAGES) {
        const b = button(p.label, 'nav-tab' + (p.id === current ? ' on' : ''), p.icon, () => {
            if (p.id !== current) go(p.id);
        });
        if (p.id === current) b.setAttribute('aria-current', 'page');
        tabs.appendChild(b);
    }
    node.appendChild(tabs);
    return node;
}

// ----- opening a page on a filter ------------------------------------------------------

const HANDOFF = 'handoff';

/**
 * Opens another of the plugin's pages, on a filter when one is given.
 * `openView` takes only the view's id, so the filter goes ahead of it into
 * the plugin's storage, and the page takes it from there as it loads -- once,
 * and only within a few seconds, so a stale one never applies to a visit
 * long after.
 */
export function go(viewId: string, filter?: Record<string, string>): void {
    const open = (): void => void sdk.openView(viewId).catch(fail);
    if (!filter || !sdk.storage) return open();
    sdk.storage.set(HANDOFF, { view: viewId, filter, at: Date.now() }).then(open, open);
}

/** The filter another page opened this one on, or the address's own. */
export async function arrival(viewId: string): Promise<Record<string, string>> {
    const hash = readHash();
    const store = sdk.storage;
    if (!store) return hash;
    try {
        const h = await store.get<{ view: string; filter: Record<string, string>; at: number }>(HANDOFF);
        if (h && h.view === viewId && Date.now() - h.at < 15_000) {
            await store.remove(HANDOFF);
            return { ...h.filter };
        }
    } catch {
        // Storage is a convenience; the address still works without it.
    }
    return hash;
}

// ----- not installed, not answering ------------------------------------------------------

/** Whether the feed already knows there is nothing to draw: not answering, or not installed. */
export function absent(feed: FeedState): boolean {
    const s = feed.summary;
    return Boolean(s && (!s.checked || !s.installed)) || Boolean(feed.errors.vulnerability && !feed.data.vulnerability.length && !feed.served.size);
}

/** Whether the feed says there is nothing to draw, and why, drawn into `box`. Returns true when it drew. */
export function drawAbsence(box: HTMLElement, feed: FeedState | null): boolean {
    const summary = feed?.summary;
    if (!feed || !summary) return false;
    if (!summary.checked) {
        absentPage(box, 'This cluster did not answer', 'Whether trivy-operator runs here could not be checked — which is not the same as it not running. The page tries again on its own.', summary.error);
        return true;
    }
    if (!summary.installed) {
        const missing = summary.requirements.filter((r) => !r.served && !r.optional).map((r) => r.kind);
        absentPage(
            box,
            'trivy-operator is not installed',
            'This cluster does not serve the VulnerabilityReport kind trivy-operator writes. Install the operator and it starts scanning every workload’s images straight away; the first reports appear here within a few minutes.',
            missing.join(', '),
            true,
        );
        return true;
    }
    if (feed.errors.vulnerability && !feed.data.vulnerability.length) {
        absentPage(box, 'The reports could not be read', 'Your account may not be allowed to list trivy-operator’s reports in this cluster.', feed.errors.vulnerability);
        return true;
    }
    return false;
}

function absentPage(box: HTMLElement, title: string, text: string, detail: string, install = false): void {
    box.textContent = '';
    const card = el('section', 'absent');
    const art = el('div', 'empty-art brand');
    art.appendChild(mark('mark big'));
    add(card, art, el('h1', 'absent-title', title), el('p', 'absent-text', text));
    if (detail) card.appendChild(el('code', 'absent-detail', detail));
    if (install) {
        const steps = el('pre', 'absent-code');
        steps.textContent = [
            'helm repo add aqua https://aquasecurity.github.io/helm-charts/',
            'helm repo update',
            'helm install trivy-operator aqua/trivy-operator \\',
            '  --namespace trivy-system --create-namespace',
        ].join('\n');
        card.appendChild(steps);
        const cta = el('div', 'cta');
        cta.appendChild(button('Installation guide', 'primary', 'book', () => void sdk.openUrl(INSTALL_DOCS).catch(fail)));
        card.appendChild(cta);
    }
    box.appendChild(card);
}

/** While the first answers are on their way. */
export function loading(box: HTMLElement, text = 'Reading trivy-operator’s reports…'): void {
    box.textContent = '';
    const node = el('div', 'loading');
    add(node, el('span', 'pulse'), el('span', '', text));
    box.appendChild(node);
}
