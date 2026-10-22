// The reports trivy-operator writes, as it writes them (aquasecurity.github.io/v1alpha1).
//
// Every field is optional: the operator's own options leave parts out --
// a vulnerability report can carry only its summary, a config audit only its
// failed checks -- and an older operator wrote fewer fields. The model reads
// what is there and never assumes the rest.

export const GROUP = 'aquasecurity.github.io';

export const KINDS = {
    vulnerability: `crd:vulnerabilityreports.${GROUP}`,
    clusterVulnerability: `crd:clustervulnerabilityreports.${GROUP}`,
    configAudit: `crd:configauditreports.${GROUP}`,
    clusterConfigAudit: `crd:clusterconfigauditreports.${GROUP}`,
    exposedSecret: `crd:exposedsecretreports.${GROUP}`,
    rbac: `crd:rbacassessmentreports.${GROUP}`,
    clusterRbac: `crd:clusterrbacassessmentreports.${GROUP}`,
    infra: `crd:infraassessmentreports.${GROUP}`,
    clusterInfra: `crd:clusterinfraassessmentreports.${GROUP}`,
    compliance: `crd:clustercompliancereports.${GROUP}`,
    sbom: `crd:sbomreports.${GROUP}`,
    clusterSbom: `crd:clustersbomreports.${GROUP}`,
} as const;

export type ReportKey = keyof typeof KINDS;

// ----- severities ---------------------------------------------------------------

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

/** Worst first. */
export const SEVERITIES: readonly Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

export const SEVERITY_LABEL: Record<Severity, string> = {
    CRITICAL: 'Critical',
    HIGH: 'High',
    MEDIUM: 'Medium',
    LOW: 'Low',
    UNKNOWN: 'Unknown',
};

/** A severity as Trivy, Prometheus or a person wrote it: `CRITICAL`, `Critical`, `high`. */
export function severity(value: unknown): Severity {
    const s = String(value ?? '').toUpperCase();
    return (SEVERITIES as readonly string[]).includes(s) ? (s as Severity) : 'UNKNOWN';
}

export function rank(s: Severity): number {
    return SEVERITIES.indexOf(s);
}

export type Counts = Record<Severity, number>;

export function zero(): Counts {
    return { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
}

export function addCounts(into: Counts, from: Counts): Counts {
    for (const s of SEVERITIES) into[s] += from[s];
    return into;
}

export function total(c: Counts): number {
    return SEVERITIES.reduce((n, s) => n + c[s], 0);
}

/** The worst severity with anything in it; `null` for none at all. */
export function worst(c: Counts): Severity | null {
    return SEVERITIES.find((s) => c[s] > 0) ?? null;
}

/** Orders by the counts, worst severity first: 1 critical outranks 900 highs. */
export function compareCounts(a: Counts, b: Counts): number {
    for (const s of SEVERITIES) if (a[s] !== b[s]) return b[s] - a[s];
    return 0;
}

/** A report's `summary`, which writes counts as `criticalCount` and so on. */
export interface SummaryCounts {
    criticalCount?: number;
    highCount?: number;
    mediumCount?: number;
    lowCount?: number;
    unknownCount?: number;
    noneCount?: number;
}

export function fromSummary(s: SummaryCounts | undefined): Counts {
    return {
        CRITICAL: num(s?.criticalCount),
        HIGH: num(s?.highCount),
        MEDIUM: num(s?.mediumCount),
        LOW: num(s?.lowCount),
        UNKNOWN: num(s?.unknownCount),
    };
}

function num(v: unknown): number {
    return typeof v === 'number' && Number.isFinite(v) ? v : 0;
}

// ----- the objects ----------------------------------------------------------------

export type KubeObject = K8sDockside.KubeObject;

export interface Artifact {
    repository?: string;
    tag?: string;
    digest?: string;
    mimeType?: string;
}

export interface Scanner {
    name?: string;
    vendor?: string;
    version?: string;
}

export interface Vulnerability {
    vulnerabilityID?: string;
    resource?: string;
    installedVersion?: string;
    fixedVersion?: string;
    severity?: string;
    title?: string;
    description?: string;
    primaryLink?: string;
    links?: string[];
    score?: number;
    target?: string;
    class?: string;
    packageType?: string;
    pkgPath?: string;
    publishedDate?: string;
    lastModifiedDate?: string;
}

export interface VulnerabilityReport extends KubeObject {
    report?: {
        artifact?: Artifact;
        registry?: { server?: string };
        os?: { family?: string; name?: string; eosl?: boolean };
        scanner?: Scanner;
        summary?: SummaryCounts;
        updateTimestamp?: string;
        vulnerabilities?: Vulnerability[] | null;
    };
}

export interface Check {
    checkID?: string;
    title?: string;
    description?: string;
    severity?: string;
    category?: string;
    messages?: string[] | null;
    success?: boolean;
    remediation?: string;
    scope?: { type?: string; value?: string };
}

/** Config audit, RBAC assessment and infra assessment reports all have this shape. */
export interface AuditReport extends KubeObject {
    report?: {
        scanner?: Scanner;
        summary?: SummaryCounts;
        updateTimestamp?: string;
        checks?: Check[] | null;
    };
}

export interface ExposedSecret {
    target?: string;
    ruleID?: string;
    title?: string;
    category?: string;
    severity?: string;
    match?: string;
}

export interface ExposedSecretReport extends KubeObject {
    report?: {
        artifact?: Artifact;
        registry?: { server?: string };
        scanner?: Scanner;
        summary?: SummaryCounts;
        updateTimestamp?: string;
        secrets?: ExposedSecret[] | null;
    };
}

export interface ComplianceControl {
    id?: string;
    name?: string;
    description?: string;
    severity?: string;
    checks?: { id?: string }[];
    defaultStatus?: string;
}

export interface ComplianceReport extends KubeObject {
    spec?: {
        cron?: string;
        reportType?: string;
        compliance?: {
            id?: string;
            title?: string;
            description?: string;
            version?: string;
            platform?: string;
            type?: string;
            relatedResources?: string[];
            controls?: ComplianceControl[];
        };
    };
    status?: {
        summary?: { passCount?: number; failCount?: number };
        summaryReport?: {
            id?: string;
            title?: string;
            controlCheck?: { id?: string; name?: string; severity?: string; totalFail?: number }[];
        };
        updateTimestamp?: string;
    };
}

export interface SbomReport extends KubeObject {
    report?: {
        artifact?: Artifact;
        registry?: { server?: string };
        summary?: { componentsCount?: number; dependenciesCount?: number };
        updateTimestamp?: string;
    };
}

// ----- what a report is about ---------------------------------------------------------

/** The object a report was written for, as the operator labels it. */
export interface Subject {
    kind: string;
    name: string;
    /** `''` for a cluster-scoped object. */
    namespace: string;
    /** The container, for reports written per container; `''` otherwise. */
    container: string;
}

const L_KIND = 'trivy-operator.resource.kind';
const L_NAME = 'trivy-operator.resource.name';
const L_NS = 'trivy-operator.resource.namespace';
const L_CONTAINER = 'trivy-operator.container.name';

/**
 * What a report is about. The labels are the operator's own record; a name
 * too long for a label is cut there, so the controlling owner reference --
 * which carries the whole name -- is preferred when there is one.
 */
export function subjectOf(report: KubeObject): Subject {
    const labels = report.metadata.labels ?? {};
    const owner = report.metadata.ownerReferences?.find((o) => o.controller) ?? report.metadata.ownerReferences?.[0];
    return {
        kind: owner?.kind || labels[L_KIND] || '',
        name: owner?.name || labels[L_NAME] || report.metadata.name,
        namespace: labels[L_NS] ?? report.metadata.namespace ?? '',
        container: labels[L_CONTAINER] ?? '',
    };
}

export function updatedAt(report: { report?: { updateTimestamp?: string }; metadata: K8sDockside.ObjectMeta }): number {
    const t = Date.parse(report.report?.updateTimestamp ?? report.metadata.creationTimestamp ?? '');
    return Number.isFinite(t) ? t : 0;
}

// ----- images ---------------------------------------------------------------------------

export interface ImageRef {
    registry: string;
    repository: string;
    tag: string;
    digest: string;
}

export function imageOf(report: VulnerabilityReport | ExposedSecretReport | SbomReport): ImageRef {
    const a = report.report?.artifact ?? {};
    return {
        registry: report.report?.registry?.server ?? '',
        repository: a.repository ?? '',
        tag: a.tag ?? '',
        digest: a.digest ?? '',
    };
}

/** The key an image is counted once under: the same build in two workloads is one image. */
export function imageKey(ref: ImageRef): string {
    return `${ref.registry}/${ref.repository}` + (ref.digest ? '@' + ref.digest : ':' + ref.tag);
}

/** The image the way a person writes it: Docker Hub's prefixes left off. */
export function imageName(ref: ImageRef, opts: { tag?: boolean } = {}): string {
    let host = ref.registry;
    let repo = ref.repository;
    if (host === 'index.docker.io' || host === 'docker.io' || host === 'registry-1.docker.io') {
        host = '';
        repo = repo.replace(/^library\//, '');
    }
    const base = (host ? host + '/' : '') + (repo || '(unknown image)');
    if (opts.tag === false) return base;
    if (ref.tag) return `${base}:${ref.tag}`;
    if (ref.digest) return `${base}@${shortDigest(ref.digest)}`;
    return base;
}

export function shortDigest(digest: string): string {
    const [algo, hex] = digest.includes(':') ? digest.split(':', 2) : ['', digest];
    return (algo ? algo + ':' : '') + (hex ?? '').slice(0, 12);
}
