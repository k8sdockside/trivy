// Every report trivy-operator wrote, taken together: what the pages draw.
//
// The operator writes one vulnerability report per container of every
// workload, so one image run by five Deployments is five reports with the
// same findings. Counting reports would make a popular base image look five
// times worse than it is; the posture counts each image once (by digest, or
// by tag when there is none), each CVE once, and keeps the workloads beside
// them so the pages can say how far a finding reaches.
//
// Deployments are scanned through their ReplicaSets and CronJobs through
// their Jobs. When the ReplicaSets and Jobs can be read, a report is lifted to
// the workload a person manages; when not, it stays on the object it names.

import {
    KINDS,
    SEVERITIES,
    addCounts,
    compareCounts,
    fromSummary,
    imageKey,
    imageName,
    imageOf,
    rank,
    severity,
    subjectOf,
    total,
    updatedAt,
    worst,
    zero,
    type AuditReport,
    type ComplianceReport,
    type Counts,
    type ExposedSecretReport,
    type ImageRef,
    type KubeObject,
    type SbomReport,
    type Severity,
    type Subject,
    type VulnerabilityReport,
} from './trivy';

export interface TrivyData {
    vulnerability: VulnerabilityReport[];
    clusterVulnerability: VulnerabilityReport[];
    configAudit: AuditReport[];
    clusterConfigAudit: AuditReport[];
    exposedSecret: ExposedSecretReport[];
    rbac: AuditReport[];
    clusterRbac: AuditReport[];
    infra: AuditReport[];
    clusterInfra: AuditReport[];
    compliance: ComplianceReport[];
    sbom: SbomReport[];
    clusterSbom: SbomReport[];
    /** For lifting a ReplicaSet's report to its Deployment. */
    replicasets?: KubeObject[];
    /** For lifting a Job's report to its CronJob. */
    jobs?: KubeObject[];
}

export function emptyData(): TrivyData {
    return {
        vulnerability: [],
        clusterVulnerability: [],
        configAudit: [],
        clusterConfigAudit: [],
        exposedSecret: [],
        rbac: [],
        clusterRbac: [],
        infra: [],
        clusterInfra: [],
        compliance: [],
        sbom: [],
        clusterSbom: [],
    };
}

// ----- workloads -------------------------------------------------------------------

/** Kinds the app opens, by the Kubernetes kind a report names. */
const APP_KIND: Record<string, string> = {
    Pod: 'pods',
    ReplicaSet: 'replicasets',
    ReplicationController: 'replicationcontrollers',
    Deployment: 'deployments',
    StatefulSet: 'statefulsets',
    DaemonSet: 'daemonsets',
    Job: 'jobs',
    CronJob: 'cronjobs',
    Node: 'nodes',
    Service: 'services',
    ConfigMap: 'configmaps',
    Ingress: 'ingresses',
    NetworkPolicy: 'networkpolicies',
    ResourceQuota: 'resourcequotas',
    LimitRange: 'limitranges',
    ServiceAccount: 'serviceaccounts',
    Role: 'roles',
    RoleBinding: 'rolebindings',
    ClusterRole: 'clusterroles',
    ClusterRoleBinding: 'clusterrolebindings',
};

export function appKind(kind: string): string {
    return APP_KIND[kind] ?? '';
}

/** The object a finding belongs to, as a person manages it. */
export interface Workload {
    key: string;
    kind: string;
    name: string;
    namespace: string;
    /** The app's kind to open it with; `''` when the app has no tab for it. */
    appKind: string;
    /** The object trivy-operator actually scanned, when it is not this one (a Deployment's ReplicaSet). */
    via?: { kind: string; name: string };
}

function workloadKey(kind: string, namespace: string, name: string): string {
    return `${kind}/${namespace}/${name}`;
}

/** Follows a ReplicaSet to its Deployment and a Job to its CronJob, as far as the lists allow. */
export function makeLifter(data: Pick<TrivyData, 'replicasets' | 'jobs'>): (s: Subject) => Workload {
    const owners = new Map<string, { kind: string; name: string }>();
    const remember = (kind: string, list: KubeObject[] | undefined, ownerKind: string): void => {
        for (const o of list ?? []) {
            const ref = o.metadata.ownerReferences?.find((r) => r.controller && r.kind === ownerKind);
            if (ref) owners.set(workloadKey(kind, o.metadata.namespace ?? '', o.metadata.name), { kind: ref.kind, name: ref.name });
        }
    };
    remember('ReplicaSet', data.replicasets, 'Deployment');
    remember('Job', data.jobs, 'CronJob');

    return (s) => {
        const up = owners.get(workloadKey(s.kind, s.namespace, s.name));
        if (up) return { key: workloadKey(up.kind, s.namespace, up.name), kind: up.kind, name: up.name, namespace: s.namespace, appKind: appKind(up.kind), via: { kind: s.kind, name: s.name } };
        return { key: workloadKey(s.kind, s.namespace, s.name), kind: s.kind, name: s.name, namespace: s.namespace, appKind: appKind(s.kind) };
    };
}

/** A report, by the kind the app reads it with, for opening and rescanning. */
export interface ReportRef {
    kind: string;
    namespace: string;
    name: string;
}

// ----- vulnerabilities -------------------------------------------------------------

export interface Finding {
    id: string;
    severity: Severity;
    score: number | null;
    title: string;
    description: string;
    link: string;
    links: string[];
    pkg: string;
    installed: string;
    fixed: string;
    target: string;
    published: number;
}

export interface ImageEntry {
    key: string;
    ref: ImageRef;
    name: string;
    os: string;
    /** The OS release is past its end of support: its packages get no more fixes. */
    eosl: boolean;
    counts: Counts;
    fixable: number;
    findings: Finding[];
    /** Whether `findings` holds every vulnerability, or the operator wrote only the summary. */
    detailed: boolean;
    workloads: Workload[];
    containers: string[];
    namespaces: string[];
    reports: ReportRef[];
    updated: number;
    components: number | null;
}

export interface CveEntry {
    id: string;
    severity: Severity;
    score: number | null;
    title: string;
    description: string;
    link: string;
    links: string[];
    packages: string[];
    installed: string[];
    fixed: string[];
    fixable: boolean;
    published: number;
    images: string[];
    workloads: Workload[];
    namespaces: string[];
}

export interface WorkloadEntry {
    workload: Workload;
    counts: Counts;
    fixable: number;
    images: string[];
    containers: { name: string; image: string; counts: Counts; report: ReportRef }[];
    misconfig: Counts;
    secrets: number;
    updated: number;
}

export interface NamespaceEntry {
    namespace: string;
    vulns: Counts;
    misconfig: Counts;
    secrets: Counts;
    images: number;
    workloads: number;
}

// ----- misconfigurations ------------------------------------------------------------

export type AuditKind = 'config' | 'rbac' | 'infra';

export const AUDIT_LABEL: Record<AuditKind, string> = { config: 'Workload config', rbac: 'RBAC', infra: 'Infrastructure' };

export interface AuditFinding {
    audit: AuditKind;
    checkID: string;
    title: string;
    description: string;
    severity: Severity;
    category: string;
    messages: string[];
    remediation: string;
    workload: Workload;
    report: ReportRef;
}

export interface CheckEntry {
    audit: AuditKind;
    checkID: string;
    title: string;
    description: string;
    severity: Severity;
    category: string;
    remediation: string;
    resources: { workload: Workload; messages: string[]; report: ReportRef }[];
}

export interface ResourceEntry {
    audit: AuditKind;
    workload: Workload;
    counts: Counts;
    findings: AuditFinding[];
    /** The report only carries its summary: the checks themselves were not recorded. */
    detailed: boolean;
    report: ReportRef;
    updated: number;
}

// ----- secrets and compliance ----------------------------------------------------------

export interface SecretFinding {
    severity: Severity;
    ruleID: string;
    title: string;
    category: string;
    target: string;
    match: string;
    image: string;
    workload: Workload;
    container: string;
    report: ReportRef;
}

export interface ComplianceEntry {
    name: string;
    id: string;
    title: string;
    description: string;
    version: string;
    pass: number;
    fail: number;
    /** Passing controls of every control with a result, 0..1; `null` before the first run. */
    rate: number | null;
    controls: { id: string; name: string; severity: Severity; fail: number; description: string }[];
    updated: number;
    cron: string;
}

// ----- the whole -----------------------------------------------------------------------

export interface Posture {
    images: ImageEntry[];
    cves: CveEntry[];
    workloads: WorkloadEntry[];
    namespaces: NamespaceEntry[];
    resources: ResourceEntry[];
    checks: CheckEntry[];
    secrets: SecretFinding[];
    compliance: ComplianceEntry[];
    totals: {
        /** Each image once. */
        images: number;
        /** Each CVE once, at its severity. */
        cves: Counts;
        /** Each vulnerability in each image: the same CVE in two images counts twice. */
        findings: Counts;
        /** Image findings that have a fixed version. */
        fixable: number;
        fixableCritical: number;
        fixableHigh: number;
        /** Images free of critical and high vulnerabilities. */
        cleanImages: number;
        eoslImages: number;
        workloads: number;
        /** Failed checks, by severity, across every audit. */
        misconfig: Counts;
        misconfigBy: Record<AuditKind, Counts>;
        /** Resources audited, and how many have no critical or high failure. */
        resources: number;
        cleanResources: number;
        secrets: Counts;
        imagesWithSecrets: number;
        reports: number;
        oldest: number;
        newest: number;
        /** Reports not refreshed in a day. */
        stale: number;
    };
    /** Each CVE once, by the year it was published, by severity. */
    byYear: { year: number; counts: Counts }[];
    score: Score;
    /** A short fingerprint of what would be drawn, to skip redraws that change nothing. */
    signature: string;
}

export interface Gauge {
    id: 'images' | 'resources' | 'compliance';
    label: string;
    /** 0..1; `null` when there is nothing to measure. */
    value: number | null;
    detail: string;
}

export interface Score {
    /** 0..100; `null` when nothing has been scanned. */
    value: number | null;
    grade: 'A' | 'B' | 'C' | 'D' | 'E' | 'F' | '–';
    gauges: Gauge[];
}

const DAY = 86_400_000;

function reportRef(kind: string, o: KubeObject): ReportRef {
    return { kind, namespace: o.metadata.namespace ?? '', name: o.metadata.name };
}

function addWorkload(list: Workload[], w: Workload): void {
    if (!list.some((x) => x.key === w.key)) list.push(w);
}

export function buildPosture(data: TrivyData, opts: { now?: number } = {}): Posture {
    const now = opts.now ?? Date.now();
    const lift = makeLifter(data);

    const images = new Map<string, ImageEntry>();
    const cves = new Map<string, CveEntry & { imageSet: Set<string> }>();
    const workloads = new Map<string, WorkloadEntry>();
    const namespaces = new Map<string, NamespaceEntry & { imageSet: Set<string>; workloadSet: Set<string> }>();
    const stamps: number[] = [];

    const nsEntry = (ns: string) => {
        let e = namespaces.get(ns);
        if (!e) {
            e = { namespace: ns, vulns: zero(), misconfig: zero(), secrets: zero(), images: 0, workloads: 0, imageSet: new Set(), workloadSet: new Set() };
            namespaces.set(ns, e);
        }
        return e;
    };
    const wlEntry = (w: Workload): WorkloadEntry => {
        let e = workloads.get(w.key);
        if (!e) {
            e = { workload: w, counts: zero(), fixable: 0, images: [], containers: [], misconfig: zero(), secrets: 0, updated: 0 };
            workloads.set(w.key, e);
        }
        return e;
    };

    // Vulnerabilities: per image once, per workload in full.
    const vulnReports: [VulnerabilityReport, string][] = [
        ...data.vulnerability.map((r): [VulnerabilityReport, string] => [r, KINDS.vulnerability]),
        ...data.clusterVulnerability.map((r): [VulnerabilityReport, string] => [r, KINDS.clusterVulnerability]),
    ];
    for (const [r, kind] of vulnReports) {
        const subject = subjectOf(r);
        const w = lift(subject);
        const ref = imageOf(r);
        const key = imageKey(ref);
        const stamp = updatedAt(r);
        stamps.push(stamp);
        const list = r.report?.vulnerabilities ?? [];
        const summary = fromSummary(r.report?.summary);
        const findings: Finding[] = list.map((v) => ({
            id: v.vulnerabilityID || '(no id)',
            severity: severity(v.severity),
            score: typeof v.score === 'number' ? v.score : null,
            title: v.title ?? '',
            description: v.description ?? '',
            link: v.primaryLink ?? v.links?.[0] ?? '',
            links: v.links ?? [],
            pkg: v.resource ?? '',
            installed: v.installedVersion ?? '',
            fixed: v.fixedVersion ?? '',
            target: v.target ?? '',
            published: Date.parse(v.publishedDate ?? '') || 0,
        }));
        const counts = list.length ? countFindings(findings) : summary;
        const fixable = findings.filter((f) => f.fixed).length;
        const reportR = reportRef(kind, r);

        let img = images.get(key);
        if (!img) {
            const os = r.report?.os;
            img = {
                key,
                ref,
                name: imageName(ref),
                os: [os?.family, os?.name].filter(Boolean).join(' '),
                eosl: Boolean(os?.eosl),
                counts,
                fixable,
                findings,
                detailed: list.length > 0 || total(summary) === 0,
                workloads: [],
                containers: [],
                namespaces: [],
                reports: [],
                updated: stamp,
                components: null,
            };
            images.set(key, img);
        } else if (stamp > img.updated) {
            // The newest scan of an image speaks for it.
            Object.assign(img, { counts, fixable, findings, detailed: list.length > 0 || total(summary) === 0, updated: stamp });
        }
        addWorkload(img.workloads, w);
        if (subject.container && !img.containers.includes(subject.container)) img.containers.push(subject.container);
        if (!img.namespaces.includes(w.namespace)) img.namespaces.push(w.namespace);
        img.reports.push(reportR);

        const we = wlEntry(w);
        addCounts(we.counts, counts);
        we.fixable += fixable;
        if (!we.images.includes(key)) we.images.push(key);
        we.containers.push({ name: subject.container, image: img.name, counts, report: reportR });
        we.updated = Math.max(we.updated, stamp);

        const ns = nsEntry(w.namespace);
        addCounts(ns.vulns, counts);
        ns.imageSet.add(key);
        ns.workloadSet.add(w.key);

        for (const f of findings) {
            let c = cves.get(f.id);
            if (!c) {
                c = {
                    id: f.id,
                    severity: f.severity,
                    score: f.score,
                    title: f.title,
                    description: f.description,
                    link: f.link,
                    links: f.links,
                    packages: [],
                    installed: [],
                    fixed: [],
                    fixable: false,
                    published: f.published,
                    images: [],
                    workloads: [],
                    namespaces: [],
                    imageSet: new Set(),
                };
                cves.set(f.id, c);
            }
            if (rank(f.severity) < rank(c.severity)) c.severity = f.severity;
            if (f.score !== null && (c.score === null || f.score > c.score)) c.score = f.score;
            if (!c.title && f.title) c.title = f.title;
            if (!c.description && f.description) c.description = f.description;
            if (!c.link && f.link) c.link = f.link;
            if (f.pkg && !c.packages.includes(f.pkg)) c.packages.push(f.pkg);
            if (f.installed && !c.installed.includes(f.installed)) c.installed.push(f.installed);
            if (f.fixed && !c.fixed.includes(f.fixed)) c.fixed.push(f.fixed);
            if (f.fixed) c.fixable = true;
            c.imageSet.add(key);
            addWorkload(c.workloads, w);
            if (!c.namespaces.includes(w.namespace)) c.namespaces.push(w.namespace);
        }
    }

    // SBOMs: how many components each image is made of.
    for (const r of [...data.sbom, ...data.clusterSbom]) {
        const img = images.get(imageKey(imageOf(r)));
        const n = r.report?.summary?.componentsCount;
        if (img && typeof n === 'number') img.components = n;
    }

    // Misconfigurations: config audit, RBAC and infra, all the same shape.
    const resources: ResourceEntry[] = [];
    const checks = new Map<string, CheckEntry>();
    const audits: [AuditKind, AuditReport[], string][] = [
        ['config', data.configAudit, KINDS.configAudit],
        ['config', data.clusterConfigAudit, KINDS.clusterConfigAudit],
        ['rbac', data.rbac, KINDS.rbac],
        ['rbac', data.clusterRbac, KINDS.clusterRbac],
        ['infra', data.infra, KINDS.infra],
        ['infra', data.clusterInfra, KINDS.clusterInfra],
    ];
    const misconfigBy: Record<AuditKind, Counts> = { config: zero(), rbac: zero(), infra: zero() };
    for (const [audit, list, kind] of audits) {
        for (const r of list) {
            const w = lift(subjectOf(r));
            const ref = reportRef(kind, r);
            const stamp = updatedAt(r);
            stamps.push(stamp);
            const failed = (r.report?.checks ?? []).filter((c) => c.success === false || c.success === undefined);
            const findings: AuditFinding[] = failed.map((c) => ({
                audit,
                checkID: c.checkID ?? '',
                title: c.title ?? c.checkID ?? '',
                description: c.description ?? '',
                severity: severity(c.severity),
                category: c.category ?? '',
                messages: (c.messages ?? []).filter(Boolean),
                remediation: c.remediation ?? '',
                workload: w,
                report: ref,
            }));
            const summary = fromSummary(r.report?.summary);
            const counts = findings.length ? countFindings(findings) : summary;
            resources.push({ audit, workload: w, counts, findings, detailed: findings.length > 0 || total(summary) === 0, report: ref, updated: stamp });
            addCounts(misconfigBy[audit], counts);
            addCounts(nsEntry(w.namespace).misconfig, counts);
            // Only onto a workload that runs images: a Service's audit is not one.
            const we = workloads.get(w.key);
            if (we) addCounts(we.misconfig, counts);

            for (const f of findings) {
                const id = `${audit}/${f.checkID}`;
                let c = checks.get(id);
                if (!c) {
                    c = { audit, checkID: f.checkID, title: f.title, description: f.description, severity: f.severity, category: f.category, remediation: f.remediation, resources: [] };
                    checks.set(id, c);
                }
                if (rank(f.severity) < rank(c.severity)) c.severity = f.severity;
                c.resources.push({ workload: w, messages: f.messages, report: ref });
            }
        }
    }

    // Exposed secrets.
    const secrets: SecretFinding[] = [];
    const imagesWithSecrets = new Set<string>();
    const secretCounts = zero();
    const secretKind = KINDS.exposedSecret;
    for (const r of data.exposedSecret) {
        const subject = subjectOf(r);
        const w = lift(subject);
        const ref = imageOf(r);
        stamps.push(updatedAt(r));
        const list = r.report?.secrets ?? [];
        const counts = list.length ? zero() : fromSummary(r.report?.summary);
        for (const s of list) {
            const sev = severity(s.severity);
            counts[sev]++;
            secrets.push({
                severity: sev,
                ruleID: s.ruleID ?? '',
                title: s.title ?? s.ruleID ?? 'Secret',
                category: s.category ?? '',
                target: s.target ?? '',
                match: s.match ?? '',
                image: imageName(ref),
                workload: w,
                container: subject.container,
                report: reportRef(secretKind, r),
            });
        }
        if (total(counts)) imagesWithSecrets.add(imageKey(ref));
        addCounts(secretCounts, counts);
        addCounts(nsEntry(w.namespace).secrets, counts);
        const we = workloads.get(w.key);
        if (we) we.secrets += total(counts);
    }
    secrets.sort((a, b) => rank(a.severity) - rank(b.severity) || a.workload.key.localeCompare(b.workload.key) || a.target.localeCompare(b.target));

    // Compliance.
    const compliance: ComplianceEntry[] = data.compliance.map((r) => {
        const spec = r.spec?.compliance ?? {};
        const pass = r.status?.summary?.passCount ?? 0;
        const fail = r.status?.summary?.failCount ?? 0;
        const described = new Map((spec.controls ?? []).map((c) => [c.id ?? '', c]));
        const controls = (r.status?.summaryReport?.controlCheck ?? []).map((c) => ({
            id: c.id ?? '',
            name: c.name ?? described.get(c.id ?? '')?.name ?? '',
            severity: severity(c.severity ?? described.get(c.id ?? '')?.severity),
            fail: c.totalFail ?? 0,
            description: described.get(c.id ?? '')?.description ?? '',
        }));
        controls.sort((a, b) => (b.fail > 0 ? 1 : 0) - (a.fail > 0 ? 1 : 0) || rank(a.severity) - rank(b.severity) || b.fail - a.fail || a.id.localeCompare(b.id, undefined, { numeric: true }));
        const stamp = Date.parse(r.status?.updateTimestamp ?? '') || 0;
        if (stamp) stamps.push(stamp);
        return {
            name: r.metadata.name,
            id: spec.id ?? r.metadata.name,
            title: spec.title || r.metadata.name,
            description: spec.description ?? '',
            version: spec.version ?? '',
            pass,
            fail,
            rate: pass + fail > 0 ? pass / (pass + fail) : null,
            controls,
            updated: stamp,
            cron: r.spec?.cron ?? '',
        };
    });
    compliance.sort((a, b) => a.title.localeCompare(b.title));

    // Totals.
    const imageList = [...images.values()].sort((a, b) => compareCounts(a.counts, b.counts) || a.name.localeCompare(b.name));
    const cveList = [...cves.values()]
        .map(({ imageSet, ...c }) => ({ ...c, images: [...imageSet] }))
        .sort((a, b) => rank(a.severity) - rank(b.severity) || b.images.length - a.images.length || (b.score ?? 0) - (a.score ?? 0) || a.id.localeCompare(b.id));
    const workloadList = [...workloads.values()].sort((a, b) => compareCounts(a.counts, b.counts) || compareCounts(a.misconfig, b.misconfig) || a.workload.key.localeCompare(b.workload.key));
    const nsList = [...namespaces.values()]
        .map(({ imageSet, workloadSet, ...n }) => ({ ...n, images: imageSet.size, workloads: workloadSet.size }))
        .sort((a, b) => compareCounts(a.vulns, b.vulns) || compareCounts(a.misconfig, b.misconfig) || a.namespace.localeCompare(b.namespace));
    const checkList = [...checks.values()].sort((a, b) => rank(a.severity) - rank(b.severity) || b.resources.length - a.resources.length || a.checkID.localeCompare(b.checkID));
    resources.sort((a, b) => compareCounts(a.counts, b.counts) || a.workload.key.localeCompare(b.workload.key));

    const findings = zero();
    let fixable = 0;
    let fixableCritical = 0;
    let fixableHigh = 0;
    for (const img of imageList) {
        addCounts(findings, img.counts);
        fixable += img.fixable;
        for (const f of img.findings) {
            if (!f.fixed) continue;
            if (f.severity === 'CRITICAL') fixableCritical++;
            else if (f.severity === 'HIGH') fixableHigh++;
        }
    }
    const cveCounts = zero();
    for (const c of cveList) cveCounts[c.severity]++;
    // An image whose report carries only a summary still says how many CVEs
    // of each severity it has; with no list at all, those are the best count.
    if (!cveList.length) addCounts(cveCounts, findings);

    const misconfig = zero();
    for (const k of Object.keys(misconfigBy) as AuditKind[]) addCounts(misconfig, misconfigBy[k]);

    const cleanImages = imageList.filter((i) => !i.counts.CRITICAL && !i.counts.HIGH).length;
    const cleanResources = resources.filter((r) => !r.counts.CRITICAL && !r.counts.HIGH).length;
    const known = stamps.filter((t) => t > 0);

    const byYearMap = new Map<number, Counts>();
    for (const c of cveList) {
        if (!c.published) continue;
        const y = new Date(c.published).getUTCFullYear();
        const counts = byYearMap.get(y) ?? zero();
        counts[c.severity]++;
        byYearMap.set(y, counts);
    }
    const byYear = [...byYearMap.entries()].sort((a, b) => a[0] - b[0]).map(([year, counts]) => ({ year, counts }));

    const totals: Posture['totals'] = {
        images: imageList.length,
        cves: cveCounts,
        findings,
        fixable,
        fixableCritical,
        fixableHigh,
        cleanImages,
        eoslImages: imageList.filter((i) => i.eosl).length,
        workloads: workloadList.length,
        misconfig,
        misconfigBy,
        resources: resources.length,
        cleanResources,
        secrets: secretCounts,
        imagesWithSecrets: imagesWithSecrets.size,
        reports: vulnReports.length + audits.reduce((n, [, l]) => n + l.length, 0) + data.exposedSecret.length + data.compliance.length,
        oldest: known.length ? Math.min(...known) : 0,
        newest: known.length ? Math.max(...known) : 0,
        stale: known.filter((t) => now - t > DAY).length,
    };

    const score = scoreOf(totals, compliance);
    const posture: Posture = {
        images: imageList,
        cves: cveList,
        workloads: workloadList,
        namespaces: nsList,
        resources,
        checks: checkList,
        secrets,
        compliance,
        totals,
        byYear,
        score,
        signature: '',
    };
    posture.signature = fingerprint(
        JSON.stringify([totals, score.value, imageList.map((i) => [i.key, i.updated, i.workloads.length]), resources.map((r) => [r.report.name, r.updated]), compliance.map((c) => [c.name, c.pass, c.fail]), secrets.length]),
    );
    return posture;
}

function countFindings(list: { severity: Severity }[]): Counts {
    const c = zero();
    for (const f of list) c[f.severity]++;
    return c;
}

/**
 * The score, out of a hundred: the average of what can be measured -- the
 * share of images with no critical or high vulnerability, of resources with
 * no critical or high misconfiguration, and of compliance controls passing --
 * less a little for every critical vulnerability that has a fix waiting.
 * Simple on purpose: every gauge on the page is one of its parts.
 */
export function scoreOf(t: Posture['totals'], compliance: ComplianceEntry[]): Score {
    const pass = compliance.reduce((n, c) => n + c.pass, 0);
    const fail = compliance.reduce((n, c) => n + c.fail, 0);
    const gauges: Gauge[] = [
        {
            id: 'images',
            label: 'Images',
            value: t.images ? t.cleanImages / t.images : null,
            detail: t.images ? `${t.cleanImages} of ${t.images} free of critical and high` : 'no images scanned',
        },
        {
            id: 'resources',
            label: 'Configuration',
            value: t.resources ? t.cleanResources / t.resources : null,
            detail: t.resources ? `${t.cleanResources} of ${t.resources} resources without critical or high findings` : 'no config audits',
        },
        {
            id: 'compliance',
            label: 'Compliance',
            value: pass + fail ? pass / (pass + fail) : null,
            detail: pass + fail ? `${pass} of ${pass + fail} controls passing` : 'no compliance reports',
        },
    ];
    const measured = gauges.filter((g) => g.value !== null).map((g) => g.value as number);
    if (!measured.length) return { value: null, grade: '–', gauges };
    const base = (measured.reduce((n, v) => n + v, 0) / measured.length) * 100;
    const penalty = Math.min(15, t.fixableCritical * 0.5);
    const value = Math.max(0, Math.round(base - penalty));
    const grade = value >= 90 ? 'A' : value >= 80 ? 'B' : value >= 65 ? 'C' : value >= 50 ? 'D' : value >= 35 ? 'E' : 'F';
    return { value, grade, gauges };
}

/** A short, stable hash of a string (FNV-1a). */
export function fingerprint(text: string): string {
    let h = 0x811c9dc5;
    for (let i = 0; i < text.length; i++) {
        h ^= text.charCodeAt(i);
        h = Math.imul(h, 0x01000193);
    }
    return (h >>> 0).toString(36);
}

/** The worst severity of a set of counts, with "none" for a clean one. */
export function tone(c: Counts): Severity | 'NONE' {
    return worst(c) ?? 'NONE';
}

export { SEVERITIES, total, worst, zero };
