// Reports shaped the way trivy-operator writes them, for the tests and the
// preview: a Deployment scanned through its ReplicaSet, the same image in two
// workloads, a summary-only report, config audits with failed checks, an RBAC
// assessment, an exposed secret and a compliance report.

import type { AuditReport, ComplianceReport, ExposedSecretReport, KubeObject, VulnerabilityReport } from './model/trivy';

export const NOW = Date.parse('2026-10-22T12:00:00Z');
const hoursAgo = (h: number): string => new Date(NOW - h * 3_600_000).toISOString();

function owner(kind: string, name: string): KubeObject['metadata']['ownerReferences'] {
    return [{ apiVersion: 'apps/v1', kind, name, uid: `${kind}-${name}`, controller: true }];
}

function labels(kind: string, name: string, ns: string, container?: string): Record<string, string> {
    return {
        'trivy-operator.resource.kind': kind,
        'trivy-operator.resource.name': name,
        'trivy-operator.resource.namespace': ns,
        ...(container ? { 'trivy-operator.container.name': container } : {}),
    };
}

const nginxVulns = [
    {
        vulnerabilityID: 'CVE-2024-6387',
        resource: 'openssh-client',
        installedVersion: '1:9.2p1-2',
        fixedVersion: '1:9.2p1-2+deb12u3',
        severity: 'CRITICAL',
        title: 'openssh: regreSSHion: RCE in OpenSSH server',
        description: 'A signal handler race condition was found in sshd.',
        primaryLink: 'https://avd.aquasec.com/nvd/cve-2024-6387',
        score: 8.1,
        publishedDate: '2024-07-01T13:15:00Z',
    },
    {
        vulnerabilityID: 'CVE-2023-44487',
        resource: 'libnghttp2-14',
        installedVersion: '1.52.0-1',
        fixedVersion: '1.52.0-1+deb12u1',
        severity: 'HIGH',
        title: 'HTTP/2: Rapid Reset attack',
        primaryLink: 'https://avd.aquasec.com/nvd/cve-2023-44487',
        score: 7.5,
        publishedDate: '2023-10-10T14:15:00Z',
    },
    {
        vulnerabilityID: 'CVE-2023-4911',
        resource: 'libc6',
        installedVersion: '2.36-9',
        fixedVersion: '',
        severity: 'HIGH',
        title: 'glibc: buffer overflow in ld.so',
        score: 7.8,
        publishedDate: '2023-10-03T18:15:00Z',
    },
    { vulnerabilityID: 'CVE-2022-0001', resource: 'zlib1g', installedVersion: '1:1.2.13', fixedVersion: '', severity: 'MEDIUM', title: 'zlib: something', score: 5.3, publishedDate: '2022-02-01T00:00:00Z' },
    { vulnerabilityID: 'CVE-2011-3374', resource: 'apt', installedVersion: '2.6.1', fixedVersion: '', severity: 'LOW', title: 'apt: weak key validation', score: 3.7, publishedDate: '2019-11-26T00:15:00Z' },
];

function vulnReport(name: string, ns: string, kind: string, workload: string, container: string, repo: string, tag: string, digest: string, vulns: typeof nginxVulns, updatedHours = 2): VulnerabilityReport {
    const c = (s: string): number => vulns.filter((v) => v.severity === s).length;
    return {
        apiVersion: 'aquasecurity.github.io/v1alpha1',
        kind: 'VulnerabilityReport',
        metadata: { name, namespace: ns, uid: name, resourceVersion: '1', labels: labels(kind, workload, ns, container), ownerReferences: owner(kind, workload), creationTimestamp: hoursAgo(updatedHours) },
        report: {
            artifact: { repository: repo, tag, digest },
            registry: { server: 'index.docker.io' },
            os: { family: 'debian', name: '12.5' },
            scanner: { name: 'Trivy', vendor: 'Aqua Security', version: '0.58.0' },
            summary: { criticalCount: c('CRITICAL'), highCount: c('HIGH'), mediumCount: c('MEDIUM'), lowCount: c('LOW'), unknownCount: 0, noneCount: 0 },
            updateTimestamp: hoursAgo(updatedHours),
            vulnerabilities: vulns,
        },
    };
}

export const vulnerabilityReports: VulnerabilityReport[] = [
    vulnReport('replicaset-shop-7d9f8c-nginx', 'shop', 'ReplicaSet', 'shop-7d9f8c', 'nginx', 'library/nginx', '1.25.3', 'sha256:aaa111', nginxVulns),
    vulnReport('statefulset-cache-nginx', 'shop', 'StatefulSet', 'cache', 'nginx', 'library/nginx', '1.25.3', 'sha256:aaa111', nginxVulns),
    vulnReport('replicaset-api-55bb-api', 'payments', 'ReplicaSet', 'api-55bb', 'api', 'acme/payments-api', 'v2.1.0', 'sha256:bbb222', [nginxVulns[1]!, nginxVulns[3]!]),
    vulnReport('daemonset-agent-agent', 'monitoring', 'DaemonSet', 'agent', 'agent', 'grafana/alloy', 'v1.4.0', 'sha256:ccc333', [], 30),
    // A report the operator wrote with only its summary.
    {
        apiVersion: 'aquasecurity.github.io/v1alpha1',
        kind: 'VulnerabilityReport',
        metadata: { name: 'cronjob-backup-backup', namespace: 'payments', uid: 'cj', resourceVersion: '1', labels: labels('CronJob', 'backup', 'payments', 'backup') },
        report: {
            artifact: { repository: 'acme/backup', tag: 'latest' },
            registry: { server: 'ghcr.io' },
            os: { family: 'alpine', name: '3.12.0', eosl: true },
            summary: { criticalCount: 2, highCount: 1, mediumCount: 0, lowCount: 0 },
            updateTimestamp: hoursAgo(5),
            vulnerabilities: null,
        },
    },
];

export const replicasets: KubeObject[] = [
    { metadata: { name: 'shop-7d9f8c', namespace: 'shop', ownerReferences: owner('Deployment', 'shop'), creationTimestamp: hoursAgo(48) } },
    { metadata: { name: 'api-55bb', namespace: 'payments', ownerReferences: owner('Deployment', 'api'), creationTimestamp: hoursAgo(48) } },
];

function audit(kindName: string, name: string, ns: string, kind: string, target: string, checks: NonNullable<NonNullable<AuditReport['report']>['checks']>): AuditReport {
    const c = (s: string): number => checks.filter((x) => x.severity === s && !x.success).length;
    return {
        apiVersion: 'aquasecurity.github.io/v1alpha1',
        kind: kindName,
        metadata: { name, namespace: ns, uid: name, resourceVersion: '1', labels: labels(kind, target, ns), ownerReferences: owner(kind, target) },
        report: { summary: { criticalCount: c('CRITICAL'), highCount: c('HIGH'), mediumCount: c('MEDIUM'), lowCount: c('LOW') }, updateTimestamp: hoursAgo(3), checks },
    };
}

export const configAuditReports: AuditReport[] = [
    audit('ConfigAuditReport', 'replicaset-shop-7d9f8c', 'shop', 'ReplicaSet', 'shop-7d9f8c', [
        { checkID: 'KSV014', title: 'Root file system is not read-only', severity: 'HIGH', category: 'Kubernetes Security Check', success: false, messages: ["Container 'nginx' should set 'securityContext.readOnlyRootFilesystem' to true"], remediation: 'Change securityContext.readOnlyRootFilesystem to true.' },
        { checkID: 'KSV011', title: 'CPU not limited', severity: 'LOW', category: 'Kubernetes Security Check', success: false, messages: ["Container 'nginx' should set 'resources.limits.cpu'"] },
    ]),
    audit('ConfigAuditReport', 'replicaset-api-55bb', 'payments', 'ReplicaSet', 'api-55bb', [
        { checkID: 'KSV017', title: 'Privileged', severity: 'CRITICAL', category: 'Kubernetes Security Check', success: false, messages: ["Container 'api' should set 'securityContext.privileged' to false"], remediation: 'Change securityContext.privileged to false.' },
        { checkID: 'KSV014', title: 'Root file system is not read-only', severity: 'HIGH', category: 'Kubernetes Security Check', success: false, messages: ["Container 'api' should set 'securityContext.readOnlyRootFilesystem' to true"] },
    ]),
    audit('ConfigAuditReport', 'service-shop', 'shop', 'Service', 'shop', []),
];

export const rbacReports: AuditReport[] = [
    audit('RbacAssessmentReport', 'role-pod-reader', 'shop', 'Role', 'pod-reader', [
        { checkID: 'KSV041', title: 'Manage secrets', severity: 'CRITICAL', category: 'Kubernetes Security Check', success: false, messages: ["Role permits management of secret(s)"] },
    ]),
];

export const exposedSecretReports: ExposedSecretReport[] = [
    {
        apiVersion: 'aquasecurity.github.io/v1alpha1',
        kind: 'ExposedSecretReport',
        metadata: { name: 'replicaset-api-55bb-api', namespace: 'payments', uid: 'es1', resourceVersion: '1', labels: labels('ReplicaSet', 'api-55bb', 'payments', 'api'), ownerReferences: owner('ReplicaSet', 'api-55bb') },
        report: {
            artifact: { repository: 'acme/payments-api', tag: 'v2.1.0', digest: 'sha256:bbb222' },
            registry: { server: 'index.docker.io' },
            summary: { criticalCount: 1, highCount: 0, mediumCount: 0, lowCount: 0 },
            updateTimestamp: hoursAgo(2),
            secrets: [{ target: '/app/.env', ruleID: 'aws-access-key-id', title: 'AWS Access Key ID', category: 'AWS', severity: 'CRITICAL', match: 'AWS_ACCESS_KEY_ID=********************' }],
        },
    },
];

export const complianceReports: ComplianceReport[] = [
    {
        apiVersion: 'aquasecurity.github.io/v1alpha1',
        kind: 'ClusterComplianceReport',
        metadata: { name: 'k8s-nsa-1.0', uid: 'nsa', resourceVersion: '1' },
        spec: {
            cron: '0 */6 * * *',
            reportType: 'summary',
            compliance: {
                id: 'k8s-nsa-1.0',
                title: 'National Security Agency - Kubernetes Hardening Guidance v1.0',
                description: 'National Security Agency - Kubernetes Hardening Guidance',
                version: '1.0',
                controls: [
                    { id: '1.0', name: 'Non-root containers', severity: 'MEDIUM', description: 'Check that container is not running as root' },
                    { id: '1.1', name: 'Immutable container file systems', severity: 'LOW' },
                    { id: '1.2', name: 'Preventing privileged containers', severity: 'HIGH' },
                ],
            },
        },
        status: {
            summary: { passCount: 1, failCount: 2 },
            summaryReport: {
                id: 'k8s-nsa-1.0',
                title: 'nsa',
                controlCheck: [
                    { id: '1.0', name: 'Non-root containers', severity: 'MEDIUM', totalFail: 4 },
                    { id: '1.1', name: 'Immutable container file systems', severity: 'LOW', totalFail: 0 },
                    { id: '1.2', name: 'Preventing privileged containers', severity: 'HIGH', totalFail: 1 },
                ],
            },
            updateTimestamp: hoursAgo(1),
        },
    },
];
