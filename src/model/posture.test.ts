import { describe, expect, it } from 'vitest';
import { NOW, complianceReports, configAuditReports, exposedSecretReports, rbacReports, replicasets, vulnerabilityReports } from '../fixtures';
import { buildPosture, emptyData, type TrivyData } from './posture';
import { imageName, severity, subjectOf } from './trivy';

const data = (): TrivyData => ({
    ...emptyData(),
    vulnerability: vulnerabilityReports,
    configAudit: configAuditReports,
    rbac: rbacReports,
    exposedSecret: exposedSecretReports,
    compliance: complianceReports,
    replicasets,
});

describe('severity', () => {
    it('reads any spelling', () => {
        expect(severity('Critical')).toBe('CRITICAL');
        expect(severity('high')).toBe('HIGH');
        expect(severity('')).toBe('UNKNOWN');
        expect(severity(undefined)).toBe('UNKNOWN');
    });
});

describe('subjectOf', () => {
    it('prefers the owner reference, then the labels', () => {
        expect(subjectOf(vulnerabilityReports[0]!)).toEqual({ kind: 'ReplicaSet', name: 'shop-7d9f8c', namespace: 'shop', container: 'nginx' });
        expect(subjectOf(vulnerabilityReports[4]!)).toMatchObject({ kind: 'CronJob', name: 'backup' });
    });
});

describe('imageName', () => {
    it('leaves Docker Hub prefixes off', () => {
        expect(imageName({ registry: 'index.docker.io', repository: 'library/nginx', tag: '1.25.3', digest: '' })).toBe('nginx:1.25.3');
        expect(imageName({ registry: 'ghcr.io', repository: 'acme/backup', tag: 'latest', digest: '' })).toBe('ghcr.io/acme/backup:latest');
    });
});

describe('buildPosture', () => {
    const p = buildPosture(data(), { now: NOW });

    it('counts each image once, however many workloads run it', () => {
        expect(p.totals.images).toBe(4);
        const nginx = p.images.find((i) => i.name === 'nginx:1.25.3')!;
        expect(nginx.workloads.map((w) => w.key).sort()).toEqual(['Deployment/shop/shop', 'StatefulSet/shop/cache']);
        expect(nginx.counts).toMatchObject({ CRITICAL: 1, HIGH: 2, MEDIUM: 1, LOW: 1 });
    });

    it('counts each CVE once, at its worst', () => {
        // nginx's five, of which the API image shares two -- plus nothing from the summary-only report.
        expect(p.cves.length).toBe(5);
        expect(p.cves[0]!.id).toBe('CVE-2024-6387');
        const reset = p.cves.find((c) => c.id === 'CVE-2023-44487')!;
        expect(reset.images.length).toBe(2);
        expect(reset.workloads.length).toBe(3);
        expect(reset.fixable).toBe(true);
    });

    it('lifts a ReplicaSet to its Deployment', () => {
        const shop = p.workloads.find((w) => w.workload.name === 'shop')!;
        expect(shop.workload).toMatchObject({ kind: 'Deployment', appKind: 'deployments', via: { kind: 'ReplicaSet', name: 'shop-7d9f8c' } });
        expect(shop.misconfig).toMatchObject({ HIGH: 1, LOW: 1 });
    });

    it('uses the summary when the report has no list', () => {
        const backup = p.images.find((i) => i.name.includes('backup'))!;
        expect(backup.detailed).toBe(false);
        expect(backup.counts).toMatchObject({ CRITICAL: 2, HIGH: 1 });
        expect(backup.eosl).toBe(true);
        expect(p.totals.findings.CRITICAL).toBe(3);
    });

    it('counts findings and fixes', () => {
        expect(p.totals.fixable).toBe(3);
        expect(p.totals.fixableCritical).toBe(1);
        expect(p.totals.cleanImages).toBe(1);
    });

    it('collects misconfigurations by audit and by check', () => {
        expect(p.totals.misconfigBy.config).toMatchObject({ CRITICAL: 1, HIGH: 2, LOW: 1 });
        expect(p.totals.misconfigBy.rbac.CRITICAL).toBe(1);
        expect(p.totals.resources).toBe(4);
        const ksv014 = p.checks.find((c) => c.checkID === 'KSV014')!;
        expect(ksv014.resources.length).toBe(2);
        // A Service's audit does not become a workload with vulnerabilities.
        expect(p.workloads.some((w) => w.workload.kind === 'Service')).toBe(false);
    });

    it('lists secrets and compliance', () => {
        expect(p.secrets).toHaveLength(1);
        expect(p.secrets[0]!.workload.name).toBe('api');
        expect(p.totals.imagesWithSecrets).toBe(1);
        expect(p.compliance[0]!.rate).toBeCloseTo(1 / 3);
        expect(p.compliance[0]!.controls[0]!.id).toBe('1.2');
    });

    it('scores from its gauges', () => {
        expect(p.score.gauges.map((g) => g.id)).toEqual(['images', 'resources', 'compliance']);
        expect(p.score.value).not.toBeNull();
        expect(p.score.value!).toBeLessThan(50);
    });

    it('sorts namespaces worst first and years oldest first', () => {
        // Both have two criticals; shop has more highs.
        expect(p.namespaces[0]!.namespace).toBe('shop');
        expect(p.byYear.map((y) => y.year)).toEqual([2019, 2022, 2023, 2024]);
    });

    it('draws nothing from nothing', () => {
        const empty = buildPosture(emptyData());
        expect(empty.totals.images).toBe(0);
        expect(empty.score.value).toBeNull();
        expect(empty.score.grade).toBe('–');
    });
});
