// Built by k8sdockside-plugin from src/ -- edit the TypeScript there, not this file.
"use strict";
(() => {
  // src/model/trivy.ts
  var GROUP = "aquasecurity.github.io";
  var KINDS = {
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
    clusterSbom: `crd:clustersbomreports.${GROUP}`
  };
  var SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
  var SEVERITY_LABEL = {
    CRITICAL: "Critical",
    HIGH: "High",
    MEDIUM: "Medium",
    LOW: "Low",
    UNKNOWN: "Unknown"
  };
  function severity(value) {
    const s = String(value ?? "").toUpperCase();
    return SEVERITIES.includes(s) ? s : "UNKNOWN";
  }
  function rank(s) {
    return SEVERITIES.indexOf(s);
  }
  function zero() {
    return { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  }
  function addCounts(into, from) {
    for (const s of SEVERITIES) into[s] += from[s];
    return into;
  }
  function total(c) {
    return SEVERITIES.reduce((n, s) => n + c[s], 0);
  }
  function compareCounts(a, b) {
    for (const s of SEVERITIES) if (a[s] !== b[s]) return b[s] - a[s];
    return 0;
  }
  function fromSummary(s) {
    return {
      CRITICAL: num(s?.criticalCount),
      HIGH: num(s?.highCount),
      MEDIUM: num(s?.mediumCount),
      LOW: num(s?.lowCount),
      UNKNOWN: num(s?.unknownCount)
    };
  }
  function num(v) {
    return typeof v === "number" && Number.isFinite(v) ? v : 0;
  }
  var L_KIND = "trivy-operator.resource.kind";
  var L_NAME = "trivy-operator.resource.name";
  var L_NS = "trivy-operator.resource.namespace";
  var L_CONTAINER = "trivy-operator.container.name";
  function subjectOf(report) {
    const labels = report.metadata.labels ?? {};
    const owner = report.metadata.ownerReferences?.find((o) => o.controller) ?? report.metadata.ownerReferences?.[0];
    return {
      kind: owner?.kind || labels[L_KIND] || "",
      name: owner?.name || labels[L_NAME] || report.metadata.name,
      namespace: labels[L_NS] ?? report.metadata.namespace ?? "",
      container: labels[L_CONTAINER] ?? ""
    };
  }
  function updatedAt(report) {
    const t = Date.parse(report.report?.updateTimestamp ?? report.metadata.creationTimestamp ?? "");
    return Number.isFinite(t) ? t : 0;
  }
  function imageOf(report) {
    const a = report.report?.artifact ?? {};
    return {
      registry: report.report?.registry?.server ?? "",
      repository: a.repository ?? "",
      tag: a.tag ?? "",
      digest: a.digest ?? ""
    };
  }
  function imageKey(ref) {
    return `${ref.registry}/${ref.repository}` + (ref.digest ? "@" + ref.digest : ":" + ref.tag);
  }
  function imageName(ref, opts = {}) {
    let host = ref.registry;
    let repo = ref.repository;
    if (host === "index.docker.io" || host === "docker.io" || host === "registry-1.docker.io") {
      host = "";
      repo = repo.replace(/^library\//, "");
    }
    const base = (host ? host + "/" : "") + (repo || "(unknown image)");
    if (opts.tag === false) return base;
    if (ref.tag) return `${base}:${ref.tag}`;
    if (ref.digest) return `${base}@${shortDigest(ref.digest)}`;
    return base;
  }
  function shortDigest(digest) {
    const [algo, hex] = digest.includes(":") ? digest.split(":", 2) : ["", digest];
    return (algo ? algo + ":" : "") + (hex ?? "").slice(0, 12);
  }

  // src/model/posture.ts
  function emptyData() {
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
      clusterSbom: []
    };
  }
  var APP_KIND = {
    Pod: "pods",
    ReplicaSet: "replicasets",
    ReplicationController: "replicationcontrollers",
    Deployment: "deployments",
    StatefulSet: "statefulsets",
    DaemonSet: "daemonsets",
    Job: "jobs",
    CronJob: "cronjobs",
    Node: "nodes",
    Service: "services",
    ConfigMap: "configmaps",
    Ingress: "ingresses",
    NetworkPolicy: "networkpolicies",
    ResourceQuota: "resourcequotas",
    LimitRange: "limitranges",
    ServiceAccount: "serviceaccounts",
    Role: "roles",
    RoleBinding: "rolebindings",
    ClusterRole: "clusterroles",
    ClusterRoleBinding: "clusterrolebindings"
  };
  function appKind(kind) {
    return APP_KIND[kind] ?? "";
  }
  function workloadKey(kind, namespace, name) {
    return `${kind}/${namespace}/${name}`;
  }
  function makeLifter(data) {
    const owners = /* @__PURE__ */ new Map();
    const remember = (kind, list, ownerKind) => {
      for (const o of list ?? []) {
        const ref = o.metadata.ownerReferences?.find((r) => r.controller && r.kind === ownerKind);
        if (ref) owners.set(workloadKey(kind, o.metadata.namespace ?? "", o.metadata.name), { kind: ref.kind, name: ref.name });
      }
    };
    remember("ReplicaSet", data.replicasets, "Deployment");
    remember("Job", data.jobs, "CronJob");
    return (s) => {
      const up = owners.get(workloadKey(s.kind, s.namespace, s.name));
      if (up) return { key: workloadKey(up.kind, s.namespace, up.name), kind: up.kind, name: up.name, namespace: s.namespace, appKind: appKind(up.kind), via: { kind: s.kind, name: s.name } };
      return { key: workloadKey(s.kind, s.namespace, s.name), kind: s.kind, name: s.name, namespace: s.namespace, appKind: appKind(s.kind) };
    };
  }
  var AUDIT_LABEL = { config: "Workload config", rbac: "RBAC", infra: "Infrastructure" };
  var DAY = 864e5;
  function reportRef(kind, o) {
    return { kind, namespace: o.metadata.namespace ?? "", name: o.metadata.name };
  }
  function addWorkload(list, w) {
    if (!list.some((x) => x.key === w.key)) list.push(w);
  }
  function buildPosture(data, opts = {}) {
    const now = opts.now ?? Date.now();
    const lift = makeLifter(data);
    const images = /* @__PURE__ */ new Map();
    const cves = /* @__PURE__ */ new Map();
    const workloads = /* @__PURE__ */ new Map();
    const namespaces = /* @__PURE__ */ new Map();
    const stamps = [];
    const nsEntry = (ns) => {
      let e = namespaces.get(ns);
      if (!e) {
        e = { namespace: ns, vulns: zero(), misconfig: zero(), secrets: zero(), images: 0, workloads: 0, imageSet: /* @__PURE__ */ new Set(), workloadSet: /* @__PURE__ */ new Set() };
        namespaces.set(ns, e);
      }
      return e;
    };
    const wlEntry = (w) => {
      let e = workloads.get(w.key);
      if (!e) {
        e = { workload: w, counts: zero(), fixable: 0, images: [], containers: [], misconfig: zero(), secrets: 0, updated: 0 };
        workloads.set(w.key, e);
      }
      return e;
    };
    const vulnReports = [
      ...data.vulnerability.map((r) => [r, KINDS.vulnerability]),
      ...data.clusterVulnerability.map((r) => [r, KINDS.clusterVulnerability])
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
      const findings2 = list.map((v) => ({
        id: v.vulnerabilityID || "(no id)",
        severity: severity(v.severity),
        score: typeof v.score === "number" ? v.score : null,
        title: v.title ?? "",
        description: v.description ?? "",
        link: v.primaryLink ?? v.links?.[0] ?? "",
        links: v.links ?? [],
        pkg: v.resource ?? "",
        installed: v.installedVersion ?? "",
        fixed: v.fixedVersion ?? "",
        target: v.target ?? "",
        published: Date.parse(v.publishedDate ?? "") || 0
      }));
      const counts = list.length ? countFindings(findings2) : summary;
      const fixable2 = findings2.filter((f) => f.fixed).length;
      const reportR = reportRef(kind, r);
      let img = images.get(key);
      if (!img) {
        const os = r.report?.os;
        img = {
          key,
          ref,
          name: imageName(ref),
          os: [os?.family, os?.name].filter(Boolean).join(" "),
          eosl: Boolean(os?.eosl),
          counts,
          fixable: fixable2,
          findings: findings2,
          detailed: list.length > 0 || total(summary) === 0,
          workloads: [],
          containers: [],
          namespaces: [],
          reports: [],
          updated: stamp,
          components: null
        };
        images.set(key, img);
      } else if (stamp > img.updated) {
        Object.assign(img, { counts, fixable: fixable2, findings: findings2, detailed: list.length > 0 || total(summary) === 0, updated: stamp });
      }
      addWorkload(img.workloads, w);
      if (subject.container && !img.containers.includes(subject.container)) img.containers.push(subject.container);
      if (!img.namespaces.includes(w.namespace)) img.namespaces.push(w.namespace);
      img.reports.push(reportR);
      const we = wlEntry(w);
      addCounts(we.counts, counts);
      we.fixable += fixable2;
      if (!we.images.includes(key)) we.images.push(key);
      we.containers.push({ name: subject.container, image: img.name, counts, report: reportR });
      we.updated = Math.max(we.updated, stamp);
      const ns = nsEntry(w.namespace);
      addCounts(ns.vulns, counts);
      ns.imageSet.add(key);
      ns.workloadSet.add(w.key);
      for (const f of findings2) {
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
            imageSet: /* @__PURE__ */ new Set()
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
    for (const r of [...data.sbom, ...data.clusterSbom]) {
      const img = images.get(imageKey(imageOf(r)));
      const n = r.report?.summary?.componentsCount;
      if (img && typeof n === "number") img.components = n;
    }
    const resources = [];
    const checks = /* @__PURE__ */ new Map();
    const audits = [
      ["config", data.configAudit, KINDS.configAudit],
      ["config", data.clusterConfigAudit, KINDS.clusterConfigAudit],
      ["rbac", data.rbac, KINDS.rbac],
      ["rbac", data.clusterRbac, KINDS.clusterRbac],
      ["infra", data.infra, KINDS.infra],
      ["infra", data.clusterInfra, KINDS.clusterInfra]
    ];
    const misconfigBy = { config: zero(), rbac: zero(), infra: zero() };
    for (const [audit, list, kind] of audits) {
      for (const r of list) {
        const w = lift(subjectOf(r));
        const ref = reportRef(kind, r);
        const stamp = updatedAt(r);
        stamps.push(stamp);
        const failed = (r.report?.checks ?? []).filter((c) => c.success === false || c.success === void 0);
        const findings2 = failed.map((c) => ({
          audit,
          checkID: c.checkID ?? "",
          title: c.title ?? c.checkID ?? "",
          description: c.description ?? "",
          severity: severity(c.severity),
          category: c.category ?? "",
          messages: (c.messages ?? []).filter(Boolean),
          remediation: c.remediation ?? "",
          workload: w,
          report: ref
        }));
        const summary = fromSummary(r.report?.summary);
        const counts = findings2.length ? countFindings(findings2) : summary;
        resources.push({ audit, workload: w, counts, findings: findings2, detailed: findings2.length > 0 || total(summary) === 0, report: ref, updated: stamp });
        addCounts(misconfigBy[audit], counts);
        addCounts(nsEntry(w.namespace).misconfig, counts);
        const we = workloads.get(w.key);
        if (we) addCounts(we.misconfig, counts);
        for (const f of findings2) {
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
    const secrets = [];
    const imagesWithSecrets = /* @__PURE__ */ new Set();
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
          ruleID: s.ruleID ?? "",
          title: s.title ?? s.ruleID ?? "Secret",
          category: s.category ?? "",
          target: s.target ?? "",
          match: s.match ?? "",
          image: imageName(ref),
          workload: w,
          container: subject.container,
          report: reportRef(secretKind, r)
        });
      }
      if (total(counts)) imagesWithSecrets.add(imageKey(ref));
      addCounts(secretCounts, counts);
      addCounts(nsEntry(w.namespace).secrets, counts);
      const we = workloads.get(w.key);
      if (we) we.secrets += total(counts);
    }
    secrets.sort((a, b) => rank(a.severity) - rank(b.severity) || a.workload.key.localeCompare(b.workload.key) || a.target.localeCompare(b.target));
    const compliance = data.compliance.map((r) => {
      const spec = r.spec?.compliance ?? {};
      const pass = r.status?.summary?.passCount ?? 0;
      const fail2 = r.status?.summary?.failCount ?? 0;
      const described = new Map((spec.controls ?? []).map((c) => [c.id ?? "", c]));
      const controls = (r.status?.summaryReport?.controlCheck ?? []).map((c) => ({
        id: c.id ?? "",
        name: c.name ?? described.get(c.id ?? "")?.name ?? "",
        severity: severity(c.severity ?? described.get(c.id ?? "")?.severity),
        fail: c.totalFail ?? 0,
        description: described.get(c.id ?? "")?.description ?? ""
      }));
      controls.sort((a, b) => (b.fail > 0 ? 1 : 0) - (a.fail > 0 ? 1 : 0) || rank(a.severity) - rank(b.severity) || b.fail - a.fail || a.id.localeCompare(b.id, void 0, { numeric: true }));
      const stamp = Date.parse(r.status?.updateTimestamp ?? "") || 0;
      if (stamp) stamps.push(stamp);
      return {
        name: r.metadata.name,
        id: spec.id ?? r.metadata.name,
        title: spec.title || r.metadata.name,
        description: spec.description ?? "",
        version: spec.version ?? "",
        pass,
        fail: fail2,
        rate: pass + fail2 > 0 ? pass / (pass + fail2) : null,
        controls,
        updated: stamp,
        cron: r.spec?.cron ?? ""
      };
    });
    compliance.sort((a, b) => a.title.localeCompare(b.title));
    const imageList = [...images.values()].sort((a, b) => compareCounts(a.counts, b.counts) || a.name.localeCompare(b.name));
    const cveList = [...cves.values()].map(({ imageSet, ...c }) => ({ ...c, images: [...imageSet] })).sort((a, b) => rank(a.severity) - rank(b.severity) || b.images.length - a.images.length || (b.score ?? 0) - (a.score ?? 0) || a.id.localeCompare(b.id));
    const workloadList = [...workloads.values()].sort((a, b) => compareCounts(a.counts, b.counts) || compareCounts(a.misconfig, b.misconfig) || a.workload.key.localeCompare(b.workload.key));
    const nsList = [...namespaces.values()].map(({ imageSet, workloadSet, ...n }) => ({ ...n, images: imageSet.size, workloads: workloadSet.size })).sort((a, b) => compareCounts(a.vulns, b.vulns) || compareCounts(a.misconfig, b.misconfig) || a.namespace.localeCompare(b.namespace));
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
        if (f.severity === "CRITICAL") fixableCritical++;
        else if (f.severity === "HIGH") fixableHigh++;
      }
    }
    const cveCounts = zero();
    for (const c of cveList) cveCounts[c.severity]++;
    if (!cveList.length) addCounts(cveCounts, findings);
    const misconfig = zero();
    for (const k of Object.keys(misconfigBy)) addCounts(misconfig, misconfigBy[k]);
    const cleanImages = imageList.filter((i) => !i.counts.CRITICAL && !i.counts.HIGH).length;
    const cleanResources = resources.filter((r) => !r.counts.CRITICAL && !r.counts.HIGH).length;
    const known = stamps.filter((t) => t > 0);
    const byYearMap = /* @__PURE__ */ new Map();
    for (const c of cveList) {
      if (!c.published) continue;
      const y = new Date(c.published).getUTCFullYear();
      const counts = byYearMap.get(y) ?? zero();
      counts[c.severity]++;
      byYearMap.set(y, counts);
    }
    const byYear = [...byYearMap.entries()].sort((a, b) => a[0] - b[0]).map(([year, counts]) => ({ year, counts }));
    const totals = {
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
      stale: known.filter((t) => now - t > DAY).length
    };
    const score = scoreOf(totals, compliance);
    const posture = {
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
      signature: ""
    };
    posture.signature = fingerprint(
      JSON.stringify([totals, score.value, imageList.map((i) => [i.key, i.updated, i.workloads.length]), resources.map((r) => [r.report.name, r.updated]), compliance.map((c) => [c.name, c.pass, c.fail]), secrets.length])
    );
    return posture;
  }
  function countFindings(list) {
    const c = zero();
    for (const f of list) c[f.severity]++;
    return c;
  }
  function scoreOf(t, compliance) {
    const pass = compliance.reduce((n, c) => n + c.pass, 0);
    const fail2 = compliance.reduce((n, c) => n + c.fail, 0);
    const gauges = [
      {
        id: "images",
        label: "Images",
        value: t.images ? t.cleanImages / t.images : null,
        detail: t.images ? `${t.cleanImages} of ${t.images} free of critical and high` : "no images scanned"
      },
      {
        id: "resources",
        label: "Configuration",
        value: t.resources ? t.cleanResources / t.resources : null,
        detail: t.resources ? `${t.cleanResources} of ${t.resources} resources without critical or high findings` : "no config audits"
      },
      {
        id: "compliance",
        label: "Compliance",
        value: pass + fail2 ? pass / (pass + fail2) : null,
        detail: pass + fail2 ? `${pass} of ${pass + fail2} controls passing` : "no compliance reports"
      }
    ];
    const measured = gauges.filter((g) => g.value !== null).map((g) => g.value);
    if (!measured.length) return { value: null, grade: "–", gauges };
    const base = measured.reduce((n, v) => n + v, 0) / measured.length * 100;
    const penalty = Math.min(15, t.fixableCritical * 0.5);
    const value = Math.max(0, Math.round(base - penalty));
    const grade = value >= 90 ? "A" : value >= 80 ? "B" : value >= 65 ? "C" : value >= 50 ? "D" : value >= 35 ? "E" : "F";
    return { value, grade, gauges };
  }
  function fingerprint(text) {
    let h = 2166136261;
    for (let i = 0; i < text.length; i++) {
      h ^= text.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return (h >>> 0).toString(36);
  }

  // src/model/feed.ts
  var BY_KIND = new Map(Object.entries(KINDS).map(([k, v]) => [v, k]));
  function listPrint(items) {
    return fingerprint(items.map((o) => `${o.metadata.uid ?? o.metadata.namespace + "/" + o.metadata.name}@${o.metadata.resourceVersion ?? ""}`).join("|"));
  }
  function startFeed(bridge, opts) {
    const state2 = { data: emptyData(), served: /* @__PURE__ */ new Set(), errors: {}, ready: false, summary: null };
    const prints = /* @__PURE__ */ new Map();
    const answered = /* @__PURE__ */ new Set();
    const stops = [];
    let stopped = false;
    const settle = () => {
      const wanted = [...state2.served];
      if (opts.owners !== false) wanted.push("replicasets", "jobs");
      state2.ready = wanted.every((k) => answered.has(k) || k in state2.errors);
    };
    function accept(key, items) {
      const print = listPrint(items);
      const hadError = key in state2.errors;
      delete state2.errors[key];
      const first = !answered.has(key);
      answered.add(key);
      if (prints.get(key) === print && !hadError && !first) return;
      prints.set(key, print);
      state2.data[key] = items;
      settle();
      opts.onChange(state2);
    }
    function refuse(key, err) {
      if (state2.errors[key] === err.message) return;
      state2.errors[key] = err.message;
      settle();
      opts.onChange(state2);
    }
    const watch = (key, kind, interval) => {
      stops.push(
        bridge.watch(
          { kind, namespace: opts.namespace ?? "", interval },
          (items) => accept(key, items),
          (err) => refuse(key, err)
        )
      );
    };
    bridge.summary().then((summary) => {
      if (stopped) return;
      state2.summary = summary;
      for (const r of summary.requirements) {
        const key = BY_KIND.get(r.kind);
        if (key && (r.served || r.error) && (!opts.only || opts.only.includes(key))) state2.served.add(key);
      }
      if (!summary.checked) {
        state2.served.add("vulnerability");
      }
      settle();
      opts.onChange(state2);
      for (const key of state2.served) watch(key, KINDS[key], opts.interval ?? 3e4);
      if (opts.owners !== false) {
        watch("replicasets", "replicasets", 6e4);
        watch("jobs", "jobs", 6e4);
      }
    }).catch((err) => {
      state2.errors.vulnerability = err instanceof Error ? err.message : String(err);
      opts.onChange(state2);
    });
    return () => {
      stopped = true;
      stops.forEach((stop) => stop());
    };
  }

  // src/ui/icons.ts
  var ICONS = {
    // A shield with a tick: what Trivy is for.
    logo: ["M12 3l7.5 3v5.5c0 4.6-3.2 8.3-7.5 9.5-4.3-1.2-7.5-4.9-7.5-9.5V6z", "M8.5 12l2.5 2.5 4.5-5"],
    shield: ["M12 3l7.5 3v5.5c0 4.6-3.2 8.3-7.5 9.5-4.3-1.2-7.5-4.9-7.5-9.5V6z"],
    bug: ["M9 7.5a3 3 0 0 1 6 0", "M7 10h10v4a5 5 0 0 1-10 0z", "M12 10v9", "M4 12h3", "M17 12h3", "M4.5 7.5 7 9.5", "M19.5 7.5 17 9.5", "M4.5 18.5 7.2 16", "M19.5 18.5 16.8 16"],
    package: ["M12 3l8 4.5v9L12 21l-8-4.5v-9z", "M4 7.5l8 4.5 8-4.5", "M12 12v9", "M8 5.3l8 4.4"],
    image: ["M4 5h16v14H4z", "M4 16l4.5-4.5 3.5 3.5 2.5-2.5L20 18", "M15.5 9h.01"],
    wrench: ["M14.5 6.5a4 4 0 0 0 5 5L12 19a2.1 2.1 0 0 1-3-3l7.5-7.5", "M14.5 6.5 17 4"],
    key: ["M8 15a4 4 0 1 0 0-8 4 4 0 0 0 0 8z", "M11.5 11H21", "M18 11v3", "M15 11v2"],
    policy: ["M6 3h9l4 4v14H6z", "M14 3v5h5", "M9 13l2 2 4-4"],
    certificate: ["M5 4h14v11H5z", "M8 8h8", "M8 11h5", "M15.5 15v6l-2-1.3-2 1.3v-6"],
    rbac: ["M9 5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7z", "M2.5 20a6.5 6.5 0 0 1 10-5.5", "M15 14h6v6h-6z", "M16.5 14v-1.5a1.5 1.5 0 0 1 3 0V14"],
    server: ["M4 5h16v5H4z", "M4 14h16v5H4z", "M7.5 7.5h.01", "M7.5 16.5h.01"],
    rescan: ["M20.5 12a8.5 8.5 0 1 1-2.6-6.1", "M20.5 4v5h-5"],
    calendar: ["M4 6h16v14H4z", "M4 10h16", "M8 3.5v4", "M16 3.5v4"],
    heat: ["M4 4h5v5H4z", "M10 4h5v5h-5z", "M16 4h4v5h-4z", "M4 10h5v5H4z", "M10 10h5v5h-5z", "M4 16h5v4H4z"],
    eye: ["M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z", "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z"],
    copy: ["M9 9h11v11H9z", "M5 15H4V4h11v1"],
    sort: ["M8 4v16", "M4.5 7.5 8 4l3.5 3.5", "M16 20V4", "M12.5 16.5 16 20l3.5-3.5"],
    "chevron-up": ["M6 14.5l6-6 6 6"],
    file: ["M6 3h9l4 4v14H6z", "M14 3v5h5"],
    gauge: ["M3.5 16a8.5 8.5 0 1 1 17 0", "M12 16l4-5", "M12 16h.01"],
    rocket: ["M12 3c3 2 4.5 5 4.5 9l-2 4h-5l-2-4c0-4 1.5-7 4.5-9z", "M12 9.5h.01", "M9.5 16 7 20l3-1", "M14.5 16 17 20l-3-1"],
    play: ["M7 4.5v15l12-7.5z"],
    lock: ["M6 10.5h12v9.5H6z", "M8.5 10.5V7.5a3.5 3.5 0 0 1 7 0v3"],
    pod: ["M12 3l8 4.5v9L12 21l-8-4.5v-9z", "M12 12l8-4.5", "M12 12v9", "M12 12L4 7.5"],
    deployment: ["M3 7l9-4 9 4-9 4-9-4z", "M3 12l9 4 9-4", "M3 17l9 4 9-4"],
    statefulset: ["M12 3c4.4 0 8 1.3 8 3s-3.6 3-8 3-8-1.3-8-3 3.6-3 8-3z", "M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6", "M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"],
    daemonset: ["M17 2l4 4-4 4", "M3 11V9a4 4 0 0 1 4-4h14", "M7 22l-4-4 4-4", "M21 13v2a4 4 0 0 1-4 4H3"],
    cronjob: ["M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z", "M12 7v5l3 2"],
    job: ["M9 11.5l2.5 2.5L20 5.5", "M20 12v7a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h9"],
    replicaset: ["M9 4h11v11", "M4 9h11v11H4z"],
    owner: ["M4 5h7v14H4z", "M15 12h5", "M17.5 9.5l2.5 2.5-2.5 2.5"],
    container: ["M4 7h16v11H4z", "M4 7l2-3h12l2 3", "M9 11h6"],
    init: ["M5 12h9", "M11 8l4 4-4 4", "M19 5v14"],
    node: ["M4 5h16v5H4z", "M4 14h16v5H4z", "M7.5 7.5h.01", "M7.5 16.5h.01"],
    alert: ["M12 3.5l9.5 17h-19z", "M12 10v4", "M12 17.2h.01"],
    failed: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z", "M9 9l6 6", "M15 9l-6 6"],
    check: ["M4.5 12.5l5 5L19.5 7"],
    close: ["M6.5 6.5l11 11", "M17.5 6.5l-11 11"],
    info: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z", "M12 11v6", "M12 7.5h.01"],
    clock: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z", "M12 7v5l3.2 2"],
    search: ["M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14z", "M20 20l-4-4"],
    open: ["M14 4h6v6", "M20 4l-9 9", "M18 14v6H4V6h6"],
    chevron: ["M9.5 6l6 6-6 6"],
    "chevron-down": ["M6 9.5l6 6 6-6"],
    restart: ["M20.5 12a8.5 8.5 0 1 1-2.6-6.1", "M20.5 4v5h-5"],
    logs: ["M4 5h16v14H4z", "M7.5 9.5l2.5 2.5-2.5 2.5", "M13 15h4"],
    edit: ["M4 20h4L19 9l-4-4L4 16z", "M14 6l4 4"],
    chart: ["M4 4v16h16", "M8 15l3-4 3 2 5-6"],
    rank: ["M6 20v-5", "M12 20V9", "M18 20V4"],
    users: ["M9 5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7z", "M2.5 20a6.5 6.5 0 0 1 13 0", "M16 5.3a3.5 3.5 0 0 1 0 6.4", "M18 14.3a6.5 6.5 0 0 1 3.5 5.7"],
    namespace: ["M4 6h6l2 2h8v10H4z"],
    globe: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z", "M3 12h18", "M12 3a14 14 0 0 1 0 18", "M12 3a14 14 0 0 0 0 18"],
    book: ["M12 6.5c-1.5-1.3-3.8-2-7-2v13c3.2 0 5.5.7 7 2 1.5-1.3 3.8-2 7-2v-13c-3.2 0-5.5.7-7 2z", "M12 6.5v13"],
    link: ["M10.5 13.5a4 4 0 0 0 5.7 0l2.3-2.3a4 4 0 0 0-5.7-5.7l-1.2 1.2", "M13.5 10.5a4 4 0 0 0-5.7 0l-2.3 2.3a4 4 0 0 0 5.7 5.7l1.2-1.2"],
    filter: ["M4 5h16l-6 7.5V19l-4 1.5v-8z"],
    grid: ["M4 4h7v7H4z", "M13 4h7v7h-7z", "M4 13h7v7H4z", "M13 13h7v7h-7z"],
    dot: ["M12 13a1 1 0 1 0 0-2 1 1 0 0 0 0 2z"]
  };
  function kindIcon(kind) {
    switch (kind) {
      case "Deployment":
        return "deployment";
      case "StatefulSet":
        return "statefulset";
      case "DaemonSet":
        return "daemonset";
      case "CronJob":
        return "cronjob";
      case "Job":
        return "job";
      case "ReplicaSet":
        return "replicaset";
      case "Pod":
        return "pod";
      case "Node":
        return "node";
      case "Role":
      case "ClusterRole":
      case "RoleBinding":
      case "ClusterRoleBinding":
      case "ServiceAccount":
        return "rbac";
      case "Service":
      case "Ingress":
      case "NetworkPolicy":
        return "globe";
      case "ConfigMap":
        return "file";
      default:
        return "owner";
    }
  }

  // src/ui/dom.ts
  var SVG_NS = "http://www.w3.org/2000/svg";
  function el(tag, className = "", text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== void 0) node.textContent = String(text);
    return node;
  }
  function add(parent, ...children) {
    for (const child of children) {
      if (child === null || child === void 0 || child === false) continue;
      parent.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
    }
    return parent;
  }
  function svg(tag, attrs = {}) {
    const node = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
    return node;
  }
  function clear(node) {
    node.textContent = "";
  }
  function byId(id) {
    const node = document.getElementById(id);
    if (!node) throw new Error(`the page has no #${id}`);
    return node;
  }
  function icon(name, className = "") {
    const node = svg("svg", { viewBox: "0 0 24 24", class: "ico" + (className ? " " + className : ""), "aria-hidden": "true" });
    for (const d of ICONS[name]) node.appendChild(svg("path", { d }));
    return node;
  }
  function button(text, className, iconName, onClick) {
    const node = el("button", className);
    node.type = "button";
    if (iconName) node.appendChild(icon(iconName));
    if (text) node.appendChild(el("span", "", text));
    node.addEventListener("click", onClick);
    return node;
  }

  // src/ui/charts.ts
  function sevColour(s) {
    return `var(--sev-${s.toLowerCase()})`;
  }
  function ring(slices, centre, opts = {}) {
    const size = opts.size ?? 184;
    const thickness = opts.thickness ?? 20;
    const r = (size - thickness) / 2;
    const c = 2 * Math.PI * r;
    const mid = size / 2;
    const wrap = el("div", "ring");
    wrap.style.width = wrap.style.height = size + "px";
    const drawing = svg("svg", { viewBox: `0 0 ${size} ${size}`, class: "ring-svg", role: "img" });
    if (opts.label) drawing.setAttribute("aria-label", opts.label);
    drawing.appendChild(svg("circle", { cx: mid, cy: mid, r, class: "ring-track", "stroke-width": thickness }));
    const sum = slices.reduce((n, s) => n + s.value, 0);
    const shown = slices.filter((s) => s.value > 0);
    const gap = shown.length > 1 ? Math.min(3, c / shown.length / 4) : 0;
    let offset = 0;
    for (const s of shown) {
      const length = s.value / sum * c;
      const arc = svg("circle", {
        cx: mid,
        cy: mid,
        r,
        class: "ring-arc",
        "stroke-width": thickness,
        "stroke-dasharray": `${Math.max(0.8, length - gap)} ${c}`,
        "stroke-dashoffset": String(-offset),
        transform: `rotate(-90 ${mid} ${mid})`
      });
      arc.style.stroke = s.colour;
      const title = svg("title");
      title.textContent = s.title;
      arc.appendChild(title);
      drawing.appendChild(arc);
      offset += length;
    }
    const inner = el("div", "ring-centre");
    inner.appendChild(centre);
    add(wrap, drawing, inner);
    return wrap;
  }
  function severityRing(counts, centre, opts = {}) {
    const noun = opts.noun ?? "findings";
    const slices = SEVERITIES.map((s) => ({ value: counts[s], colour: sevColour(s), title: `${SEVERITY_LABEL[s]}: ${counts[s]} ${noun}` }));
    if (!total(counts)) slices.push({ value: 1, colour: sevColour("NONE"), title: `No ${noun}` });
    return ring(slices, centre, { ...opts, label: `${noun} by severity: ` + SEVERITIES.map((s) => `${SEVERITY_LABEL[s]} ${counts[s]}`).join(", ") });
  }
  function gauge(value, label, detail) {
    const node = el("div", "gauge " + gaugeTone(value));
    const W = 140;
    const r = 56;
    const cx = W / 2;
    const cy = 66;
    const len = Math.PI * r;
    const arcPath = `M${cx - r} ${cy} A${r} ${r} 0 0 1 ${cx + r} ${cy}`;
    const drawing = svg("svg", { viewBox: `0 0 ${W} 76`, class: "gauge-svg", role: "img", "aria-label": `${label}: ${value === null ? "not measured" : Math.round(value * 100) + "%"}` });
    drawing.appendChild(svg("path", { d: arcPath, class: "gauge-track" }));
    if (value !== null) {
      const fill = svg("path", { d: arcPath, class: "gauge-fill", "stroke-dasharray": `${Math.max(0.01, value) * len} ${len}` });
      drawing.appendChild(fill);
    }
    const text = el("div", "gauge-value", value === null ? "—" : `${Math.round(value * 100)}%`);
    add(node, drawing, text, el("div", "gauge-label", label), el("div", "gauge-detail", detail));
    node.title = detail;
    return node;
  }
  function gaugeTone(value) {
    if (value === null) return "none";
    return value >= 0.9 ? "ok" : value >= 0.7 ? "fair" : value >= 0.5 ? "warn" : "bad";
  }
  function severityBar(counts, opts = {}) {
    const sum = total(counts);
    const track = el("div", "sevbar" + (opts.className ? " " + opts.className : ""));
    const inner = el("div", "sevbar-fill");
    inner.style.width = opts.max ? `${Math.max(sum ? 2 : 0, sum / opts.max * 100)}%` : "100%";
    for (const s of SEVERITIES) {
      if (!counts[s]) continue;
      const seg = el("i", "sevbar-seg");
      seg.style.flexGrow = String(counts[s]);
      seg.style.background = sevColour(s);
      seg.title = `${SEVERITY_LABEL[s]}: ${counts[s]}`;
      inner.appendChild(seg);
    }
    track.appendChild(inner);
    track.title = sum ? SEVERITIES.filter((s) => counts[s]).map((s) => `${SEVERITY_LABEL[s]} ${counts[s]}`).join(" · ") + (opts.noun ? " " + opts.noun : "") : "none";
    return track;
  }
  function severityColumns(data, opts = {}) {
    const height = opts.height ?? 140;
    const wrap = el("div", "cols");
    const max = Math.max(1, ...data.map((d) => total(d.counts)));
    const plot = el("div", "cols-plot");
    plot.style.height = height + "px";
    for (const d of data) {
      const col = el("div", "col");
      const stack = el("div", "col-stack");
      const sum = total(d.counts);
      stack.style.height = `${sum / max * 100}%`;
      for (const s of [...SEVERITIES].reverse()) {
        if (!d.counts[s]) continue;
        const seg = el("i", "col-seg");
        seg.style.flexGrow = String(d.counts[s]);
        seg.style.background = sevColour(s);
        stack.appendChild(seg);
      }
      col.title = d.title ?? `${d.label}: ${sum} ${opts.noun ?? ""}`.trim() + (sum ? " — " + SEVERITIES.filter((s) => d.counts[s]).map((s) => `${SEVERITY_LABEL[s]} ${d.counts[s]}`).join(", ") : "");
      add(col, el("span", "col-num", sum ? String(sum) : ""), stack);
      plot.appendChild(col);
    }
    const axis = el("div", "cols-axis");
    for (const d of data) axis.appendChild(el("span", "", d.label));
    add(wrap, plot, axis);
    return wrap;
  }
  function heatmap(columns, rows) {
    const grid = el("div", "heat");
    grid.style.gridTemplateColumns = `minmax(110px, 1.6fr) repeat(${columns.length}, minmax(52px, 1fr))`;
    grid.appendChild(el("span", "heat-corner"));
    for (const c of columns) {
      const h = el("span", "heat-col", c.label);
      if (c.title) h.title = c.title;
      grid.appendChild(h);
    }
    const max = columns.map((_, i) => Math.max(0, ...rows.map((r) => r.values[i] ?? 0)));
    for (const r of rows) {
      const label = r.onClick ? el("button", "heat-row link") : el("span", "heat-row");
      label.textContent = r.label;
      if (r.onClick) {
        label.type = "button";
        label.addEventListener("click", r.onClick);
      }
      if (r.title) label.title = r.title;
      grid.appendChild(label);
      r.values.forEach((v, i) => {
        const cell = el("span", "heat-cell" + (v ? "" : " empty"), v ? compact(v) : "·");
        const m = max[i] ?? 0;
        if (v && m) {
          const strength = 25 + Math.round(Math.sqrt(v) / Math.sqrt(m) * 70);
          cell.style.setProperty("--heat", columns[i].colour);
          cell.style.setProperty("--strength", `${strength}%`);
          if (strength > 60) cell.classList.add("strong");
        }
        cell.title = `${r.label} · ${columns[i].label}: ${v}`;
        grid.appendChild(cell);
      });
    }
    return grid;
  }
  function compact(n) {
    if (n < 1e3) return String(n);
    if (n < 1e4) return (n / 1e3).toFixed(1).replace(/\.0$/, "") + "k";
    if (n < 1e6) return Math.round(n / 1e3) + "k";
    return (n / 1e6).toFixed(1).replace(/\.0$/, "") + "M";
  }
  function formatValue(v, unit) {
    if (!Number.isFinite(v)) return "—";
    const round = (n) => Math.abs(n) >= 100 ? String(Math.round(n)) : Math.abs(n) >= 10 ? n.toFixed(1).replace(/\.0$/, "") : n.toFixed(2).replace(/\.?0+$/, "") || "0";
    switch (unit) {
      case "count":
        return compact(Math.round(v));
      case "percent":
        return `${round(v * 100)}%`;
      case "ops/s":
        return `${round(v)}/s`;
      case "seconds":
        return v < 120 ? `${round(v)}s` : v < 7200 ? `${round(v / 60)}m` : `${round(v / 3600)}h`;
      default:
        return round(v);
    }
  }
  var gradients = 0;
  function lineChart(chart, colourOf, order = () => 0) {
    const card2 = el("article", "chart");
    const head = el("div", "chart-head");
    head.appendChild(el("h3", "", chart.label));
    card2.appendChild(head);
    if (chart.description) card2.appendChild(el("p", "chart-desc", chart.description));
    const series = chart.series.filter((s) => s.points.length > 0).sort((a, b) => order(a.name, b.name));
    if (chart.error || !series.length) {
      card2.appendChild(el("p", "quiet", chart.error ? chart.error : "No data in this window."));
      return card2;
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
    const x = (t) => (t - minT) / (maxT - minT) * W;
    const y = (v) => H - Math.max(0, v) / top * H;
    const step = (maxT - minT) / 60;
    const plot = el("div", "chart-plot");
    const drawing = svg("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", class: "chart-svg", role: "img" });
    drawing.setAttribute("aria-label", `${chart.label}: ${series.map((s) => `${s.name || chart.label} ${formatValue(s.points[s.points.length - 1].v, chart.unit)}`).join(", ")}`);
    const defs = svg("defs");
    drawing.appendChild(defs);
    for (const f of [0.25, 0.5, 0.75, 1]) {
      const gy = H * (1 - f / 1.15);
      drawing.appendChild(svg("line", { x1: 0, x2: W, y1: gy, y2: gy, class: "chart-grid" }));
    }
    const legend = el("div", "chart-legend");
    series.forEach((s, i) => {
      const colour = colourOf(s.name, i);
      const id = `fill-${++gradients}`;
      const gradient = svg("linearGradient", { id, x1: 0, y1: 0, x2: 0, y2: 1 });
      const a = svg("stop", { offset: "0%", "stop-opacity": 0.3 });
      const b = svg("stop", { offset: "100%", "stop-opacity": 0 });
      a.style.stopColor = colour;
      b.style.stopColor = colour;
      add(gradient, a, b);
      defs.appendChild(gradient);
      const runs = [];
      let run = [];
      s.points.forEach((p, j) => {
        const prev = s.points[j - 1];
        if (!Number.isFinite(p.v) || prev && p.t - prev.t > step * 3) {
          if (run.length) runs.push(run);
          run = [];
          if (!Number.isFinite(p.v)) return;
        }
        run.push(p);
      });
      if (run.length) runs.push(run);
      for (const r of runs) {
        const d = r.map((p, j) => `${j ? "L" : "M"}${x(p.t).toFixed(1)} ${y(p.v).toFixed(1)}`).join(" ");
        const first = r[0];
        const last = r[r.length - 1];
        drawing.appendChild(svg("path", { d: `${d} L${x(last.t).toFixed(1)} ${H} L${x(first.t).toFixed(1)} ${H} Z`, fill: `url(#${id})`, class: "chart-area" }));
        const line = svg("path", { d, class: "chart-line" });
        line.style.stroke = colour;
        drawing.appendChild(line);
      }
      const latest = s.points[s.points.length - 1];
      const key = el("span", "chart-key");
      const dot = el("i", "dot");
      dot.style.background = colour;
      add(key, dot, el("span", "", s.name || chart.label), el("strong", "", formatValue(latest.v, chart.unit)));
      legend.appendChild(key);
    });
    add(plot, drawing, el("span", "chart-top", formatValue(maxV, chart.unit)));
    add(card2, plot, legend);
    return card2;
  }

  // src/ui/format.ts
  function plural(n, one, many = one + "s") {
    return `${n} ${n === 1 ? one : many}`;
  }
  function percent(part, whole) {
    if (!whole) return "0%";
    const p = part / whole * 100;
    return (p > 0 && p < 1 ? "<1" : String(Math.round(p))) + "%";
  }
  function words(list) {
    if (list.length <= 1) return list[0] ?? "";
    return list.slice(0, -1).join(", ") + " and " + list[list.length - 1];
  }

  // src/ui/page.ts
  var sdk = k8sdockside;
  function message(err) {
    return err instanceof Error ? err.message : String(err);
  }
  var banner = {
    show(err) {
      const node = byId("error");
      node.textContent = message(err);
      node.hidden = false;
    },
    clear() {
      byId("error").hidden = true;
    }
  };
  function every(ms, fn, onError = banner.show) {
    let stopped = false;
    let timer;
    const run = () => {
      Promise.resolve().then(fn).catch((err) => {
        if (!stopped) onError(err);
      }).then(() => {
        if (!stopped) timer = setTimeout(run, ms);
      });
    };
    run();
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
  }
  function politely(root, redraw2) {
    let pressed = false;
    let owed = false;
    const busy = () => {
      if (pressed) return true;
      const active = document.activeElement;
      if (active && root.contains(active) && /^(INPUT|SELECT|TEXTAREA)$/.test(active.tagName)) return true;
      const selection = document.getSelection();
      if (selection && !selection.isCollapsed && selection.anchorNode && root.contains(selection.anchorNode)) return true;
      return false;
    };
    const settle = () => {
      if (owed && !busy()) {
        owed = false;
        keepFocus(root, redraw2);
      }
    };
    root.addEventListener("pointerdown", () => pressed = true);
    window.addEventListener("pointerup", () => {
      pressed = false;
      setTimeout(settle, 0);
    });
    window.addEventListener("pointercancel", () => {
      pressed = false;
      settle();
    });
    root.addEventListener("focusout", () => setTimeout(settle, 0));
    document.addEventListener("selectionchange", () => {
      if (owed) setTimeout(settle, 0);
    });
    return () => {
      if (busy()) owed = true;
      else keepFocus(root, redraw2);
    };
  }
  function keepFocus(root, redraw2) {
    const active = document.activeElement;
    const key = active instanceof HTMLElement && root.contains(active) ? active.dataset.focus : void 0;
    redraw2();
    if (key) {
      const again = [...root.querySelectorAll("[data-focus]")].find((n) => n.dataset.focus === key);
      again?.focus({ preventScroll: true });
    }
  }

  // src/ui/shell.ts
  var INSTALL_DOCS = "https://aquasecurity.github.io/trivy-operator/latest/getting-started/installation/helm/";
  var PAGES = [
    { id: "overview", label: "Overview", icon: "logo" },
    { id: "vulnerabilities", label: "Vulnerabilities", icon: "bug" },
    { id: "misconfigurations", label: "Misconfigurations", icon: "policy" },
    { id: "secrets", label: "Exposed secrets", icon: "key" },
    { id: "compliance", label: "Compliance", icon: "certificate" }
  ];
  function fail(err) {
    banner.show(err);
  }
  function mark(className = "mark") {
    const img = el("img", className);
    img.src = "logo.png";
    img.alt = "";
    return img;
  }
  function aquaMark(className = "mark small") {
    const img = el("img", className);
    img.src = "aqua.png";
    img.alt = "";
    return img;
  }
  function nav(current, ctx) {
    const node = el("nav", "nav");
    const brand = el("span", "nav-brand");
    add(brand, mark(), el("span", "", "Trivy"), ctx?.contextName ? el("span", "faint", "· " + ctx.contextName) : null);
    node.appendChild(brand);
    const tabs = el("div", "nav-tabs");
    for (const p of PAGES) {
      const b = button(p.label, "nav-tab" + (p.id === current ? " on" : ""), p.icon, () => {
        if (p.id !== current) go(p.id);
      });
      if (p.id === current) b.setAttribute("aria-current", "page");
      tabs.appendChild(b);
    }
    node.appendChild(tabs);
    return node;
  }
  var HANDOFF = "handoff";
  function go(viewId, filter) {
    const open = () => void sdk.openView(viewId).catch(fail);
    if (!filter || !sdk.storage) return open();
    sdk.storage.set(HANDOFF, { view: viewId, filter, at: Date.now() }).then(open, open);
  }
  function absent(feed) {
    const s = feed.summary;
    return Boolean(s && (!s.checked || !s.installed)) || Boolean(feed.errors.vulnerability && !feed.data.vulnerability.length && !feed.served.size);
  }
  function drawAbsence(box, feed) {
    const summary = feed?.summary;
    if (!feed || !summary) return false;
    if (!summary.checked) {
      absentPage(box, "This cluster did not answer", "Whether trivy-operator runs here could not be checked — which is not the same as it not running. The page tries again on its own.", summary.error);
      return true;
    }
    if (!summary.installed) {
      const missing = summary.requirements.filter((r) => !r.served && !r.optional).map((r) => r.kind);
      absentPage(
        box,
        "trivy-operator is not installed",
        "This cluster does not serve the VulnerabilityReport kind trivy-operator writes. Install the operator and it starts scanning every workload’s images straight away; the first reports appear here within a few minutes.",
        missing.join(", "),
        true
      );
      return true;
    }
    if (feed.errors.vulnerability && !feed.data.vulnerability.length) {
      absentPage(box, "The reports could not be read", "Your account may not be allowed to list trivy-operator’s reports in this cluster.", feed.errors.vulnerability);
      return true;
    }
    return false;
  }
  function absentPage(box, title, text, detail, install = false) {
    box.textContent = "";
    const card2 = el("section", "absent");
    const art = el("div", "empty-art brand");
    art.appendChild(mark("mark big"));
    add(card2, art, el("h1", "absent-title", title), el("p", "absent-text", text));
    if (detail) card2.appendChild(el("code", "absent-detail", detail));
    if (install) {
      const steps = el("pre", "absent-code");
      steps.textContent = [
        "helm repo add aqua https://aquasecurity.github.io/helm-charts/",
        "helm repo update",
        "helm install trivy-operator aqua/trivy-operator \\",
        "  --namespace trivy-system --create-namespace"
      ].join("\n");
      card2.appendChild(steps);
      const cta = el("div", "cta");
      cta.appendChild(button("Installation guide", "primary", "book", () => void sdk.openUrl(INSTALL_DOCS).catch(fail)));
      card2.appendChild(cta);
    }
    box.appendChild(card2);
  }
  function loading(box, text = "Reading trivy-operator’s reports…") {
    box.textContent = "";
    const node = el("div", "loading");
    add(node, el("span", "pulse"), el("span", "", text));
    box.appendChild(node);
  }

  // src/ui/widgets.ts
  function sevChip(s, count, title) {
    const node = el("span", "sev sev-" + s.toLowerCase());
    node.appendChild(el("span", "sev-name", SEVERITY_LABEL[s]));
    if (count !== void 0) node.appendChild(el("strong", "sev-count", compact(count)));
    if (title) node.title = title;
    return node;
  }
  function countCells(c, opts = {}) {
    const node = el("span", "cells");
    for (const s of SEVERITIES) {
      if (s === "UNKNOWN" && !opts.unknown && !c.UNKNOWN) continue;
      const cell = el("span", "cell sev-" + s.toLowerCase() + (c[s] ? "" : " zero"), c[s] ? compact(c[s]) : "0");
      cell.title = `${SEVERITY_LABEL[s]}: ${c[s]}`;
      node.appendChild(cell);
    }
    return node;
  }
  function workloadButton(w, opts = {}) {
    const node = button("", "wl", kindIcon(w.kind), () => openWorkload(w, opts.onFail));
    node.dataset.focus = "wl:" + w.key;
    add(
      node,
      el("span", "wl-kind", w.kind || "Object"),
      el("span", "wl-name", w.name),
      opts.namespace !== false && w.namespace ? el("span", "wl-ns", w.namespace) : null,
      opts.detail ? el("span", "wl-detail", opts.detail) : null
    );
    node.title = w.appKind ? `Open ${w.kind} ${w.namespace ? w.namespace + "/" : ""}${w.name}` + (w.via ? ` (scanned through ${w.via.kind} ${w.via.name})` : "") : `${w.kind} ${w.name}: the app has no tab for this kind`;
    if (!w.appKind) node.disabled = true;
    return node;
  }
  function openWorkload(w, onFail) {
    if (!w.appKind) return;
    sdk.open({ kind: w.appKind, namespace: w.namespace, name: w.name }).catch((err) => onFail?.(err));
  }
  function externalLink(text, url, onFail) {
    if (!/^https?:\/\//i.test(url)) return el("span", "", text);
    const b = el("button", "link ext");
    b.type = "button";
    add(b, el("span", "", text), icon("open"));
    b.title = url;
    b.addEventListener("click", (e) => {
      e.stopPropagation();
      sdk.openUrl(url).catch((err) => onFail?.(err));
    });
    return b;
  }
  function age(ms) {
    if (!ms) return "never";
    const f = sdk.format;
    if (f) return f.age(ms) + " ago";
    const d = Math.max(0, Date.now() - ms);
    if (d < 6e4) return "just now";
    if (d < 36e5) return `${Math.round(d / 6e4)}m ago`;
    if (d < 1728e5) return `${Math.round(d / 36e5)}h ago`;
    return `${Math.round(d / 864e5)}d ago`;
  }
  function severityLegend(c, opts = {}) {
    const node = el("div", "sev-legend");
    const sum = total(c);
    for (const s of SEVERITIES) {
      if (s === "UNKNOWN" && !c.UNKNOWN && !opts.unknown) continue;
      const row = opts.onPick ? el("button", "sev-legend-row") : el("div", "sev-legend-row");
      if (opts.onPick) {
        row.type = "button";
        row.addEventListener("click", () => opts.onPick(s));
        row.title = `Show only ${SEVERITY_LABEL[s].toLowerCase()}`;
      }
      const dot = el("i", "swatch sev-bg-" + s.toLowerCase());
      const share = el("span", "sev-legend-share");
      const fill = el("i");
      fill.style.width = sum ? `${c[s] / sum * 100}%` : "0";
      fill.className = "sev-bg-" + s.toLowerCase();
      share.appendChild(fill);
      add(row, dot, el("span", "sev-legend-name", SEVERITY_LABEL[s]), share, el("strong", "sev-legend-count", compact(c[s])));
      node.appendChild(row);
    }
    return node;
  }

  // src/pages/overview.ts
  var CHARTS_EVERY = 6e4;
  var HISTORY_MINUTES = 24 * 60;
  var state = { ctx: null, feed: null, posture: null, panel: null, sig: "" };
  function strong(text, className = "") {
    return el("strong", className, String(text));
  }
  function card(id, title, iconName, sub, action) {
    const box = el("section", "card " + id);
    const head = el("div", "card-head");
    add(head, icon(iconName), el("h2", "", title));
    if (sub) head.appendChild(el("span", "card-sub", sub));
    if (action) {
      action.classList.add("push");
      head.appendChild(action);
    }
    box.appendChild(head);
    return box;
  }
  function verdict(p) {
    const t = p.totals;
    if (!t.images && !t.resources) return { tone: "info", icon: "clock", status: "trivy-operator has not written any reports yet" };
    if (t.cves.CRITICAL) {
      const fix = t.fixableCritical ? ` — ${plural(t.fixableCritical, "fix is", "fixes are")} waiting` : "";
      return { tone: "error", icon: "alert", status: `${plural(t.cves.CRITICAL, "critical vulnerability", "critical vulnerabilities")} in the running images${fix}` };
    }
    if (t.secrets.CRITICAL || t.secrets.HIGH) return { tone: "error", icon: "key", status: `${plural(t.secrets.CRITICAL + t.secrets.HIGH, "secret is", "secrets are")} exposed inside images` };
    if (t.cves.HIGH || t.misconfig.CRITICAL) {
      const parts = [];
      if (t.cves.HIGH) parts.push(plural(t.cves.HIGH, "high vulnerability", "high vulnerabilities"));
      if (t.misconfig.CRITICAL) parts.push(plural(t.misconfig.CRITICAL, "critical misconfiguration", "critical misconfigurations"));
      return { tone: "warn", icon: "alert", status: `No critical vulnerabilities — ${words(parts)} to look at` };
    }
    return { tone: "ok", icon: "check", status: "No critical or high vulnerabilities in any running image" };
  }
  function headline(p) {
    const t = p.totals;
    const cves = total(t.cves);
    if (!t.images) return t.resources ? `${plural(t.resources, "resource")} audited` : "Waiting for the first scans";
    return `${compact(cves)} ${cves === 1 ? "vulnerability" : "vulnerabilities"} across ${plural(t.images, "image")}`;
  }
  function story(p) {
    const t = p.totals;
    const node = el("p", "story");
    if (t.images) {
      add(node, strong(plural(t.workloads, "workload")), " run ", strong(plural(t.images, "scanned image")), "; ", strong(`${t.cleanImages}`, t.cleanImages === t.images ? "ok" : ""), ` ${t.cleanImages === 1 ? "is" : "are"} free of critical and high vulnerabilities. `);
      const findings = total(t.findings);
      if (findings) add(node, strong(percent(t.fixable, findings), t.fixable ? "ok" : ""), " of the findings have a fixed version available. ");
      if (t.eoslImages) add(node, strong(t.eoslImages, "warnish"), ` ${t.eoslImages === 1 ? "image runs" : "images run"} an operating system past its end of support. `);
    }
    const mis = total(t.misconfig);
    if (t.resources) add(node, strong(compact(mis), t.misconfig.CRITICAL || t.misconfig.HIGH ? "warnish" : ""), ` failed ${mis === 1 ? "check" : "checks"} on ${plural(t.resources, "audited resource")}`);
    const sec = total(t.secrets);
    if (sec) add(node, t.resources ? ", and " : "", strong(sec, "bad"), ` exposed ${sec === 1 ? "secret" : "secrets"} in ${plural(t.imagesWithSecrets, "image")}`);
    if (t.resources || sec) add(node, ".");
    return node;
  }
  function drawHero(p) {
    const v = verdict(p);
    const hero = el("section", "hero " + v.tone);
    const main = el("div", "hero-main");
    const h1 = el("h1", "verdict");
    add(h1, icon(v.icon), el("span", "", headline(p)));
    const status = el("p", "status " + v.tone);
    add(status, el("i", "sdot " + v.tone), el("span", "", v.status));
    const cta = el("div", "cta");
    add(
      cta,
      button("Vulnerabilities", "primary", "bug", () => go("vulnerabilities")),
      button("Fixable critical & high", "ghost", "wrench", () => go("vulnerabilities", { sev: "CRITICAL,HIGH", fix: "1" })),
      button("Misconfigurations", "ghost", "policy", () => go("misconfigurations")),
      button("Compliance", "ghost", "certificate", () => go("compliance"))
    );
    add(main, h1, status, story(p), cta);
    hero.appendChild(main);
    hero.appendChild(scoreDial(p));
    return hero;
  }
  var GRADE_TONE = { A: "ok", B: "ok", C: "fair", D: "warn", E: "bad", F: "bad", "–": "none" };
  function scoreDial(p) {
    const s = p.score;
    const side = el("div", "hero-side");
    const tone = GRADE_TONE[s.grade] ?? "none";
    const centre = el("div", "ring-text");
    add(centre, el("div", "grade grade-" + tone, s.grade), el("div", "ring-small", s.value === null ? "not scored yet" : `${s.value} / 100`));
    const fill = s.value ?? 0;
    const dial = ring(
      [
        { value: fill, colour: `var(--tone-${tone})`, title: `Security score ${s.value ?? "—"} of 100` },
        { value: 100 - fill, colour: "transparent", title: "" }
      ],
      centre,
      { size: 170, thickness: 16, label: `Security score ${s.value ?? "not measured"} of 100, grade ${s.grade}` }
    );
    dial.classList.add("score-ring");
    const caption = el("div", "score-caption");
    add(caption, el("span", "mini-title", "Security score"), el("span", "faint small", "The average of the gauges below, less a little for every critical fix left waiting."));
    add(side, dial, caption);
    return side;
  }
  function drawGauges(p) {
    const box = card("gauges", "What the score is made of", "gauge");
    const row = el("div", "gauge-row");
    const target = {
      images: () => go("vulnerabilities", { group: "image" }),
      resources: () => go("misconfigurations"),
      compliance: () => go("compliance")
    };
    for (const g of p.score.gauges) {
      const gnode = gauge(g.value, g.label, g.detail);
      const b = el("button", "gauge-button");
      b.type = "button";
      b.dataset.focus = "gauge:" + g.id;
      b.appendChild(gnode);
      b.addEventListener("click", target[g.id] ?? (() => void 0));
      row.appendChild(b);
    }
    box.appendChild(row);
    return box;
  }
  function drawSeverity(p) {
    const t = p.totals;
    const box = card("severity", "Vulnerabilities by severity", "bug", "Each CVE counted once, at its worst.");
    const body = el("div", "sev-body");
    const centre = el("div", "ring-text");
    const cves = total(t.cves);
    add(centre, el("div", "ring-big", compact(cves)), el("div", "ring-small", cves === 1 ? "CVE" : "CVEs"));
    body.appendChild(severityRing(t.cves, centre, { size: 168, thickness: 18, noun: "CVEs" }));
    const side = el("div", "sev-side");
    side.appendChild(severityLegend(t.cves, { onPick: (s) => go("vulnerabilities", { sev: s }) }));
    const findings = total(t.findings);
    const fix = el("div", "fixmeter");
    const bar = el("div", "meter-bar big");
    const fill = el("i", "meter-fill ok");
    fill.style.width = findings ? `${t.fixable / findings * 100}%` : "0";
    bar.appendChild(fill);
    const fixLine = el("div", "fixmeter-line");
    add(fixLine, icon("wrench"), el("span", "", "Fix available"), strong(findings ? percent(t.fixable, findings) : "—"));
    add(fix, fixLine, bar, el("div", "faint small", `${compact(t.fixable)} of ${compact(findings)} findings · ${t.fixableCritical} critical, ${t.fixableHigh} high`));
    side.appendChild(fix);
    body.appendChild(side);
    box.appendChild(body);
    return box;
  }
  function tile(label, value, sub, tone, iconName, onClick, extra) {
    const node = onClick ? el("button", "stat" + (tone ? " " + tone : "")) : el("div", "stat" + (tone ? " " + tone : ""));
    if (onClick) {
      node.type = "button";
      node.addEventListener("click", onClick);
      node.dataset.focus = "tile:" + label;
    }
    const top = el("div", "stat-top");
    add(top, icon(iconName), el("span", "", label));
    add(node, top, el("div", "stat-value", value), extra ?? null, el("div", "stat-sub", sub));
    return node;
  }
  function drawStats(p) {
    const t = p.totals;
    const box = el("section", "stats");
    const mis = total(t.misconfig);
    const sec = total(t.secrets);
    const clean = el("div", "stat-meter");
    const cf = el("i");
    cf.style.width = percent(t.cleanImages, t.images);
    clean.appendChild(cf);
    add(
      box,
      tile("Critical", compact(t.cves.CRITICAL), t.cves.CRITICAL ? `${t.fixableCritical} with a fix` : "none found", t.cves.CRITICAL ? "critical" : "ok", "alert", () => go("vulnerabilities", { sev: "CRITICAL" })),
      tile("High", compact(t.cves.HIGH), t.cves.HIGH ? `${t.fixableHigh} with a fix` : "none found", t.cves.HIGH ? "high" : "ok", "alert", () => go("vulnerabilities", { sev: "HIGH" })),
      tile("Images scanned", String(t.images), `${t.cleanImages} clean of critical and high`, "", "image", () => go("vulnerabilities", { group: "image" }), clean),
      tile("Misconfigurations", compact(mis), mis ? `${t.misconfig.CRITICAL} critical · ${t.misconfig.HIGH} high` : t.resources ? "every check passes" : "no audits yet", t.misconfig.CRITICAL ? "critical" : t.misconfig.HIGH ? "high" : mis ? "" : "ok", "policy", () => go("misconfigurations")),
      tile("Exposed secrets", String(sec), sec ? `in ${plural(t.imagesWithSecrets, "image")}` : "none found", sec ? "critical" : "ok", "key", () => go("secrets")),
      tile("Last scan", t.newest ? age(t.newest) : "—", t.stale ? `${plural(t.stale, "report")} older than a day` : `${plural(t.reports, "report")}, all fresh`, t.stale ? "warn" : "", "clock")
    );
    return box;
  }
  function drawHeatmap(p) {
    const box = card("heatmap", "Namespaces", "heat", "Darker is more, compared within each column.");
    const rows = p.namespaces.filter((n) => total(n.vulns) + total(n.misconfig) + total(n.secrets) > 0).slice(0, 14);
    if (!rows.length) {
      box.appendChild(el("p", "quiet", "No namespace has any findings."));
      return box;
    }
    const cols = [
      ...["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => ({ label: SEVERITY_LABEL[s], colour: sevColour(s), title: `${SEVERITY_LABEL[s]} vulnerability findings` })),
      { label: "Config", colour: "var(--c-accent)", title: "Failed configuration, RBAC and infra checks" },
      { label: "Secrets", colour: sevColour("CRITICAL"), title: "Exposed secrets in images" }
    ];
    box.appendChild(
      heatmap(
        cols,
        rows.map((n) => ({
          label: n.namespace || "(cluster)",
          values: [n.vulns.CRITICAL, n.vulns.HIGH, n.vulns.MEDIUM, n.vulns.LOW, total(n.misconfig), total(n.secrets)],
          title: `${n.namespace || "cluster-scoped"}: ${plural(n.images, "image")}, ${plural(n.workloads, "workload")} — open its vulnerabilities`,
          onClick: () => go("vulnerabilities", { ns: n.namespace, group: "workload" })
        }))
      )
    );
    if (p.namespaces.length > rows.length) box.appendChild(el("p", "faint small more-note", `and ${plural(p.namespaces.length - rows.length, "more namespace")}`));
    return box;
  }
  function drawImages(p) {
    const box = card("top-images", "Most vulnerable images", "image", "", button("All images", "ghost small", "grid", () => go("vulnerabilities", { group: "image" })));
    const top = p.images.filter((i) => total(i.counts) > 0).slice(0, 8);
    if (!top.length) {
      box.appendChild(el("p", "quiet", p.images.length ? "No scanned image has a known vulnerability." : "No images scanned yet."));
      return box;
    }
    const max = Math.max(...top.map((i) => total(i.counts)));
    const list = el("ol", "bars");
    for (const img of top) {
      const li = el("li");
      const row = el("button", "bar-row");
      row.type = "button";
      row.dataset.focus = "img:" + img.key;
      row.title = `${img.name}
${img.os}${img.eosl ? " (end of support)" : ""}
Used by ${plural(img.workloads.length, "workload")}`;
      row.addEventListener("click", () => go("vulnerabilities", { group: "image", q: img.name }));
      const label = el("div", "bar-label");
      add(label, el("span", "iname", img.name), img.eosl ? el("span", "tag warn", "EOSL") : null, el("span", "bar-note", `${plural(img.workloads.length, "workload")} · ${compact(total(img.counts))}`));
      add(row, label, severityBar(img.counts, { max }), countCells(img.counts));
      li.appendChild(row);
      list.appendChild(li);
    }
    box.appendChild(list);
    return box;
  }
  function drawWorkloads(p) {
    const box = card("top-workloads", "Workloads at risk", "deployment", "", button("All workloads", "ghost small", "grid", () => go("vulnerabilities", { group: "workload" })));
    const top = p.workloads.filter((w) => w.counts.CRITICAL || w.counts.HIGH).slice(0, 8);
    if (!top.length) {
      box.appendChild(el("p", "quiet", "No workload runs an image with a critical or high vulnerability."));
      return box;
    }
    const list = el("ol", "wl-list");
    for (const w of top) {
      const li = el("li", "wl-row");
      const right = el("div", "wl-right");
      add(right, countCells(w.counts), w.secrets ? sevChip("CRITICAL", w.secrets, "Exposed secrets") : null);
      add(li, workloadButton(w.workload, { onFail: fail, detail: plural(w.images.length, "image") }), right);
      list.appendChild(li);
    }
    box.appendChild(list);
    return box;
  }
  function drawCves(p) {
    const box = card("top-cves", "CVEs that reach the furthest", "bug", "Critical and high first, then by how many images carry them.", button("All vulnerabilities", "ghost small", "grid", () => go("vulnerabilities")));
    const top = p.cves.filter((c) => c.severity === "CRITICAL" || c.severity === "HIGH").slice(0, 10);
    const list = top.length ? top : p.cves.slice(0, 10);
    if (!list.length) {
      box.appendChild(el("p", "quiet", "No vulnerabilities found."));
      return box;
    }
    const maxImages = Math.max(...list.map((c) => c.images.length));
    const table = el("table", "tbl compact");
    const hr = el("tr");
    for (const h of ["Severity", "CVE", "Package", "Fixed in", "Score", "Images", "Workloads"]) hr.appendChild(el("th", h === "Images" ? "reach" : "", h));
    const head = el("thead");
    head.appendChild(hr);
    table.appendChild(head);
    const body = el("tbody");
    for (const c of list) body.appendChild(cveRow(c, maxImages));
    table.appendChild(body);
    const scroll = el("div", "tbl-scroll");
    scroll.appendChild(table);
    box.appendChild(scroll);
    return box;
  }
  function cveRow(c, maxImages) {
    const tr = el("tr", "tbl-row clickable");
    tr.dataset.tone = c.severity.toLowerCase();
    tr.title = c.title || c.id;
    tr.addEventListener("click", (e) => {
      if (e.target.closest("button")) return;
      go("vulnerabilities", { group: "cve", q: c.id, open: c.id });
    });
    const id = el("td", "cve-id");
    add(id, c.link ? externalLink(c.id, c.link, fail) : el("span", "mono", c.id), c.title ? el("div", "cve-title", c.title) : null);
    const pkg = el("td", "mono small", c.packages.slice(0, 2).join(", ") + (c.packages.length > 2 ? ` +${c.packages.length - 2}` : ""));
    const fixed = el("td");
    fixed.appendChild(c.fixable ? el("span", "fixed mono", c.fixed.slice(0, 2).join(", ")) : el("span", "faint", "no fix yet"));
    const reach = el("td", "reach");
    const bar = el("span", "reach-bar");
    const fill = el("i");
    fill.style.width = `${c.images.length / maxImages * 100}%`;
    fill.style.background = sevColour(c.severity);
    bar.appendChild(fill);
    add(reach, bar, el("span", "reach-n", String(c.images.length)));
    const sevTd = el("td");
    sevTd.appendChild(sevChip(c.severity));
    add(tr, sevTd, id, pkg, fixed, el("td", "num", c.score === null ? "—" : c.score.toFixed(1)), reach, el("td", "num", String(c.workloads.length)));
    return tr;
  }
  function drawYears(p) {
    const box = card("years", "When the CVEs were published", "calendar", "Old CVEs still running are the easiest wins: their fixes have been out for a while.");
    if (!p.byYear.length) {
      box.appendChild(el("p", "quiet", "The reports carry no publication dates."));
      return box;
    }
    const years = p.byYear;
    const shown = years.slice(-12);
    const older = years.slice(0, -12);
    const data = shown.map((y) => ({ label: String(y.year), counts: y.counts }));
    if (older.length) {
      const c = zero();
      for (const y of older) for (const s of SEVERITIES) c[s] += y.counts[s];
      data.unshift({ label: `≤${older[older.length - 1].year}`, counts: c });
    }
    box.appendChild(severityColumns(data, { noun: "CVEs" }));
    return box;
  }
  function drawMisconfig(p) {
    const t = p.totals;
    const box = card("misconfig", "Misconfigurations", "policy", "", button("Open", "ghost small", "grid", () => go("misconfigurations")));
    if (!t.resources) {
      box.appendChild(el("p", "quiet", "No config audit reports yet. trivy-operator writes them when its config audit scanner is on, as it is by default."));
      return box;
    }
    const body = el("div", "sev-body");
    const centre = el("div", "ring-text");
    const n = total(t.misconfig);
    add(centre, el("div", "ring-big", compact(n)), el("div", "ring-small", n === 1 ? "failed check" : "failed checks"));
    body.appendChild(severityRing(t.misconfig, centre, { size: 140, thickness: 15, noun: "failed checks" }));
    const side = el("div", "sev-side");
    const kinds = el("div", "audit-kinds");
    const max = Math.max(1, ...Object.keys(t.misconfigBy).map((k) => total(t.misconfigBy[k])));
    for (const k of Object.keys(t.misconfigBy)) {
      const c = t.misconfigBy[k];
      const row = el("button", "audit-kind");
      row.type = "button";
      row.addEventListener("click", () => go("misconfigurations", { audit: k }));
      add(row, el("span", "audit-label", AUDIT_LABEL[k]), severityBar(c, { max }), el("strong", "", compact(total(c))));
      kinds.appendChild(row);
    }
    side.appendChild(kinds);
    body.appendChild(side);
    box.appendChild(body);
    const checks = p.checks.slice(0, 5);
    if (checks.length) {
      const list = el("ol", "check-list");
      list.appendChild(el("div", "mini-title", "Failing most often"));
      for (const c of checks) {
        const li = el("li");
        const b = el("button", "check-row");
        b.type = "button";
        b.title = c.description || c.title;
        b.addEventListener("click", () => go("misconfigurations", { group: "check", q: c.checkID, audit: c.audit }));
        add(b, sevChip(c.severity), el("span", "check-id mono", c.checkID), el("span", "check-title", c.title), el("span", "check-n", plural(c.resources.length, "resource")));
        li.appendChild(b);
        list.appendChild(li);
      }
      box.appendChild(list);
    }
    return box;
  }
  function drawSecrets(p) {
    const box = card("secrets", "Exposed secrets", "key", "", p.secrets.length ? button("Open", "ghost small", "grid", () => go("secrets")) : void 0);
    if (!p.secrets.length) {
      const ok = el("div", "all-clear");
      add(ok, icon("check"), el("span", "", p.totals.images ? "No secrets found inside any scanned image." : "No exposed secret reports yet."));
      box.appendChild(ok);
      return box;
    }
    box.classList.add("alarm");
    const list = el("ol", "secret-list");
    for (const s of p.secrets.slice(0, 6)) {
      const li = el("li", "secret-row");
      const what = el("div", "secret-what");
      add(what, sevChip(s.severity), el("span", "secret-title", s.title), el("span", "faint mono small", s.target));
      add(li, what, workloadButton(s.workload, { onFail: fail }));
      list.appendChild(li);
    }
    box.appendChild(list);
    if (p.secrets.length > 6) box.appendChild(el("p", "faint small more-note", `and ${plural(p.secrets.length - 6, "more")}`));
    return box;
  }
  function drawCompliance(p) {
    if (!p.compliance.length) return null;
    const box = card("compliance", "Compliance", "certificate", "Controls passing in each report trivy-operator keeps.", button("Open", "ghost small", "grid", () => go("compliance")));
    const grid = el("div", "comp-grid");
    for (const c of p.compliance) {
      const b = el("button", "comp-card");
      b.type = "button";
      b.dataset.focus = "comp:" + c.name;
      b.addEventListener("click", () => go("compliance", { report: c.name }));
      const rate = c.rate;
      const tone = rate === null ? "none" : rate >= 0.9 ? "ok" : rate >= 0.7 ? "fair" : rate >= 0.5 ? "warn" : "bad";
      const centre = el("div", "ring-text");
      add(centre, el("div", "ring-mid", rate === null ? "—" : `${Math.round(rate * 100)}%`));
      const r = ring(
        [
          { value: c.pass, colour: `var(--tone-${tone})`, title: `${c.pass} passing` },
          { value: c.fail, colour: "var(--c-line)", title: `${c.fail} failing` }
        ],
        centre,
        { size: 92, thickness: 10, label: `${c.title}: ${c.pass} of ${c.pass + c.fail} controls passing` }
      );
      const text = el("div", "comp-text");
      const worstControls = c.controls.filter((x) => x.fail > 0).slice(0, 2);
      add(text, el("div", "comp-title", c.title), el("div", "faint small", `${c.pass} passing · ${c.fail} failing` + (c.updated ? ` · ${age(c.updated)}` : "")));
      for (const w of worstControls) {
        const line = el("div", "comp-control");
        add(line, el("i", "sdot sev-bg-" + w.severity.toLowerCase()), el("span", "", `${w.id} ${w.name}`));
        text.appendChild(line);
      }
      add(b, r, text);
      grid.appendChild(b);
    }
    box.appendChild(grid);
    return box;
  }
  function seriesColour(name) {
    const s = severity(name);
    return sevColour(s);
  }
  function seriesOrder(a, b) {
    return SEVERITIES.indexOf(severity(a)) - SEVERITIES.indexOf(severity(b));
  }
  function drawHistory() {
    const box = byId("history");
    clear(box);
    const panel = state.panel;
    box.hidden = !panel || !panel.attached || !state.posture || !state.posture.totals.reports;
    if (box.hidden || !panel) return;
    const head = el("div", "section-head");
    add(head, icon("chart"), el("h2", "", `Over the last ${Math.round(panel.range / 60) || 24} hours`));
    if (panel.source.available && panel.source.describe) head.appendChild(el("span", "card-sub", "From Prometheus at " + panel.source.describe));
    box.appendChild(head);
    if (!panel.source.available) {
      box.appendChild(el("p", "quiet", "No Prometheus was found in this cluster, so there is no history to draw — everything above comes from the reports themselves. " + (panel.source.error || "If yours lives somewhere the app did not look, set its address in the cluster’s settings.")));
      return;
    }
    const row = el("div", "chart-row");
    for (const chart of panel.charts) row.appendChild(lineChart(chart, seriesColour, seriesOrder));
    box.appendChild(row);
  }
  function drawFoot() {
    const box = el("footer", "foot");
    const summary = state.feed?.summary;
    if (summary && summary.requirements.length) {
      const reqs = el("div", "reqs");
      reqs.appendChild(el("span", "reqs-label", "Reports this cluster serves"));
      for (const r of summary.requirements) {
        const tone = r.error ? "warn" : r.served ? "ok" : r.optional ? "muted" : "error";
        const chip = el("span", "chip " + tone);
        add(chip, icon(r.error ? "alert" : r.served ? "check" : "close"), el("span", "", r.label));
        chip.title = r.error || r.kind;
        reqs.appendChild(chip);
      }
      box.appendChild(reqs);
    }
    const errors = Object.entries(state.feed?.errors ?? {});
    if (errors.length) {
      const note = el("p", "foot-note");
      add(note, icon("info"), el("span", "", "Could not read: " + errors.map(([k, m]) => `${k} (${m})`).join(" · ")));
      box.appendChild(note);
    }
    const plugin = state.ctx?.plugin;
    const about = el("div", "about");
    const who = el("span", "about-name");
    add(who, mark(), el("span", "", plugin?.name || "Trivy"), plugin?.version ? el("span", "about-version", "v" + plugin.version) : null);
    about.appendChild(who);
    const credit = el("span", "about-credit");
    add(credit, aquaMark(), el("span", "", "Reports by trivy-operator, from Aqua Security"));
    about.appendChild(credit);
    const go2 = el("div", "go");
    add(
      go2,
      button("Operator", "ghost small", "rocket", () => go("operator")),
      button("Scan jobs", "ghost small", "play", () => go("scan-jobs"))
    );
    about.appendChild(go2);
    for (const l of plugin?.links ?? []) about.appendChild(externalLink(l.label || l.url, l.url, fail));
    box.appendChild(about);
    return box;
  }
  function render() {
    const main = byId("main");
    byId("nav").replaceChildren(nav("overview", state.ctx));
    const foot = byId("foot");
    if (drawAbsence(main, state.feed)) {
      byId("history").hidden = true;
      foot.replaceChildren(drawFoot());
      return;
    }
    const p = state.posture;
    if (!p) return;
    clear(main);
    foot.replaceChildren(drawFoot());
    if (!p.totals.reports) {
      const wait = el("section", "absent");
      const art = el("div", "empty-art brand");
      art.appendChild(mark("mark big"));
      add(
        wait,
        art,
        el("h1", "absent-title", "No reports yet"),
        el("p", "absent-text", "trivy-operator is installed but has not written a report yet. Its first scan jobs run as soon as it starts — each pulls a vulnerability database and then one image, so the first reports take a few minutes. They appear here on their own.")
      );
      const cta = el("div", "cta");
      add(cta, button("Scan jobs", "primary", "play", () => go("scan-jobs")), button("Operator pods", "ghost", "rocket", () => go("operator")));
      wait.appendChild(cta);
      main.appendChild(wait);
      return;
    }
    const top = el("div", "grid two wide-left");
    add(top, drawSeverity(p), drawGauges(p));
    const mid = el("div", "grid two");
    add(mid, drawHeatmap(p), drawImages(p));
    const low = el("div", "grid two");
    add(low, drawMisconfig(p), drawSecrets(p));
    const last = el("div", "grid two");
    add(last, drawWorkloads(p), drawYears(p));
    add(main, drawHero(p), drawStats(p), top, mid, drawCves(p), low, drawCompliance(p), last);
    drawHistory();
  }
  var redraw = politely(document.body, render);
  function onFeed(feed) {
    state.feed = feed;
    if (!feed.ready && !absent(feed)) return;
    const posture = buildPosture(feed.data);
    const sig = posture.signature + JSON.stringify(feed.errors) + (feed.summary ? "s" : "") + (feed.ready ? "r" : "");
    if (sig === state.sig) return;
    state.posture = posture;
    state.sig = sig;
    banner.clear();
    redraw();
  }
  loading(byId("main"));
  sdk.ready().then((ctx) => {
    state.ctx = ctx;
    byId("nav").replaceChildren(nav("overview", ctx));
    startFeed(sdk, { onChange: onFeed });
    every(CHARTS_EVERY, async () => {
      state.panel = await sdk.charts({ minutes: HISTORY_MINUTES });
      if (state.posture) drawHistory();
    });
  }).catch(fail);
})();
