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
    const remember2 = (kind, list, ownerKind) => {
      for (const o of list ?? []) {
        const ref = o.metadata.ownerReferences?.find((r) => r.controller && r.kind === ownerKind);
        if (ref) owners.set(workloadKey(kind, o.metadata.namespace ?? "", o.metadata.name), { kind: ref.kind, name: ref.name });
      }
    };
    remember2("ReplicaSet", data.replicasets, "Deployment");
    remember2("Job", data.jobs, "CronJob");
    return (s) => {
      const up = owners.get(workloadKey(s.kind, s.namespace, s.name));
      if (up) return { key: workloadKey(up.kind, s.namespace, up.name), kind: up.kind, name: up.name, namespace: s.namespace, appKind: appKind(up.kind), via: { kind: s.kind, name: s.name } };
      return { key: workloadKey(s.kind, s.namespace, s.name), kind: s.kind, name: s.name, namespace: s.namespace, appKind: appKind(s.kind) };
    };
  }
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
  function compact(n) {
    if (n < 1e3) return String(n);
    if (n < 1e4) return (n / 1e3).toFixed(1).replace(/\.0$/, "") + "k";
    if (n < 1e6) return Math.round(n / 1e3) + "k";
    return (n / 1e6).toFixed(1).replace(/\.0$/, "") + "M";
  }

  // src/ui/filters.ts
  function searchBox(value, placeholder, onInput) {
    const wrap = el("label", "search");
    wrap.appendChild(icon("search"));
    const input = el("input");
    input.type = "search";
    input.value = value;
    input.placeholder = placeholder;
    input.dataset.focus = "search";
    input.setAttribute("aria-label", placeholder);
    let timer;
    input.addEventListener("input", () => {
      clearTimeout(timer);
      timer = setTimeout(() => onInput(input.value), 160);
    });
    wrap.appendChild(input);
    return wrap;
  }
  function severityToggles(on, counts, onChange) {
    const node = el("div", "sev-toggles");
    for (const s of SEVERITIES) {
      if (s === "UNKNOWN" && !counts.UNKNOWN && !on.has(s)) continue;
      const active = on.has(s);
      const b = el("button", "sev-toggle sev-" + s.toLowerCase() + (active ? " on" : "") + (on.size && !active ? " off" : ""));
      b.type = "button";
      b.dataset.focus = "sev:" + s;
      b.setAttribute("aria-pressed", String(active));
      add(b, el("span", "", SEVERITY_LABEL[s]), el("strong", "", compact(counts[s])));
      b.addEventListener("click", () => {
        const next = new Set(on);
        if (next.has(s)) next.delete(s);
        else next.add(s);
        onChange(next);
      });
      node.appendChild(b);
    }
    if (on.size) {
      const clear = el("button", "ghost small");
      clear.type = "button";
      clear.textContent = "All";
      clear.addEventListener("click", () => onChange(/* @__PURE__ */ new Set()));
      node.appendChild(clear);
    }
    return node;
  }
  function namespaceSelect(namespaces, value, onPick) {
    const wrap = el("label", "ns-pick");
    wrap.appendChild(icon("namespace"));
    const select = el("select");
    select.dataset.focus = "ns";
    select.setAttribute("aria-label", "Namespace");
    const all = el("option", "", "All namespaces");
    all.value = "";
    select.appendChild(all);
    const list = [...new Set(namespaces)].sort();
    if (value && !list.includes(value)) list.unshift(value);
    for (const ns of list) {
      const o = el("option", "", ns || "(cluster-scoped)");
      o.value = ns || "-";
      select.appendChild(o);
    }
    select.value = value;
    select.addEventListener("change", () => onPick(select.value));
    wrap.appendChild(select);
    return wrap;
  }
  function readSeverities(text) {
    const out = /* @__PURE__ */ new Set();
    for (const part of (text ?? "").split(",")) {
      const s = part.trim().toUpperCase();
      if (SEVERITIES.includes(s)) out.add(s);
    }
    return out;
  }
  function writeSeverities(set) {
    return SEVERITIES.filter((s) => set.has(s)).join(",");
  }
  function nsMatch(filter, ns) {
    if (!filter) return true;
    return filter === "-" ? ns === "" : ns === filter;
  }
  function matches(q, ...texts) {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean);
    if (!words.length) return true;
    const hay = texts.filter(Boolean).join(" ").toLowerCase();
    return words.every((w) => hay.includes(w));
  }
  function mountToolbar(bar, search2, before, after) {
    for (const child of [...bar.children]) if (child !== search2) child.remove();
    if (search2.parentElement !== bar) bar.appendChild(search2);
    for (const node of before) bar.insertBefore(node, search2);
    for (const node of after) bar.appendChild(node);
  }

  // src/ui/format.ts
  function plural(n, one, many = one + "s") {
    return `${n} ${n === 1 ? one : many}`;
  }

  // src/ui/page.ts
  var sdk = k8sdockside;
  function message(err) {
    return err instanceof Error ? err.message : String(err);
  }
  function declined(err) {
    return /declined/.test(message(err));
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
  function readHash() {
    const out = {};
    for (const pair of location.hash.replace(/^#/, "").split("&")) {
      const cut = pair.indexOf("=");
      if (cut <= 0) continue;
      try {
        out[pair.slice(0, cut)] = decodeURIComponent(pair.slice(cut + 1));
      } catch {
      }
    }
    return out;
  }
  function writeHash(values) {
    const text = Object.entries(values).filter((entry) => typeof entry[1] === "string" && entry[1] !== "").map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("&");
    const hash = text ? "#" + text : "";
    if (hash === location.hash || !hash && !location.hash) return;
    try {
      history.replaceState(null, "", hash || location.pathname);
    } catch {
      try {
        location.hash = text;
      } catch {
      }
    }
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
  async function arrival(viewId) {
    const hash = readHash();
    const store = sdk.storage;
    if (!store) return hash;
    try {
      const h = await store.get(HANDOFF);
      if (h && h.view === viewId && Date.now() - h.at < 15e3) {
        await store.remove(HANDOFF);
        return { ...h.filter };
      }
    } catch {
    }
    return hash;
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
  function absentPage(box, title, text, detail2, install = false) {
    box.textContent = "";
    const card = el("section", "absent");
    const art = el("div", "empty-art brand");
    art.appendChild(mark("mark big"));
    add(card, art, el("h1", "absent-title", title), el("p", "absent-text", text));
    if (detail2) card.appendChild(el("code", "absent-detail", detail2));
    if (install) {
      const steps = el("pre", "absent-code");
      steps.textContent = [
        "helm repo add aqua https://aquasecurity.github.io/helm-charts/",
        "helm repo update",
        "helm install trivy-operator aqua/trivy-operator \\",
        "  --namespace trivy-system --create-namespace"
      ].join("\n");
      card.appendChild(steps);
      const cta = el("div", "cta");
      cta.appendChild(button("Installation guide", "primary", "book", () => void sdk.openUrl(INSTALL_DOCS).catch(fail)));
      card.appendChild(cta);
    }
    box.appendChild(card);
  }
  function loading(box, text = "Reading trivy-operator’s reports…") {
    box.textContent = "";
    const node = el("div", "loading");
    add(node, el("span", "pulse"), el("span", "", text));
    box.appendChild(node);
  }

  // src/ui/table.ts
  function tableState(sort = "", dir = 1, page = 100) {
    return { sort, dir, open: /* @__PURE__ */ new Set(), limit: page };
  }
  function drawTable(box, opts) {
    const { columns: columns2, state: state2 } = opts;
    const page = opts.page ?? 100;
    box.textContent = "";
    if (!opts.rows.length) {
      box.appendChild(el("p", "quiet table-empty", opts.empty ?? "Nothing to show."));
      return;
    }
    const col = columns2.find((c) => c.id === state2.sort && c.sort);
    const rows2 = col ? [...opts.rows].sort((a, b) => col.sort(a, b) * state2.dir) : opts.rows;
    const redraw2 = () => {
      drawTable(box, opts);
      opts.onState?.(state2);
    };
    const table = el("table", "tbl");
    const head = el("thead");
    const hr = el("tr");
    if (opts.expand) hr.appendChild(el("th", "tbl-toggle"));
    for (const c of columns2) {
      const th = el("th", c.className ?? "");
      if (c.title) th.title = c.title;
      if (c.sort) {
        const b = el("button", "tbl-sort" + (state2.sort === c.id ? " on" : ""));
        b.type = "button";
        b.dataset.focus = "sort:" + c.id;
        add(b, el("span", "", c.label), icon(state2.sort === c.id ? state2.dir === 1 ? "chevron-up" : "chevron-down" : "sort"));
        b.addEventListener("click", () => {
          if (state2.sort === c.id) state2.dir = state2.dir === 1 ? -1 : 1;
          else {
            state2.sort = c.id;
            state2.dir = 1;
          }
          redraw2();
        });
        th.appendChild(b);
        th.setAttribute("aria-sort", state2.sort === c.id ? state2.dir === 1 ? "ascending" : "descending" : "none");
      } else {
        th.textContent = c.label;
      }
      hr.appendChild(th);
    }
    head.appendChild(hr);
    table.appendChild(head);
    const body = el("tbody");
    const shown = rows2.slice(0, state2.limit);
    for (const row of shown) {
      const key = opts.key(row);
      const open = state2.open.has(key);
      const tr = el("tr", "tbl-row" + (open ? " open" : "") + (opts.expand ? " expandable" : ""));
      const tone = opts.tone?.(row);
      if (tone) tr.dataset.tone = tone;
      if (opts.expand) {
        const td = el("td", "tbl-toggle");
        const b = el("button", "tbl-open");
        b.type = "button";
        b.dataset.focus = "open:" + key;
        b.setAttribute("aria-expanded", String(open));
        b.setAttribute("aria-label", open ? "Close details" : "Open details");
        b.appendChild(icon(open ? "chevron-down" : "chevron"));
        td.appendChild(b);
        tr.appendChild(td);
        const toggle = () => {
          if (state2.open.has(key)) state2.open.delete(key);
          else state2.open.add(key);
          redraw2();
        };
        b.addEventListener("click", (e) => {
          e.stopPropagation();
          toggle();
        });
        tr.addEventListener("click", (e) => {
          const t = e.target;
          if (t.closest("button, a, input, select") || document.getSelection()?.toString()) return;
          toggle();
        });
      }
      for (const c of columns2) {
        const td = el("td", c.className ?? "");
        const content = c.cell(row);
        add(td, ...Array.isArray(content) ? content : [content]);
        tr.appendChild(td);
      }
      body.appendChild(tr);
      if (open && opts.expand) {
        const dr = el("tr", "tbl-detail");
        if (tone) dr.dataset.tone = tone;
        const td = el("td");
        td.colSpan = columns2.length + 1;
        td.appendChild(opts.expand(row));
        dr.appendChild(td);
        body.appendChild(dr);
      }
    }
    table.appendChild(body);
    const scroll = el("div", "tbl-scroll");
    scroll.appendChild(table);
    box.appendChild(scroll);
    const foot = el("div", "tbl-foot");
    foot.appendChild(el("span", "faint", rows2.length > shown.length ? `Showing ${shown.length} of ${rows2.length}` : `${rows2.length} ${rows2.length === 1 ? "row" : "rows"}`));
    if (rows2.length > shown.length) {
      const more = el("button", "ghost small");
      more.type = "button";
      more.dataset.focus = "more";
      add(more, icon("chevron-down"), el("span", "", `Show ${Math.min(page, rows2.length - shown.length)} more`));
      more.addEventListener("click", () => {
        state2.limit += page;
        redraw2();
      });
      const all = el("button", "ghost small");
      all.type = "button";
      all.textContent = "Show all";
      all.addEventListener("click", () => {
        state2.limit = rows2.length;
        redraw2();
      });
      add(foot, more, all);
    }
    box.appendChild(foot);
  }
  function byText(a, b) {
    return a.localeCompare(b, void 0, { numeric: true, sensitivity: "base" });
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
  function fact(label, value) {
    const node = el("div", "fact");
    const v = el("div", "fact-value");
    add(v, value);
    add(node, el("div", "fact-label", label), v);
    return node;
  }

  // src/pages/secrets.ts
  var state = {
    ctx: null,
    feed: null,
    posture: null,
    sig: "",
    filters: { q: "", sev: /* @__PURE__ */ new Set(), ns: "" },
    table: tableState("severity")
  };
  function keyOf(s) {
    return `${s.report.namespace}/${s.report.name}/${s.target}/${s.ruleID}/${s.match}`;
  }
  function remember() {
    const f = state.filters;
    writeHash({ q: f.q, sev: writeSeverities(f.sev), ns: f.ns, sort: state.table.sort === "severity" ? "" : state.table.sort, dir: state.table.dir === -1 ? "desc" : "" });
  }
  function rows(p, f, opts = {}) {
    return p.secrets.filter(
      (s) => (opts.sev === false || !f.sev.size || f.sev.has(s.severity)) && nsMatch(f.ns, s.workload.namespace) && matches(f.q, s.title, s.ruleID, s.category, s.target, s.image, s.workload.name, s.workload.namespace, s.container)
    );
  }
  function columns() {
    return [
      { id: "severity", label: "Severity", sort: (a, b) => rank(a.severity) - rank(b.severity), cell: (s) => sevChip(s.severity) },
      {
        id: "title",
        label: "Secret",
        className: "grow",
        sort: (a, b) => byText(a.title, b.title),
        cell: (s) => {
          const node = el("div", "cve-id");
          add(node, el("span", "strong", s.title), el("div", "cve-title", [s.category, s.ruleID].filter(Boolean).join(" · ")));
          return node;
        }
      },
      { id: "target", label: "File in the image", sort: (a, b) => byText(a.target, b.target), cell: (s) => el("span", "mono small", s.target || "—") },
      { id: "image", label: "Image", sort: (a, b) => byText(a.image, b.image), cell: (s) => el("span", "iname small", s.image) },
      { id: "workload", label: "Workload", sort: (a, b) => byText(a.workload.name, b.workload.name), cell: (s) => workloadButton(s.workload, { onFail: fail }) }
    ];
  }
  function detail(s) {
    const box = el("div", "detail");
    if (s.match) {
      const m = el("div", "match");
      add(m, el("span", "mini-title", "What Trivy matched (masked)"), el("code", "match-code", s.match));
      box.appendChild(m);
    }
    const facts = el("div", "facts");
    add(facts, fact("Rule", s.ruleID || "—"), fact("Category", s.category || "—"), fact("File", s.target || "—"), fact("Container", s.container || "—"), fact("Image", s.image));
    box.appendChild(facts);
    const advice = el("div", "remedy");
    add(
      advice,
      el("span", "mini-title", "What to do"),
      el("p", "", "Treat the secret as leaked: anyone who can pull the image can read it. Revoke or rotate it first, then rebuild the image without it — pass it at run time from a Secret instead — and push the new build.")
    );
    box.appendChild(advice);
    if (s.report.kind === KINDS.exposedSecret) {
      const actions = el("div", "detail-actions");
      actions.appendChild(
        button("Rescan", "ghost small", "rescan", () => {
          sdk.run("rescan-secrets", { namespace: s.report.namespace, name: s.report.name }).catch((err) => {
            if (!declined(err)) fail(err);
          });
        })
      );
      box.appendChild(actions);
    }
    return box;
  }
  function setFilters(next) {
    Object.assign(state.filters, next);
    state.table.limit = 100;
    remember();
    keepFocus(document.body, render);
  }
  var search = null;
  function render() {
    byId("nav").replaceChildren(nav("secrets", state.ctx));
    const main = byId("main");
    const bar = byId("toolbar");
    if (drawAbsence(main, state.feed)) {
      bar.hidden = true;
      return;
    }
    const p = state.posture;
    if (!p) return;
    main.textContent = "";
    if (!p.secrets.length) {
      bar.hidden = true;
      const ok = el("section", "absent calm");
      const art = el("div", "empty-art ok");
      art.appendChild(icon("check"));
      add(
        ok,
        art,
        el("h1", "absent-title", "No exposed secrets"),
        el("p", "absent-text", p.totals.images ? `trivy-operator looked through ${plural(p.totals.images, "image")} and found no keys, tokens or passwords written into any of them.` : "No exposed secret reports yet: trivy-operator writes them alongside each image’s vulnerability report.")
      );
      main.appendChild(ok);
      return;
    }
    const f = state.filters;
    bar.hidden = false;
    search ??= searchBox(f.q, "Search secret, file, image, workload…", (q) => setFilters({ q }));
    const counts = zero();
    for (const s of rows(p, f, { sev: false })) counts[s.severity]++;
    const row1 = el("div", "toolbar-row");
    row1.appendChild(
      namespaceSelect(
        p.secrets.map((s) => s.workload.namespace),
        f.ns,
        (ns) => setFilters({ ns })
      )
    );
    const row2 = el("div", "toolbar-row");
    row2.appendChild(severityToggles(f.sev, counts, (sev) => setFilters({ sev })));
    mountToolbar(bar, search, [row1], [row2]);
    const list = rows(p, f);
    const shown = zero();
    for (const s of list) shown[s.severity]++;
    const hero = el("section", "secret-hero");
    const centre = el("div", "ring-text");
    add(centre, el("div", "ring-big", String(p.secrets.length)), el("div", "ring-small", p.secrets.length === 1 ? "secret" : "secrets"));
    const all = zero();
    for (const s of p.secrets) all[s.severity]++;
    const text = el("div", "secret-hero-text");
    add(
      text,
      el("h1", "verdict", `${plural(p.secrets.length, "secret")} exposed in ${plural(p.totals.imagesWithSecrets, "image")}`),
      el("p", "story", "Anything written into an image can be read by anyone who can pull it. Rotate each one, then rebuild the image without it.")
    );
    add(hero, severityRing(all, centre, { size: 120, thickness: 13, noun: "secrets" }), text);
    main.appendChild(hero);
    const result = el("div", "result");
    add(result, el("strong", "", String(list.length)), el("span", "faint", list.length === 1 ? " finding" : " findings"), severityBar(shown, { className: "result-bar" }), countCells(shown));
    const box = el("div", "table-box");
    add(main, result, box);
    drawTable(box, { columns: columns(), rows: list, key: keyOf, expand: detail, state: state.table, onState: remember, tone: (s) => s.severity.toLowerCase(), empty: "No secret matches these filters." });
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
  sdk.ready().then(async (ctx) => {
    state.ctx = ctx;
    byId("nav").replaceChildren(nav("secrets", ctx));
    const h = await arrival("secrets");
    state.filters = { q: h.q ?? "", sev: readSeverities(h.sev), ns: h.ns ?? "" };
    if (h.sort) state.table.sort = h.sort;
    if (h.dir === "desc") state.table.dir = -1;
    remember();
    startFeed(sdk, { onChange: onFeed, only: ["vulnerability", "exposedSecret"] });
  }).catch(fail);
})();
