# Trivy — a K8s Dockside plugin

A plugin for the [K8s Dockside](https://github.com/k8sdockside/k8sdockside)
desktop app that turns the reports
[trivy-operator](https://aquasecurity.github.io/trivy-operator/latest/) writes
into one picture of the cluster's security: **vulnerabilities** in every
running image, **misconfigurations** of workloads, roles and nodes,
**secrets** left inside images, and **compliance** with the CIS, NSA and Pod
Security Standards benchmarks.

It reads only the operator's own report kinds (`aquasecurity.github.io/v1alpha1`)
and the ReplicaSets and Jobs that name a report's Deployment or CronJob. It
never reads a Secret. Needs **K8s Dockside 0.1.12 or newer** and trivy-operator
in the cluster; Prometheus is optional, for the history charts.

## What it shows

**Overview** — replaces the app's generated overview page.

- A headline — *1,204 vulnerabilities across 38 images* — with a verdict under
  it (*12 critical vulnerabilities in the running images — 9 fixes are
  waiting*) and a sentence with the numbers that matter.
- A **security score** out of 100, graded A–F, and the three **gauges** it is
  the average of: images free of critical and high vulnerabilities, audited
  resources without critical or high misconfigurations, and compliance
  controls passing — less a little for every critical fix left waiting.
- **Vulnerabilities by severity** as a ring, each CVE counted once, and how
  many findings have a fixed version.
- Tiles for critical, high, images scanned, misconfigurations, exposed secrets
  and how fresh the scans are — each opens the page behind it, filtered.
- A **namespace heatmap**: critical, high, medium, low, config and secrets per
  namespace, each column shaded against its own largest value.
- The **most vulnerable images** and **workloads at risk**, as bars split by
  severity.
- The **CVEs that reach the furthest**: critical and high first, by how many
  images carry them, with the fixed version.
- **Misconfigurations** by audit (workload config, RBAC, infrastructure) and
  the checks failing most often; **exposed secrets**; each **compliance**
  report's pass rate and its worst failing controls.
- **When the CVEs were published**, by year: old CVEs still running are the
  easiest wins.
- Vulnerabilities, misconfigurations, exposed secrets and RBAC findings over
  the last day, from trivy-operator's own metrics, when the cluster has a
  Prometheus.

**Vulnerabilities** — every vulnerability, grouped **by CVE** (what to patch),
**by image** (what to rebuild) or **by workload** (who to tell). Search,
severity toggles with counts, a namespace picker and *Has a fix*. Every column
sorts; open a row for the description, links, fixed versions, the images and
workloads it is in, each container's findings, and **Rescan**.

**Misconfigurations** — failed config audit, RBAC assessment and infra
assessment checks, **by check** or **by resource**, with what Trivy saw and
how to fix it.

**Exposed secrets** — each secret Trivy matched, the file in the image, the
workload running it, and what to do. The match is shown as Trivy writes it:
masked.

**Compliance** — each ClusterComplianceReport as a pass rate, its failing
controls by severity, and every control, failing first.

**Trivy panel** in the detail view of every Deployment, StatefulSet,
DaemonSet, ReplicaSet, CronJob, Job and Pod: its vulnerabilities by severity,
each container's image and worst CVEs with their fixes, failed config checks,
exposed secrets, and **Rescan**. A Deployment's reports are found through its
ReplicaSets, a CronJob's through its Jobs, and a Pod's through its owner.

Plus a table view of every report kind, the operator's pods and its scan jobs.

**Rescan** deletes a report: trivy-operator notices and scans again. The app
asks you first, and you type the report's name to confirm.

## Install

**Settings → Plugins → Available → Trivy**, or **From a repository** with

```
https://github.com/k8sdockside/trivy
```

Nothing is built on install: the app reads `plugin.json` and serves the
committed `ui/`.

## Develop

```sh
npm install
npm run watch      # rebuilds ui/ on every change under src/
npm run preview    # every page drawn from src/fixtures.ts into preview/
dev/up.sh          # a kind cluster with trivy-operator and things to find
```

| Script | |
| --- | --- |
| `npm run build` | bundles `src/` into `ui/` |
| `npm run typecheck` | `tsc --noEmit`, strict |
| `npm test` | the model's unit tests and a render test of every page |
| `npm run check` | typecheck + tests + a fresh build compared with `ui/` |

Run `npm run build` and commit `ui/` with every change to `src/`. To check
the manifest the way the app loads it:

```sh
go run github.com/k8sdockside/k8sdockside/cmd/plugincheck@main .
```

| File | |
| --- | --- |
| `src/model/trivy.ts` | the report kinds and their shapes, severities, what a report is about, image names |
| `src/model/posture.ts` | every report taken together: images and CVEs counted once, workloads, namespaces, checks, secrets, compliance, the score |
| `src/model/feed.ts` | watching the report kinds the cluster serves |
| `src/ui/charts.ts` | rings, gauges, severity bars, columns, the heatmap, line charts — plain SVG and HTML |
| `src/ui/table.ts` | the sortable, expandable, paged table every working page uses |
| `src/pages/*` | one `.html` and `.ts` per page |

## License

Apache 2.0 — see [LICENSE](LICENSE).
