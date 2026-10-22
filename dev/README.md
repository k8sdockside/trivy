# Trying the plugin on a kind cluster

`dev/up.sh` makes a local Kubernetes cluster with
[trivy-operator](https://aquasecurity.github.io/trivy-operator/latest/) and a
few workloads that give it something to find, so every page of the plugin has
real reports behind it.

```sh
dev/up.sh     # a few minutes: the operator, then a scan job per workload
dev/down.sh   # deletes the kind cluster and everything in it
```

It needs `docker` (or podman, with `KIND_EXPERIMENTAL_PROVIDER=podman`),
[`kind`](https://kind.sigs.k8s.io), `kubectl` and `helm`. It creates a kind
cluster called `trivy-dev` (set `CLUSTER=` for another name), installs the
operator from Aqua's Helm chart into `trivy-system`, with the compliance
reports running every half hour, and applies `dev/samples/`. It never changes
which kubectl context is current.

| Sample | Gives the plugin |
| --- | --- |
| `shop/legacy-web` (`nginx:1.21.0`) | Hundreds of vulnerabilities, many with fixes, critical among them |
| `shop/cache` (`redis:6.0.5`, a StatefulSet) | A second image and a workload kind that is not a Deployment |
| `payments/api` (`python:3.8.0-slim`, privileged) | Critical and high config audit findings |
| `payments/secrets-reader` (a Role) | An RBAC assessment finding |

The system workloads kind runs (kube-proxy, CoreDNS, kindnet, the local path
provisioner) are scanned too, so the heatmap has more than two namespaces.

Without a cluster at all, `npm run preview` draws every page from the
fixtures in `src/fixtures.ts`, in the app's light and dark themes, into
`preview/`.
