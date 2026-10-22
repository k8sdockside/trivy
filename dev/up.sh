#!/usr/bin/env bash
# A kind cluster with trivy-operator and a few workloads that give it
# something to find: an old nginx full of CVEs, a privileged container, a
# Role that can read Secrets, and an image with a key baked into it.
#
#   dev/up.sh               create (or reuse) the kind cluster and install everything
#   CLUSTER=foo dev/up.sh   under another kind cluster name
#
# It never changes which kubectl context is current: kind switches to the new
# cluster when it creates one, and this script switches back. Every kubectl
# and helm call names the kind context explicitly.
#
# Needs: docker (or podman with KIND_EXPERIMENTAL_PROVIDER=podman), kind,
# kubectl and helm.

set -euo pipefail

CLUSTER="${CLUSTER:-trivy-dev}"
CONTEXT="kind-${CLUSTER}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
k() { kubectl --context "${CONTEXT}" "$@"; }

for tool in kind kubectl helm; do
    command -v "${tool}" >/dev/null || { echo "dev/up.sh needs ${tool} on the PATH" >&2; exit 1; }
done

previous="$(kubectl config current-context 2>/dev/null || true)"

if kind get clusters 2>/dev/null | grep -qx "${CLUSTER}"; then
    say "kind cluster ${CLUSTER} is already there; reusing it"
else
    say "Creating kind cluster ${CLUSTER}"
    kind create cluster --name "${CLUSTER}" --wait 120s
fi

if [[ -n "${previous}" && "${previous}" != "${CONTEXT}" ]]; then
    kubectl config use-context "${previous}" >/dev/null
    echo "(current kubectl context left at ${previous}; this script uses ${CONTEXT})"
fi

say "Installing trivy-operator"
helm repo add aqua https://aquasecurity.github.io/helm-charts/ >/dev/null 2>&1 || true
helm repo update aqua >/dev/null
helm --kube-context "${CONTEXT}" upgrade --install trivy-operator aqua/trivy-operator \
    --namespace trivy-system --create-namespace \
    --set operator.scanJobsConcurrentLimit=3 \
    --set compliance.cron="*/30 * * * *" \
    --set trivy.ignoreUnfixed=false \
    --wait --timeout 5m

say "Applying the samples"
k apply -f "${HERE}/samples/"

say "Done"
cat <<EOF2

trivy-operator now scans every workload. Each scan job first downloads the
vulnerability database, so the first reports take a few minutes; watch them
arrive with

  kubectl --context ${CONTEXT} get vulnerabilityreports,configauditreports,exposedsecretreports -A

Open the context "${CONTEXT}" in K8s Dockside and go to Plugins -> Trivy.

  - shop/legacy-web     nginx:1.21.0, hundreds of CVEs, many with fixes
  - shop/cache          redis:6.0.5 as a StatefulSet
  - payments/api        privileged, root file system writable: config findings
  - payments/secrets-reader  a Role that can read and list Secrets: RBAC findings

Delete it all with dev/down.sh.
EOF2
