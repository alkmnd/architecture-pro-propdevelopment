#!/usr/bin/env bash

set -euo pipefail

CLUSTER_NAME="minikube"
CA_CRT="${HOME}/.minikube/ca.crt"
CA_KEY="${HOME}/.minikube/ca.key"
DAYS=365
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

echo "==> work dir: ${WORKDIR}"

if [[ ! -f "${CA_CRT}" || ! -f "${CA_KEY}" ]]; then
  echo "Error (${CA_CRT} / ${CA_KEY})."
  exit 1
fi

if ! kubectl get nodes >/dev/null 2>&1; then
  echo "Error"
  exit 1
fi


create_user() {
  local USER="$1"
  local GROUP="$2"
  local KEY="${WORKDIR}/${USER}.key"
  local CSR="${WORKDIR}/${USER}.csr"
  local CRT="${WORKDIR}/${USER}.crt"

  echo ""
  echo "==> create user: ${USER} (group ${GROUP})"

  openssl genrsa -out "${KEY}" 2048 2>/dev/null

  openssl req -new -key "${KEY}" -out "${CSR}" \
    -subj "/CN=${USER}/O=${GROUP}" 2>/dev/null

  openssl x509 -req -in "${CSR}" \
    -CA "${CA_CRT}" -CAkey "${CA_KEY}" \
    -CAcreateserial -out "${CRT}" -days "${DAYS}" 2>/dev/null

  kubectl config set-credentials "${USER}" \
    --client-certificate="${CRT}" \
    --client-key="${KEY}" >/dev/null

  kubectl config set-context "${USER}-context" \
    --cluster="${CLUSTER_NAME}" \
    --user="${USER}" >/dev/null

  echo "    ok: user ${USER} created, context ${USER}-context"
}

create_user "devops-user" "devops"
create_user "sec-user" "security-officers"
create_user "viewer-user" "viewers"

echo ""
echo "==> done. current contexts in kubeconfig:"
kubectl config get-contexts