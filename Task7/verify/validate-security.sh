#!/usr/bin/env bash
# validate-security.sh — проверка constraints Gatekeeper.
# Подтверждает, что Gatekeeper установлен и применяет ограничения в namespace audit-zone.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"

pass=0
fail=0

echo "==> 1/4 Gatekeeper установлен?"
if kubectl get ns gatekeeper-system >/dev/null 2>&1; then
  echo "  [PASS] namespace gatekeeper-system существует"
  pass=$((pass+1))
else
  echo "  [FAIL] gatekeeper-system не найден"
  fail=$((fail+1))
fi

echo "==> 2/4 ConstraintTemplate зарегистрированы?"
for ct in k8sdisallowprivileged k8sdisallowhostpath k8srequirerunasnonroot; do
  if kubectl get constrainttemplates.templates.gatekeeper.sh "$ct" >/dev/null 2>&1; then
    echo "  [PASS] $ct"
    pass=$((pass+1))
  else
    echo "  [FAIL] $ct отсутствует"
    fail=$((fail+1))
  fi
done

echo "==> 3/4 Constraints присутствуют и применяются (deny)?"
constraints=(
  "k8sdisallowprivileged.constraints.gatekeeper.sh/disallow-privileged"
  "k8sdisallowhostpath.constraints.gatekeeper.sh/disallow-hostpath"
  "k8srequirerunasnonroot.constraints.gatekeeper.sh/require-runasnonroot"
)
for c in "${constraints[@]}"; do
  ea=$(kubectl get "$c" -o jsonpath='{.spec.enforcementAction}' 2>/dev/null)
  if [ "$ea" = "deny" ]; then
    tv=$(kubectl get "$c" -o jsonpath='{.status.totalViolations}' 2>/dev/null)
    echo "  [PASS] $c (deny, нарушений=${tv:-0})"
    pass=$((pass+1))
  else
    echo "  [FAIL] $c не применяется (enforcementAction=${ea:-отсутствует})"
    fail=$((fail+1))
  fi
done

echo "==> 4/4 Gatekeeper отклоняет под, который проходит PSA, но нарушает правило Gatekeeper"
kubectl delete pod gatekeeper-test --ignore-not-found >/dev/null 2>&1 || true
out=$(cat <<'EOF' | kubectl apply -f - 2>&1
apiVersion: v1
kind: Pod
metadata:
  name: gatekeeper-test
  namespace: audit-zone
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 101
    runAsGroup: 101
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: nginx
      image: nginxinc/nginx-unprivileged
      securityContext:
        allowPrivilegeEscalation: false
        runAsNonRoot: true
        runAsUser: 101
        capabilities:
          drop:
            - ALL
        seccompProfile:
          type: RuntimeDefault
  restartPolicy: Never
EOF
)
if echo "$out" | grep -qiE "denied|Gatekeeper|readOnlyRootFilesystem"; then
  echo "  [PASS] Gatekeeper отклонил нарушение, видимое только Gatekeeper"
  echo "        $(echo "$out" | head -1)"
  pass=$((pass+1))
else
  echo "  [FAIL] под не был отклонён Gatekeeper"
  echo "$out" | sed 's/^/        /'
  fail=$((fail+1))
fi
kubectl delete pod gatekeeper-test --ignore-not-found >/dev/null 2>&1 || true

echo
echo "Итог: $pass проверок пройдено, $fail с ошибками"
[ "$fail" -eq 0 ]