#!/usr/bin/env bash
# verify-admission.sh — проверка PodSecurity Admission.
# Создаёт audit-zone (restricted), применяет небезопасные манифесты и ожидает их отклонения.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"

NS="$ROOT/01-create-namespace.yaml"
INSECURE="$ROOT/insecure-manifests"
SECURE="$ROOT/secure-manifests"

pass=0
fail=0

clean() {
  kubectl delete pods -n audit-zone --all --ignore-not-found >/dev/null 2>&1 || true
  sleep 1
}

check_reject() {
  local file="$1" label="$2"
  clean
  local out
  out=$(kubectl apply -f "$file" 2>&1)
  if echo "$out" | grep -qiE "forbidden|PodSecurity|denied"; then
    echo "  [PASS] отклонён: $label"
    pass=$((pass+1))
  else
    echo "  [FAIL] НЕ отклонён: $label"
    echo "$out" | sed 's/^/        /'
    fail=$((fail+1))
  fi
}

# Проверка, что манифест ПРИНЯТ (под создан)
check_accept() {
  local file="$1" label="$2"
  clean
  local out
  out=$(kubectl apply -f "$file" 2>&1)
  if echo "$out" | grep -qiE "created|configured|unchanged"; then
    echo "  [PASS] принят: $label"
    pass=$((pass+1))
  else
    echo "  [FAIL] НЕ принят: $label"
    echo "$out" | sed 's/^/        /'
    fail=$((fail+1))
  fi
}

echo "==> 1/3 создаём namespace audit-zone с PodSecurity restricted"
kubectl apply -f "$NS"
echo

echo "==> 2/3 небезопасные манифесты должны быть отклонены PodSecurity Admission"
for f in "$INSECURE"/*.yaml; do
  check_reject "$f" "$(basename "$f")"
done
echo

echo "==> 3/3 безопасные манифесты должны быть приняты"
for f in "$SECURE"/*.yaml; do
  check_accept "$f" "$(basename "$f")"
done

clean
echo
echo "Итог: $pass принято/отклонено корректно, $fail с ошибками"
[ "$fail" -eq 0 ]