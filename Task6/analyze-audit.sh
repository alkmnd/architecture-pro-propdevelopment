#!/usr/bin/env bash
set -uo pipefail

LOG="${1:-audit-extract-source.log}"
OUT="${2:-audit-extract.json}"

if [ "$LOG" = "-" ]; then
  SRC=/dev/stdin
else
  SRC="$LOG"
fi

read -r -d '' JQ_PROG <<'JQ' || true
def short(ev): {
  ts: ev.requestReceivedTimestamp, level: ev.level, verb: ev.verb,
  user: ev.user.username,
  impersonatedUser: (ev.impersonatedUser.username // null),
  sourceIPs: (ev.sourceIPs // []),
  resource: ev.objectRef.resource, subresource: ev.objectRef.subresource,
  namespace: ev.objectRef.namespace, name: ev.objectRef.name, apiGroup: ev.objectRef.apiGroup,
  code: ev.responseStatus.code, reason: ev.responseStatus.reason,
  decision: (ev.annotations."authorization.k8s.io/decision" // null)
};
{
  stats: { total: length },
  findings: {
    secret_access:
      ( map( select( .objectRef.resource=="secrets"
                     and (.verb=="get" or .verb=="list" or .verb=="watch") ) )
        | map(short(.)) ),
    privileged_pod:
      ( map( select( .objectRef.resource=="pods" and .verb=="create"
                     and ((.requestObject.spec.containers // [])
                          | any(.securityContext.privileged == true)) ) )
        | map(short(.)) ),
    exec:
      ( map( select( .objectRef.subresource=="exec" ) ) | map(short(.)) ),
    rbac_escalation:
      ( map( select( (.objectRef.resource=="rolebindings"
                      or .objectRef.resource=="clusterrolebindings")
                     and .verb=="create" ) )
        | map(short(.)) ),
    impersonation:
      ( map( select( .impersonatedUser != null ) ) | map(short(.)) )
  }
}
JQ

if [ "$LOG" = "-" ]; then
  jq -c 'select(.stage=="ResponseComplete")' /dev/stdin | jq -s "$JQ_PROG" > "$OUT"
else
  jq -c 'select(.stage=="ResponseComplete")' "$LOG" | jq -s "$JQ_PROG" > "$OUT"
fi

total=$(jq -r '.stats.total' "$OUT")
echo "Processed events (ResponseComplete): $total"
echo
echo "=== 1. Secret access (get/list/watch) ==="
jq -r '.findings.secret_access[] | "  \(.ts) user=\(.user) impersonated=\(.impersonatedUser // "-") verb=\(.verb) ns=\(.namespace) code=\(.code)"' "$OUT" 2>/dev/null
echo
echo "=== 2. kubectl exec (subresource=exec) ==="
jq -r '.findings.exec[] | "  \(.ts) user=\(.user) ns=\(.namespace) pod=\(.name) code=\(.code)"' "$OUT" 2>/dev/null
echo
echo "=== 3. Privileged pods (securityContext.privileged=true) ==="
jq -r '.findings.privileged_pod[] | "  \(.ts) user=\(.user) ns=\(.namespace) name=\(.name) code=\(.code)"' "$OUT" 2>/dev/null
echo
echo "=== 4. audit-policy removal (grep) ==="
if [ "$LOG" != "-" ]; then
  n=$(grep -ci 'audit-policy' "$LOG" 2>/dev/null)
  n=${n:-0}
  echo "  matches: $n"
  grep -i 'audit-policy' "$LOG" 2>/dev/null | head -3 | sed 's/^/  /'
  [ "$n" -eq 0 ] && echo "  (kubectl delete -f failed client-side; never reached apiserver)"
fi
echo
echo "=== 5. RBAC escalation (rolebindings/clusterrolebindings create) ==="
jq -r '.findings.rbac_escalation[] | "  \(.ts) user=\(.user) res=\(.resource) ns=\(.namespace // "-") name=\(.name) code=\(.code)"' "$OUT" 2>/dev/null
echo
echo "=== 6. Impersonation (--as) ==="
jq -r '.findings.impersonation[] | "  \(.ts) user=\(.user) -> \(.impersonatedUser) res=\(.resource // "-") code=\(.code)"' "$OUT" 2>/dev/null
echo
echo "Output: $OUT"
