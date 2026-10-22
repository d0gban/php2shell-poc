#!/usr/bin/env bash
# PHP2Shell lab scanner — queries each container's /assess.php?format=json and prints a verdict table.
# Usage:  ./scan/check.sh            (defaults to the compose ports)
#         ./scan/check.sh 8080 8081 8082
set -u

PORTS=("${@:-}")
if [ -z "${PORTS[0]}" ]; then PORTS=(8080 8081 8082); fi
LABELS=("EOL" "OUTDATED" "PATCHED")

have_jq() { command -v jq >/dev/null 2>&1; }

echo "PHP2Shell lab — CVE-2026-109618 / CVE-2026-109619"
echo "Scanned: $(date -u '+%Y-%m-%d %H:%M:%SZ')"
echo
printf '%-10s %-6s %-10s %-16s %-7s %s\n' "ROLE" "PORT" "PHP" "STATUS" "FOOTHLD" "FIXED-IN"
printf '%s\n' "---------------------------------------------------------------------------------"

i=0
for port in "${PORTS[@]}"; do
  label="${LABELS[$i]:-SVC$i}"
  url="http://localhost:${port}/assess.php?format=json"
  body="$(curl -fsS --max-time 5 "$url" 2>/dev/null)"
  if [ -z "$body" ]; then
    printf '%-10s %-6s %-10s %-16s %-7s %s\n' "$label" "$port" "-" "UNREACHABLE" "-" "-"
    i=$((i+1)); continue
  fi
  if have_jq; then
    ver="$(printf '%s' "$body"  | jq -r '.php_version')"
    stat="$(printf '%s' "$body" | jq -r '.status')"
    fixed="$(printf '%s' "$body"| jq -r '.fixed_in // "none (EOL)"')"
    foot="$(printf '%s' "$body" | jq -r 'if .foothold_simulation then "yes" else "no" end')"
  else
    # pure-shell fallback (no jq)
    ver="$(printf   '%s' "$body" | sed -n 's/.*"php_version": *"\([^"]*\)".*/\1/p' | head -1)"
    stat="$(printf  '%s' "$body" | sed -n 's/.*"status": *"\([^"]*\)".*/\1/p' | head -1)"
    fixed="$(printf '%s' "$body" | sed -n 's/.*"fixed_in": *"\([^"]*\)".*/\1/p' | head -1)"; fixed="${fixed:-none (EOL)}"
    foot="$(printf  '%s' "$body" | grep -q '"foothold_simulation": *true' && echo yes || echo no)"
  fi
  printf '%-10s %-6s %-10s %-16s %-7s %s\n' "$label" "$port" "$ver" "$stat" "$foot" "$fixed"
  i=$((i+1))
done

echo
echo "Legend: STATUS = PATCHED (safe) | VULNERABLE | EOL_UNSUPPORTED (vulnerable, no upstream fix)"
echo "        FOOTHLD = whether the labeled post-exploitation simulation is reachable on that host"
