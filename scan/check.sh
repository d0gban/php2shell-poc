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
printf '%-10s %-6s %-10s %-16s %s\n' "ROLE" "PORT" "PHP" "STATUS" "FIXED-IN"
printf '%s\n' "-----------------------------------------------------------------"

i=0
for port in "${PORTS[@]}"; do
  label="${LABELS[$i]:-SVC$i}"
  url="http://${LAB_HOST:-localhost}:${port}/assess.php?format=json"   # LAB_HOST overrides for a non-loopback bind
  body="$(curl -fsS --max-time 5 "$url" 2>/dev/null)"
  if [ -z "$body" ]; then
    printf '%-10s %-6s %-10s %-16s %s\n' "$label" "$port" "-" "UNREACHABLE" "-"
    i=$((i+1)); continue
  fi
  if have_jq; then
    ver="$(printf '%s' "$body"  | jq -r '.php_version')"
    stat="$(printf '%s' "$body" | jq -r '.status')"
    fixed="$(printf '%s' "$body"| jq -r '.fixed_in // "none (EOL)"')"
  else
    # pure-shell fallback (no jq)
    ver="$(printf   '%s' "$body" | sed -n 's/.*"php_version": *"\([^"]*\)".*/\1/p' | head -1)"
    stat="$(printf  '%s' "$body" | sed -n 's/.*"status": *"\([^"]*\)".*/\1/p' | head -1)"
    fixed="$(printf '%s' "$body" | sed -n 's/.*"fixed_in": *"\([^"]*\)".*/\1/p' | head -1)"; fixed="${fixed:-none (EOL)}"
  fi
  printf '%-10s %-6s %-10s %-16s %s\n' "$label" "$port" "$ver" "$stat" "$fixed"
  i=$((i+1))
done

echo
echo "Legend: STATUS = PATCHED (safe) | VULNERABLE | EOL_UNSUPPORTED (vulnerable, no upstream fix)"

# -----------------------------------------------------------------------------
# App-layer sink checks (LFI + session fixation) — BENIGN presence probes only.
# Same recon/identification class as scan/vuln-checker.py: no RCE, no payload.
#   LFI       : traversal read of the world-readable /etc/passwd. OPEN if the
#               response carries a "root:" line, WAF-BLOCKED on 403, FIXED on 404.
#   FIXATION  : ask /login.php to adopt a chosen id; OPEN if the page echoes it back.
# These probe the APP (identical on all three hosts), so the result is the same
# per port unless a WAF/patch differs. Use them to confirm your WAF actually blocks.
# -----------------------------------------------------------------------------
UA="php2shell-lab-check/1.0 (+lab; benign presence probe)"
FIX_ID="labprobe-fixation-0000"
echo
printf '%-10s %-6s %-18s %s\n' "ROLE" "PORT" "LFI(view.php)" "SESSION-FIXATION(login.php)"
printf '%s\n' "-----------------------------------------------------------------"

i=0
for port in "${PORTS[@]}"; do
  label="${LABELS[$i]:-SVC$i}"
  host="${LAB_HOST:-localhost}"

  # --- LFI presence: read a world-readable file via path traversal -----------
  lfi_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -A "$UA" \
      "http://${host}:${port}/view.php?doc=../../../../etc/passwd" 2>/dev/null)"
  lfi_body="$(curl -s --max-time 5 -A "$UA" \
      "http://${host}:${port}/view.php?doc=../../../../etc/passwd" 2>/dev/null)"
  if   [ "$lfi_code" = "403" ];                     then lfi="WAF-BLOCKED"
  elif printf '%s' "$lfi_body" | grep -q '^root:';  then lfi="OPEN"
  elif [ "$lfi_code" = "404" ];                     then lfi="FIXED"
  elif [ -z "$lfi_code" ] || [ "$lfi_code" = "000" ];then lfi="UNREACHABLE"
  else                                                   lfi="NOT-CONFIRMED($lfi_code)"
  fi

  # --- Fixation presence: does the app adopt a caller-supplied id? -----------
  fx_body="$(curl -s --max-time 5 -A "$UA" \
      "http://${host}:${port}/login.php?sid=${FIX_ID}" 2>/dev/null)"
  if   [ -z "$fx_body" ];                            then fx="UNREACHABLE"
  elif printf '%s' "$fx_body" | grep -q "$FIX_ID";   then fx="OPEN"
  else                                                    fx="NOT-ADOPTED"
  fi

  printf '%-10s %-6s %-18s %s\n' "$label" "$port" "$lfi" "$fx"
  i=$((i+1))
done

echo
echo "Legend: LFI/FIXATION = OPEN (vuln present) | WAF-BLOCKED (403) | FIXED/NOT-ADOPTED | UNREACHABLE"
echo "        Benign recon only — reads /etc/passwd and reflects a probe id; no exploit, no RCE."
