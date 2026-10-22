#!/usr/bin/env bash
# =============================================================================
# killchain.sh — validate that your WAF blocks PHP2Shell at EACH kill-chain
# stage: (1) passive recon, (2) active recon, (3) exploitation.
#
#   !!  NOT AN EXPLOIT.  !!
#   Every request here is benign. Stage 3 carries the *exploitation-stage HTTP
#   SHAPE* (multipart + PHP_SESSION_UPLOAD_PROGRESS + an oversized field) — the
#   bytes a WAF rule matches — but NO memory-corruption primitive, no heap
#   grooming, no payload. It cannot achieve RCE against any target, patched or
#   not. The WAF's block decision is identical for this shape and a real attack,
#   which is exactly why it validates your rules. Use only on your own lab.
#
# Why no "real" confirmation exploit: for this use-after-free, triggering the bug
# IS the weaponizable primitive, so a non-RCE "confirm" trigger is still the
# dangerous part. Exposure for PHP2Shell is confirmed by VERSION + CONFIG
# (scan/vuln-checker.py, /assess.php), the same way vendor scanners do it.
#
# Usage:
#   bash scan/killchain.sh                         # hit lab ports directly (baseline, no WAF)
#   TARGET=http://your-waf bash scan/killchain.sh  # send through your WAF and compare
#
# Reading it: with a tuned WAF in front, each stage's probe should be BLOCKED
# (403/406/429/reset) while ordinary traffic stays 200. Direct at the lab (no
# WAF) everything returns 200 — that is your baseline, not a pass/fail.
# =============================================================================
set -u

if [ -n "${TARGET:-}" ]; then TARGETS=("$TARGET"); else
  H="${LAB_HOST:-127.0.0.1}"; TARGETS=("http://${H}:8080" "http://${H}:8081" "http://${H}:8082")
fi
MARKER="killchain-$(date -u +%Y%m%dT%H%M%SZ)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
printf 'benign killchain probe — not an exploit — %s\n' "$MARKER" > "$TMP/u.bin"
# a benign "oversized" field (64 KB of a single char) to exercise size-based rules
BIGFIELD="$(head -c 65536 /dev/zero | tr '\0' 'A')"

send() { # $1=label $2=url ; rest=curl args
  local label="$1" url="$2"; shift 2
  local code; code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@" "$url" 2>/dev/null)"
  [ -z "$code" ] && code="000"
  if [ "$code" = "000" ]; then printf '    %-26s %s\n' "$label" "no-response (reset/blocked?)"
  else printf '    %-26s HTTP %s\n' "$label" "$code"; fi
}

echo "PHP2Shell kill-chain WAF validation — $(date -u '+%Y-%m-%d %H:%M:%SZ')"
echo "Marker: ${MARKER}   (grep WAF/app logs for this)"

for url in "${TARGETS[@]}"; do
  echo
  echo "=== TARGET ${url} ==================================================="

  # -- Stage 1: PASSIVE RECON ---------------------------------------------------
  # Attacker reads banners/version without 'attacking'. A plain GET; what leaks
  # is the fingerprint. WAF/edge action: strip Server/X-Powered-By, suppress
  # version tokens (ServerTokens Prod, unset X-Powered-By), detect enumeration.
  echo "  [1] passive recon  (expect WAF to SCRUB banners, not necessarily block)"
  hdr="$(curl -fsSI --max-time 8 "$url/" 2>/dev/null | tr -d '\r')"
  echo "    Server:        $(printf '%s' "$hdr" | sed -n 's/^Server: //Ip' | head -1)"
  echo "    X-Powered-By:  $(printf '%s' "$hdr" | sed -n 's/^X-Powered-By: //Ip' | head -1)"

  # -- Stage 2: ACTIVE RECON ----------------------------------------------------
  # Scanner/checker traffic: recognisable UA + probing endpoints. WAF action:
  # block known-scanner UAs (rule 1000200), rate/anomaly limit.
  echo "  [2] active recon   (expect WAF to BLOCK scanner UA / probes)"
  send "scanner-UA GET /"        "$url/"             -A "php2shell-vuln-checker/1.0 (+lab)"
  send "assess probe"            "$url/assess.php?format=json" -A "nuclei/3.0 (lab)"
  send "odd-path probe"          "$url/.env"         -A "whatweb/0.5 (lab)"

  # -- Stage 3: EXPLOITATION (SHAPE ONLY, inert) --------------------------------
  # The HTTP envelope of the attack: multipart + PHP_SESSION_UPLOAD_PROGRESS +
  # an oversized field. No primitive. WAF action: block (rules 1000100/120/130).
  echo "  [3] exploitation   (SHAPE ONLY — expect WAF to BLOCK; carries no primitive)"
  send "control GET (must pass)" "$url/"             -X GET
  send "multipart+upload_prog"   "$url/index.php" \
      -F "PHP_SESSION_UPLOAD_PROGRESS=${MARKER}" \
      -F "file=@${TMP}/u.bin;type=application/octet-stream;filename=${MARKER}.bin"
  send "oversized-field"         "$url/index.php" \
      -F "PHP_SESSION_UPLOAD_PROGRESS=${MARKER}" \
      -F "bigfield=${BIGFIELD}"
done

cat <<'NOTE'

Expected with a tuned WAF in front (TARGET=...):
  [1] passive    -> Server/X-Powered-By scrubbed; version-enumeration alerted.
  [2] active     -> scanner-UA requests blocked (rule 1000200); "control" stays 200.
  [3] exploit    -> multipart/PHP_SESSION_UPLOAD_PROGRESS/oversized blocked
                    (rules 1000100/1000120/1000130); plain "control GET" stays 200.
Direct at the lab (no WAF) everything is 200 = baseline. Confirm the match in
logs/<role>/ (raw capture) by grepping the marker above.
NOTE
