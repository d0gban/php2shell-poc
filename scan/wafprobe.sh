#!/usr/bin/env bash
# =============================================================================
# wafprobe.sh — validate your WAF against PHP2Shell with BENIGN, inert probes.
# (CVE-2026-109618 / CVE-2026-109619).
#
#   !!  NOT AN EXPLOIT.  !!
#   Every request is benign. The exploitation probes carry the attack's HTTP
#   SHAPE (multipart + PHP_SESSION_UPLOAD_PROGRESS + an oversized field) — the
#   bytes a WAF rule matches — but NO memory-corruption primitive, no heap
#   grooming, no payload. They cannot achieve RCE against any target, patched or
#   not. The WAF's block decision is identical for this shape and a real attack,
#   which is exactly why it validates your rules. Use only on your own lab.
#
# Two modes:
#   bash scan/wafprobe.sh             # full kill-chain: passive+active recon +
#   bash scan/wafprobe.sh stages      #   exploitation shape, per stage (default)
#   bash scan/wafprobe.sh sig         # signature-only: control / sig / sig-name
#
# Targets (any mode): default = the 3 lab ports direct (baseline, no WAF).
#   TARGET=http://your-waf bash scan/wafprobe.sh          # send through your WAF
#   bash scan/wafprobe.sh sig http://host:8080 http://h:8081   # explicit targets
#   LAB_HOST=192.168.56.10 bash scan/wafprobe.sh
#
# Reading it: with a tuned WAF in front, each stage/sig probe should be BLOCKED
# (403/406/429/reset) while ordinary "control" traffic stays 200. Direct at the
# lab (no WAF) everything returns 200 — that is your baseline, not a pass/fail.
#
# Why no "real" confirmation exploit: for this use-after-free, triggering the bug
# IS the weaponizable primitive, so a non-RCE "confirm" trigger is still the
# dangerous part. Exposure is confirmed by VERSION + CONFIG (scan/vuln-checker.py,
# /assess.php), the same way vendor scanners do it.
# =============================================================================
set -u

# --- mode (optional first arg) + targets -------------------------------------
MODE="stages"
case "${1:-}" in
  stages|sig) MODE="$1"; shift ;;
  -h|--help)  sed -n '2,33p' "$0"; exit 0 ;;
esac

if [ "$#" -gt 0 ]; then
  TARGETS=("$@")
elif [ -n "${TARGET:-}" ]; then
  TARGETS=("$TARGET")
else
  H="${LAB_HOST:-127.0.0.1}"
  TARGETS=("http://${H}:8080" "http://${H}:8081" "http://${H}:8082")
fi

MARKER="wafprobe-$(date -u +%Y%m%dT%H%M%SZ)"   # unique, greppable, obviously benign
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
printf 'benign WAF probe — not an exploit — %s\n' "$MARKER" > "$TMP/u.bin"
# a benign "oversized" field (64 KB of a single char) to exercise size-based rules
BIGFIELD="$(head -c 65536 /dev/zero | tr '\0' 'A')"

# curl -> "HTTP <code>" or "no-response (reset/blocked?)"
send() { # $1=label $2=url ; rest=curl args
  local label="$1" url="$2"; shift 2
  local code; code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@" "$url" 2>/dev/null)"
  [ -z "$code" ] && code="000"
  if [ "$code" = "000" ]; then printf '    %-26s %s\n' "$label" "no-response (reset/blocked?)"
  else printf '    %-26s HTTP %s\n' "$label" "$code"; fi
}

# -----------------------------------------------------------------------------
# mode: stages — full kill-chain (passive recon / active recon / exploitation)
# -----------------------------------------------------------------------------
do_stages(){
  echo "PHP2Shell kill-chain WAF validation — $(date -u '+%Y-%m-%d %H:%M:%SZ')"
  echo "Marker: ${MARKER}   (grep WAF/app logs for this)"

  local url hdr
  for url in "${TARGETS[@]}"; do
    echo
    echo "=== TARGET ${url} ==================================================="

    # -- Stage 1: PASSIVE RECON -------------------------------------------------
    echo "  [1] passive recon  (expect WAF to SCRUB banners, not necessarily block)"
    hdr="$(curl -fsSI --max-time 8 "$url/" 2>/dev/null | tr -d '\r')"
    echo "    Server:        $(printf '%s' "$hdr" | sed -n 's/^Server: //Ip' | head -1)"
    echo "    X-Powered-By:  $(printf '%s' "$hdr" | sed -n 's/^X-Powered-By: //Ip' | head -1)"

    # -- Stage 2: ACTIVE RECON --------------------------------------------------
    echo "  [2] active recon   (expect WAF to BLOCK scanner UA / probes)"
    send "scanner-UA GET /"        "$url/"             -A "php2shell-vuln-checker/1.0 (+lab)"
    send "assess probe"            "$url/assess.php?format=json" -A "nuclei/3.0 (lab)"
    send "odd-path probe"          "$url/.env"         -A "whatweb/0.5 (lab)"

    # -- Stage 3: EXPLOITATION (SHAPE ONLY, inert) ------------------------------
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
}

# -----------------------------------------------------------------------------
# mode: sig — signature-only detection probes (control / sig / sig-name)
# -----------------------------------------------------------------------------
do_sig(){
  echo "PHP2Shell WAF detection probe — $(date -u '+%Y-%m-%d %H:%M:%SZ')"
  echo "Marker: ${MARKER}   (grep your WAF/app logs for this string)"

  local url
  for url in "${TARGETS[@]}"; do
    echo
    echo "=== TARGET ${url} ==================================================="
    # 1) control — an ordinary GET; a good rule must NOT flag this.
    send "control" "$url/" -X GET
    # 2) signature — multipart upload carrying the PHP_SESSION_UPLOAD_PROGRESS field.
    #    The progress field must precede the file part, mirroring the real pattern.
    send "sig" "$url/index.php" \
      -F "PHP_SESSION_UPLOAD_PROGRESS=${MARKER}" \
      -F "file=@${TMP}/u.bin;type=application/octet-stream;filename=${MARKER}.bin"
    # 3) sig-name — same marker via the upload_progress session name convention.
    send "sig-name" "$url/" \
      -H "X-Probe: ${MARKER}" \
      -F "upload_progress_${MARKER}=1" \
      -F "PHP_SESSION_UPLOAD_PROGRESS=${MARKER}"
  done

  cat <<'NOTE'

Next:
  - With a WAF in front (TARGET=...): a tuned rule blocks "sig"/"sig-name" (403/406/501/
    reset) but leaves "control" at 200.
  - Detection content to build from (per the public advisories): multipart/form-data POST
    whose body contains the literal string  PHP_SESSION_UPLOAD_PROGRESS .
  - Confirm your rule also fires in logs: grep for the marker above on both WAF and app side.
  - False-positive check: the "control" probe and normal app traffic must stay allowed.
NOTE
}

case "$MODE" in
  stages) do_stages ;;
  sig)    do_sig ;;
esac
