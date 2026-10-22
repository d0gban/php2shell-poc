#!/usr/bin/env bash
# =============================================================================
# waf-test.sh — blue-team WAF/IDS detection probe for PHP2Shell
# (CVE-2026-109618 / CVE-2026-109619).
#
# Sends request traffic that carries the *detection signature* of the PHP2Shell
# attack — an unauthenticated multipart upload containing the
# `PHP_SESSION_UPLOAD_PROGRESS` marker — so you can tune and validate WAF/IDS
# rules against realistic-looking requests.
#
#   !!  THIS IS NOT AN EXPLOIT.  !!
#   PHP_SESSION_UPLOAD_PROGRESS is a normal, documented PHP upload field. These
#   probes only exercise the request *pattern* a rule would match. They carry no
#   memory-corruption primitive, no symbol offsets, no heap grooming and no
#   command payload — they cannot achieve RCE against any target, patched or not.
#   Use only against your own lab / systems you are authorized to test.
#
# Usage:
#   bash scan/waf-test.sh                      # probe the 3 lab ports directly (baseline, no WAF)
#   TARGET=http://waf.local:80 bash scan/waf-test.sh   # probe through your WAF front end
#   bash scan/waf-test.sh http://host:8080 http://host:8081   # explicit targets
#
# Reading results: send the SAME probes through your WAF and compare. A rule
# that works turns the "sig" probe into a block (403/406/501/429/reset) while
# leaving the "control" probe at 200. Hitting the app directly (no WAF) returns
# 200 for both — that is your baseline, not a failure.
# =============================================================================
set -u

# --- targets ------------------------------------------------------------------
if [ "$#" -gt 0 ]; then
  TARGETS=("$@")
elif [ -n "${TARGET:-}" ]; then
  TARGETS=("$TARGET")
else
  H="${LAB_HOST:-127.0.0.1}"
  TARGETS=("http://${H}:8080" "http://${H}:8081" "http://${H}:8082")
fi

MARKER="waf-probe-$(date -u +%Y%m%dT%H%M%SZ)"   # unique, greppable, obviously benign
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
printf 'benign WAF detection probe — not an exploit — %s\n' "$MARKER" > "$TMP/upload.bin"

# curl -> "HTTP <code>" or "no-response (blocked/reset)"
send() {  # $1=label  $2=url  shift 2 -> extra curl args
  local label="$1" url="$2"; shift 2
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@" "$url" 2>/dev/null)"
  if [ -z "$code" ] || [ "$code" = "000" ]; then
    printf '%-9s %-38s %s\n' "$label" "$url" "no-response (reset/blocked?)"
  else
    printf '%-9s %-38s HTTP %s\n' "$label" "$url" "$code"
  fi
}

echo "PHP2Shell WAF detection probe — $(date -u '+%Y-%m-%d %H:%M:%SZ')"
echo "Marker: ${MARKER}   (grep your WAF/app logs for this string)"
echo
printf '%-9s %-38s %s\n' "PROBE" "TARGET" "RESULT"
printf '%s\n' "-----------------------------------------------------------------------"

for url in "${TARGETS[@]}"; do
  # 1) control — an ordinary GET; a good rule must NOT flag this.
  send "control" "$url/" -X GET

  # 2) signature — multipart upload carrying the PHP_SESSION_UPLOAD_PROGRESS field.
  #    The progress field must precede the file part, mirroring the real pattern.
  send "sig" "$url/index.php" \
    -F "PHP_SESSION_UPLOAD_PROGRESS=${MARKER}" \
    -F "file=@${TMP}/upload.bin;type=application/octet-stream;filename=${MARKER}.bin"

  # 3) sig-name — same marker expressed via the upload_progress session name
  #    convention some rules key on, as a second detection angle.
  send "sig-name" "$url/" \
    -H "X-Probe: ${MARKER}" \
    -F "upload_progress_${MARKER}=1" \
    -F "PHP_SESSION_UPLOAD_PROGRESS=${MARKER}"
  echo
done

cat <<NOTE
Next:
  - With a WAF in front (TARGET=...): a tuned rule blocks "sig"/"sig-name" (403/406/501/
    reset) but leaves "control" at 200.
  - Detection content to build from (per the public advisories): multipart/form-data POST
    whose body contains the literal string  PHP_SESSION_UPLOAD_PROGRESS .
  - Confirm your rule also fires in logs: grep for the marker above on both WAF and app side.
  - False-positive check: the "control" probe and normal app traffic must stay allowed.
NOTE
