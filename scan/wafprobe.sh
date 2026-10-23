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
# For every probe it shows the ACTUAL request body (captured from curl's own
# trace), the ACTUAL response (status + key headers + a body snippet), and ends
# each target with a SUMMARY TABLE: the current response vs. the response a
# tuned WAF should give. Run it directly at the lab (baseline = current state),
# then through your WAF, and drive each "CURRENT" toward its "EXPECTED".
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
#   BODY_MAX=4000 bash scan/wafprobe.sh                   # widen body truncation
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
BODY_MAX="${BODY_MAX:-1400}"                    # max request-body chars shown per probe
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
printf 'benign WAF probe — not an exploit — %s\n' "$MARKER" > "$TMP/u.bin"
# a benign "oversized" field (64 KB of a single char) to exercise size-based rules
BIGFIELD="$(head -c 65536 /dev/zero | tr '\0' 'A')"

# expected-under-a-tuned-WAF outcomes (what each "CURRENT" should become)
EXP_PASS="HTTP 200 — legit, must pass"
EXP_BLOCK="HTTP 403 / reset — block"
EXP_SCRUB="HTTP 200, banners scrubbed"

# --- table state (reset per target) ------------------------------------------
TBL_L=(); TBL_S=(); TBL_C=(); TBL_E=()
table_reset(){ TBL_L=(); TBL_S=(); TBL_C=(); TBL_E=(); }
table_add(){ TBL_L+=("$1"); TBL_S+=("$2"); TBL_C+=("$3"); TBL_E+=("$4"); }
table_print(){
  printf '\n  SUMMARY — current vs. expected (tuned WAF)\n'
  printf '  %-13s %-34s %-12s %s\n' "PROBE" "REQUEST SHAPE" "CURRENT" "EXPECTED"
  printf '  %s\n' "---------------------------------------------------------------------------------------"
  local i
  for i in "${!TBL_L[@]}"; do
    printf '  %-13s %-34s %-12s %s\n' "${TBL_L[$i]}" "${TBL_S[$i]}" "${TBL_C[$i]}" "${TBL_E[$i]}"
  done
}

# --- helpers -----------------------------------------------------------------
hdr(){ printf '%s' "$1" | tr -d '\r' | sed -n "s/^$2: //Ip" | head -1; }

# reconstruct the actual request body from a curl --trace-ascii dump: the bytes
# under every "=> Send data" block, with the "0000: " offset prefixes stripped.
req_body(){
  awk '
    /^=> Send data/      { grab=1; next }
    /^=> Send header/    { grab=0 }
    /^<= Recv/           { grab=0 }
    /^== Info/           { grab=0 }
    grab==1 { s=$0; sub(/^[0-9a-f]+: /,"",s); printf "%s\n", s }
  ' "$1"
}

# first line of the request ("POST /x HTTP/1.1"), from the "=> Send header" block only.
req_firstline(){
  awk '/^=> Send header/{g=1;next}
       g && /^[0-9a-f]+: /{s=$0; sub(/^[0-9a-f]+: /,"",s); sub(/\r$/,"",s); print s; exit}' "$1"
}

# a REQUEST header value (not the response), scoped to the "=> Send header" block.
# $1=trace  $2=header name (lowercase)
req_hdr(){
  awk -v want="$2" '
    /^=> Send header/{g=1;next}
    /^=> Send data/{g=0} /^<= Recv/{g=0} /^== Info/{g=0}
    g { s=$0; sub(/^[0-9a-f]+: /,"",s); sub(/\r$/,"",s);
        n=index(s,": "); if(n>0){k=tolower(substr(s,1,n-1)); if(k==want){print substr(s,n+2); exit}} }
  ' "$1"
}

# send + render one probe.  $1=label $2=shape $3=expected $4=url ; rest=curl args
send(){
  local label="$1" shape="$2" expected="$3" url="$4"; shift 4
  local trace="$TMP/trace" rh="$TMP/rh" rb="$TMP/rb" code
  : > "$trace"; : > "$rh"; : > "$rb"
  code="$(curl -s --trace-ascii "$trace" -D "$rh" -o "$rb" -w '%{http_code}' \
          --max-time 10 "$@" "$url" 2>/dev/null)"
  [ -z "$code" ] && code="000"

  # --- request side ----------------------------------------------------------
  local reqline ctype clen body
  reqline="$(req_firstline "$trace")"
  ctype="$(req_hdr "$trace" 'content-type')"
  clen="$(req_hdr "$trace" 'content-length')"
  body="$(req_body "$trace")"

  printf '  -- [%s] %s\n' "$label" "$shape"
  printf '     REQUEST : %s\n' "${reqline:-<none>}"
  [ -n "$ctype" ] && printf '               Content-Type: %s\n' "$ctype"
  [ -n "$clen" ]  && printf '               Content-Length: %s\n' "$clen"
  if [ -n "$body" ]; then
    local shown truncated=""
    shown="$(printf '%s' "$body" | head -c "$BODY_MAX")"
    [ "${#body}" -gt "$BODY_MAX" ] && truncated=" … [truncated, ${#body} bytes total]"
    printf '               body:\n'
    printf '%s\n' "$shown" | sed 's/^/                 | /'
    [ -n "$truncated" ] && printf '                 |%s\n' "$truncated"
  else
    printf '               body: <none>\n'
  fi

  # --- response side ---------------------------------------------------------
  local status server xpb rctype snippet
  if [ "$code" = "000" ]; then
    printf '     RESPONSE: no-response (connection reset / blocked)\n'
  else
    status="$(head -1 "$rh" | tr -d '\r')"
    server="$(hdr "$(cat "$rh")" 'Server')"
    xpb="$(hdr "$(cat "$rh")" 'X-Powered-By')"
    rctype="$(hdr "$(cat "$rh")" 'Content-Type')"
    snippet="$(tr '\n' ' ' < "$rb" | tr -s ' ' | head -c 160)"
    printf '     RESPONSE: %s\n' "${status:-HTTP ${code}}"
    [ -n "$server" ]  && printf '               Server: %s\n' "$server"
    [ -n "$xpb" ]     && printf '               X-Powered-By: %s\n' "$xpb"
    [ -n "$rctype" ]  && printf '               Content-Type: %s\n' "$rctype"
    [ -n "$snippet" ] && printf '               body: %s\n' "$snippet"
  fi

  printf '     CURRENT : HTTP %s   |   EXPECTED (tuned WAF): %s\n\n' "$code" "$expected"
  table_add "$label" "$shape" "HTTP ${code}" "$expected"
}

# -----------------------------------------------------------------------------
# mode: stages — full kill-chain (passive recon / active recon / exploitation)
# -----------------------------------------------------------------------------
do_stages(){
  echo "PHP2Shell kill-chain WAF validation — $(date -u '+%Y-%m-%d %H:%M:%SZ')"
  echo "Marker: ${MARKER}   (grep WAF/app logs for this)"

  local url
  for url in "${TARGETS[@]}"; do
    echo
    echo "=== TARGET ${url} ==================================================="
    table_reset

    echo "  [1] passive recon  (expect WAF to SCRUB banners, not necessarily block)"
    send "passive" "GET / (read banners)" "$EXP_SCRUB" "$url/" -X GET

    echo "  [2] active recon   (expect WAF to BLOCK scanner UA / probes)"
    send "scanner-UA" "GET / UA=php2shell-vuln-checker" "$EXP_BLOCK" "$url/"  -A "php2shell-vuln-checker/1.0 (+lab)"
    send "assess"     "GET /assess.php UA=nuclei"        "$EXP_BLOCK" "$url/assess.php?format=json" -A "nuclei/3.0 (lab)"
    send "odd-path"   "GET /.env UA=whatweb"             "$EXP_BLOCK" "$url/.env" -A "whatweb/0.5 (lab)"

    echo "  [3] exploitation   (SHAPE ONLY — expect WAF to BLOCK; carries no primitive)"
    send "control"    "GET / (ordinary)" "$EXP_PASS" "$url/" -X GET
    send "multipart"  "POST multipart + UPLOAD_PROGRESS" "$EXP_BLOCK" "$url/index.php" \
        -F "PHP_SESSION_UPLOAD_PROGRESS=${MARKER}" \
        -F "file=@${TMP}/u.bin;type=application/octet-stream;filename=${MARKER}.bin"
    send "oversized"  "POST UPLOAD_PROGRESS + 64KB field" "$EXP_BLOCK" "$url/index.php" \
        -F "PHP_SESSION_UPLOAD_PROGRESS=${MARKER}" \
        -F "bigfield=${BIGFIELD}"

    table_print
  done

  cat <<'NOTE'

Reading it:
  [1] passive    -> Server/X-Powered-By scrubbed; version-enumeration alerted.
  [2] active     -> scanner-UA requests blocked (rule 1000200); "control" stays 200.
  [3] exploit    -> multipart/PHP_SESSION_UPLOAD_PROGRESS/oversized blocked
                    (rules 1000100/1000120/1000130); plain "control GET" stays 200.
Direct at the lab (no WAF) every CURRENT is 200/leaky = baseline. Behind a tuned
WAF each CURRENT should match its EXPECTED. Confirm in logs/<role>/ by grepping
the marker above.
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
    table_reset

    # control — an ordinary GET; a good rule must NOT flag this.
    send "control" "GET / (ordinary)" "$EXP_PASS" "$url/" -X GET
    # sig — multipart upload carrying the PHP_SESSION_UPLOAD_PROGRESS field first.
    send "sig" "POST multipart + UPLOAD_PROGRESS" "$EXP_BLOCK" "$url/index.php" \
      -F "PHP_SESSION_UPLOAD_PROGRESS=${MARKER}" \
      -F "file=@${TMP}/u.bin;type=application/octet-stream;filename=${MARKER}.bin"
    # sig-name — same marker via the upload_progress session name convention.
    send "sig-name" "POST upload_progress_<marker> field" "$EXP_BLOCK" "$url/" \
      -H "X-Probe: ${MARKER}" \
      -F "upload_progress_${MARKER}=1" \
      -F "PHP_SESSION_UPLOAD_PROGRESS=${MARKER}"

    table_print
  done

  cat <<'NOTE'

Reading it:
  - Baseline (direct at the lab, no WAF): every CURRENT is HTTP 200 — that is the
    current state, not a pass/fail.
  - Behind a tuned WAF (TARGET=...): "sig"/"sig-name" CURRENT should become
    403/reset while "control" stays 200. A "control" that turns 403 = too strict.
  - Detection content to build from (public advisories): multipart/form-data POST
    whose body contains the literal string  PHP_SESSION_UPLOAD_PROGRESS  (visible
    in the REQUEST body above). Confirm your rule fires in logs via the marker.
NOTE
}

case "$MODE" in
  stages) do_stages ;;
  sig)    do_sig ;;
esac
