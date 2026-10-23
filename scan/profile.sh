#!/usr/bin/env bash
# =============================================================================
# profile.sh — fingerprint + per-version HTTP behaviour for the three lab hosts.
#
# Two read-only, benign modes (no exploit, no attack primitive):
#
#   bash scan/profile.sh            # behaviour profile (default)
#   bash scan/profile.sh behavior   #   per-version observable HTTP behaviour
#   bash scan/profile.sh verify     #   prove the server fingerprint is REAL, not
#                                    #   spoofed by app header() calls
#
#   LAB_HOST=192.168.56.10 bash scan/profile.sh [mode]
#
# Both modes only send ordinary requests (GET, a normal small upload, an empty
# POST, a 404) and report what comes back. `verify` additionally cross-checks the
# live in-container binaries when docker is available.
# =============================================================================
set -u
LAB_HOST="${LAB_HOST:-127.0.0.1}"
PORTS=(8080 8081 8082)
ROLES=(EOL OUTDATED PATCHED)
NAMES=(php2shell-eol php2shell-outdated php2shell-patched)

# single-header value, case-insensitive, CR-stripped
hdr(){ printf '%s' "$1" | tr -d '\r' | sed -n "s/^$2: //Ip" | head -1; }

# -----------------------------------------------------------------------------
# mode: behavior — per-version observable HTTP behaviour profiler
# -----------------------------------------------------------------------------
do_behavior(){
  local TMP; TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' RETURN
  printf 'benign profiler payload\n' > "$TMP/u.bin"
  # status + total_time for a request; extra curl args after the url
  probe(){ curl -s -o /dev/null -w '%{http_code} %{time_total}s' --max-time 10 "$@" 2>/dev/null || printf 'no-response'; }

  echo "PHP2Shell lab — per-version HTTP behaviour profile"
  echo "Scanned: $(date -u '+%Y-%m-%d %H:%M:%SZ')   Host: ${LAB_HOST}"

  local i port role base
  for i in 0 1 2; do
    port="${PORTS[$i]}"; role="${ROLES[$i]}"; base="http://${LAB_HOST}:${port}"
    echo
    echo "== ${role} (:${port}) ==============================================="

    local root_h php sid e404
    root_h="$(curl -fsSI "${base}/" 2>/dev/null || true)"
    if [ -z "$root_h" ]; then echo "    unreachable (is the lab up?)"; continue; fi

    php="$(curl -fsS "${base}/assess.php?format=json" 2>/dev/null | sed -n 's/.*"php_version": *"\([^"]*\)".*/\1/p' | head -1)"
    echo "    PHP version      : ${php:-?}"
    echo "    Server banner    : $(hdr "$root_h" 'Server')"
    echo "    X-Powered-By     : $(hdr "$root_h" 'X-Powered-By')"

    # PHPSESSID cookie shape (CVE-2026-109619 keys on abnormal session cookies)
    sid="$(curl -fssI "${base}/assess.php" 2>/dev/null | tr -d '\r' | sed -n 's/.*PHPSESSID=\([^;]*\).*/\1/Ip' | head -1)"
    echo "    PHPSESSID format : ${sid:+len=${#sid} value=${sid}}${sid:-<none set>}"

    # Observable responses to ordinary request classes (status + timing)
    echo "    responses:"
    echo "      GET /                     -> $(probe "${base}/" -X GET)"
    echo "      GET /nonexistent-404      -> $(probe "${base}/no-such-path-404" -X GET)"
    echo "      empty POST /index.php     -> $(probe "${base}/index.php" -X POST)"
    echo "      normal upload /index.php  -> $(probe "${base}/index.php" -F "file=@${TMP}/u.bin")"

    # 404 banner leak (ServerTokens Full) — useful for fingerprint-based rules
    e404="$(hdr "$(curl -fsSI "${base}/no-such-path-404" 2>/dev/null || true)" 'Server')"
    echo "    404 Server banner: ${e404}"
  done

  cat <<'NOTE'

Reading it:
  - The Server / X-Powered-By / 404 banner columns differ per PHP version — these
    are the fingerprint tokens a version-aware rule or an inventory scan keys on.
  - PHPSESSID length/charset is your baseline for CVE-2026-109619 anomaly rules
    (flag response cookies far outside this shape).
  - Status/timing for the request classes above is your FALSE-POSITIVE baseline:
    whatever a tuned WAF rule does to the wafprobe.sh "sig" probe, it must leave
    these ordinary requests untouched.
  - Compare the two vulnerable hosts against the patched one (:8082): a good rule
    set behaves the same on all three (it targets the attack shape, not "any PHP").
NOTE
}

# -----------------------------------------------------------------------------
# mode: verify — prove the server fingerprint is REAL, not spoofed
# -----------------------------------------------------------------------------
do_verify(){
  local pass=0 fail=0 skip=0
  ok(){   printf '    \033[32m[PASS]\033[0m %s\n' "$*"; pass=$((pass+1)); }
  no(){   printf '    \033[31m[FAIL]\033[0m %s\n' "$*"; fail=$((fail+1)); }
  skp(){  printf '    \033[33m[SKIP]\033[0m %s\n' "$*"; skip=$((skip+1)); }

  local have_docker=0
  command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && have_docker=1
  [ "$have_docker" -eq 0 ] && echo "note: docker not available — in-container checks will be skipped (HTTP checks still run)."

  local i port name
  for i in 0 1 2; do
    port="${PORTS[$i]}"; name="${NAMES[$i]}"
    echo
    echo "== ${name} (:${port}) =================================================="

    # --- live HTTP headers ---------------------------------------------------
    local root_hdr srv xpb modphp_ver sapi_web
    root_hdr="$(curl -fsSI "http://${LAB_HOST}:${port}/" 2>/dev/null || true)"
    if [ -z "$root_hdr" ]; then no "host unreachable on :${port} (is the lab up?)"; continue; fi
    srv="$(hdr "$root_hdr" 'Server')"
    xpb="$(hdr "$root_hdr" 'X-Powered-By')"
    echo "    Server:       ${srv}"
    echo "    X-Powered-By: ${xpb}"

    modphp_ver="$(curl -fsS "http://${LAB_HOST}:${port}/assess.php?format=json" 2>/dev/null \
                 | sed -n 's/.*"php_version": *"\([^"]*\)".*/\1/p' | head -1)"
    sapi_web="$(curl -fsS "http://${LAB_HOST}:${port}/assess.php?format=json" 2>/dev/null \
               | sed -n 's/.*"sapi": *"\([^"]*\)".*/\1/p' | head -1)"
    echo "    PHP (web SAPI): ${modphp_ver:-?}   SAPI: ${sapi_web:-?}"

    # 1) The web app must NOT set these headers itself.
    if [ "$have_docker" -eq 1 ]; then
      if docker exec "$name" sh -c 'grep -rqiE "header\\([\"'\'']?(Server|X-Powered-By)" /var/www/html' 2>/dev/null; then
        no "web app sets a Server/X-Powered-By header (that would be a spoof)"
      else
        ok "web app sets no Server/X-Powered-By header — not spoofed by app code"
      fi
    else
      skp "app-spoof check (needs docker)"
    fi

    # 2) Banner PHP token must equal the LIVE mod_php version (auto-tracks each build).
    if [ -n "$modphp_ver" ]; then
      if printf '%s' "$srv" | grep -q "PHP/${modphp_ver}\b"; then
        ok "Server banner PHP token == live mod_php (${modphp_ver})"
      else
        no "Server banner PHP token != live mod_php (${modphp_ver})"
      fi
      if [ "$xpb" = "PHP/${modphp_ver}" ]; then
        ok "X-Powered-By == live mod_php (${modphp_ver})"
      else
        no "X-Powered-By (${xpb}) != live mod_php (${modphp_ver})"
      fi
    else
      skp "mod_php version cross-check (assess.php?format=json unreachable)"
    fi

    # 3) In-container binaries really are those versions.
    if [ "$have_docker" -eq 1 ]; then
      local cli_php ssl_lib mpm ssl_tok
      cli_php="$(docker exec "$name" php -r 'echo PHP_VERSION;' 2>/dev/null)"
      ssl_lib="$(docker exec "$name" php -r 'echo OPENSSL_VERSION_TEXT;' 2>/dev/null)"
      mpm="$(docker exec "$name" apache2ctl -V 2>/dev/null | sed -n 's/^Server MPM: *//p' | head -1)"
      echo "    php -r PHP_VERSION     -> ${cli_php}"
      echo "    php -r OPENSSL_VERSION -> ${ssl_lib}"
      echo "    Apache MPM             -> ${mpm:-?}   (mod_php requires prefork)"
      if docker exec "$name" apache2ctl -M 2>/dev/null | grep -q ssl_module; then
        ok "mod_ssl is really loaded — the OpenSSL token in the banner is genuine"
      else
        no "mod_ssl NOT loaded, yet the banner advertises OpenSSL"
      fi
      ssl_tok="$(printf '%s' "$srv" | sed -n 's/.*OpenSSL\/\([^ ]*\).*/\1/p')"
      if [ -n "$ssl_tok" ] && printf '%s' "$ssl_lib" | grep -q "$ssl_tok"; then
        ok "Server banner OpenSSL token (${ssl_tok}) matches the linked OpenSSL lib"
      else
        no "Server banner OpenSSL token (${ssl_tok}) != linked lib (${ssl_lib})"
      fi
    else
      skp "in-container binary + mod_ssl checks (needs docker)"
    fi

    # 4) Behavioural proof: a STATIC file carries the Apache Server banner but NO
    #    X-Powered-By (because it isn't served by PHP). A naive fake can't do this.
    local css_hdr css_srv css_xpb
    css_hdr="$(curl -fsSI "http://${LAB_HOST}:${port}/assets/style.css" 2>/dev/null || true)"
    css_srv="$(hdr "$css_hdr" 'Server')"
    css_xpb="$(hdr "$css_hdr" 'X-Powered-By')"
    if [ -n "$css_srv" ] && [ -z "$css_xpb" ]; then
      ok "static .css has the Apache Server banner but no X-Powered-By — genuine mod_php behaviour"
    else
      no "static-file header behaviour inconsistent with real Apache/mod_php (Server='${css_srv}' XPB='${css_xpb}')"
    fi

    # 5) Error page (404) still leaks the full token (ServerTokens Full, not a PHP trick).
    local e404_srv
    e404_srv="$(hdr "$(curl -fsSI "http://${LAB_HOST}:${port}/this-path-does-not-exist-404" 2>/dev/null || true)" 'Server')"
    if printf '%s' "$e404_srv" | grep -qi 'PHP/'; then
      ok "Apache's own 404 page leaks the PHP token too (pure Apache config, no PHP involved)"
    else
      no "404 Server banner missing PHP token (got '${e404_srv}')"
    fi
  done

  echo
  echo "================================================================"
  printf 'RESULT: %d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
  if [ "$fail" -eq 0 ] && [ "$pass" -gt 0 ]; then
    echo "=> Fingerprint is REAL: headers come from the live Apache/PHP/OpenSSL runtime, not faked."
    return 0
  else
    echo "=> Review the FAIL lines above."
    return 1
  fi
}

case "${1:-behavior}" in
  behavior|profile|"") do_behavior ;;
  verify)              do_verify ;;
  -h|--help)           sed -n '2,20p' "$0"; exit 0 ;;
  *) echo "unknown mode: $1 (use: behavior | verify)" >&2; exit 2 ;;
esac
