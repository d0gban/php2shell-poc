#!/usr/bin/env bash
# =============================================================================
# verify.sh — prove the lab's server fingerprint is REAL, not spoofed.
#
# Checks, per container, that the Server / X-Powered-By headers are produced by
# the genuine Apache + PHP + OpenSSL runtime and match the live binaries — not
# faked by a header() call in the web app.
#
#   bash scan/verify.sh                 # uses 127.0.0.1 and the default names
#   LAB_HOST=192.168.56.10 bash scan/verify.sh
# =============================================================================
set -u
LAB_HOST="${LAB_HOST:-127.0.0.1}"
PORTS=(8080 8081 8082)
NAMES=(php2shell-eol php2shell-outdated php2shell-patched)

pass=0; fail=0; skip=0
ok(){   printf '    \033[32m[PASS]\033[0m %s\n' "$*"; pass=$((pass+1)); }
no(){   printf '    \033[31m[FAIL]\033[0m %s\n' "$*"; fail=$((fail+1)); }
skp(){  printf '    \033[33m[SKIP]\033[0m %s\n' "$*"; skip=$((skip+1)); }

have_docker=0
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && have_docker=1
[ "$have_docker" -eq 0 ] && echo "note: docker not available — in-container checks will be skipped (HTTP checks still run)."

hdr_val(){ printf '%s' "$1" | tr -d '\r' | sed -n "s/^$2: //Ip" | head -1; }

for i in 0 1 2; do
  port="${PORTS[$i]}"; name="${NAMES[$i]}"
  echo
  echo "== ${name} (:${port}) =================================================="

  # --- live HTTP headers -----------------------------------------------------
  root_hdr="$(curl -fsSI "http://${LAB_HOST}:${port}/" 2>/dev/null || true)"
  if [ -z "$root_hdr" ]; then no "host unreachable on :${port} (is the lab up?)"; continue; fi
  srv="$(hdr_val "$root_hdr" 'Server')"
  xpb="$(hdr_val "$root_hdr" 'X-Powered-By')"
  echo "    Server:       ${srv}"
  echo "    X-Powered-By: ${xpb}"

  # mod_php's own reported version (evaluated by the web SAPI serving requests)
  modphp_ver="$(curl -fsS "http://${LAB_HOST}:${port}/assess.php?format=json" 2>/dev/null \
               | sed -n 's/.*"php_version": *"\([^"]*\)".*/\1/p' | head -1)"
  # actual PHP version running + the SAPI serving requests (HTTP-only; no docker needed)
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
    # the OpenSSL token in the Server banner should match the linked lib (e.g. 1.1.1w / 3.x)
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
  css_hdr="$(curl -fsSI "http://${LAB_HOST}:${port}/assets/style.css" 2>/dev/null || true)"
  css_srv="$(hdr_val "$css_hdr" 'Server')"
  css_xpb="$(hdr_val "$css_hdr" 'X-Powered-By')"
  if [ -n "$css_srv" ] && [ -z "$css_xpb" ]; then
    ok "static .css has the Apache Server banner but no X-Powered-By — genuine mod_php behaviour"
  else
    no "static-file header behaviour inconsistent with real Apache/mod_php (Server='${css_srv}' XPB='${css_xpb}')"
  fi

  # 5) Error page (404) still leaks the full token (ServerTokens Full, not a PHP trick).
  e404_srv="$(hdr_val "$(curl -fsSI "http://${LAB_HOST}:${port}/this-path-does-not-exist-404" 2>/dev/null || true)" 'Server')"
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
  exit 0
else
  echo "=> Review the FAIL lines above."
  exit 1
fi
