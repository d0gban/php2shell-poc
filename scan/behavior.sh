#!/usr/bin/env bash
# =============================================================================
# behavior.sh — per-PHP-version OBSERVABLE behaviour profiler.
#
# Characterises how each lab host behaves at the HTTP layer so you can build
# version-aware WAF/IDS rules and spot version-specific detection differences.
# It sends only ordinary, benign requests (a GET, a normal small upload, an
# empty POST, a 404) and records what comes back. It carries NO exploit and no
# attack primitive — it profiles the server, it does not attack it.
#
#   bash scan/behavior.sh
#   LAB_HOST=192.168.56.10 bash scan/behavior.sh
# =============================================================================
set -u
LAB_HOST="${LAB_HOST:-127.0.0.1}"
PORTS=(8080 8081 8082)
ROLES=(EOL OUTDATED PATCHED)
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
printf 'benign profiler payload\n' > "$TMP/u.bin"

hdr(){ printf '%s' "$1" | tr -d '\r' | sed -n "s/^$2: //Ip" | head -1; }

# status + total_time for a request; extra curl args after the url
probe(){ curl -s -o /dev/null -w '%{http_code} %{time_total}s' --max-time 10 "$@" 2>/dev/null || printf 'no-response'; }

echo "PHP2Shell lab — per-version HTTP behaviour profile"
echo "Scanned: $(date -u '+%Y-%m-%d %H:%M:%SZ')   Host: ${LAB_HOST}"

for i in 0 1 2; do
  port="${PORTS[$i]}"; role="${ROLES[$i]}"
  base="http://${LAB_HOST}:${port}"
  echo
  echo "== ${role} (:${port}) ==============================================="

  root_h="$(curl -fsSI "${base}/" 2>/dev/null || true)"
  if [ -z "$root_h" ]; then echo "    unreachable (is the lab up?)"; continue; fi

  php="$(curl -fsS "${base}/assess.php?format=json" 2>/dev/null | sed -n 's/.*"php_version": *"\([^"]*\)".*/\1/p' | head -1)"
  echo "    PHP version      : ${php:-?}"
  echo "    Server banner    : $(hdr "$root_h" 'Server')"
  echo "    X-Powered-By     : $(hdr "$root_h" 'X-Powered-By')"

  # PHPSESSID cookie shape (CVE-2026-109619 keys on abnormal session cookies)
  setc="$(curl -fsSI "${base}/" -c "$TMP/c.txt" 2>/dev/null; hdr "$(curl -fsSI "${base}/" 2>/dev/null)" 'Set-Cookie')"
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
    whatever a tuned WAF rule does to the waf-test.sh "sig" probe, it must leave
    these ordinary requests untouched.
  - Compare the two vulnerable hosts against the patched one (:8082): a good rule
    set behaves the same on all three (it targets the attack shape, not "any PHP").
NOTE
