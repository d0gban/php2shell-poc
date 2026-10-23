#!/usr/bin/env bash
# =============================================================================
# offsec-check.sh — does each lab host match the OffSec / 9bie PHP2Shell PoC
# target profile? Prints a 4-column table: the required value vs. :8080 / :8081 /
# :8082, with [ok]/[NO] per cell.
#
# OffSec PoC target requirements (PHP 8.4.26 / mod_php, prefork):
#   PHP 8.4.26 · SAPI apache2handler · display_errors=1 · memory_limit=8M ·
#   max_input_vars=1000 · session.use_cookies=1 · session.use_strict_mode=0 ·
#   session.upload_progress.enabled=1 · single-worker prefork (MaxRequestWorkers 1)
#
# Only :8081 (8.4.26, outdated) is the intended FULL match. :8080 is 8.0.30 (EOL)
# and :8082 is 8.4.27 (patched), so they differ on PHP version by design — the
# other columns are there to compare config across the matrix.
#
# Data sources (no new app endpoint needed):
#   - PHP version + WEB SAPI : HTTP  /assess.php?format=json  (the real web SAPI;
#                              `docker exec php -r` would report the CLI SAPI).
#   - php.ini directives     : docker exec php -r ini_get(...)  (authoritative,
#                              incl. max_input_vars). Falls back to the values
#                              /assess.php already exposes when docker is absent.
#   - MPM + MaxRequestWorkers : docker exec apache2ctl -M / the mounted conf.
#
#   bash scan/offsec-check.sh
#   LAB_HOST=192.168.56.10 bash scan/offsec-check.sh
# =============================================================================
set -u
LAB_HOST="${LAB_HOST:-127.0.0.1}"
PORTS=(8080 8081 8082)
CONTS=(php2shell-eol php2shell-outdated php2shell-patched)
COLS=("8080 eol" "8081 outdated" "8082 patched")

have_docker=0
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && have_docker=1

# per-field actual values, indexed by host 0..2
VER=();  SAPI=(); DERR=(); MEM=(); MIV=(); COOK=(); STRICT=(); UPROG=(); MPM=(); MRW=()

# pull one JSON field (flat string value) from assess.php output
jval(){ printf '%s' "$1" | grep -oE "\"$2\"[ ]*:[ ]*\"[^\"]*\"" | head -1 | sed -E 's/.*"([^"]*)"$/\1/'; }
# pull a config_audit "current" value for a given directive key (pretty JSON)
jcurrent(){ printf '%s' "$1" | grep -A3 "\"key\": \"$2\"" | grep -m1 '"current"' | sed -E 's/.*"current": *"([^"]*)".*/\1/'; }

fetch(){
  local i="$1" port="${PORTS[$i]}" c="${CONTS[$i]}" json raw mpm mrw
  json="$(curl -fsS "http://${LAB_HOST}:${port}/assess.php?format=json" 2>/dev/null || true)"

  VER[$i]="$(jval "$json" php_version)"
  SAPI[$i]="$(jval "$json" sapi)"

  if [ "$have_docker" -eq 1 ]; then
    raw="$(docker exec "$c" php -r '$k=["display_errors","memory_limit","max_input_vars","session.use_cookies","session.use_strict_mode","session.upload_progress.enabled"];foreach($k as $x){echo $x."=".ini_get($x)."\n";}' 2>/dev/null)"
    DERR[$i]="$(printf '%s\n' "$raw"   | sed -n 's/^display_errors=//p')"
    MEM[$i]="$(printf '%s\n' "$raw"    | sed -n 's/^memory_limit=//p')"
    MIV[$i]="$(printf '%s\n' "$raw"    | sed -n 's/^max_input_vars=//p')"
    COOK[$i]="$(printf '%s\n' "$raw"   | sed -n 's/^session.use_cookies=//p')"
    STRICT[$i]="$(printf '%s\n' "$raw" | sed -n 's/^session.use_strict_mode=//p')"
    UPROG[$i]="$(printf '%s\n' "$raw"  | sed -n 's/^session.upload_progress.enabled=//p')"
    mpm="$(docker exec "$c" apache2ctl -M 2>/dev/null | grep -oiE 'mpm_[a-z]+' | head -1)"
    MPM[$i]="${mpm#mpm_}"
    mrw="$(docker exec "$c" sh -c "grep -rhiE '^[[:space:]]*MaxRequestWorkers' /etc/apache2 2>/dev/null | tail -1 | awk '{print \$NF}'")"
    MRW[$i]="$mrw"
  else
    # docker-less fallback: use what /assess.php already exposes
    DERR[$i]="$(jcurrent "$json" display_errors)"
    MEM[$i]="$(jcurrent "$json" memory_limit)"
    COOK[$i]="$(jcurrent "$json" session.use_cookies)"
    STRICT[$i]="$(jcurrent "$json" session.use_strict_mode)"
    UPROG[$i]="$(jcurrent "$json" session.upload_progress.enabled)"
    MIV[$i]=""; MPM[$i]=""; MRW[$i]=""     # not available over HTTP
  fi
}

# normalise an on/off-ish value to 1 or 0
nbool(){ case "$(printf '%s' "$1" | tr 'A-Z' 'a-z')" in 1|on|"on (1)"|true) echo 1 ;; *) echo 0 ;; esac; }

# format one cell: "<value> [ok|NO]" (or "needs-docker" / "unreachable")
cell(){ # $1=actual $2=required $3=cmp(bool|mem|str|mpm) $4=dockeronly(1=needs docker)
  local a="$1" req="$2" cmp="$3" donly="${4:-0}" ok=0 disp
  if [ -z "$a" ]; then
    { [ "$donly" = 1 ] && [ "$have_docker" -eq 0 ]; } && { printf '%-17s' "needs-docker"; return; }
    printf '%-17s' "unreachable"; return
  fi
  case "$cmp" in
    bool) [ "$(nbool "$a")" = "$req" ] && ok=1 ;;
    mem)  [ "$(printf '%s' "$a" | tr -d ' ' | tr 'a-z' 'A-Z')" = "$req" ] && ok=1 ;;
    str)  [ "$a" = "$req" ] && ok=1 ;;
    mpm)  printf '%s' "$a" | grep -qi prefork && ok=1 ;;
  esac
  [ "$ok" = 1 ] && disp="$a [ok]" || disp="$a [NO]"
  printf '%-17s' "$disp"
}

row(){ # $1=label  $2..4=preformatted cells
  printf '  %-30s %s %s %s\n' "$1" "$2" "$3" "$4"
}

echo "PHP2Shell — OffSec target-profile check — $(date -u '+%Y-%m-%d %H:%M:%SZ')"
[ "$have_docker" -eq 1 ] && echo "docker: available (php.ini/MPM read from containers)" \
                         || echo "docker: NOT available — max_input_vars/MPM/workers need it; run where docker works"
echo

for i in 0 1 2; do fetch "$i"; done

printf '  %-30s %-17s %-17s %-17s\n' "OffSec required" "${COLS[0]}" "${COLS[1]}" "${COLS[2]}"
printf '  %s\n' "---------------------------------------------------------------------------------------------"
row "PHP == 8.4.26"                 "$(cell "${VER[0]}" 8.4.26 str)"          "$(cell "${VER[1]}" 8.4.26 str)"          "$(cell "${VER[2]}" 8.4.26 str)"
row "SAPI == apache2handler"        "$(cell "${SAPI[0]}" apache2handler str)" "$(cell "${SAPI[1]}" apache2handler str)" "$(cell "${SAPI[2]}" apache2handler str)"
row "display_errors == 1"           "$(cell "${DERR[0]}" 1 bool)"             "$(cell "${DERR[1]}" 1 bool)"             "$(cell "${DERR[2]}" 1 bool)"
row "memory_limit == 8M"            "$(cell "${MEM[0]}" 8M mem)"              "$(cell "${MEM[1]}" 8M mem)"              "$(cell "${MEM[2]}" 8M mem)"
row "max_input_vars == 1000"        "$(cell "${MIV[0]}" 1000 str 1)"         "$(cell "${MIV[1]}" 1000 str 1)"         "$(cell "${MIV[2]}" 1000 str 1)"
row "session.use_cookies == 1"      "$(cell "${COOK[0]}" 1 bool)"            "$(cell "${COOK[1]}" 1 bool)"            "$(cell "${COOK[2]}" 1 bool)"
row "session.use_strict_mode == 0"  "$(cell "${STRICT[0]}" 0 bool)"          "$(cell "${STRICT[1]}" 0 bool)"          "$(cell "${STRICT[2]}" 0 bool)"
row "upload_progress.enabled == 1"  "$(cell "${UPROG[0]}" 1 bool)"           "$(cell "${UPROG[1]}" 1 bool)"           "$(cell "${UPROG[2]}" 1 bool)"
row "MPM == prefork"                "$(cell "${MPM[0]}" prefork mpm 1)"       "$(cell "${MPM[1]}" prefork mpm 1)"       "$(cell "${MPM[2]}" prefork mpm 1)"
row "MaxRequestWorkers == 1"        "$(cell "${MRW[0]}" 1 str 1)"            "$(cell "${MRW[1]}" 1 str 1)"            "$(cell "${MRW[2]}" 1 str 1)"

cat <<'NOTE'

[ok] = matches the OffSec PoC requirement · [NO] = differs · needs-docker/unreachable = not read.
Only :8081 (8.4.26) is meant to match EVERY row — that is the exploit target. :8080 (8.0.30 EOL)
and :8082 (8.4.27 patched) differ on PHP version by design; the patched host is NOT exploitable.
display_errors=1 is a HARD requirement of the current public PoC (no RCE path published for =0).
NOTE
