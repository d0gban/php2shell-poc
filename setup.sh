#!/usr/bin/env bash
# =============================================================================
# PHP2Shell lab — one-command setup.
# Builds and launches the 3-version PHP matrix, waits until each app answers,
# then prints an info panel with ports, PHP states, URLs and live verdicts.
#
#   bash setup.sh            # build + start (default: --tuned config profile)
#   bash setup.sh --tuned    # apply config/php2shell-tune.ini (deliberately weakened)
#   bash setup.sh --stock    # run on the stock php.ini-production baseline instead
#   bash setup.sh --down     # stop and remove the lab
#   bash setup.sh --help     # usage
#
# The config profile sets which .ini is mounted into every container's conf.d.
# Compare the two: /assess.php's "Current config" column changes between them.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; CYN=$'\033[36m'; BLD=$'\033[1m'; RST=$'\033[0m'

say()  { printf '%s\n' "$*"; }
ok()   { printf '%s[ OK ]%s %s\n'   "$GRN" "$RST" "$*"; }
warn() { printf '%s[WARN]%s %s\n'   "$YEL" "$RST" "$*"; }
err()  { printf '%s[FAIL]%s %s\n'   "$RED" "$RST" "$*"; }

# --- resolve a working `docker compose` (v2) or `docker-compose` (v1) ----------
DC=""
pick_compose() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    DC="docker compose"
  elif command -v docker-compose >/dev/null 2>&1; then
    DC="docker-compose"
  fi
}

require_docker() {
  pick_compose
  if [ -z "$DC" ]; then
    err "Docker (with Compose v2) was not found on PATH."
    cat <<'HELP'

  This lab needs Docker. Install options:

  Windows / macOS : Docker Desktop  -> https://www.docker.com/products/docker-desktop/
      (Windows also needs WSL2; after install, reboot and relaunch Git Bash.)
      winget install -e --id Docker.DockerDesktop

  Linux           : Docker Engine   -> https://docs.docker.com/engine/install/
      curl -fsSL https://get.docker.com | sh

  Verify, then re-run this script:
      docker compose version
      bash setup.sh
HELP
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    err "Docker is installed but the daemon is not running. Start Docker Desktop / dockerd and retry."
    exit 1
  fi
  ok "Using: $DC"
}

# --- argument parsing ---------------------------------------------------------
# Config profile: which .ini docker-compose mounts into each container's conf.d.
#   tuned (default) -> ./config/php2shell-tune.ini   (deliberately weakened)
#   stock           -> ./config/php2shell-stock.ini  (no-op; php.ini-production baseline)
PROFILE="tuned"
DO_DOWN=0
usage() {
  cat <<'USAGE'
PHP2Shell lab — setup

  bash setup.sh            build + start (default: --tuned config profile)
  bash setup.sh --tuned    apply config/php2shell-tune.ini (deliberately weakened)
  bash setup.sh --stock    run on the stock php.ini-production baseline instead
  bash setup.sh --down     stop and remove the lab
  bash setup.sh --help     this help

The config profile sets which .ini is mounted into each container's conf.d.
Compare the two: /assess.php's "Current config" column changes between them.
USAGE
  exit "${1:-0}"
}
for arg in "$@"; do
  case "$arg" in
    --down)          DO_DOWN=1 ;;
    --stock)         PROFILE="stock" ;;
    --tuned|--tune)  PROFILE="tuned" ;;
    -h|--help)       usage 0 ;;
    *) err "Unknown option: $arg"; usage 1 ;;
  esac
done

case "$PROFILE" in
  stock) export PHP_TUNE_INI="./config/php2shell-stock.ini" ;;
  *)     export PHP_TUNE_INI="./config/php2shell-tune.ini" ;;
esac

# --- teardown -----------------------------------------------------------------
if [ "$DO_DOWN" = "1" ]; then
  pick_compose; [ -z "$DC" ] && { err "docker compose not found"; exit 1; }
  $DC down
  ok "Lab stopped."
  exit 0
fi

# --- ports/roles (kept in sync with docker-compose.yml) -----------------------
PORTS=(8080 8081 8082)
ROLES=("EOL (end-of-life)" "OUTDATED" "PATCHED")
EXPECT=("VULNERABLE" "VULNERABLE" "PATCHED")

# --- resolve the host to probe / print, honouring LAB_BIND from .env ----------
# (compose publishes on LAB_BIND; a non-loopback bind means localhost won't answer.)
LAB_BIND="${LAB_BIND:-$(sed -n 's/^LAB_BIND=//p' .env 2>/dev/null | tail -1)}"
LAB_BIND="${LAB_BIND:-127.0.0.1}"
case "$LAB_BIND" in
  ""|0.0.0.0) HOST=127.0.0.1 ;;   # bound to all ifaces -> loopback works locally
  *)          HOST="$LAB_BIND" ;; # bound to a specific IP -> probe that IP
esac

printf '\n%s== PHP2Shell lab — CVE-2026-109618 / CVE-2026-109619 ==%s\n\n' "$BLD" "$RST"
require_docker

# --- clear any previous lab instances for a clean slate -----------------------
# Every run starts fresh: stop and remove the lab's containers (and orphans from a
# renamed/removed service) so no stale instance keeps running on a port or serves
# an outdated image. Logs live in host bind-mounts, so they survive this teardown.
say ""
say "${CYN}Clearing previous lab instances...${RST}"
$DC down --remove-orphans >/dev/null 2>&1 || true
ok "Previous containers cleared."

say ""
if [ "$PROFILE" = "stock" ]; then
  ok "Config profile: ${BLD}stock${RST} (php.ini-production COMPARISON baseline — $PHP_TUNE_INI). Not the exploit profile; use --tuned for the PoC repro."
else
  warn "Config profile: ${BLD}tuned${RST} (deliberately weakened — $PHP_TUNE_INI). This is the PHP2Shell PoC repro profile (matches its preconditions + single-worker prefork)."
fi
say "${CYN}Building and starting 3 containers (first run pulls PHP images)...${RST}"
bash scan/sync-webapp.sh                        # generate webapp-{eol,outdated,patched}/ from ./webapp
mkdir -p logs/eol logs/outdated logs/patched   # host mount dirs for raw HTTP capture
$DC up --build -d

# --- wait until each app answers ----------------------------------------------
say ""
say "Waiting for the web apps to come up..."
for idx in 0 1 2; do
  port="${PORTS[$idx]}"
  for _ in $(seq 1 40); do
    if curl -fsS --max-time 2 "http://${HOST}:${port}/assess.php?format=json" >/dev/null 2>&1; then
      ok "port ${port} ready (${ROLES[$idx]})"
      break
    fi
    sleep 1
  done
done

# --- info panel ---------------------------------------------------------------
line() { printf '  +%s+\n' "---------------------------------------------------------------------------"; }
say ""
printf '%s  PHP2Shell lab is up — 3 web apps, 3 PHP states%s\n' "$BLD" "$RST"
line
printf '  | %-22s | %-5s | %-28s | %-9s |\n' "ROLE" "PORT" "URL" "EXPECT"
line
for idx in 0 1 2; do
  printf '  | %-22s | %-5s | %-28s | %-9s |\n' \
    "${ROLES[$idx]}" "${PORTS[$idx]}" "http://${HOST}:${PORTS[$idx]}" "${EXPECT[$idx]}"
done
line

# --- live verdicts from the scanner ------------------------------------------
say ""
say "${CYN}Live verdicts:${RST}"
if [ -f scan/check.sh ]; then LAB_HOST="$HOST" bash scan/check.sh || true; fi

cat <<INFO

  Try it:
    - Landing page ....... http://${HOST}:8080  (and :8081, :8082)
    - Self-assessment .... http://${HOST}:8080/assess.php
    - Machine-readable ... http://${HOST}:8080/assess.php?format=json
    - Patched baseline ... http://${HOST}:8082   (compare fingerprint vs the vulnerable hosts)

  Stop the lab:
    bash setup.sh --down

INFO
ok "Done."
