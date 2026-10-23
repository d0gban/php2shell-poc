#!/usr/bin/env bash
# =============================================================================
# sync-webapp.sh — generate the three per-target webapp trees from one source.
#
# WHY THIS EXISTS
#   docker-compose mounts a SEPARATE tree into each host so you can perturb one
#   node (e.g. blank index.php on the :8081 repro) without touching the others.
#   But keeping three full copies in git triples the code you have to read and
#   maintain. So git tracks ONE source — ./webapp — and this script derives the
#   three mounted trees from it. The generated trees are .gitignore'd build
#   artifacts, not source. Edit ./webapp; never edit webapp-{eol,outdated,patched}
#   by hand (this script overwrites them).
#
#   setup.sh and `make up` run this before `docker compose up`, so the mount
#   targets always exist and match the source.
#
# PER-TARGET OVERLAYS
#   The three trees are IDENTICAL by design — "only the PHP runtime differs".
#   There is currently no per-target divergence. If you ever need one (e.g. a
#   different payload on a single host), add it in the overlay section below,
#   explicitly, so the difference is visible in one place.
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")/.."           # repo root
SRC="webapp"
TARGETS="eol outdated patched"

[ -d "$SRC" ] || { echo "sync-webapp: source ./$SRC missing" >&2; exit 1; }

for t in $TARGETS; do
  dst="webapp-$t"
  rm -rf "$dst"
  cp -r "$SRC" "$dst"
done

# --- per-target overlays -----------------------------------------------------
# (none — all three trees are identical. Add per-target tweaks here if ever needed.)

echo "sync-webapp: generated webapp-{$(echo $TARGETS | tr ' ' ',')} from ./$SRC (identical trees)"
