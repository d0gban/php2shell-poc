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
#   The three trees start identical ("only the PHP runtime differs"). The sole
#   deliberate divergence is applied below: the OUTDATED host (:8081) is the
#   PHP2Shell exploit repro target, and the extra app code perturbs the heap, so
#   its index.php is blanked to a minimal page for the cleanest repro. The EOL
#   (:8080) and patched (:8082) hosts keep the full landing page as the
#   comparison matrix. Add further per-target overlays here, explicitly.
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
# :8081 outdated = PHP2Shell repro target -> minimal index.php (heap-clean repro).
printf '<?php echo "OK";' > webapp-outdated/index.php

echo "sync-webapp: generated webapp-{$(echo $TARGETS | tr ' ' ',')} from ./$SRC"
echo "  eol/patched index.php: full landing page | outdated index.php: blanked (repro)"
