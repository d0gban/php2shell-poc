#!/usr/bin/env bash
# fetch-stock-ini.sh — write the BYTE-EXACT official php.ini-production from the
# pinned lab image into config/php2shell-stock.ini.
#
# The authoring environment had no Docker, so config/php2shell-stock.ini ships as
# a faithful production-mirror of the lab-audited directives. Run this where Docker
# is available to replace it with the literal upstream file (all directives/comments).
#
#   bash config/fetch-stock-ini.sh            # uses OLD_TAG from .env (8.4.26-apache)
#   bash config/fetch-stock-ini.sh 8.4.27-apache
set -euo pipefail
cd "$(dirname "$0")/.."

TAG="${1:-}"
if [ -z "$TAG" ]; then
  TAG="$(sed -n 's/^OLD_TAG=//p' .env 2>/dev/null | tail -1)"
  TAG="${TAG:-8.4.26-apache}"
fi
OUT="config/php2shell-stock.ini"

command -v docker >/dev/null 2>&1 || { echo "docker not found on PATH" >&2; exit 1; }

echo "Pulling php.ini-production from php:${TAG} ..."
header="; php2shell-stock.ini — EXACT php.ini-production from php:${TAG} (fetched $(date -u '+%Y-%m-%dT%H:%M:%SZ'))
; Regenerate with: bash config/fetch-stock-ini.sh ${TAG}
"
{
  printf '%s\n' "$header"
  docker run --rm "php:${TAG}" cat /usr/local/etc/php/php.ini-production
} > "$OUT"

echo "Wrote $(wc -l < "$OUT") lines to ${OUT}"
echo "Sanity check (must be production values):"
grep -E '^\s*(memory_limit|post_max_size|display_errors)\s*=' "$OUT" || true
