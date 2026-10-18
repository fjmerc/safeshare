#!/bin/sh
# Prints the SHA-256 of every web file the server embeds (internal/static/web),
# one "<hash>  <path>" line per file in sha256sum format, sorted by path.
#
# Each release publishes this list as web-assets.sha256. To check it yourself,
# run this script in a checkout of the release tag and compare; to check a
# running server against it, use `safeshare-cli verify <url>`.
#
#   scripts/web-asset-hashes.sh > web-assets.sha256
#   (cd internal/static/web && sha256sum -c ../../../web-assets.sha256)
set -eu

if command -v sha256sum >/dev/null 2>&1; then
	sum() { sha256sum "$1"; }
else
	sum() { shasum -a 256 "$1"; } # macOS
fi

cd "$(dirname "$0")/../internal/static/web"
# Like go:embed web/*, skip names starting with "." or "_" below the top level.
# Collected first: sh has no pipefail, and a failure must not print a short list.
list=$(find . \( -path './*/.*' -o -path './*/_*' \) -prune -o -type f -print | sed 's|^\./||' | LC_ALL=C sort)
case "$list" in
*index.html*) ;;
*) echo "web-asset-hashes.sh: no index.html under internal/static/web" >&2; exit 1 ;;
esac
printf '%s\n' "$list" | while IFS= read -r f; do
	sum "$f" || exit 1
done
