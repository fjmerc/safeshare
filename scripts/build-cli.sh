#!/bin/sh
# Builds safeshare-cli for every platform a release ships, reproducibly:
# the same source and Go version give byte-identical binaries on any
# machine. Releases attach the binaries and their SHA-256 sums
# (safeshare-cli.sha256). To check a release's binaries, check out its tag
# (git checkout vX.Y.Z), then:
#
#   scripts/build-cli.sh --check safeshare-cli.sha256
#
# Builds run in the official golang image for the Go version in go.mod's
# toolchain line (Docker needed), or with --local-go using the go on PATH
# (same version required). Without --check, binaries are written to OUTDIR
# (default dist/) with their sums in OUTDIR/safeshare-cli.sha256.
# Set TMPDIR if the Docker daemon cannot see /tmp.
# Exits 1 if any binary differs from the sums, 2 if it couldn't build.
set -eu

usage="usage: $0 [--local-go] [--check SUMS | OUTDIR]"
local_go=0
check=""
while [ $# -gt 0 ]; do
	case "$1" in
	--local-go) local_go=1; shift ;;
	--check) check=${2:?$usage}; shift 2 ;;
	-*) echo "$usage" >&2; exit 2 ;;
	*) break ;;
	esac
done

root=$(cd "$(dirname "$0")/.." && pwd)
gover=$(sed -n 's/^toolchain go//p' "$root/go.mod")
if [ -z "$gover" ]; then
	echo "no toolchain line in go.mod; can't tell which Go version to build with" >&2
	exit 2
fi
if [ "$local_go" = 1 ] && [ "$(GOTOOLCHAIN=local go env GOVERSION)" != "go$gover" ]; then
	echo "--local-go needs Go $gover (go.mod's toolchain), found $(GOTOOLCHAIN=local go env GOVERSION)" >&2
	exit 2
fi

if [ -n "$check" ]; then
	out=$(mktemp -d "${TMPDIR:-/tmp}/build-cli.XXXXXX")
	trap 'rm -rf "$out"' EXIT
else
	out=${1:-dist}
	mkdir -p "$out"
	out=$(cd "$out" && pwd)
fi

# GOOS/GOARCH pairs; each binary is safeshare-cli-GOOS-GOARCH(.exe). Same
# flags as the Dockerfile's server build.
targets="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"

if [ "$local_go" = 1 ]; then
	for t in $targets; do
		os=${t%/*} arch=${t#*/} ext=""
		[ "$os" = windows ] && ext=.exe
		(cd "$root/sdk/go" && CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" GOTOOLCHAIN=local GOFLAGS=-mod=readonly \
			go build -trimpath -buildvcs=false -ldflags="-w -s" -o "$out/safeshare-cli-$os-$arch$ext" ./cmd/safeshare-cli)
	done
else
	docker pull -q "golang:$gover" >/dev/null
	docker run --rm -v "$root":/src:ro -v "$out":/out -w /src/sdk/go \
		-e CGO_ENABLED=0 -e GOTOOLCHAIN=local -e GOFLAGS=-mod=readonly -e TARGETS="$targets" \
		--user "$(id -u):$(id -g)" -e HOME=/tmp -e GOCACHE=/tmp/cache -e GOPATH=/tmp/go \
		"golang:$gover" sh -c 'for t in $TARGETS; do os=${t%/*}; arch=${t#*/}; ext=""; [ "$os" = windows ] && ext=.exe;
			GOOS=$os GOARCH=$arch go build -trimpath -buildvcs=false -ldflags="-w -s" -o "/out/safeshare-cli-$os-$arch$ext" ./cmd/safeshare-cli || exit 1; done'
fi

if command -v sha256sum >/dev/null 2>&1; then
	sums() { (cd "$out" && sha256sum safeshare-cli-*); }
else
	sums() { (cd "$out" && shasum -a 256 safeshare-cli-*); } # macOS
fi

if [ -z "$check" ]; then
	sums >"$out/safeshare-cli.sha256"
	cat "$out/safeshare-cli.sha256"
	exit 0
fi

failed=0
sums >"$out/built.sha256"
while read -r want name; do
	got=$(grep "  $name\$" "$out/built.sha256" | cut -d' ' -f1)
	if [ -z "$got" ]; then
		echo "MISSING  $name (not built here)"
		failed=1
	elif [ "$got" = "$want" ]; then
		echo "match    $name"
	else
		echo "DIFFERS  $name"
		failed=1
	fi
done <"$check"
if [ "$failed" = 0 ]; then
	echo "OK: every binary in $check rebuilds byte-for-byte from this checkout."
fi
exit "$failed"
