#!/bin/sh
# Rebuilds the server binaries from this checkout and checks they are
# byte-identical to the ones in a SafeShare Docker image, and that the image
# starts them the way the Dockerfile says. Check out the tag of
# the release first (git checkout vX.Y.Z), then:
#
#   scripts/verify-image.sh fjmerc/safeshare:1.17.0
#   scripts/verify-image.sh fjmerc/safeshare:1.17.0 linux/arm64
#
# Builds run in the official golang image for the Go version in go.mod
# (Docker needed), or with --local-go using the go on PATH (same version
# required). --sums FILE also writes the SHA-256 of each verified binary.
# Set TMPDIR if the Docker daemon cannot see /tmp.
# Exits 1 if any binary differs, 2 if it couldn't check.
set -eu

usage="usage: $0 [--local-go] [--sums FILE] IMAGE [PLATFORM...]"
local_go=0
sums=""
while [ $# -gt 0 ]; do
	case "$1" in
	--local-go) local_go=1; shift ;;
	--sums) sums=${2:?$usage}; shift 2 ;;
	-*) echo "$usage" >&2; exit 2 ;;
	*) break ;;
	esac
done
image=${1:?$usage}
shift
platforms=${*:-linux/amd64 linux/arm64}

root=$(cd "$(dirname "$0")/.." && pwd)
gover=$(sed -n 's/^toolchain go//p' "$root/go.mod")
if [ -z "$gover" ]; then
	echo "no toolchain line in go.mod; can't tell which Go version built the image" >&2
	exit 2
fi
if [ "$local_go" = 1 ] && [ "$(GOTOOLCHAIN=local go env GOVERSION)" != "go$gover" ]; then
	echo "--local-go needs Go $gover (go.mod's toolchain), found $(GOTOOLCHAIN=local go env GOVERSION)" >&2
	exit 2
fi
binaries="safeshare import-file migrate-encryption"
work=$(mktemp -d "${TMPDIR:-/tmp}/verify-image.XXXXXX")
trap 'rm -rf "$work"' EXIT
[ -z "$sums" ] || : >"$sums"

# Same flags as the Dockerfile.
build() { # arch outdir
	if [ "$local_go" = 1 ]; then
		for b in $binaries; do
			(cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH="$1" GOTOOLCHAIN=local \
				go build -a -trimpath -buildvcs=false -ldflags="-w -s" -o "$2/$b" "./cmd/$b")
		done
	else
		docker pull -q "golang:$gover" >/dev/null
		docker run --rm -v "$root":/src:ro -v "$2":/out -w /src \
			-e CGO_ENABLED=0 -e GOOS=linux -e GOARCH="$1" -e GOTOOLCHAIN=local \
			-e BINARIES="$binaries" --user "$(id -u):$(id -g)" -e HOME=/tmp -e GOCACHE=/tmp/cache -e GOPATH=/tmp/go \
			"golang:$gover" sh -c 'for b in $BINARIES; do go build -a -trimpath -buildvcs=false -ldflags="-w -s" -o "/out/$b" "./cmd/$b" || exit 1; done'
	fi
}

if command -v sha256sum >/dev/null 2>&1; then
	hash() { sha256sum "$1" | cut -d' ' -f1; }
else
	hash() { shasum -a 256 "$1" | cut -d' ' -f1; } # macOS
fi

# What the image runs, as the Dockerfile sets it. Checked too: genuine
# binaries don't help if the image starts something else. CI runs this script
# on every pull request, so it fails if the Dockerfile changes without this.
want_config='null ["./safeshare"] /app safeshare ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","PORT=8080","DB_PATH=/app/data/safeshare.db","UPLOAD_DIR=/app/uploads","MAX_FILE_SIZE=104857600","DEFAULT_EXPIRATION_HOURS=24","CLEANUP_INTERVAL_MINUTES=60","PUBLIC_URL="] ["CMD-SHELL","wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1"] null null'
config_format='{{json .Config.Entrypoint}} {{json .Config.Cmd}} {{.Config.WorkingDir}} {{.Config.User}} {{json .Config.Env}} {{json .Config.Healthcheck.Test}} {{json .Config.Shell}} {{json .Config.OnBuild}}'

failed=0
for plat in $platforms; do
	arch=${plat#linux/}
	mkdir -p "$work/$arch/image" "$work/$arch/source"
	# A local-only image can't be pulled; docker create then uses it as is.
	docker pull -q --platform "$plat" "$image" >/dev/null 2>&1 || true
	id=$(docker create --platform "$plat" "$image")
	img_id=$(docker inspect --format '{{.Image}}' "$id")
	got=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$img_id")
	if [ "$got" != "$plat" ]; then
		docker rm "$id" >/dev/null
		echo "$image is $got here, not $plat; pull it for $plat first" >&2
		exit 2
	fi
	config=$(docker image inspect --format "$config_format" "$img_id")
	if [ "$config" = "$want_config" ]; then
		echo "  identical  linux/$arch start command, user, working directory, environment and health check"
	else
		echo "  DIFFERENT  linux/$arch image settings:"
		echo "             image:      $config"
		echo "             Dockerfile: $want_config"
		failed=1
	fi
	for b in $binaries; do
		# -L: copy what a symlink points to, i.e. what actually runs; then
		# refuse anything that still isn't a plain file.
		docker cp -q -L "$id:/app/$b" "$work/$arch/image/$b"
		if [ ! -f "$work/$arch/image/$b" ] || [ -L "$work/$arch/image/$b" ]; then
			docker rm "$id" >/dev/null
			echo "linux/$arch /app/$b in the image is not a regular file" >&2
			exit 2
		fi
	done
	docker rm "$id" >/dev/null

	echo "Building linux/$arch from source with Go $gover..."
	build "$arch" "$work/$arch/source"

	for b in $binaries; do
		img=$(hash "$work/$arch/image/$b")
		src=$(hash "$work/$arch/source/$b")
		if [ -z "$img" ] || [ -z "$src" ]; then
			echo "could not hash linux/$arch $b" >&2
			exit 2
		fi
		if [ "$img" = "$src" ]; then
			echo "  identical  linux/$arch $b  $img"
			[ -z "$sums" ] || echo "$img  linux-$arch/$b" >>"$sums"
		else
			echo "  DIFFERENT  linux/$arch $b  image $img, source $src"
			failed=1
		fi
	done
done

if [ "$failed" = 1 ]; then
	echo "NOT REPRODUCED: the image doesn't match this checkout ($(git -C "$root" describe --tags --always --dirty 2>/dev/null || echo unknown))." >&2
	exit 1
fi
echo "REPRODUCED: the image's binaries and start settings match this checkout. (Its Alpine packages, such as CA certificates, are not checked.)"
