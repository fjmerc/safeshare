#!/bin/bash

# SafeShare Test Runner Script
# Runs the unit test suite with coverage inside a Docker container, the same
# way CI's `test` job does (.github/workflows/build-and-push.yml).
# Note: Requires Docker (Go is run inside the container).
#
# Packages: ./internal/... except internal/repository/postgres and
# internal/storage/s3, which need live services (see scripts/test-postgres.sh
# and scripts/test-minio.sh).
#
# Environment overrides:
#   GO_IMAGE   Docker image to run (default: golang:<toolchain from go.mod>)
#   THRESHOLD  Minimum total coverage in percent (default: 60)

set -euo pipefail

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== SafeShare Test Suite (Docker) ===${NC}"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed${NC}"
    echo "This script runs tests inside a Docker container."
    echo "Please install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker daemon is running
if ! docker info &> /dev/null; then
    echo -e "${RED}Error: Docker daemon is not running${NC}"
    echo "Please start Docker and try again."
    exit 1
fi

# Get absolute path to project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# go.mod's toolchain line is the single source of truth for the Go version
# (CI's setup-go reads it too).
GO_VERSION="$(awk '/^toolchain go/ { sub(/^go/, "", $2); print $2 }' "$PROJECT_ROOT/go.mod")"
if [ -z "$GO_VERSION" ]; then
    echo -e "${RED}Error: no 'toolchain goX.Y.Z' line in go.mod${NC}"
    exit 1
fi
GO_IMAGE="${GO_IMAGE:-golang:$GO_VERSION}"
THRESHOLD="${THRESHOLD:-60}"

# Clean previous coverage files
echo -e "${YELLOW}Cleaning previous coverage data...${NC}"
rm -f "$PROJECT_ROOT/coverage.out" "$PROJECT_ROOT/coverage.html"

echo -e "${YELLOW}Running tests with coverage analysis...${NC}"
echo -e "${YELLOW}(Running in ${GO_IMAGE}; module and build caches persist in the"
echo -e " safeshare-gomod and safeshare-gocache Docker volumes)${NC}"
echo ""

# One container runs the tests and writes both reports. Named volumes keep the
# module download and build caches between runs.
if ! docker run --rm \
    -v "$PROJECT_ROOT:/workspace" \
    -v safeshare-gomod:/go/pkg/mod \
    -v safeshare-gocache:/root/.cache/go-build \
    -w /workspace \
    -e GOFLAGS=-buildvcs=false \
    "$GO_IMAGE" \
    sh -c '
        set -e
        pkgs=$(go list ./internal/... | grep -v -E "(repository/postgres|storage/s3)")
        go test $pkgs -cover -coverprofile=coverage.out -covermode=atomic -timeout=30m
        echo ""
        go tool cover -func=coverage.out | tail -20
        go tool cover -html=coverage.out -o coverage.html
    '; then
    echo -e "${RED}Tests failed!${NC}"
    exit 1
fi

echo -e "${GREEN}HTML coverage report generated: coverage.html${NC}"

# The total line looks like: "total:  (statements)  66.8%"
COVERAGE="$(docker run --rm \
    -v "$PROJECT_ROOT:/workspace" \
    -v safeshare-gomod:/go/pkg/mod \
    -v safeshare-gocache:/root/.cache/go-build \
    -w /workspace \
    -e GOFLAGS=-buildvcs=false \
    "$GO_IMAGE" \
    go tool cover -func=coverage.out | awk '/^total:/ { print $NF }')"
if [ -z "$COVERAGE" ]; then
    echo -e "${RED}Could not read total coverage from coverage.out${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}Total Coverage: ${COVERAGE}${NC}"

# Check coverage threshold (awk, so no dependency on bc)
if awk -v c="${COVERAGE%\%}" -v t="$THRESHOLD" 'BEGIN { exit !(c < t) }'; then
    echo -e "${RED}Coverage ${COVERAGE} is below the ${THRESHOLD}% threshold${NC}"
    exit 1
fi
echo -e "${GREEN}Coverage meets ${THRESHOLD}% threshold ✓${NC}"

echo ""
echo -e "${GREEN}=== Test run completed successfully ===${NC}"
