#!/bin/bash

# SafeShare Test Runner Script with Race Detection
# Detects data races in concurrent code inside a Docker container.
# Note: Requires Docker (Go is run inside the container).
#
# Usage:
#   ./scripts/run-tests-race.sh                    # CI's race set (see below)
#   ./scripts/run-tests-race.sh ./internal/config  # just these packages
#
# By default it runs the packages CI's `race` job covers
# (.github/workflows/build-and-push.yml): internal/handlers plus the core
# packages. CI splits handlers into four shards; run whole here, handlers
# takes 20-50 minutes under -race depending on the machine.
#
# internal/benchmarks is left out on purpose: its timing limits are tuned for
# normal runs, and TestLoad_CleanupWorkerWithManyExpiredFiles exceeds its
# 10s limit under -race.
#
# Environment overrides:
#   GO_IMAGE      Docker image to run (default: golang:<toolchain from go.mod>)
#   RACE_TIMEOUT  go test -timeout value (default: 90m)

set -euo pipefail

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== SafeShare Race Detection Test (Docker) ===${NC}"
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
RACE_TIMEOUT="${RACE_TIMEOUT:-90m}"

if [ "$#" -gt 0 ]; then
    PACKAGES=("$@")
else
    PACKAGES=(
        ./internal/handlers
        ./internal/middleware
        ./internal/database
        ./internal/utils
        ./internal/repository/sqlite
    )
fi

echo -e "${YELLOW}Running tests with race detector...${NC}"
echo -e "${YELLOW}(Running in ${GO_IMAGE}, timeout ${RACE_TIMEOUT})${NC}"
echo -e "${YELLOW}Packages: ${PACKAGES[*]}${NC}"
echo -e "${YELLOW}This takes much longer than a normal test run.${NC}"
echo ""

if ! docker run --rm \
    -v "$PROJECT_ROOT:/workspace" \
    -v safeshare-gomod:/go/pkg/mod \
    -v safeshare-gocache:/root/.cache/go-build \
    -w /workspace \
    -e GOFLAGS=-buildvcs=false \
    "$GO_IMAGE" \
    go test -race -timeout="$RACE_TIMEOUT" "${PACKAGES[@]}"; then
    echo -e "${RED}Race conditions detected or tests failed!${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}=== No race conditions detected ✓ ===${NC}"
