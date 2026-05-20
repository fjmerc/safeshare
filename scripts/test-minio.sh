#!/bin/bash
# MinIO Integration Test Runner (SH-2.2)
#
# Runs the streaming S3 encrypted-storage integration tests against a local
# MinIO container. Asserts bounded heap use under large-file workloads and
# concurrency.
#
# Usage:
#   ./scripts/test-minio.sh              # Run all integration tests
#   ./scripts/test-minio.sh -v           # Verbose output
#   ./scripts/test-minio.sh -k           # Keep MinIO container running after tests
#   ./scripts/test-minio.sh -c           # Generate HTML coverage report
#   ./scripts/test-minio.sh -s SIZE_GB   # Override large-file size (default: 1)

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
MINIO_HOST="localhost"
MINIO_PORT="9100"
MINIO_ACCESS_KEY="minioadmin"
MINIO_SECRET_KEY="minioadmin123"
MINIO_BUCKET="safeshare-test"

VERBOSE=""
KEEP_CONTAINERS=false
GENERATE_HTML_REPORT=false
# Default to 1 GB locally; CI overrides via SH22_LARGE_FILE_SIZE_GB.
LARGE_FILE_SIZE_GB="${SH22_LARGE_FILE_SIZE_GB:-1}"

while getopts "vkchs:" opt; do
  case $opt in
    v) VERBOSE="-v" ;;
    k) KEEP_CONTAINERS=true ;;
    c) GENERATE_HTML_REPORT=true ;;
    s) LARGE_FILE_SIZE_GB="$OPTARG" ;;
    h)
      echo "MinIO Integration Test Runner (SH-2.2)"
      echo ""
      echo "Usage: $0 [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  -v             Verbose output"
      echo "  -k             Keep MinIO container running after tests"
      echo "  -c             Generate HTML coverage report"
      echo "  -s SIZE_GB     Large-file test size (default: 1, CI default: 5)"
      echo "  -h             Show this help"
      exit 0
      ;;
    \?) echo "Invalid option: -$OPTARG" >&2; exit 1 ;;
  esac
done

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"
cd "$PROJECT_ROOT"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}MinIO Integration Test Runner (SH-2.2)${NC}"
echo -e "${BLUE}Large-file size: ${LARGE_FILE_SIZE_GB} GB${NC}"
echo -e "${BLUE}========================================${NC}"

cleanup() {
    if [ "$KEEP_CONTAINERS" = false ]; then
        echo -e "\n${YELLOW}Cleaning up...${NC}"
        "${COMPOSE[@]}" -f docker-compose.minio-test.yml down -v 2>/dev/null || true
    else
        echo -e "\n${YELLOW}Keeping containers running (-k flag set)${NC}"
        echo -e "To stop containers manually: ${COMPOSE[*]} -f docker-compose.minio-test.yml down -v"
    fi
}
trap cleanup EXIT

if ! docker info >/dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running${NC}"
    exit 1
fi

# Resolve docker compose binary: v2 plugin (`docker compose`) is the modern
# default; v1 standalone (`docker-compose`) is the legacy form some hosts /
# CI images still ship. Prefer v2 when both are present.
if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
else
    echo -e "${RED}Error: neither 'docker compose' (v2) nor 'docker-compose' (v1) available${NC}"
    exit 1
fi

echo -e "\n${BLUE}Step 1: Starting MinIO container...${NC}"
"${COMPOSE[@]}" -f docker-compose.minio-test.yml up -d --wait

echo -e "${BLUE}Step 1b: Creating test bucket...${NC}"
# Run mc inside the minio container to bootstrap the bucket. Idempotent:
# `mb -p` and `mb` itself return 0 on "already exists".
docker exec safeshare-minio-test sh -c "\
    mc alias set local http://127.0.0.1:9000 ${MINIO_ACCESS_KEY} ${MINIO_SECRET_KEY} >/dev/null && \
    mc mb -p local/${MINIO_BUCKET} >/dev/null 2>&1 || true"
echo -e "${GREEN}MinIO ready, bucket '${MINIO_BUCKET}' available${NC}"

echo -e "\n${BLUE}Step 2: Running integration tests...${NC}"
TEST_CMD="go test -tags=integration $VERBOSE ./internal/storage/s3/... \
    -cover -coverprofile=/app/coverage-minio.out -covermode=atomic -timeout=15m"

if docker run --rm \
    --network host \
    -v "$PROJECT_ROOT":/app \
    -v safeshare-gomodcache:/go/pkg/mod \
    -w /app \
    -e MINIO_HOST="$MINIO_HOST" \
    -e MINIO_PORT="$MINIO_PORT" \
    -e MINIO_ACCESS_KEY="$MINIO_ACCESS_KEY" \
    -e MINIO_SECRET_KEY="$MINIO_SECRET_KEY" \
    -e MINIO_BUCKET="$MINIO_BUCKET" \
    -e SH22_LARGE_FILE_SIZE_GB="$LARGE_FILE_SIZE_GB" \
    -e GOFLAGS="-buildvcs=false" \
    golang:1.25 $TEST_CMD; then
    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}All MinIO integration tests passed!${NC}"
    echo -e "${GREEN}========================================${NC}"
else
    echo -e "\n${RED}========================================${NC}"
    echo -e "${RED}Some tests failed!${NC}"
    echo -e "${RED}========================================${NC}"
    exit 1
fi

echo -e "\n${BLUE}Step 3: Coverage summary${NC}"
docker run --rm \
    -v "$PROJECT_ROOT":/app \
    -v safeshare-gomodcache:/go/pkg/mod \
    -w /app \
    golang:1.25 go tool cover -func=/app/coverage-minio.out | grep -E "^total:|internal/storage/s3"

if [ "$GENERATE_HTML_REPORT" = true ]; then
    echo -e "\n${BLUE}Step 4: Generating HTML coverage report...${NC}"
    docker run --rm \
        -v "$PROJECT_ROOT":/app \
        -v safeshare-gomodcache:/go/pkg/mod \
        -w /app \
        golang:1.25 go tool cover -html=/app/coverage-minio.out -o /app/coverage-minio.html
    echo -e "${GREEN}HTML report generated: coverage-minio.html${NC}"
fi

echo -e "\n${GREEN}Done!${NC}"
