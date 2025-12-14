#!/bin/bash
# PostgreSQL Integration Test Runner
#
# This script runs the PostgreSQL repository integration tests in a Docker environment.
# It handles:
# 1. Starting a PostgreSQL container
# 2. Running tests with proper environment variables
# 3. Collecting coverage data
# 4. Cleaning up containers
#
# Usage:
#   ./scripts/test-postgres.sh              # Run all tests
#   ./scripts/test-postgres.sh -v           # Run with verbose output
#   ./scripts/test-postgres.sh -k           # Keep containers running after tests
#   ./scripts/test-postgres.sh -c           # Generate HTML coverage report

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
POSTGRES_HOST="localhost"
POSTGRES_PORT="5433"
POSTGRES_USER="safeshare_test"
POSTGRES_PASSWORD="test_password"
POSTGRES_DB="safeshare_test"
POSTGRES_SSLMODE="disable"

# Script options
VERBOSE=""
KEEP_CONTAINERS=false
GENERATE_HTML_REPORT=false

# Parse command line arguments
while getopts "vkch" opt; do
  case $opt in
    v)
      VERBOSE="-v"
      ;;
    k)
      KEEP_CONTAINERS=true
      ;;
    c)
      GENERATE_HTML_REPORT=true
      ;;
    h)
      echo "PostgreSQL Integration Test Runner"
      echo ""
      echo "Usage: $0 [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  -v    Verbose output (show individual test results)"
      echo "  -k    Keep PostgreSQL container running after tests"
      echo "  -c    Generate HTML coverage report"
      echo "  -h    Show this help message"
      echo ""
      exit 0
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
  esac
done

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

cd "$PROJECT_ROOT"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}PostgreSQL Integration Test Runner${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Cleanup function
cleanup() {
    if [ "$KEEP_CONTAINERS" = false ]; then
        echo -e "\n${YELLOW}Cleaning up...${NC}"
        docker-compose -f docker-compose.postgres-test.yml down -v 2>/dev/null || true
    else
        echo -e "\n${YELLOW}Keeping containers running (-k flag set)${NC}"
        echo -e "To stop containers manually: docker-compose -f docker-compose.postgres-test.yml down -v"
    fi
}

# Set up cleanup trap
trap cleanup EXIT

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running${NC}"
    exit 1
fi

# Start PostgreSQL container
echo -e "${BLUE}Step 1: Starting PostgreSQL container...${NC}"
docker-compose -f docker-compose.postgres-test.yml up -d --wait

# Wait for PostgreSQL to be ready
echo -e "${BLUE}Step 2: Waiting for PostgreSQL to be ready...${NC}"
MAX_RETRIES=30
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if docker exec safeshare-postgres-test pg_isready -U $POSTGRES_USER -d $POSTGRES_DB >/dev/null 2>&1; then
        echo -e "${GREEN}PostgreSQL is ready!${NC}"
        break
    fi
    RETRY_COUNT=$((RETRY_COUNT + 1))
    echo "Waiting for PostgreSQL... ($RETRY_COUNT/$MAX_RETRIES)"
    sleep 1
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    echo -e "${RED}Error: PostgreSQL did not become ready in time${NC}"
    docker logs safeshare-postgres-test
    exit 1
fi

# Run tests in Docker container
echo -e "\n${BLUE}Step 3: Running integration tests...${NC}"
echo ""

# Build the test command
TEST_CMD="go test -tags=integration $VERBOSE ./internal/repository/postgres/... \
    -cover -coverprofile=/app/coverage-postgres.out -covermode=atomic"

# Run tests
if docker run --rm \
    --network host \
    -v "$PROJECT_ROOT":/app \
    -w /app \
    -e POSTGRES_HOST=$POSTGRES_HOST \
    -e POSTGRES_PORT=$POSTGRES_PORT \
    -e POSTGRES_USER=$POSTGRES_USER \
    -e POSTGRES_PASSWORD=$POSTGRES_PASSWORD \
    -e POSTGRES_DB=$POSTGRES_DB \
    -e POSTGRES_SSLMODE=$POSTGRES_SSLMODE \
    golang:1.24 $TEST_CMD; then
    
    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}All tests passed!${NC}"
    echo -e "${GREEN}========================================${NC}"
else
    echo -e "\n${RED}========================================${NC}"
    echo -e "${RED}Some tests failed!${NC}"
    echo -e "${RED}========================================${NC}"
    exit 1
fi

# Show coverage summary
echo -e "\n${BLUE}Step 4: Coverage Summary${NC}"
echo ""

docker run --rm \
    -v "$PROJECT_ROOT":/app \
    -w /app \
    golang:1.24 go tool cover -func=/app/coverage-postgres.out | grep -E "^total:|internal/repository/postgres"

# Generate HTML report if requested
if [ "$GENERATE_HTML_REPORT" = true ]; then
    echo -e "\n${BLUE}Step 5: Generating HTML coverage report...${NC}"
    docker run --rm \
        -v "$PROJECT_ROOT":/app \
        -w /app \
        golang:1.24 go tool cover -html=/app/coverage-postgres.out -o /app/coverage-postgres.html
    echo -e "${GREEN}HTML report generated: coverage-postgres.html${NC}"
fi

echo -e "\n${GREEN}Done!${NC}"
