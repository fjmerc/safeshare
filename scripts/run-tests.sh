#!/bin/bash

# SafeShare Test Runner Script
# Runs tests with coverage analysis inside Docker container
# Note: Requires Docker (Go is run inside container)

set -e

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

# Clean previous coverage files
echo -e "${YELLOW}Cleaning previous coverage data...${NC}"
rm -f "$PROJECT_ROOT/coverage.out" "$PROJECT_ROOT/coverage.html"

# Run tests with coverage inside Docker
echo -e "${YELLOW}Running tests with coverage analysis...${NC}"
echo -e "${YELLOW}(Running in golang:1.24 Docker container)${NC}"
echo ""

docker run --rm \
    -v "$PROJECT_ROOT:/workspace" \
    -w /workspace \
    golang:1.24 \
    go test ./... -cover -coverprofile=coverage.out -coverpkg=./... -timeout=10m

# Check if tests passed
if [ $? -ne 0 ]; then
    echo -e "${RED}Tests failed!${NC}"
    exit 1
fi

# Generate coverage report inside Docker
echo ""
echo -e "${YELLOW}Generating coverage report...${NC}"
docker run --rm \
    -v "$PROJECT_ROOT:/workspace" \
    -w /workspace \
    golang:1.24 \
    go tool cover -func=coverage.out | tail -20

# Generate HTML coverage report inside Docker
docker run --rm \
    -v "$PROJECT_ROOT:/workspace" \
    -w /workspace \
    golang:1.24 \
    go tool cover -html=coverage.out -o coverage.html

echo -e "${GREEN}HTML coverage report generated: coverage.html${NC}"

# Calculate total coverage inside Docker
COVERAGE=$(docker run --rm \
    -v "$PROJECT_ROOT:/workspace" \
    -w /workspace \
    golang:1.24 \
    go tool cover -func=coverage.out | grep total | awk '{print $3}')

echo ""
echo -e "${GREEN}Total Coverage: ${COVERAGE}${NC}"

# Check coverage threshold (60%)
COVERAGE_NUM=$(echo $COVERAGE | sed 's/%//')
if (( $(echo "$COVERAGE_NUM < 60" | bc -l) )); then
    echo -e "${YELLOW}Warning: Coverage is below 60% threshold${NC}"
else
    echo -e "${GREEN}Coverage meets 60% threshold ✓${NC}"
fi

echo ""
echo -e "${GREEN}=== Test run completed successfully ===${NC}"
