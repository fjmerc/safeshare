#!/bin/bash

# SafeShare Test Runner Script with Race Detection
# Detects data races in concurrent code inside Docker container
# Note: Requires Docker (Go is run inside container)

set -e

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

# Run tests with race detector inside Docker
echo -e "${YELLOW}Running tests with race detector...${NC}"
echo -e "${YELLOW}(Running in golang:1.24 Docker container)${NC}"
echo -e "${YELLOW}This may take longer than normal test runs.${NC}"
echo ""

docker run --rm \
    -v "$PROJECT_ROOT:/workspace" \
    -w /workspace \
    golang:1.24 \
    go test ./... -race -timeout=15m

# Check if tests passed
if [ $? -ne 0 ]; then
    echo -e "${RED}Race conditions detected or tests failed!${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}=== No race conditions detected ✓ ===${NC}"
