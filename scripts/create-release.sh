#!/bin/bash
# SafeShare Release Helper
# Creates tagged releases following semantic versioning

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== SafeShare Release Helper ===${NC}"
echo ""

# Get current branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo -e "Current branch: ${YELLOW}${CURRENT_BRANCH}${NC}"

# Get latest tag
LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
echo -e "Latest tag: ${YELLOW}${LATEST_TAG}${NC}"
echo ""

# Parse semantic version
if [[ $LATEST_TAG =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    MAJOR="${BASH_REMATCH[1]}"
    MINOR="${BASH_REMATCH[2]}"
    PATCH="${BASH_REMATCH[3]}"
else
    echo -e "${YELLOW}No valid semantic version found, starting from v0.0.0${NC}"
    MAJOR=0
    MINOR=0
    PATCH=0
fi

# Version bump menu
echo "Select version bump type:"
echo "  1) Major (breaking changes)    - ${MAJOR}.x.x -> $((MAJOR+1)).0.0"
echo "  2) Minor (new features)        - x.${MINOR}.x -> ${MAJOR}.$((MINOR+1)).0"
echo "  3) Patch (bug fixes)           - x.x.${PATCH} -> ${MAJOR}.${MINOR}.$((PATCH+1))"
echo "  4) Custom version"
echo ""
read -p "Choice (1-4): " choice

case $choice in
    1)
        NEW_VERSION="v$((MAJOR+1)).0.0"
        ;;
    2)
        NEW_VERSION="v${MAJOR}.$((MINOR+1)).0"
        ;;
    3)
        NEW_VERSION="v${MAJOR}.${MINOR}.$((PATCH+1))"
        ;;
    4)
        read -p "Enter custom version (e.g., v2.1.0): " NEW_VERSION
        if [[ ! $NEW_VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo -e "${RED}Invalid version format. Must be vX.Y.Z${NC}"
            exit 1
        fi
        ;;
    *)
        echo -e "${RED}Invalid choice${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${BLUE}New version: ${GREEN}${NEW_VERSION}${NC}"
echo ""

# Get release notes
read -p "Enter release notes (optional): " RELEASE_NOTES

# Confirm
echo ""
echo -e "${YELLOW}Summary:${NC}"
echo "  Version: ${NEW_VERSION}"
echo "  Branch: ${CURRENT_BRANCH}"
if [ -n "$RELEASE_NOTES" ]; then
    echo "  Notes: ${RELEASE_NOTES}"
fi
echo ""
read -p "Create release tag? (y/N): " confirm

if [[ $confirm != "y" && $confirm != "Y" ]]; then
    echo -e "${YELLOW}Cancelled${NC}"
    exit 0
fi

# Create tag
echo ""
echo -e "${YELLOW}Creating tag ${NEW_VERSION}...${NC}"

if [ -n "$RELEASE_NOTES" ]; then
    git tag -a ${NEW_VERSION} -m "${RELEASE_NOTES}"
else
    git tag -a ${NEW_VERSION} -m "Release ${NEW_VERSION}"
fi

echo -e "${GREEN}✓ Tag created locally${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "  1. Push tag: git push origin ${NEW_VERSION}"
echo "  2. Push branch: git push origin ${CURRENT_BRANCH}"
echo "  3. Create GitHub release (optional)"
echo ""
echo -e "${YELLOW}To push tag now:${NC}"
echo "  git push origin ${NEW_VERSION}"
echo ""

# Option to push immediately
read -p "Push tag to origin now? (y/N): " push_confirm

if [[ $push_confirm == "y" || $push_confirm == "Y" ]]; then
    git push origin ${NEW_VERSION}
    echo -e "${GREEN}✓ Tag pushed to origin${NC}"
fi

echo ""
echo -e "${GREEN}Release process complete!${NC}"
echo ""
