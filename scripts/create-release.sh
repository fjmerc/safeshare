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

# Verify on main branch (Git Flow requirement)
if [[ "$CURRENT_BRANCH" != "main" ]]; then
    echo ""
    echo -e "${RED}ERROR: Release tags must be created on 'main' branch${NC}"
    echo -e "${YELLOW}You are currently on: ${CURRENT_BRANCH}${NC}"
    echo ""
    echo -e "${BLUE}Git Flow Release Process:${NC}"
    echo "  1. Create release branch from develop:"
    echo "     ${YELLOW}git checkout -b release/vX.Y.Z develop${NC}"
    echo ""
    echo "  2. Make final fixes and update CHANGELOG.md on release branch"
    echo ""
    echo "  3. Merge release branch to main:"
    echo "     ${YELLOW}git checkout main${NC}"
    echo "     ${YELLOW}git merge --no-ff release/vX.Y.Z${NC}"
    echo ""
    echo "  4. Tag the release on main (this script)"
    echo ""
    echo "  5. Merge release branch back to develop:"
    echo "     ${YELLOW}git checkout develop${NC}"
    echo "     ${YELLOW}git merge --no-ff release/vX.Y.Z${NC}"
    echo ""
    echo "  6. Delete release branch:"
    echo "     ${YELLOW}git branch -d release/vX.Y.Z${NC}"
    echo ""
    echo -e "${BLUE}See docs/VERSION_STRATEGY.md for complete details${NC}"
    exit 1
fi

# Check for uncommitted changes
if ! git diff-index --quiet HEAD --; then
    echo ""
    echo -e "${RED}ERROR: You have uncommitted changes${NC}"
    echo -e "${YELLOW}Commit or stash changes before creating a release tag${NC}"
    echo ""
    git status --short
    exit 1
fi

# Check if behind remote
echo ""
echo -e "${YELLOW}Checking if main is up to date with remote...${NC}"
git fetch origin main --quiet
LOCAL_COMMIT=$(git rev-parse main)
REMOTE_COMMIT=$(git rev-parse origin/main)

if [[ "$LOCAL_COMMIT" != "$REMOTE_COMMIT" ]]; then
    echo -e "${RED}ERROR: Local main is not in sync with origin/main${NC}"
    echo -e "${YELLOW}Pull latest changes first: git pull origin main${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Branch is up to date${NC}"

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

# Check CHANGELOG.md
echo -e "${YELLOW}⚠ IMPORTANT: Have you updated CHANGELOG.md?${NC}"
echo "  - Move items from [Unreleased] to [${NEW_VERSION#v}]"
echo "  - Add release date"
echo "  - Add comparison link"
echo ""
read -p "CHANGELOG.md is updated? (y/N): " changelog_confirm

if [[ $changelog_confirm != "y" && $changelog_confirm != "Y" ]]; then
    echo -e "${YELLOW}Please update CHANGELOG.md before creating release tag${NC}"
    echo "See docs/VERSION_STRATEGY.md section 'Changelog Management'"
    exit 0
fi

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
echo -e "${BLUE}Next steps (Git Flow):${NC}"
echo "  1. Push tag and main branch:"
echo "     ${YELLOW}git push origin main ${NEW_VERSION}${NC}"
echo ""
echo "  2. Merge release branch back to develop:"
echo "     ${YELLOW}git checkout develop${NC}"
echo "     ${YELLOW}git merge --no-ff release/${NEW_VERSION}${NC}"
echo "     ${YELLOW}git push origin develop${NC}"
echo ""
echo "  3. Delete release branch:"
echo "     ${YELLOW}git branch -d release/${NEW_VERSION}${NC}"
echo "     ${YELLOW}git push origin --delete release/${NEW_VERSION}${NC}"
echo ""
echo "  4. (Optional) Create GitHub release with notes"
echo ""
echo -e "${YELLOW}To push main and tag now:${NC}"
echo "  git push origin main ${NEW_VERSION}"
echo ""

# Option to push immediately
read -p "Push main branch and tag to origin now? (y/N): " push_confirm

if [[ $push_confirm == "y" || $push_confirm == "Y" ]]; then
    git push origin main ${NEW_VERSION}
    echo -e "${GREEN}✓ Main branch and tag pushed to origin${NC}"
    echo ""
    echo -e "${YELLOW}REMINDER: Don't forget to merge back to develop (see steps above)${NC}"
fi

echo ""
echo -e "${GREEN}Release process complete!${NC}"
echo ""
