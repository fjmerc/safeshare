#!/bin/bash

# SafeShare Release Helper
# This script helps you create properly versioned releases

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored messages
print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_error() { echo -e "${RED}✗${NC} $1"; }
print_info() { echo -e "${BLUE}ℹ${NC} $1"; }
print_prompt() { echo -e "${YELLOW}?${NC} $1"; }

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    print_error "Not a git repository. Please run this script from the SafeShare project root."
    exit 1
fi

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║           SafeShare Release Helper                        ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check if we're on main branch
current_branch=$(git branch --show-current)
if [[ "$current_branch" != "main" ]]; then
    print_error "You must be on the 'main' branch to create a release."
    print_info "Current branch: ${current_branch}"
    echo ""
    print_info "Release workflow:"
    echo "  1. Merge develop → main (via PR)"
    echo "  2. Checkout main: git checkout main"
    echo "  3. Pull latest: git pull origin main"
    echo "  4. Run this script: ./scripts/create-release.sh"
    exit 1
fi

# Get current version from tags
current_version=$(git describe --tags --abbrev=0 2>/dev/null)
if [[ -z "$current_version" ]]; then
    current_version="v0.0.0"
    print_info "No existing tags found. Starting from ${current_version}"
else
    print_info "Current version: ${current_version}"
fi

# Parse version (remove 'v' prefix if present)
version_number="${current_version#v}"
IFS='.' read -r -a version_parts <<< "$version_number"
major="${version_parts[0]}"
minor="${version_parts[1]}"
patch="${version_parts[2]}"

echo ""
print_prompt "What type of release is this?"
echo ""
echo "  1) Major release  (breaking changes)       →  v$((major+1)).0.0"
echo "  2) Minor release  (new features)           →  v${major}.$((minor+1)).0"
echo "  3) Patch release  (bug fixes only)         →  v${major}.${minor}.$((patch+1))"
echo ""
read -p "Enter your choice (1-3): " choice

case $choice in
    1)
        new_version="v$((major+1)).0.0"
        release_type="Major"
        ;;
    2)
        new_version="v${major}.$((minor+1)).0"
        release_type="Minor"
        ;;
    3)
        new_version="v${major}.${minor}.$((patch+1))"
        release_type="Patch"
        ;;
    *)
        print_error "Invalid choice. Exiting."
        exit 1
        ;;
esac

echo ""
print_info "${release_type} release: ${current_version} → ${new_version}"
echo ""

# Get release notes
print_prompt "Enter release notes (or press Enter to use auto-generated notes):"
read -p "> " release_notes

if [[ -z "$release_notes" ]]; then
    # Auto-generate release notes from commits since last tag
    print_info "Generating release notes from commits..."
    if [[ "$current_version" == "v0.0.0" ]]; then
        commit_range="HEAD"
    else
        commit_range="${current_version}..HEAD"
    fi

    release_notes="Release ${new_version}

Changes since ${current_version}:
$(git log ${commit_range} --pretty=format:"- %s" --no-merges | head -20)

See full changelog: https://github.com/fjmerc/safeshare/compare/${current_version}...${new_version}"
fi

echo ""
print_info "Release tag: ${new_version}"
echo ""
echo "─────────────────────────────────────────────────────────────"
echo "${release_notes}"
echo "─────────────────────────────────────────────────────────────"
echo ""

# Confirm
read -p "Create this release? (y/n): " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    print_error "Cancelled."
    exit 0
fi

echo ""
print_info "Creating annotated tag ${new_version}..."

# Create annotated tag
if ! git tag -a "$new_version" -m "$release_notes"; then
    print_error "Failed to create tag."
    exit 1
fi

print_success "Tag created successfully!"

# Push tag
echo ""
print_prompt "Push tag to GitHub? This will trigger CI/CD to build and publish Docker images."
read -p "Push now? (y/n): " push_confirm

if [[ "$push_confirm" =~ ^[Yy]$ ]]; then
    print_info "Pushing tag to origin..."
    if ! git push origin "$new_version"; then
        print_error "Failed to push tag. You can push manually with: git push origin ${new_version}"
        exit 1
    fi

    print_success "Tag pushed successfully!"
    echo ""
    print_info "GitHub Actions is now building and publishing:"
    echo "  • Docker images: fjmerc/safeshare:${new_version}"
    echo "  • GitHub Release: https://github.com/fjmerc/safeshare/releases/tag/${new_version}"
    echo ""
    print_info "Monitor progress: https://github.com/fjmerc/safeshare/actions"
else
    print_info "Tag created locally but not pushed."
    echo ""
    print_info "To push later, run: git push origin ${new_version}"
fi

echo ""
print_info "Don't forget to sync main back to develop:"
echo "  git checkout develop"
echo "  git pull origin develop"
echo "  git merge main"
echo "  git push origin develop"
echo ""
print_success "Release ${new_version} complete!"
echo ""
