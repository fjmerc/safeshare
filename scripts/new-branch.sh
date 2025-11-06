#!/bin/bash

# SafeShare Git Flow Branch Helper
# This script helps you create branches following the Git Flow strategy

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
echo "║        SafeShare Git Flow Branch Helper                   ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Ask what type of work
print_prompt "What are you working on?"
echo ""
echo "  1) New feature          (branches from: develop)"
echo "  2) Bug fix              (branches from: develop)"
echo "  3) Documentation        (branches from: develop)"
echo "  4) Hotfix               (branches from: main - for production bugs)"
echo "  5) Release preparation  (branches from: develop)"
echo ""
read -p "Enter your choice (1-5): " choice

# Determine branch prefix and base branch
case $choice in
    1)
        prefix="feature"
        base_branch="develop"
        description="new feature"
        ;;
    2)
        prefix="bugfix"
        base_branch="develop"
        description="bug fix"
        ;;
    3)
        prefix="docs"
        base_branch="develop"
        description="documentation update"
        ;;
    4)
        prefix="hotfix"
        base_branch="main"
        description="production hotfix"
        ;;
    5)
        prefix="release"
        base_branch="develop"
        description="release preparation"
        ;;
    *)
        print_error "Invalid choice. Exiting."
        exit 1
        ;;
esac

echo ""
print_info "Creating a ${description} branch"

# Ask for branch name
echo ""
print_prompt "Enter a descriptive name for your branch (use kebab-case, e.g., 'add-email-notifications'):"
read -p "> " branch_name

# Validate branch name
if [[ -z "$branch_name" ]]; then
    print_error "Branch name cannot be empty. Exiting."
    exit 1
fi

# Convert to lowercase and replace spaces/underscores with hyphens
branch_name=$(echo "$branch_name" | tr '[:upper:]' '[:lower:]' | tr '_' '-' | tr ' ' '-')

# Remove any non-alphanumeric characters except hyphens
branch_name=$(echo "$branch_name" | sed 's/[^a-z0-9-]//g')

# Construct full branch name
full_branch_name="${prefix}/${branch_name}"

# Check if branch already exists
if git show-ref --verify --quiet "refs/heads/${full_branch_name}"; then
    print_error "Branch '${full_branch_name}' already exists!"
    echo ""
    print_info "To switch to it, run: git checkout ${full_branch_name}"
    exit 1
fi

echo ""
print_info "Branch name: ${full_branch_name}"
print_info "Base branch: ${base_branch}"
echo ""

# Confirm with user
read -p "Create this branch? (y/n): " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    print_error "Cancelled."
    exit 0
fi

echo ""
print_info "Fetching latest changes from remote..."
if ! git fetch origin; then
    print_error "Failed to fetch from remote. Check your network connection."
    exit 1
fi

# Checkout base branch
print_info "Checking out ${base_branch}..."
if ! git checkout "$base_branch"; then
    print_error "Failed to checkout ${base_branch}. Please check your git status."
    exit 1
fi

# Pull latest changes
print_info "Pulling latest changes from ${base_branch}..."
if ! git pull origin "$base_branch"; then
    print_error "Failed to pull from ${base_branch}. Please resolve any conflicts manually."
    exit 1
fi

# Create and checkout new branch
print_info "Creating and checking out ${full_branch_name}..."
if ! git checkout -b "$full_branch_name"; then
    print_error "Failed to create branch ${full_branch_name}."
    exit 1
fi

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                    SUCCESS!                                ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
print_success "Created and switched to branch: ${full_branch_name}"
echo ""
print_info "Next steps:"
echo "  1. Make your changes"
echo "  2. Commit your changes: git add . && git commit -m 'description'"
echo "  3. Push to GitHub: git push origin ${full_branch_name}"
echo "  4. Create a Pull Request on GitHub to merge into ${base_branch}"
echo ""
print_info "Your branch will be merged into: ${base_branch}"

# Special note for hotfix and release branches
if [[ "$prefix" == "hotfix" ]]; then
    echo ""
    print_info "⚠️  HOTFIX NOTE:"
    echo "  After merging to main, remember to also merge into develop!"
elif [[ "$prefix" == "release" ]]; then
    echo ""
    print_info "⚠️  RELEASE NOTE:"
    echo "  When ready, merge to main and tag with version (e.g., v1.0.1)"
    echo "  Then merge main back to develop to sync changes"
fi

echo ""
