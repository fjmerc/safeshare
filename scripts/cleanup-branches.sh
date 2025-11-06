#!/bin/bash

# SafeShare Branch Cleanup Helper
# This script helps you delete branches that have been merged

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored messages
print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_error() { echo -e "${RED}✗${NC} $1"; }
print_info() { echo -e "${BLUE}ℹ${NC} $1"; }
print_prompt() { echo -e "${YELLOW}?${NC} $1"; }
print_branch() { echo -e "${CYAN}  →${NC} $1"; }

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    print_error "Not a git repository. Please run this script from the SafeShare project root."
    exit 1
fi

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║         SafeShare Branch Cleanup Helper                   ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Get current branch
current_branch=$(git branch --show-current)
print_info "Current branch: ${current_branch}"

# Fetch latest info from remote
print_info "Fetching latest information from remote..."
git fetch --prune origin > /dev/null 2>&1

echo ""
print_prompt "What would you like to clean up?"
echo ""
echo "  1) Delete a specific local branch"
echo "  2) Clean up all merged branches (safe - only deletes already merged)"
echo "  3) List all branches (to see what exists)"
echo "  4) Delete a remote branch"
echo ""
read -p "Enter your choice (1-4): " choice

case $choice in
    1)
        # Delete specific local branch
        echo ""
        print_info "Local branches:"
        git branch | grep -v "^\*" | sed 's/^/  /'
        echo ""
        print_prompt "Enter the branch name to delete:"
        read -p "> " branch_name

        # Remove leading/trailing whitespace
        branch_name=$(echo "$branch_name" | xargs)

        if [[ -z "$branch_name" ]]; then
            print_error "No branch name provided. Exiting."
            exit 1
        fi

        # Check if trying to delete current branch
        if [[ "$branch_name" == "$current_branch" ]]; then
            print_error "Cannot delete the current branch. Please switch to another branch first."
            echo ""
            print_info "Switch branch with: git checkout develop"
            exit 1
        fi

        # Check if trying to delete main or develop
        if [[ "$branch_name" == "main" || "$branch_name" == "develop" ]]; then
            print_error "Cannot delete main or develop branches!"
            exit 1
        fi

        # Check if branch exists
        if ! git show-ref --verify --quiet "refs/heads/${branch_name}"; then
            print_error "Branch '${branch_name}' does not exist."
            exit 1
        fi

        # Check if branch is merged
        if git branch --merged | grep -q "^[* ]*${branch_name}$"; then
            print_info "✓ Branch '${branch_name}' is merged into current branch"
            merge_status="merged"
        else
            print_info "⚠️  Branch '${branch_name}' is NOT merged into current branch"
            merge_status="unmerged"
        fi

        echo ""
        if [[ "$merge_status" == "unmerged" ]]; then
            print_prompt "This branch has unmerged changes. Are you sure you want to delete it? (y/n):"
        else
            print_prompt "Delete local branch '${branch_name}'? (y/n):"
        fi
        read -p "> " confirm

        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            print_error "Cancelled."
            exit 0
        fi

        # Delete the branch
        if [[ "$merge_status" == "unmerged" ]]; then
            git branch -D "$branch_name"
        else
            git branch -d "$branch_name"
        fi

        if [[ $? -eq 0 ]]; then
            print_success "Deleted local branch: ${branch_name}"

            # Ask about remote
            if git ls-remote --heads origin "$branch_name" | grep -q "$branch_name"; then
                echo ""
                print_prompt "Remote branch 'origin/${branch_name}' also exists. Delete it? (y/n):"
                read -p "> " delete_remote

                if [[ "$delete_remote" =~ ^[Yy]$ ]]; then
                    git push origin --delete "$branch_name"
                    if [[ $? -eq 0 ]]; then
                        print_success "Deleted remote branch: origin/${branch_name}"
                    else
                        print_error "Failed to delete remote branch"
                    fi
                fi
            fi
        else
            print_error "Failed to delete branch"
            exit 1
        fi
        ;;

    2)
        # Clean up all merged branches
        echo ""
        print_info "Finding branches that have been merged into ${current_branch}..."

        # Get list of merged branches (excluding main, develop, and current)
        merged_branches=$(git branch --merged | grep -v "^\*" | grep -v "main" | grep -v "develop" | sed 's/^[ \t]*//')

        if [[ -z "$merged_branches" ]]; then
            print_success "No merged branches to clean up!"
            exit 0
        fi

        echo ""
        print_info "The following branches have been merged and can be safely deleted:"
        echo ""
        echo "$merged_branches" | while read branch; do
            print_branch "$branch"
        done

        echo ""
        print_prompt "Delete all these branches? (y/n):"
        read -p "> " confirm

        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            print_error "Cancelled."
            exit 0
        fi

        echo ""
        deleted_count=0
        echo "$merged_branches" | while read branch; do
            if [[ -n "$branch" ]]; then
                git branch -d "$branch" 2>/dev/null
                if [[ $? -eq 0 ]]; then
                    print_success "Deleted: ${branch}"
                    deleted_count=$((deleted_count + 1))
                fi
            fi
        done

        echo ""
        print_success "Cleanup complete!"

        # Ask about remote branches
        echo ""
        print_prompt "Also delete these branches from remote? (y/n):"
        read -p "> " delete_remote

        if [[ "$delete_remote" =~ ^[Yy]$ ]]; then
            echo ""
            echo "$merged_branches" | while read branch; do
                if [[ -n "$branch" ]]; then
                    if git ls-remote --heads origin "$branch" | grep -q "$branch"; then
                        git push origin --delete "$branch" 2>/dev/null
                        if [[ $? -eq 0 ]]; then
                            print_success "Deleted remote: origin/${branch}"
                        fi
                    fi
                fi
            done
        fi
        ;;

    3)
        # List all branches
        echo ""
        print_info "Local branches:"
        git branch -vv

        echo ""
        print_info "Remote branches:"
        git branch -r

        echo ""
        print_info "Merged branches (safe to delete):"
        merged=$(git branch --merged | grep -v "^\*" | grep -v "main" | grep -v "develop")
        if [[ -z "$merged" ]]; then
            echo "  (none)"
        else
            echo "$merged"
        fi
        ;;

    4)
        # Delete remote branch
        echo ""
        print_info "Remote branches:"
        git branch -r | grep -v "HEAD" | sed 's/origin\///' | sed 's/^/  /'
        echo ""
        print_prompt "Enter the remote branch name to delete (without 'origin/'):"
        read -p "> " branch_name

        branch_name=$(echo "$branch_name" | xargs)

        if [[ -z "$branch_name" ]]; then
            print_error "No branch name provided. Exiting."
            exit 1
        fi

        if [[ "$branch_name" == "main" || "$branch_name" == "develop" ]]; then
            print_error "Cannot delete main or develop branches!"
            exit 1
        fi

        # Check if remote branch exists
        if ! git ls-remote --heads origin "$branch_name" | grep -q "$branch_name"; then
            print_error "Remote branch 'origin/${branch_name}' does not exist."
            exit 1
        fi

        echo ""
        print_prompt "Delete remote branch 'origin/${branch_name}'? (y/n):"
        read -p "> " confirm

        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            print_error "Cancelled."
            exit 0
        fi

        git push origin --delete "$branch_name"
        if [[ $? -eq 0 ]]; then
            print_success "Deleted remote branch: origin/${branch_name}"

            # Check if local branch exists
            if git show-ref --verify --quiet "refs/heads/${branch_name}"; then
                echo ""
                print_prompt "Local branch '${branch_name}' also exists. Delete it? (y/n):"
                read -p "> " delete_local

                if [[ "$delete_local" =~ ^[Yy]$ ]]; then
                    if [[ "$branch_name" != "$current_branch" ]]; then
                        git branch -d "$branch_name" 2>/dev/null || git branch -D "$branch_name"
                        if [[ $? -eq 0 ]]; then
                            print_success "Deleted local branch: ${branch_name}"
                        fi
                    else
                        print_error "Cannot delete current branch. Switch to another branch first."
                    fi
                fi
            fi
        else
            print_error "Failed to delete remote branch"
            exit 1
        fi
        ;;

    *)
        print_error "Invalid choice. Exiting."
        exit 1
        ;;
esac

echo ""
print_info "Current branch: ${current_branch}"
echo ""
