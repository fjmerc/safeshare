#!/bin/bash
# SafeShare Branch Cleanup Helper
# Safely delete merged branches

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== SafeShare Branch Cleanup Helper ===${NC}"
echo ""

# Protected branches
PROTECTED_BRANCHES=("main" "develop")

# Function to check if branch is protected
is_protected() {
    local branch=$1
    for protected in "${PROTECTED_BRANCHES[@]}"; do
        if [[ "$branch" == "$protected" ]]; then
            return 0
        fi
    done
    return 1
}

# Menu
echo "Select cleanup option:"
echo "  1) Delete specific local branch"
echo "  2) Clean up all merged branches (safe)"
echo "  3) List all branches"
echo "  4) Delete remote branch"
echo ""
read -p "Choice (1-4): " choice

case $choice in
    1)
        # Delete specific local branch
        echo ""
        echo -e "${YELLOW}Local branches:${NC}"
        git branch | grep -v "^\*"
        echo ""
        read -p "Enter branch name to delete: " BRANCH_NAME

        if [ -z "$BRANCH_NAME" ]; then
            echo -e "${RED}Branch name cannot be empty${NC}"
            exit 1
        fi

        # Check if protected
        if is_protected "$BRANCH_NAME"; then
            echo -e "${RED}Cannot delete protected branch: ${BRANCH_NAME}${NC}"
            exit 1
        fi

        # Check if branch exists
        if ! git show-ref --verify --quiet refs/heads/${BRANCH_NAME}; then
            echo -e "${RED}Branch '${BRANCH_NAME}' does not exist${NC}"
            exit 1
        fi

        # Check if merged
        if git branch --merged | grep -q "^[* ]*${BRANCH_NAME}$"; then
            echo -e "${GREEN}Branch is merged, safe to delete${NC}"
            git branch -d ${BRANCH_NAME}
            echo -e "${GREEN}✓ Branch deleted${NC}"
        else
            echo -e "${YELLOW}Warning: Branch is NOT merged${NC}"
            read -p "Force delete? (y/N): " confirm
            if [[ $confirm == "y" || $confirm == "Y" ]]; then
                git branch -D ${BRANCH_NAME}
                echo -e "${GREEN}✓ Branch force deleted${NC}"
            else
                echo -e "${YELLOW}Cancelled${NC}"
            fi
        fi
        ;;

    2)
        # Clean up all merged branches
        echo ""
        echo -e "${YELLOW}Finding merged branches...${NC}"

        CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
        MERGED_BRANCHES=$(git branch --merged | grep -v "^\*" | grep -v "main" | grep -v "develop" | xargs echo)

        if [ -z "$MERGED_BRANCHES" ]; then
            echo -e "${GREEN}No merged branches to clean up${NC}"
            exit 0
        fi

        echo -e "${BLUE}The following branches are merged and will be deleted:${NC}"
        echo "$MERGED_BRANCHES"
        echo ""
        read -p "Proceed with deletion? (y/N): " confirm

        if [[ $confirm == "y" || $confirm == "Y" ]]; then
            git branch --merged | grep -v "^\*" | grep -v "main" | grep -v "develop" | xargs -r git branch -d
            echo -e "${GREEN}✓ Cleanup complete${NC}"
        else
            echo -e "${YELLOW}Cancelled${NC}"
        fi
        ;;

    3)
        # List all branches
        echo ""
        echo -e "${BLUE}Local branches:${NC}"
        git branch -vv
        echo ""
        echo -e "${BLUE}Remote branches:${NC}"
        git branch -r
        ;;

    4)
        # Delete remote branch
        echo ""
        echo -e "${YELLOW}Remote branches:${NC}"
        git branch -r | grep -v "HEAD"
        echo ""
        read -p "Enter remote branch to delete (e.g., origin/feature/old-feature): " REMOTE_BRANCH

        if [ -z "$REMOTE_BRANCH" ]; then
            echo -e "${RED}Branch name cannot be empty${NC}"
            exit 1
        fi

        # Extract remote and branch name
        REMOTE=$(echo $REMOTE_BRANCH | cut -d'/' -f1)
        BRANCH=$(echo $REMOTE_BRANCH | cut -d'/' -f2-)

        # Check if protected
        if is_protected "$BRANCH"; then
            echo -e "${RED}Cannot delete protected branch: ${BRANCH}${NC}"
            exit 1
        fi

        echo -e "${YELLOW}Warning: This will delete ${REMOTE_BRANCH}${NC}"
        read -p "Are you sure? (y/N): " confirm

        if [[ $confirm == "y" || $confirm == "Y" ]]; then
            git push ${REMOTE} --delete ${BRANCH}
            echo -e "${GREEN}✓ Remote branch deleted${NC}"
        else
            echo -e "${YELLOW}Cancelled${NC}"
        fi
        ;;

    *)
        echo -e "${RED}Invalid choice${NC}"
        exit 1
        ;;
esac

echo ""
