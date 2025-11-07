#!/bin/bash
# SafeShare Git Flow Branch Helper
# Creates properly named branches following Git Flow conventions

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== SafeShare Git Flow Branch Helper ===${NC}"
echo ""

# Get current branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo -e "Current branch: ${YELLOW}${CURRENT_BRANCH}${NC}"
echo ""

# Branch type menu
echo "Select branch type:"
echo "  1) feature/    - New feature (base: develop)"
echo "  2) bugfix/     - Bug fix (base: develop)"
echo "  3) docs/       - Documentation (base: develop)"
echo "  4) hotfix/     - Production hotfix (base: main)"
echo "  5) release/    - Release preparation (base: develop)"
echo ""
read -p "Choice (1-5): " choice

case $choice in
    1)
        BRANCH_TYPE="feature"
        BASE_BRANCH="develop"
        ;;
    2)
        BRANCH_TYPE="bugfix"
        BASE_BRANCH="develop"
        ;;
    3)
        BRANCH_TYPE="docs"
        BASE_BRANCH="develop"
        ;;
    4)
        BRANCH_TYPE="hotfix"
        BASE_BRANCH="main"
        ;;
    5)
        BRANCH_TYPE="release"
        BASE_BRANCH="develop"
        ;;
    *)
        echo -e "${RED}Invalid choice${NC}"
        exit 1
        ;;
esac

# Get branch name
echo ""
read -p "Enter branch name (e.g., add-user-auth): " BRANCH_NAME

if [ -z "$BRANCH_NAME" ]; then
    echo -e "${RED}Branch name cannot be empty${NC}"
    exit 1
fi

# Construct full branch name
FULL_BRANCH_NAME="${BRANCH_TYPE}/${BRANCH_NAME}"

echo ""
echo -e "${BLUE}Creating branch: ${GREEN}${FULL_BRANCH_NAME}${NC}"
echo -e "${BLUE}Base branch: ${GREEN}${BASE_BRANCH}${NC}"
echo ""

# Fetch latest changes
echo -e "${YELLOW}Fetching latest changes...${NC}"
git fetch origin

# Check if base branch exists
if ! git show-ref --verify --quiet refs/heads/${BASE_BRANCH}; then
    echo -e "${RED}Base branch '${BASE_BRANCH}' does not exist locally${NC}"
    echo -e "${YELLOW}Checking out ${BASE_BRANCH} from origin...${NC}"
    git checkout -b ${BASE_BRANCH} origin/${BASE_BRANCH}
else
    # Switch to base branch
    echo -e "${YELLOW}Switching to ${BASE_BRANCH}...${NC}"
    git checkout ${BASE_BRANCH}

    # Pull latest changes
    echo -e "${YELLOW}Pulling latest changes...${NC}"
    git pull origin ${BASE_BRANCH}
fi

# Create and checkout new branch
echo -e "${YELLOW}Creating new branch ${FULL_BRANCH_NAME}...${NC}"
git checkout -b ${FULL_BRANCH_NAME}

echo ""
echo -e "${GREEN}✓ Branch created successfully!${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "  1. Make your changes"
echo "  2. Commit: git add . && git commit -m 'your message'"
echo "  3. Push: git push -u origin ${FULL_BRANCH_NAME}"
echo "  4. Create PR to merge into ${BASE_BRANCH}"
echo ""
