#!/bin/bash
# SafeShare PR Merge Helper
# Approve, merge, and cleanup PRs following Git Flow

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== SafeShare PR Merge Helper ===${NC}"
echo ""

# Check if gh CLI is authenticated
if ! gh auth status >/dev/null 2>&1; then
    echo -e "${RED}ERROR: GitHub CLI not authenticated${NC}"
    echo "Run: gh auth login"
    exit 1
fi

# Get current branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo -e "Current branch: ${YELLOW}${CURRENT_BRANCH}${NC}"

# Check if we're on a feature/bugfix/perf/docs/hotfix branch
if [[ ! $CURRENT_BRANCH =~ ^(feature|bugfix|perf|docs|hotfix)/ ]]; then
    echo -e "${YELLOW}Warning: Not on a feature/bugfix/perf/docs/hotfix branch${NC}"
    read -p "Enter PR number manually: " PR_NUMBER
else
    # Try to find PR for current branch
    PR_INFO=$(gh pr list --head "${CURRENT_BRANCH}" --json number,title 2>/dev/null || echo "[]")
    PR_COUNT=$(echo "$PR_INFO" | jq '. | length')

    if [ "$PR_COUNT" -eq 0 ]; then
        echo -e "${RED}ERROR: No PR found for branch '${CURRENT_BRANCH}'${NC}"
        echo "Create PR first with: gh pr create --base develop --fill"
        exit 1
    fi

    PR_NUMBER=$(echo "$PR_INFO" | jq -r '.[0].number')
    PR_TITLE=$(echo "$PR_INFO" | jq -r '.[0].title')

    echo -e "Found PR #${YELLOW}${PR_NUMBER}${NC}: ${PR_TITLE}"
fi

echo ""

# Get PR details
echo -e "${BLUE}Fetching PR details...${NC}"
PR_DETAILS=$(gh pr view ${PR_NUMBER} --json title,state,isDraft,mergeable,statusCheckRollup,reviewDecision,baseRefName)

PR_STATE=$(echo "$PR_DETAILS" | jq -r '.state')
PR_DRAFT=$(echo "$PR_DETAILS" | jq -r '.isDraft')
PR_MERGEABLE=$(echo "$PR_DETAILS" | jq -r '.mergeable')
PR_REVIEW=$(echo "$PR_DETAILS" | jq -r '.reviewDecision')
PR_BASE=$(echo "$PR_DETAILS" | jq -r '.baseRefName')
PR_CHECKS=$(echo "$PR_DETAILS" | jq -r '.statusCheckRollup[]?.state' 2>/dev/null || echo "")

echo ""
echo -e "${BLUE}PR Status:${NC}"
echo "  State: ${PR_STATE}"
echo "  Draft: ${PR_DRAFT}"
echo "  Base: ${PR_BASE}"
echo "  Mergeable: ${PR_MERGEABLE}"
echo "  Review: ${PR_REVIEW}"

# Check CI/CD status
if [ -n "$PR_CHECKS" ]; then
    FAILED_CHECKS=$(echo "$PR_CHECKS" | grep -c "FAILURE" || true)
    PENDING_CHECKS=$(echo "$PR_CHECKS" | grep -c "PENDING" || true)

    if [ "$FAILED_CHECKS" -gt 0 ]; then
        echo -e "  ${RED}CI/CD: FAILING${NC}"
        echo ""
        echo -e "${RED}WARNING: PR has failing checks${NC}"
        read -p "Continue anyway? (y/N): " continue_failed
        if [[ $continue_failed != "y" && $continue_failed != "Y" ]]; then
            echo "Cancelled"
            exit 0
        fi
    elif [ "$PENDING_CHECKS" -gt 0 ]; then
        echo -e "  ${YELLOW}CI/CD: PENDING${NC}"
    else
        echo -e "  ${GREEN}CI/CD: PASSING${NC}"
    fi
else
    echo "  CI/CD: Not configured"
fi

echo ""

# Check if PR is draft
if [ "$PR_DRAFT" = "true" ]; then
    echo -e "${RED}ERROR: PR is in draft state${NC}"
    echo "Mark PR as ready for review first"
    exit 1
fi

# Check if PR is closed/merged
if [ "$PR_STATE" != "OPEN" ]; then
    echo -e "${RED}ERROR: PR is ${PR_STATE}${NC}"
    exit 1
fi

# Get PR author and current user for self-approval check
PR_AUTHOR=$(gh pr view ${PR_NUMBER} --json author -q '.author.login' 2>/dev/null || echo "unknown")
CURRENT_USER=$(gh api user -q '.login' 2>/dev/null || echo "unknown")

# Approve PR if not already approved
if [ "$PR_REVIEW" != "APPROVED" ]; then
    # Check if user is the PR author (can't self-approve)
    if [ "$PR_AUTHOR" = "$CURRENT_USER" ]; then
        echo -e "${YELLOW}Note: You are the PR author${NC}"
        echo -e "${BLUE}GitHub does not allow self-approval of pull requests${NC}"
        echo -e "${GREEN}Proceeding to merge without approval...${NC}"
        echo ""
        echo -e "${BLUE}Note: If branch protection requires approval, merge will fail${NC}"
        echo -e "${BLUE}In that case, ask another team member to review and approve${NC}"
    else
        # User is not the author, can approve
        echo -e "${YELLOW}PR is not approved yet${NC}"
        read -p "Approve PR now? (y/N): " approve_confirm

        if [[ $approve_confirm == "y" || $approve_confirm == "Y" ]]; then
            echo -e "${YELLOW}Approving PR...${NC}"
            gh pr review ${PR_NUMBER} --approve
            echo -e "${GREEN}✓ PR approved${NC}"
        else
            echo -e "${YELLOW}Skipping approval${NC}"
            echo -e "${BLUE}Note: Merge may fail if branch protection requires approval${NC}"
        fi
    fi
else
    echo -e "${GREEN}✓ PR is approved${NC}"
fi

echo ""

# Choose merge strategy
echo -e "${BLUE}=== Merge Strategy Explanation ===${NC}"
echo ""
echo -e "${YELLOW}1) Merge Commit${NC}"
echo "   • Creates a merge commit that preserves all individual commits"
echo "   • History: All branch commits + merge commit"
echo "   • Use when: Feature has meaningful commit history worth preserving"
echo "   • Example: 5 commits → all 5 commits + 1 merge commit"
echo ""
echo -e "${GREEN}2) Squash and Merge [RECOMMENDED]${NC}"
echo "   • Combines ALL commits into a single commit"
echo "   • History: One clean commit with PR title/description"
echo "   • Use when: Most cases - cleaner, easier to read history"
echo "   • Example: 5 commits → 1 combined commit"
echo "   • Why recommended: Easier to revert, understand, and maintain"
echo ""
echo -e "${YELLOW}3) Rebase and Merge${NC}"
echo "   • Replays commits linearly on base branch (no merge commit)"
echo "   • History: Individual commits appear directly on base branch"
echo "   • Use when: Want linear history AND preserve individual commits"
echo "   • Example: 5 commits → 5 commits replayed on develop"
echo ""
echo -e "${BLUE}Select merge strategy:${NC}"
read -p "Choice (1-3, default: 2): " merge_choice

case ${merge_choice:-2} in
    1)
        MERGE_STRATEGY="--merge"
        STRATEGY_NAME="merge commit"
        ;;
    2)
        MERGE_STRATEGY="--squash"
        STRATEGY_NAME="squash and merge"
        ;;
    3)
        MERGE_STRATEGY="--rebase"
        STRATEGY_NAME="rebase and merge"
        ;;
    *)
        echo -e "${RED}Invalid choice${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${YELLOW}Ready to merge PR #${PR_NUMBER} using ${STRATEGY_NAME}${NC}"
read -p "Proceed with merge? (y/N): " merge_confirm

if [[ $merge_confirm != "y" && $merge_confirm != "Y" ]]; then
    echo -e "${YELLOW}Cancelled${NC}"
    exit 0
fi

# Merge PR
echo ""
echo -e "${YELLOW}Merging PR...${NC}"
gh pr merge ${PR_NUMBER} ${MERGE_STRATEGY} --delete-branch

echo -e "${GREEN}✓ PR merged and remote branch deleted${NC}"

# Switch to base branch and pull latest
echo ""
echo -e "${YELLOW}Switching to ${PR_BASE} and pulling latest...${NC}"
git checkout ${PR_BASE}
git pull origin ${PR_BASE}

# Delete local branch if it still exists and we're not on it
if git show-ref --verify --quiet refs/heads/${CURRENT_BRANCH}; then
    echo -e "${YELLOW}Deleting local branch ${CURRENT_BRANCH}...${NC}"
    git branch -d ${CURRENT_BRANCH} 2>/dev/null || git branch -D ${CURRENT_BRANCH}
    echo -e "${GREEN}✓ Local branch deleted${NC}"
fi

echo ""
echo -e "${GREEN}✓✓✓ Git Flow complete! ✓✓✓${NC}"
echo ""
echo -e "${BLUE}Summary:${NC}"
echo "  • PR #${PR_NUMBER} merged to ${PR_BASE}"
echo "  • Remote branch deleted"
echo "  • Local branch deleted"
echo "  • Switched to ${PR_BASE} with latest changes"
echo ""
