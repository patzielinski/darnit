#!/bin/bash
# =============================================================================
# create-test-repo.sh
# Creates a minimal non-compliant test repository for OpenSSF Baseline testing
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Defaults
REPO_NAME="${1:-baseline-test-repo}"
GITHUB_ORG="${2:-}"  # Optional: GitHub org/user
CREATE_GITHUB="${3:-true}"
MAKE_TEMPLATE="${4:-false}"

usage() {
    echo "Usage: $0 [repo-name] [github-org] [create-github] [make-template]"
    echo ""
    echo "Arguments:"
    echo "  repo-name      Name of the repository (default: baseline-test-repo)"
    echo "  github-org     GitHub org or username (default: authenticated user)"
    echo "  create-github  Create GitHub repo: true/false (default: true)"
    echo "  make-template  Make it a template repo: true/false (default: false)"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Local + GitHub repo"
    echo "  $0 my-test-repo                       # Custom name"
    echo "  $0 my-test-repo myorg                 # In specific org"
    echo "  $0 my-test-repo myorg true true       # As template repo"
    echo "  $0 my-test-repo '' false              # Local only, no GitHub"
    exit 1
}

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    usage
fi

echo -e "${GREEN}=== OpenSSF Baseline Test Repo Generator ===${NC}"
echo ""

# Check if gh is installed for GitHub operations
if [[ "$CREATE_GITHUB" == "true" ]]; then
    if ! command -v gh &> /dev/null; then
        echo -e "${RED}Error: 'gh' CLI not found. Install it or set create-github to false.${NC}"
        echo "  brew install gh  # macOS"
        echo "  Or: https://cli.github.com/"
        exit 1
    fi

    # Check if authenticated
    if ! gh auth status &> /dev/null; then
        echo -e "${RED}Error: Not authenticated with GitHub CLI.${NC}"
        echo "  Run: gh auth login"
        exit 1
    fi

    # Get default org/user if not specified
    if [[ -z "$GITHUB_ORG" ]]; then
        GITHUB_ORG=$(gh api user --jq '.login')
        echo -e "${YELLOW}Using GitHub user: $GITHUB_ORG${NC}"
    fi
fi

# Check if directory already exists
if [[ -d "$REPO_NAME" ]]; then
    echo -e "${RED}Error: Directory '$REPO_NAME' already exists.${NC}"
    exit 1
fi

echo -e "${GREEN}Creating test repository: $REPO_NAME${NC}"
echo ""

# =============================================================================
# Create Local Repository
# =============================================================================

mkdir -p "$REPO_NAME/src"
cd "$REPO_NAME"

# Initialize git
git init --quiet

# -----------------------------------------------------------------------------
# package.json - Intentionally minimal (no license, no description)
# -----------------------------------------------------------------------------
cat > package.json << 'EOF'
{
  "name": "baseline-test",
  "version": "0.0.1",
  "main": "src/index.js",
  "scripts": {
    "start": "node src/index.js"
  },
  "dependencies": {
    "chalk": "^4.1.2"
  }
}
EOF

# -----------------------------------------------------------------------------
# src/index.js - Simple working code
# -----------------------------------------------------------------------------
cat > src/index.js << 'EOF'
const chalk = require('chalk');

console.log(chalk.green('Hello from baseline-test!'));
console.log(chalk.yellow('This repo intentionally has no security controls.'));
console.log('');
console.log('Run an OpenSSF Baseline audit to see what is missing:');
console.log(chalk.cyan('  audit_openssf_baseline(local_path=".")'));
console.log('');
console.log('Then implement fixes one by one to reach 100% compliance!');
EOF

# -----------------------------------------------------------------------------
# .gitignore - Intentionally MISSING common security exclusions
# This is a minimal .gitignore that does NOT exclude:
# - .env files (security issue!)
# - credentials (security issue!)
# - binaries (compliance issue!)
# -----------------------------------------------------------------------------
cat > .gitignore << 'EOF'
# Intentionally minimal .gitignore for testing
# This is MISSING important security exclusions!
node_modules/
EOF

# Initial commit
git add .
git commit --quiet -m "Initial commit - intentionally non-compliant

This repository is designed for testing OpenSSF Baseline compliance.
It intentionally fails all 61 OSPS controls so you can:
1. Run an audit and see all failures
2. Fix issues one by one
3. Track progress to 100% compliance"

echo -e "${GREEN}✓ Local repository created${NC}"

# =============================================================================
# Create GitHub Repository
# =============================================================================

if [[ "$CREATE_GITHUB" == "true" ]]; then
    echo ""
    echo -e "${GREEN}Creating GitHub repository: $GITHUB_ORG/$REPO_NAME${NC}"

    # Create the GitHub repo (public, no wiki, no projects for simplicity)
    gh repo create "$GITHUB_ORG/$REPO_NAME" \
        --public \
        --source=. \
        --remote=origin \
        --description="OpenSSF Baseline test repo - intentionally non-compliant for testing" \
        --push

    echo -e "${GREEN}✓ GitHub repository created${NC}"

    # Make it a template if requested
    if [[ "$MAKE_TEMPLATE" == "true" ]]; then
        echo ""
        echo -e "${GREEN}Making repository a template...${NC}"

        # Use GitHub API to set template flag
        gh api \
            --method PATCH \
            -H "Accept: application/vnd.github+json" \
            "/repos/$GITHUB_ORG/$REPO_NAME" \
            -f is_template=true

        echo -e "${GREEN}✓ Repository is now a template${NC}"
        echo ""
        echo -e "${YELLOW}To use the template:${NC}"
        echo "  1. Go to: https://github.com/$GITHUB_ORG/$REPO_NAME"
        echo "  2. Click 'Use this template' → 'Create a new repository'"
        echo "  Or use CLI:"
        echo "    gh repo create my-new-test --template $GITHUB_ORG/$REPO_NAME"
    fi

    REPO_URL="https://github.com/$GITHUB_ORG/$REPO_NAME"
else
    REPO_URL="(local only)"
fi

# =============================================================================
# Summary
# =============================================================================

echo ""
echo -e "${GREEN}=== Repository Created ===${NC}"
echo ""
echo "  Location: $(pwd)"
echo "  GitHub:   $REPO_URL"
echo ""
echo -e "${YELLOW}What's intentionally MISSING (for testing):${NC}"
echo "  ✗ LICENSE file"
echo "  ✗ README.md"
echo "  ✗ SECURITY.md"
echo "  ✗ CONTRIBUTING.md"
echo "  ✗ CI/CD workflows"
echo "  ✗ Branch protection"
echo "  ✗ Security exclusions in .gitignore"
echo "  ✗ Package lockfile"
echo "  ✗ ...and 50+ more controls"
echo ""
echo -e "${GREEN}Next steps:${NC}"
echo "  1. cd $REPO_NAME"
echo "  2. npm install"
echo "  3. Run an OpenSSF Baseline audit"
echo "  4. Start implementing fixes!"
echo ""
echo -e "${YELLOW}Quick audit command:${NC}"
echo "  audit_openssf_baseline(local_path='$(pwd)', level=3)"
echo ""
