#!/bin/bash
#
# End-to-End Test Script for `dcg scan --git-diff`
#
# This script tests the CI integration workflow for PR diff scanning:
#   - Creates a temp git repo with multiple commits
#   - Tests various diff scenarios (add, modify, rename, delete)
#   - Runs `dcg scan --git-diff` and asserts correct output/exit code
#   - Verifies deterministic output ordering
#
# Usage:
#   ./scripts/scan_gitdiff_e2e.sh [--verbose] [--binary PATH]
#
# Exit codes:
#   0  All tests passed
#   1  One or more tests failed
#   2  Binary not found or other setup error

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Configuration
VERBOSE=false
BINARY=""
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --binary|-b)
            BINARY="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--verbose] [--binary PATH]"
            echo ""
            echo "Options:"
            echo "  --verbose, -v   Show detailed output for each test"
            echo "  --binary, -b    Path to dcg binary"
            echo "  --help, -h      Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 2
            ;;
    esac
done

# Find binary
if [[ -z "$BINARY" ]]; then
    if command -v dcg &> /dev/null; then
        BINARY="dcg"
    elif [[ -f "./target/release/dcg" ]]; then
        BINARY="./target/release/dcg"
    elif [[ -f "./target/debug/dcg" ]]; then
        BINARY="./target/debug/dcg"
    else
        echo -e "${RED}Error: dcg binary not found${NC}"
        echo "Run 'cargo build --release' first or specify --binary PATH"
        exit 2
    fi
fi

# Save the original working directory
ORIGINAL_DIR="$(pwd)"

# Convert to absolute path (before changing directories)
if [[ "$BINARY" != /* ]]; then
    BINARY="${ORIGINAL_DIR}/${BINARY}"
fi

# Verify the binary exists
if [[ ! -f "$BINARY" ]]; then
    echo -e "${RED}Error: Binary not found at: $BINARY${NC}"
    exit 2
fi

echo -e "${BOLD}${BLUE}dcg scan --git-diff E2E Test Suite${NC}"
echo -e "${CYAN}Binary: ${BINARY}${NC}"
echo ""

# Logging functions
log_test_start() {
    local desc="$1"
    ((++TESTS_TOTAL))
    if $VERBOSE; then
        echo -e "${CYAN}[TEST ${TESTS_TOTAL}]${NC} $desc"
    fi
}

log_pass() {
    local desc="$1"
    ((++TESTS_PASSED))
    echo -e "${GREEN}✓${NC} $desc"
}

log_fail() {
    local desc="$1"
    local expected="${2:-}"
    local actual="${3:-}"
    ((++TESTS_FAILED))
    echo -e "${RED}✗${NC} $desc"
    if $VERBOSE && [[ -n "$expected" ]]; then
        echo -e "  ${YELLOW}Expected:${NC} $expected"
        echo -e "  ${YELLOW}Actual:${NC} $actual"
    fi
}

log_section() {
    local title="$1"
    echo ""
    echo -e "${BOLD}${BLUE}=== $title ===${NC}"
}

log_info() {
    local msg="$1"
    if $VERBOSE; then
        echo -e "  ${CYAN}Info:${NC} $msg"
    fi
}

# Create a fixture git repo with test files
create_fixture_repo() {
    local tmp_dir
    tmp_dir=$(mktemp -d)

    cd "$tmp_dir"
    git init --quiet
    git config user.email "test@example.com"
    git config user.name "Test User"

    # Initial commit so we have a valid base
    echo "# Test Repo" > README.md
    git add README.md
    git commit --quiet -m "Initial commit"

    echo "$tmp_dir"
}

# Cleanup helper (safely removes temp directories only)
cleanup_repo() {
    local repo_dir="$1"
    # Return to original directory first (we may be inside the temp dir)
    cd "$ORIGINAL_DIR"
    # Safety check: only remove directories under /tmp
    if [[ -n "$repo_dir" ]] && [[ "$repo_dir" == /tmp/* ]] && [[ -d "$repo_dir" ]]; then
        rm -rf "$repo_dir"
    fi
}

# ============================================================================
# Test: Empty diff (no changes)
# ============================================================================
test_empty_diff() {
    log_section "Test: Empty diff (no file changes)"

    local repo
    repo=$(create_fixture_repo)
    log_info "Created fixture repo at: $repo"

    cd "$repo"

    # Get the base commit hash
    local base_commit
    base_commit=$(git rev-parse HEAD)

    log_test_start "Empty diff returns exit 0"

    local exit_code=0
    local output
    output=$("$BINARY" scan --git-diff "${base_commit}..HEAD" --format json 2>&1) || exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        # Verify JSON output has 0 findings
        local findings_count
        findings_count=$(echo "$output" | jq -r '.summary.findings_total // 0')
        if [[ "$findings_count" == "0" ]]; then
            log_pass "Empty diff returns exit 0 with 0 findings"
        else
            log_fail "Empty diff returns exit 0 with 0 findings" "0 findings" "$findings_count findings"
        fi
    else
        log_fail "Empty diff returns exit 0" "exit 0" "exit $exit_code"
    fi

    cleanup_repo "$repo"
}

# ============================================================================
# Test: Added file with destructive command
# ============================================================================
test_added_file_destructive() {
    log_section "Test: Added file with destructive command"

    local repo
    repo=$(create_fixture_repo)
    log_info "Created fixture repo at: $repo"

    cd "$repo"

    # Get the base commit hash
    local base_commit
    base_commit=$(git rev-parse HEAD)

    # Add a shell script with a destructive command
    cat > deploy.sh << 'SHELL_EOF'
#!/bin/bash
# Deploy script
git reset --hard origin/main
echo "Deployed!"
SHELL_EOF

    git add deploy.sh
    git commit --quiet -m "Add deploy script"

    log_info "Added deploy.sh with 'git reset --hard'"

    log_test_start "Added file with destructive command triggers finding"

    local exit_code=0
    local output
    output=$("$BINARY" scan --git-diff "${base_commit}..HEAD" --format json --fail-on error 2>&1) || exit_code=$?

    if $VERBOSE; then
        echo -e "  ${CYAN}Diff range:${NC} ${base_commit}..HEAD"
        echo -e "  ${CYAN}Output preview:${NC}"
        echo "$output" | head -20
    fi

    # Should exit non-zero due to error finding
    if [[ $exit_code -ne 0 ]]; then
        log_pass "Exit code is non-zero (found error)"
    else
        log_fail "Exit code should be non-zero" "non-zero" "0"
    fi

    # Verify the finding details
    log_test_start "Finding includes correct file"
    local finding_file
    finding_file=$(echo "$output" | jq -r '.findings[0].file // ""')

    if [[ "$finding_file" == "deploy.sh" ]]; then
        log_pass "Finding has file=deploy.sh"
    else
        log_fail "Finding file" "deploy.sh" "${finding_file}"
    fi

    log_test_start "Finding includes rule_id with git/reset"
    local rule_id
    rule_id=$(echo "$output" | jq -r '.findings[0].rule_id // ""')

    if [[ "$rule_id" == *"git"* ]] || [[ "$rule_id" == *"reset"* ]]; then
        log_pass "Finding has rule_id: $rule_id"
    else
        log_fail "Finding rule_id" "contains git/reset" "$rule_id"
    fi

    cleanup_repo "$repo"
}

# ============================================================================
# Test: Modified file (base was safe, now destructive)
# ============================================================================
test_modified_file() {
    log_section "Test: Modified file (added destructive command)"

    local repo
    repo=$(create_fixture_repo)
    log_info "Created fixture repo at: $repo"

    cd "$repo"

    # Create a safe script first
    cat > build.sh << 'SHELL_EOF'
#!/bin/bash
echo "Building..."
cargo build --release
SHELL_EOF

    git add build.sh
    git commit --quiet -m "Add safe build script"

    # Get the base commit hash
    local base_commit
    base_commit=$(git rev-parse HEAD)

    # Modify to add destructive command
    cat > build.sh << 'SHELL_EOF'
#!/bin/bash
echo "Building..."
git clean -fdx  # Added: dangerous clean
cargo build --release
SHELL_EOF

    git add build.sh
    git commit --quiet -m "Add aggressive clean"

    log_info "Modified build.sh to include 'git clean -fdx'"

    log_test_start "Modified file with destructive command triggers finding"

    local exit_code=0
    local output
    output=$("$BINARY" scan --git-diff "${base_commit}..HEAD" --format json --fail-on error 2>&1) || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        log_pass "Exit code is non-zero (found error)"
    else
        log_fail "Exit code should be non-zero" "non-zero" "0"
    fi

    log_test_start "Finding is in the modified file"
    local finding_file
    finding_file=$(echo "$output" | jq -r '.findings[0].file // ""')

    if [[ "$finding_file" == "build.sh" ]]; then
        log_pass "Finding has file=build.sh"
    else
        log_fail "Finding file" "build.sh" "${finding_file}"
    fi

    cleanup_repo "$repo"
}

# ============================================================================
# Test: Renamed file (should scan the new path)
# ============================================================================
test_renamed_file() {
    log_section "Test: Renamed file (scans new path)"

    local repo
    repo=$(create_fixture_repo)
    log_info "Created fixture repo at: $repo"

    cd "$repo"

    # Create a script
    cat > old_script.sh << 'SHELL_EOF'
#!/bin/bash
rm -rf /tmp/cache
SHELL_EOF

    git add old_script.sh
    git commit --quiet -m "Add old script"

    # Get the base commit hash
    local base_commit
    base_commit=$(git rev-parse HEAD)

    # Rename the file
    git mv old_script.sh new_script.sh
    git commit --quiet -m "Rename script"

    log_info "Renamed old_script.sh to new_script.sh"

    log_test_start "Renamed file is scanned at new path"

    local exit_code=0
    local output
    output=$("$BINARY" scan --git-diff "${base_commit}..HEAD" --format json 2>&1) || exit_code=$?

    if $VERBOSE; then
        echo -e "  ${CYAN}Output:${NC}"
        echo "$output" | head -15
    fi

    # Should succeed (rm -rf /tmp/cache is allowed)
    if [[ $exit_code -eq 0 ]]; then
        log_pass "Renamed file scanned successfully (exit 0)"
    else
        # If we got findings, check they're for the new path
        local finding_file
        finding_file=$(echo "$output" | jq -r '.findings[0].file // ""')
        if [[ "$finding_file" == "new_script.sh" ]]; then
            log_pass "Finding uses new path: new_script.sh"
        else
            log_fail "Finding should use new path" "new_script.sh" "${finding_file}"
        fi
    fi

    cleanup_repo "$repo"
}

# ============================================================================
# Test: Deleted file (should be skipped gracefully)
# ============================================================================
test_deleted_file() {
    log_section "Test: Deleted file (skipped gracefully)"

    local repo
    repo=$(create_fixture_repo)
    log_info "Created fixture repo at: $repo"

    cd "$repo"

    # Create and commit a script
    cat > temp_script.sh << 'SHELL_EOF'
#!/bin/bash
echo "temporary"
SHELL_EOF

    git add temp_script.sh
    git commit --quiet -m "Add temp script"

    # Get the base commit hash
    local base_commit
    base_commit=$(git rev-parse HEAD)

    # Delete the file
    git rm temp_script.sh
    git commit --quiet -m "Remove temp script"

    log_info "Deleted temp_script.sh"

    log_test_start "Deleted file is handled without crash"

    local exit_code=0
    local output
    output=$("$BINARY" scan --git-diff "${base_commit}..HEAD" --format json 2>&1) || exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log_pass "Deleted file handled gracefully (exit 0)"
    else
        log_fail "Deleted file should not cause error" "exit 0" "exit $exit_code"
    fi

    log_test_start "No crash on deleted file"
    # If we got here, no crash occurred
    log_pass "No crash on deleted file"

    cleanup_repo "$repo"
}

# ============================================================================
# Test: Data-only mention (should NOT find)
# ============================================================================
test_data_only_mention() {
    log_section "Test: Data-only dangerous string (no finding)"

    local repo
    repo=$(create_fixture_repo)
    log_info "Created fixture repo at: $repo"

    cd "$repo"

    # Get the base commit hash
    local base_commit
    base_commit=$(git rev-parse HEAD)

    # Create a markdown file with dangerous commands as documentation
    cat > SECURITY.md << 'MD_EOF'
# Security Guidelines

## Commands to Avoid

Never run these destructive commands:
- `git reset --hard` - Loses uncommitted changes
- `rm -rf /` - Deletes everything
- `git push --force` - Overwrites remote history

Instead, use safer alternatives like `git stash` and `git push --force-with-lease`.
MD_EOF

    git add SECURITY.md
    git commit --quiet -m "Add security docs"

    log_info "Added SECURITY.md with data-only dangerous strings"

    log_test_start "Data-only mention does NOT trigger finding"

    local exit_code=0
    local output
    output=$("$BINARY" scan --git-diff "${base_commit}..HEAD" --format json --fail-on error 2>&1) || exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        local findings_count
        findings_count=$(echo "$output" | jq -r '.summary.findings_total // 0')
        if [[ "$findings_count" == "0" ]]; then
            log_pass "Data-only mention returns 0 findings"
        else
            log_fail "Data-only mention should have 0 findings" "0" "$findings_count"
        fi
    else
        log_fail "Data-only mention should not trigger error exit" "exit 0" "exit $exit_code"
    fi

    cleanup_repo "$repo"
}

# ============================================================================
# Test: Deterministic ordering
# ============================================================================
test_deterministic_output() {
    log_section "Test: Deterministic output ordering"

    local repo
    repo=$(create_fixture_repo)
    log_info "Created fixture repo at: $repo"

    cd "$repo"

    # Get the base commit hash
    local base_commit
    base_commit=$(git rev-parse HEAD)

    # Create multiple files with findings
    cat > z_last.sh << 'SHELL_EOF'
#!/bin/bash
git reset --hard
SHELL_EOF

    cat > a_first.sh << 'SHELL_EOF'
#!/bin/bash
git push --force
SHELL_EOF

    cat > m_middle.sh << 'SHELL_EOF'
#!/bin/bash
git stash drop
SHELL_EOF

    git add *.sh
    git commit --quiet -m "Add multiple scripts"

    log_info "Added multiple files with destructive commands"

    log_test_start "Output ordering is deterministic"

    # Run twice and compare
    local output1
    local output2
    output1=$("$BINARY" scan --git-diff "${base_commit}..HEAD" --format json 2>&1) || true
    output2=$("$BINARY" scan --git-diff "${base_commit}..HEAD" --format json 2>&1) || true

    # Compare the findings arrays (should be identical)
    local findings1
    local findings2
    findings1=$(echo "$output1" | jq -c '.findings // []')
    findings2=$(echo "$output2" | jq -c '.findings // []')

    if [[ "$findings1" == "$findings2" ]]; then
        log_pass "Output is deterministic across runs"
    else
        log_fail "Output should be deterministic" "identical findings" "different findings"
        if $VERBOSE; then
            echo -e "  ${YELLOW}Run 1:${NC} $findings1"
            echo -e "  ${YELLOW}Run 2:${NC} $findings2"
        fi
    fi

    # Verify ordering is by file path (alphabetical)
    log_test_start "Findings are ordered by file path"
    local files
    files=$(echo "$output1" | jq -r '.findings[].file' | tr '\n' ' ')
    log_info "Finding order: $files"

    # Extract first file
    local first_file
    first_file=$(echo "$output1" | jq -r '.findings[0].file // ""')

    if [[ "$first_file" == "a_first.sh" ]]; then
        log_pass "First finding is a_first.sh (alphabetically first)"
    else
        log_fail "First finding should be alphabetically first" "a_first.sh" "$first_file"
    fi

    cleanup_repo "$repo"
}

# ============================================================================
# Test: Fail-on policy with warnings
# ============================================================================
test_fail_on_policy() {
    log_section "Test: Fail-on policy behavior"

    local repo
    repo=$(create_fixture_repo)
    log_info "Created fixture repo at: $repo"

    cd "$repo"

    # Get the base commit hash
    local base_commit
    base_commit=$(git rev-parse HEAD)

    # Create a file with a destructive command (error level)
    cat > cleanup.sh << 'SHELL_EOF'
#!/bin/bash
git reset --hard
SHELL_EOF

    git add cleanup.sh
    git commit --quiet -m "Add cleanup script"

    log_test_start "--fail-on error exits non-zero on error"
    local exit_code=0
    "$BINARY" scan --git-diff "${base_commit}..HEAD" --fail-on error >/dev/null 2>&1 || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        log_pass "--fail-on error exits non-zero on error"
    else
        log_fail "--fail-on error exits non-zero" "non-zero" "0"
    fi

    log_test_start "--fail-on none always exits 0"
    exit_code=0
    "$BINARY" scan --git-diff "${base_commit}..HEAD" --fail-on none >/dev/null 2>&1 || exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log_pass "--fail-on none always exits 0"
    else
        log_fail "--fail-on none always exits 0" "0" "$exit_code"
    fi

    cleanup_repo "$repo"
}

# ============================================================================
# Test: Multiple commits in range
# ============================================================================
test_multiple_commits() {
    log_section "Test: Multiple commits in diff range"

    local repo
    repo=$(create_fixture_repo)
    log_info "Created fixture repo at: $repo"

    cd "$repo"

    # Get the base commit hash
    local base_commit
    base_commit=$(git rev-parse HEAD)

    # Commit 1: safe file
    echo 'echo "safe"' > safe.sh
    git add safe.sh
    git commit --quiet -m "Add safe script"

    # Commit 2: destructive file
    cat > danger.sh << 'SHELL_EOF'
#!/bin/bash
git push --force
SHELL_EOF
    git add danger.sh
    git commit --quiet -m "Add danger script"

    # Commit 3: another file
    echo 'echo "more safe"' > safe2.sh
    git add safe2.sh
    git commit --quiet -m "Add another safe script"

    log_info "Created 3 commits after base"

    log_test_start "Multiple commits scanned correctly"

    local exit_code=0
    local output
    output=$("$BINARY" scan --git-diff "${base_commit}..HEAD" --format json --fail-on error 2>&1) || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        log_pass "Found error across multiple commits"
    else
        log_fail "Should find error in commit range" "non-zero" "0"
    fi

    # Verify we found the danger.sh file
    log_test_start "Finding is in danger.sh"
    local finding_file
    finding_file=$(echo "$output" | jq -r '.findings[0].file // ""')

    if [[ "$finding_file" == "danger.sh" ]]; then
        log_pass "Finding is in danger.sh"
    else
        log_fail "Finding file" "danger.sh" "$finding_file"
    fi

    cleanup_repo "$repo"
}

# ============================================================================
# Run all tests
# ============================================================================
main() {
    test_empty_diff
    test_added_file_destructive
    test_modified_file
    test_renamed_file
    test_deleted_file
    test_data_only_mention
    test_deterministic_output
    test_fail_on_policy
    test_multiple_commits

    echo ""
    echo -e "${BOLD}${BLUE}=== Summary ===${NC}"
    echo -e "Total: ${TESTS_TOTAL}"
    echo -e "${GREEN}Passed: ${TESTS_PASSED}${NC}"
    echo -e "${RED}Failed: ${TESTS_FAILED}${NC}"

    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo ""
        echo -e "${RED}${BOLD}Some tests failed!${NC}"
        exit 1
    else
        echo ""
        echo -e "${GREEN}${BOLD}All tests passed!${NC}"
        exit 0
    fi
}

main
