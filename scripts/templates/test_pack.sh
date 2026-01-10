#!/bin/bash
#
# Template for Pack E2E Tests
#
# Copy this file to scripts/test_pack_<your_pack_name>.sh and customize it.
# This script tests a specific pack's blocking/allowing behavior.
#
# Usage:
#   ./scripts/test_pack_<name>.sh [--verbose] [--binary PATH]
#

set -euo pipefail

# --- Configuration ---
PACK_NAME="<your_pack_name>"  # e.g. "containers.docker"
PACK_KEYWORD="<tool_name>"    # e.g. "docker"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

VERBOSE=false
BINARY=""
TESTS_PASSED=0
TESTS_FAILED=0

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --verbose|-v) VERBOSE=true; shift ;;
        --binary|-b) BINARY="$2"; shift 2 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

# Resolve absolute path to the binary to support running from any directory
if [[ -z "$BINARY" ]]; then
    # Try to find dcg in common build locations relative to the script or current dir
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)" # Assuming scripts/templates/ location
    
    if [[ -f "$PROJECT_ROOT/target/release/dcg" ]]; then 
        BINARY="$PROJECT_ROOT/target/release/dcg"
    elif [[ -f "$PROJECT_ROOT/target/debug/dcg" ]]; then 
        BINARY="$PROJECT_ROOT/target/debug/dcg"
    elif command -v dcg &>/dev/null; then 
        BINARY="dcg"
    else 
        echo "Error: dcg binary not found. Build it with 'cargo build --release' or use --binary"
        exit 1
    fi
fi

# Ensure binary path is absolute if it's a file
if [[ -f "$BINARY" && "$BINARY" != /* ]]; then
    BINARY="$(cd "$(dirname "$BINARY")" && pwd)/$(basename "$BINARY")"
fi

# JSON-escape a string for safe embedding in a JSON string literal.
# Handles backslashes, quotes, and common control characters.
json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    echo -n "$s"
}

# Helper: Test a command
test_cmd() {
    local cmd="$1"
    local expected="$2" # "block" or "allow"
    local desc="$3"

    # Create JSON input using robust escaping
    local escaped_cmd
    escaped_cmd=$(json_escape "$cmd")
    local json="{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"$escaped_cmd\"}}"
    local encoded
    encoded=$(echo -n "$json" | base64 -w 0)

    # Run dcg with the pack enabled
    # We force enable the pack to ensure it's active even if config doesn't have it
    local out
    out=$(echo "$encoded" | base64 -d | DCG_PACKS="$PACK_NAME" "$BINARY" 2>&1 || true)

    # Analyze result
    if [[ "$expected" == "block" ]]; then
        if echo "$out" | grep -q '"permissionDecision"' && echo "$out" | grep -q '"deny"'; then
            [[ "$VERBOSE" == "true" ]] && echo -e "${GREEN}PASS${NC} [BLOCK] $desc"
            ((TESTS_PASSED++))
        else
            echo -e "${RED}FAIL${NC} [BLOCK] $desc"
            echo "  Expected block, got allow/other."
            echo "  Output: $out"
            ((TESTS_FAILED++))
        fi
    else # expected == allow
        if [[ -z "$out" ]] || ! echo "$out" | grep -q '"permissionDecision"'; then
            [[ "$VERBOSE" == "true" ]] && echo -e "${GREEN}PASS${NC} [ALLOW] $desc"
            ((TESTS_PASSED++))
        else
            echo -e "${RED}FAIL${NC} [ALLOW] $desc"
            echo "  Expected allow, got block."
            echo "  Output: $out"
            ((TESTS_FAILED++))
        fi
    fi
}

echo "Testing pack: $PACK_NAME"
echo "Binary: $BINARY"
echo "----------------------------------------"

# --- TEST CASES START HERE ---

# 1. DESTRUCTIVE TESTS (Should BLOCK)
# test_cmd "<destructive_command>" "block" "<description>"
# Example:
# test_cmd "docker system prune -f" "block" "Prune with force flag"

# 2. SAFE TESTS (Should ALLOW)
# test_cmd "<safe_command>" "allow" "<description>"
# Example:
# test_cmd "docker ps" "allow" "List containers"

# 3. EDGE CASES (Quotes, flags, paths)
# test_cmd "docker system   prune" "block" "Extra spaces"

# --- TEST CASES END HERE ---

echo "----------------------------------------"
echo "Tests Passed: $TESTS_PASSED"
echo "Tests Failed: $TESTS_FAILED"

if [[ $TESTS_FAILED -gt 0 ]]; then
    exit 1
else
    exit 0
fi
