# git_safety_guard

A high-performance Claude Code hook that blocks destructive commands before they execute, protecting your work from accidental deletion by AI coding agents.

> **Note on the name:** Despite being called `git_safety_guard`, this tool protects against a broader class of destructive operations—not just git commands. The name reflects the project's origins but is admittedly a misnomer. The tool blocks destructive git commands, dangerous filesystem operations (`rm -rf`), and is designed to be extended to cover database operations, container commands, and other irreversible actions. Think of it as a **"destructive command guard"** for AI agents.

## Origins & Authors

This project began as a Python script by Jeffrey Emanuel, who recognized that AI coding agents—while incredibly useful—have a tendency to occasionally run catastrophic commands that destroy hours of uncommitted work. The original implementation was a simple but effective hook that intercepted dangerous git and filesystem commands before execution.

- **[Jeffrey Emanuel](https://github.com/Dicklesworthstone)** - Original concept and Python implementation ([source](https://github.com/Dicklesworthstone/misc_coding_agent_tips_and_scripts/blob/main/DESTRUCTIVE_GIT_COMMAND_CLAUDE_HOOKS_SETUP.md))
- **[Dowwie](https://github.com/Dowwie)** - Rust port with performance optimizations

The Rust port maintains 100% pattern compatibility with the original Python implementation while adding sub-millisecond execution through SIMD-accelerated filtering and lazy-compiled regex patterns.

## Why This Exists

AI coding agents are powerful but fallible. They can accidentally run destructive commands that wipe out hours of uncommitted work, drop database tables, or delete critical files. Common scenarios include:

- **"Let me clean up the build artifacts"** → `rm -rf ./src` (typo)
- **"I'll reset to the last commit"** → `git reset --hard` (destroys uncommitted changes)
- **"Let me fix the merge conflict"** → `git checkout -- .` (discards all modifications)
- **"I'll clean up untracked files"** → `git clean -fd` (permanently deletes untracked files)

This hook intercepts dangerous commands *before* execution and blocks them with a clear explanation, giving you a chance to stash your changes first—or consciously decide to proceed by running the command manually.

## What It Blocks

**Git commands that destroy uncommitted work:**
- `git reset --hard` / `git reset --merge` - destroys uncommitted changes
- `git checkout -- <file>` - discards file modifications
- `git restore <file>` (without `--staged`) - discards uncommitted changes
- `git clean -f` - permanently deletes untracked files

**Git commands that can destroy remote history:**
- `git push --force` / `git push -f` - overwrites remote commits
- `git branch -D` - force-deletes branches without merge check

**Git commands that destroy stashed work:**
- `git stash drop` / `git stash clear` - permanently deletes stashes

**Filesystem commands:**
- `rm -rf` on any path outside `/tmp`, `/var/tmp`, or `$TMPDIR`

## What It Allows

**Safe git operations pass through silently:**
- `git status`, `git log`, `git diff`, `git add`, `git commit`, `git push`, `git pull`, `git fetch`
- `git branch -d` (safe delete with merge check)
- `git stash`, `git stash pop`, `git stash list`

**Explicitly safe patterns:**
- `git checkout -b <branch>` - creating new branches
- `git checkout --orphan <branch>` - creating orphan branches
- `git restore --staged <file>` - unstaging (safe, doesn't touch working tree)
- `git clean -n` / `git clean --dry-run` - preview mode
- `rm -rf /tmp/*`, `rm -rf /var/tmp/*`, `rm -rf $TMPDIR/*` - temp directory cleanup

## Planned Expansion (Future Scope)

The name `git_safety_guard` is a historical artifact. The tool is designed to expand beyond git to protect against all classes of destructive operations that AI agents might accidentally execute. Planned additions include:

### Database Operations (High Priority)

| Command Pattern | Risk | Status |
|-----------------|------|--------|
| `DROP TABLE`, `DROP DATABASE` | Destroys schema and data | Planned |
| `TRUNCATE TABLE` | Deletes all data instantly | Planned |
| `DELETE FROM` without `WHERE` | Mass data deletion | Planned |
| `mysql -e "DROP..."` | CLI-based destruction | Planned |
| `psql -c "DROP..."` | PostgreSQL destruction | Planned |
| `redis-cli FLUSHALL` | Wipes entire Redis | Planned |
| `mongosh "db.dropDatabase()"` | MongoDB destruction | Planned |

### Container & Infrastructure (Medium Priority)

| Command Pattern | Risk | Status |
|-----------------|------|--------|
| `docker system prune -af` | Removes all containers, images, volumes | Planned |
| `docker rm -f` | Force-removes running containers | Planned |
| `docker volume rm` | Deletes persistent data | Planned |
| `kubectl delete namespace` | Destroys entire namespace | Planned |
| `kubectl delete all --all` | Mass resource deletion | Planned |

### Additional Git Operations (Medium Priority)

| Command Pattern | Risk | Status |
|-----------------|------|--------|
| `git gc --prune=now` | Can lose unreachable commits | Planned |
| `git reflog expire --expire=now` | Destroys reflog safety net | Planned |
| `git filter-branch` | Rewrites entire history | Planned |

### File Operations (Medium Priority)

| Command Pattern | Risk | Status |
|-----------------|------|--------|
| `mv` overwriting files outside temp | Silent data loss | Planned |
| `> file` (redirect truncation) | Overwrites file contents | Planned |
| `truncate -s 0` | Empties file contents | Planned |

### Low-Level Operations (Lower Priority)

| Command Pattern | Risk | Status |
|-----------------|------|--------|
| `dd of=/dev/...` | Disk destruction | Planned |
| `mkfs`, `mkfs.ext4` | Filesystem destruction | Planned |
| `fdisk`, `parted` | Partition table modification | Planned |
| `chmod 777` on sensitive paths | Security degradation | Planned |

If you encounter commands that should be blocked, please file an issue describing the scenario.

## Installation

### Quick Install (Recommended)

The easiest way to install is using the install script, which downloads a prebuilt binary for your platform:

```bash
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/git_safety_guard/master/install.sh | bash
```

**With options:**

```bash
# Easy mode: auto-update PATH in shell rc files
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/git_safety_guard/master/install.sh | bash -s -- --easy-mode

# Install specific version
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/git_safety_guard/master/install.sh | bash -s -- --version v0.1.0

# Install to /usr/local/bin (system-wide, requires sudo)
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/git_safety_guard/master/install.sh | sudo bash -s -- --system

# Build from source instead of downloading binary
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/git_safety_guard/master/install.sh | bash -s -- --from-source
```

The install script:
- Automatically detects your OS and architecture
- Downloads the appropriate prebuilt binary
- Verifies SHA256 checksums for security
- Falls back to building from source if no prebuilt is available
- Offers to update your PATH

### From source (requires Rust nightly)

This project uses Rust Edition 2024 features and requires the nightly toolchain. The repository includes a `rust-toolchain.toml` that automatically selects the correct toolchain.

```bash
# Install Rust nightly if you don't have it
rustup install nightly

# Install directly from GitHub
cargo +nightly install --git https://github.com/Dicklesworthstone/git_safety_guard
```

### Manual build

```bash
git clone https://github.com/Dicklesworthstone/git_safety_guard
cd git_safety_guard
# rust-toolchain.toml automatically selects nightly
cargo build --release
cp target/release/git_safety_guard ~/.local/bin/
```

### Prebuilt Binaries

Prebuilt binaries are available for:
- Linux x86_64 (`x86_64-unknown-linux-gnu`)
- Linux ARM64 (`aarch64-unknown-linux-gnu`)
- macOS Intel (`x86_64-apple-darwin`)
- macOS Apple Silicon (`aarch64-apple-darwin`)
- Windows (`x86_64-pc-windows-msvc`)

Download from [GitHub Releases](https://github.com/Dicklesworthstone/git_safety_guard/releases) and verify the SHA256 checksum.

## Claude Code Configuration

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "git_safety_guard"
          }
        ]
      }
    ]
  }
}
```

**Important:** Restart Claude Code after adding the hook configuration.

## How It Works

1. Claude Code invokes the hook before executing any Bash command
2. The hook receives the command as JSON on stdin
3. Commands are normalized (e.g., `/usr/bin/git` becomes `git`)
4. Safe patterns are checked first (whitelist approach)
5. Destructive patterns are checked second (blacklist approach)
6. If destructive: outputs JSON denial with explanation
7. If safe: exits silently (no output = allow)

The hook is designed for minimal latency with sub-millisecond execution on typical commands.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Claude Code                               │
│                                                                  │
│  User: "delete the build artifacts"                             │
│  Agent: executes `rm -rf ./build`                               │
│                                                                  │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼ PreToolUse hook (stdin: JSON)
┌─────────────────────────────────────────────────────────────────┐
│                     git_safety_guard                             │
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │    Parse     │───▶│  Normalize   │───▶│ Quick Reject │       │
│  │    JSON      │    │   Command    │    │   Filter     │       │
│  └──────────────┘    └──────────────┘    └──────┬───────┘       │
│                                                  │               │
│                      ┌───────────────────────────┘               │
│                      ▼                                           │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   Pattern Matching                        │   │
│  │                                                           │   │
│  │   1. Check SAFE_PATTERNS (whitelist) ──▶ Allow if match  │   │
│  │   2. Check DESTRUCTIVE_PATTERNS ──────▶ Deny if match    │   │
│  │   3. No match ────────────────────────▶ Allow (default)  │   │
│  │                                                           │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼ stdout: JSON (deny) or empty (allow)
┌─────────────────────────────────────────────────────────────────┐
│                        Claude Code                               │
│                                                                  │
│  If denied: Shows block message, does NOT execute command       │
│  If allowed: Proceeds with command execution                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Processing Pipeline

**Stage 1: JSON Parsing**
- Reads the hook input from stdin
- Validates the structure matches Claude Code's `PreToolUse` format
- Extracts the command string from `tool_input.command`
- Non-Bash tools are immediately allowed (no output)

**Stage 2: Command Normalization**
- Strips absolute paths from `git` and `rm` binaries
- `/usr/bin/git status` → `git status`
- `/bin/rm -rf /tmp/foo` → `rm -rf /tmp/foo`
- Uses regex with lookahead to preserve arguments containing paths

**Stage 3: Quick Rejection Filter**
- O(n) substring search for "git" or "rm" in the command
- Commands without these substrings bypass regex matching entirely
- Handles 99%+ of non-destructive commands (ls, cat, cargo, npm, etc.)

**Stage 4: Pattern Matching**
- Safe patterns checked first (short-circuit on match → allow)
- Destructive patterns checked second (match → deny with reason)
- No match on either → default allow

## Design Principles

### 1. Whitelist-First Architecture

Safe patterns are checked *before* destructive patterns. This design ensures that explicitly safe commands (like `git checkout -b`) are never accidentally blocked, even if they partially match a destructive pattern (like `git checkout`).

```
git checkout -b feature    →  Matches SAFE "checkout-new-branch"  →  ALLOW
git checkout -- file.txt   →  No safe match, matches DESTRUCTIVE  →  DENY
```

### 2. Fail-Safe Defaults

The hook uses a **default-allow** policy for unrecognized commands. This ensures:
- The hook never breaks legitimate workflows
- Only *known* dangerous patterns are blocked
- New git commands are allowed until explicitly categorized

### 3. Zero False Negatives Philosophy

The pattern set prioritizes **never allowing dangerous commands** over avoiding false positives. A few extra prompts for manual confirmation are acceptable; lost work is not.

### 4. Defense in Depth

This hook is one layer of protection. It complements (not replaces):
- Regular commits and pushes
- Git stash before risky operations
- Proper backup strategies
- Code review processes

### 5. Minimal Latency

Every Bash command passes through this hook. Performance is critical:
- Lazy-initialized static regex patterns (compiled once, reused)
- Quick rejection filter eliminates 99%+ of commands before regex
- No heap allocations on the hot path for safe commands
- Sub-millisecond execution for typical commands

## Pattern Matching System

### Safe Patterns (Whitelist)

The safe pattern list contains 28 patterns covering:

| Category | Patterns | Purpose |
|----------|----------|---------|
| Branch creation | `checkout -b`, `checkout --orphan` | Creating branches is safe |
| Staged-only | `restore --staged`, `restore -S` | Unstaging doesn't touch working tree |
| Dry run | `clean -n`, `clean --dry-run` | Preview mode, no actual deletion |
| Temp cleanup | `rm -rf /tmp/*`, `rm -rf /var/tmp/*` | Ephemeral directories are safe |
| Variable expansion | `rm -rf $TMPDIR/*`, `rm -rf ${TMPDIR}/*` | Shell variable forms |
| Quoted paths | `rm -rf "$TMPDIR/*"` | Quoted variable forms |
| Separate flags | `rm -r -f /tmp/*` | Flag ordering variants |
| Long flags | `rm --recursive --force /tmp/*` | GNU-style long options |

### Destructive Patterns (Blacklist)

The destructive pattern list contains 16 patterns covering:

| Category | Pattern | Reason |
|----------|---------|--------|
| Work destruction | `reset --hard`, `reset --merge` | Destroys uncommitted changes |
| File reversion | `checkout -- <path>` | Discards file modifications |
| Worktree restore | `restore` (without --staged) | Discards uncommitted changes |
| Untracked deletion | `clean -f` | Permanently removes untracked files |
| History rewrite | `push --force`, `push -f` | Can destroy remote commits |
| Unsafe branch delete | `branch -D` | Force-deletes without merge check |
| Stash destruction | `stash drop`, `stash clear` | Permanently deletes stashed work |
| Filesystem nuke | `rm -rf` (non-temp paths) | Recursive deletion outside temp |

### Pattern Syntax

Patterns use [fancy-regex](https://github.com/fancy-regex/fancy-regex) for advanced features:

```rust
// Negative lookahead: block restore UNLESS --staged is present
r"git\s+restore\s+(?!--staged\b)(?!-S\b)"

// Negative lookahead: don't match --force-with-lease
r"git\s+push\s+.*--force(?![-a-z])"

// Character class: match any flag ordering
r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*"
```

## Edge Cases Handled

### Path Normalization

Commands may use absolute paths to binaries:

```bash
/usr/bin/git reset --hard          # Blocked ✓
/usr/local/bin/git checkout -- .   # Blocked ✓
/bin/rm -rf /home/user             # Blocked ✓
```

The normalizer uses regex to strip paths while preserving arguments:

```bash
git add /usr/bin/something         # "/usr/bin/something" is an argument, preserved
```

### Flag Ordering Variants

The `rm` command accepts flags in many forms:

```bash
rm -rf /path          # Combined flags
rm -fr /path          # Reversed order
rm -r -f /path        # Separate flags
rm -f -r /path        # Separate, reversed
rm --recursive --force /path    # Long flags
rm --force --recursive /path    # Long flags, reversed
rm -rf --no-preserve-root /     # Additional flags
```

All variants are handled by flexible regex patterns.

### Shell Variable Expansion

Temp directory variables come in multiple forms:

```bash
rm -rf $TMPDIR/build           # Unquoted, simple
rm -rf ${TMPDIR}/build         # Unquoted, braced
rm -rf "$TMPDIR/build"         # Quoted, simple
rm -rf "${TMPDIR}/build"       # Quoted, braced
rm -rf "${TMPDIR:-/tmp}/build" # With default value
```

### Git Flag Combinations

Git commands can have flags in various positions:

```bash
git push --force                  # Blocked ✓
git push origin main --force      # Blocked ✓
git push --force origin main      # Blocked ✓
git push -f                       # Blocked ✓
git push --force-with-lease       # Allowed ✓ (safe alternative)
```

### Staged vs Worktree Restore

The restore command has nuanced safety:

```bash
git restore --staged file.txt           # Allowed ✓ (unstaging only)
git restore -S file.txt                 # Allowed ✓ (short flag)
git restore file.txt                    # Blocked (discards changes)
git restore --worktree file.txt         # Blocked (explicit worktree)
git restore --staged --worktree file    # Blocked (includes worktree)
git restore -S -W file.txt              # Blocked (includes worktree)
```

## Performance Optimizations

### 1. Lazy Static Initialization

Regex patterns are compiled once on first use via `LazyLock`:

```rust
static SAFE_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    vec![
        pattern!("checkout-new-branch", r"git\s+checkout\s+-b\s+"),
        // ... 27 more patterns
    ]
});
```

Subsequent invocations reuse the compiled patterns with zero compilation overhead.

### 2. Quick Rejection Filter

Before any regex matching, a simple substring check filters out irrelevant commands:

```rust
fn quick_reject(cmd: &str) -> bool {
    !(cmd.contains("git") || cmd.contains("rm"))
}
```

For commands like `ls -la`, `cargo build`, or `npm install`, this check short-circuits the entire matching pipeline.

### 3. Early Exit on Safe Match

Safe patterns are checked first. On match, the function returns immediately without checking destructive patterns:

```rust
for pattern in SAFE_PATTERNS.iter() {
    if pattern.regex.is_match(&normalized).unwrap_or(false) {
        return;  // Allow immediately
    }
}
```

### 4. Compile-Time Pattern Validation

The `pattern!` and `destructive!` macros include the pattern name in panic messages, making invalid patterns fail at first execution with clear diagnostics:

```rust
macro_rules! pattern {
    ($name:literal, $re:literal) => {
        Pattern {
            regex: Regex::new($re).expect(concat!("pattern '", $name, "' should compile")),
            name: $name,
        }
    };
}
```

### 5. Zero-Copy JSON Parsing

The `serde_json` parser operates on the input buffer without unnecessary copies. The command string is extracted directly from the parsed JSON value.

### 6. Release Profile Optimization

The release build uses aggressive optimization settings:

```toml
[profile.release]
opt-level = 3       # Maximum optimization level
lto = true          # Link-time optimization across crates
codegen-units = 1   # Single codegen unit for better optimization
panic = "abort"     # Smaller binary, no unwinding overhead
strip = true        # Remove debug symbols
```

## Example Block Message

When a destructive command is intercepted:

```
BLOCKED by git_safety_guard

Reason: git reset --hard destroys uncommitted changes. Use 'git stash' first.

Command: git reset --hard HEAD~1

If this operation is truly needed, ask the user for explicit permission
and have them run the command manually.
```

## Security Considerations

### What This Protects Against

- **Accidental data loss**: AI agents running `git checkout --` or `git reset --hard` on files with uncommitted changes
- **Remote history destruction**: Force pushes that overwrite shared branch history
- **Stash loss**: Dropping or clearing stashes containing important work-in-progress
- **Filesystem accidents**: Recursive deletion outside designated temp directories

### What This Does NOT Protect Against (Yet)

**Currently not covered (see Planned Expansion above):**
- **Database operations**: `DROP TABLE`, `TRUNCATE`, `DELETE FROM` without WHERE, etc.
- **Container operations**: `docker system prune`, `kubectl delete`, etc.
- **File moves/overwrites**: `mv` to overwrite important files, redirect truncation (`> file`)
- **Low-level disk operations**: `dd`, `mkfs`, `fdisk`, etc.

**Inherent limitations:**
- **Malicious actors**: A determined attacker can bypass this hook
- **Non-Bash commands**: Direct file writes via Python/JavaScript, API calls, etc. are not intercepted
- **Committed but unpushed work**: The hook doesn't prevent loss of local-only commits
- **Bugs in allowed commands**: A `git commit` that accidentally includes wrong files
- **Commands in scripts**: If an agent runs `./deploy.sh`, we don't inspect what's inside the script

### Threat Model

This hook assumes the AI agent is **well-intentioned but fallible**. It's designed to catch honest mistakes, not adversarial attacks. The hook runs with the same permissions as the Claude Code process.

## Troubleshooting

### Hook not blocking commands

1. **Check hook registration**: Verify `~/.claude/settings.json` contains the hook configuration
2. **Restart Claude Code**: Configuration changes require a restart
3. **Check binary location**: Ensure `git_safety_guard` is in your PATH
4. **Test manually**: Run `echo '{"tool_name":"Bash","tool_input":{"command":"git reset --hard"}}' | git_safety_guard`

### Hook blocking safe commands

1. **Check for false positives**: Some edge cases may not be covered by safe patterns
2. **File an issue**: Report the command that was incorrectly blocked
3. **Temporary bypass**: Have the user run the command manually in a separate terminal

### Performance issues

1. **Check pattern count**: Excessive custom patterns can slow matching
2. **Profile with `--release`**: Debug builds are significantly slower
3. **Check stdin buffering**: Slow JSON input can delay processing

## Running Tests

### Unit Tests

```bash
cargo test
```

The test suite includes 70+ tests covering:

- **normalize_command_tests**: Path stripping for git and rm binaries
- **quick_reject_tests**: Fast-path filtering for non-git/rm commands
- **safe_pattern_tests**: Whitelist accuracy for all safe pattern variants
- **destructive_pattern_tests**: Blacklist coverage for all dangerous commands
- **input_parsing_tests**: JSON parsing robustness and edge cases
- **deny_output_tests**: Output format validation
- **integration_tests**: End-to-end pipeline verification

### Test with Coverage

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
```

### End-to-End Testing

Create a test script to verify hook behavior:

```bash
#!/bin/bash
set -e

# Test helper
test_command() {
    local cmd="$1"
    local expected="$2"
    local desc="$3"

    result=$(echo "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"$cmd\"}}" | git_safety_guard)

    if [ "$expected" = "block" ]; then
        if echo "$result" | grep -q "permissionDecision.*deny"; then
            echo "✓ BLOCKED: $desc"
        else
            echo "✗ FAILED (should block): $desc"
            exit 1
        fi
    else
        if [ -z "$result" ]; then
            echo "✓ ALLOWED: $desc"
        else
            echo "✗ FAILED (should allow): $desc"
            exit 1
        fi
    fi
}

# Destructive commands (should block)
test_command "git reset --hard" "block" "git reset --hard"
test_command "git checkout -- ." "block" "git checkout -- ."
test_command "git restore file.txt" "block" "git restore without --staged"
test_command "git clean -f" "block" "git clean -f"
test_command "git push --force" "block" "git push --force"
test_command "git push -f" "block" "git push -f"
test_command "git branch -D feature" "block" "git branch -D"
test_command "git stash drop" "block" "git stash drop"
test_command "git stash clear" "block" "git stash clear"
test_command "rm -rf /" "block" "rm -rf /"
test_command "rm -rf ~/" "block" "rm -rf ~/"
test_command "rm -rf ./build" "block" "rm -rf relative path"

# Safe commands (should allow)
test_command "git status" "allow" "git status"
test_command "git log" "allow" "git log"
test_command "git diff" "allow" "git diff"
test_command "git add ." "allow" "git add"
test_command "git commit -m test" "allow" "git commit"
test_command "git push" "allow" "git push (no force)"
test_command "git checkout -b feature" "allow" "git checkout -b"
test_command "git restore --staged file" "allow" "git restore --staged"
test_command "git clean -n" "allow" "git clean -n (dry run)"
test_command "rm -rf /tmp/build" "allow" "rm -rf /tmp/"
test_command "ls -la" "allow" "non-git/rm command"
test_command "cargo build" "allow" "cargo command"

echo ""
echo "All tests passed!"
```

## FAQ

**Q: Why block `git branch -D` but allow `git branch -d`?**

The lowercase `-d` only deletes branches that have been fully merged. The uppercase `-D` force-deletes regardless of merge status, potentially losing commits that exist only on that branch.

**Q: Why is `git push --force-with-lease` allowed?**

Force-with-lease is a safer alternative that refuses to push if the remote has commits you haven't seen. It prevents accidentally overwriting someone else's work.

**Q: Why block all `rm -rf` outside temp directories?**

Recursive forced deletion is one of the most dangerous filesystem operations. Even with good intentions, a typo or wrong variable expansion can delete critical files. Temp directories are designed to be ephemeral.

**Q: Can I add custom patterns?**

Currently, patterns are compiled into the binary. For custom patterns, fork the repository and modify `SAFE_PATTERNS` or `DESTRUCTIVE_PATTERNS` in `src/main.rs`.

**Q: What if I really need to run a blocked command?**

The block message instructs the AI to ask you for explicit permission. You can then run the command manually in a separate terminal, ensuring you've made a conscious decision.

**Q: Does this work with other AI coding tools?**

The hook is designed for Claude Code's `PreToolUse` hook protocol. Other tools would need adapters to match the expected JSON input/output format.

**Q: Why is it called `git_safety_guard` if it blocks more than git commands?**

Historical reasons. The project started as a git-focused safety hook (see Origins above), but the scope has expanded to cover filesystem operations and is planned to expand further to databases, containers, and more. Think of it as a "destructive command guard" that happens to have a git-centric name. Renaming would break existing installations, so we've kept the name while clarifying its broader purpose.

**Q: Will you add support for blocking database/Docker/Kubernetes commands?**

Yes! See the "Planned Expansion" section above. The architecture is designed to easily add new command categories. If you encounter a destructive command that should be blocked, please file an issue.

## Contributing

*About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

## License

MIT
