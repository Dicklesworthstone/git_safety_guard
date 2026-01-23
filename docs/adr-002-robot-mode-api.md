# ADR-002: Unified Robot Mode API for AI Agent Integration

## Status

Proposed

## Context

dcg (Destructive Command Guard) is used as a hook by AI coding agents like Claude Code, Gemini CLI, and others. These agents need to parse dcg's output programmatically. Currently, the CLI has several inconsistencies that make agent integration more complex than necessary:

### Current Problems

1. **Inconsistent format flags**: Commands use `-f`, `-F`, `-o`, or `--json` boolean flags
2. **Inconsistent defaults**: Some commands default to `pretty`, others to `json` or `text`
3. **No unified robot mode**: Each command must be configured individually for machine output
4. **Inconsistent exit codes**: No documented, standardized exit codes across commands
5. **Mixed stderr behavior**: Some commands emit decorative output even in CI environments
6. **JSON field naming**: Hook output uses camelCase (protocol requirement), others use snake_case

### Agent Requirements

AI agents need:
- Pure JSON on stdout (no ANSI codes, no decorative text)
- Silent stderr (or at minimum, no interference with stdout parsing)
- Predictable exit codes for decision-making
- Stable JSON schema that doesn't break between versions
- Single flag to enable "machine mode" across all commands

## Decision

We will implement a unified **robot mode** that provides a consistent, agent-friendly interface across all dcg commands.

### 1. Global `--robot` Flag

```rust
#[derive(Parser)]
pub struct Cli {
    /// Enable robot/machine mode for AI agent integration
    ///
    /// When enabled:
    /// - All output is JSON on stdout
    /// - stderr is completely silent
    /// - Exit codes follow standardized values
    /// - Human-friendly decorations are suppressed
    #[arg(long, global = true, env = "DCG_ROBOT")]
    pub robot: bool,

    // ... existing fields
}
```

### 2. Standardized Exit Codes

Create `src/exit_codes.rs`:

```rust
//! Standardized exit codes for dcg commands.
//!
//! These codes are stable and documented for agent consumption.

/// Command completed successfully (allowed, passed, healthy)
pub const EXIT_SUCCESS: i32 = 0;

/// Command was denied/blocked by a security rule
pub const EXIT_DENIED: i32 = 1;

/// Command triggered a warning (with --fail-on warn)
pub const EXIT_WARNING: i32 = 2;

/// Configuration error (invalid config file, missing required config)
pub const EXIT_CONFIG_ERROR: i32 = 3;

/// Parse/input error (invalid JSON, malformed command)
pub const EXIT_PARSE_ERROR: i32 = 4;

/// IO error (file not found, permission denied, network error)
pub const EXIT_IO_ERROR: i32 = 5;
```

### 3. Unified OutputFormat Enum

```rust
/// Output format for all dcg commands.
///
/// This enum is shared across all commands for consistency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum OutputFormat {
    /// Human-readable colored output (default for interactive use)
    #[default]
    #[value(alias = "text", alias = "human")]
    Pretty,

    /// Structured JSON output (for agents and scripting)
    #[value(alias = "sarif", alias = "structured")]
    Json,

    /// JSON Lines format (one JSON object per line)
    #[value(name = "jsonl")]
    Jsonl,

    /// Compact single-line output (for specific commands like explain)
    Compact,
}
```

### 4. Robot Mode Behavior

When `--robot` or `DCG_ROBOT=1` is set:

| Aspect | Normal Mode | Robot Mode |
|--------|-------------|------------|
| stdout | JSON or pretty | Always JSON |
| stderr | Rich output | Silent |
| Exit codes | Varies | Standardized |
| ANSI codes | If TTY | Never |
| Progress | Shown | Hidden |
| Warnings | stderr | In JSON |

### 5. JSON Response Envelope

All robot-mode JSON responses include metadata:

```json
{
  "dcg_version": "1.2.3",
  "schema_version": 1,
  "command_name": "test",
  "success": true,
  "data": {
    // Command-specific payload
  },
  "metadata": {
    "elapsed_ms": 42,
    "robot_mode": true,
    "agent": {
      "detected": "claude-code",
      "trust_level": "medium"
    }
  }
}
```

### 6. Migration Strategy

1. **Phase 1 (Non-Breaking)**
   - Add `--robot` flag and `DCG_ROBOT` env var
   - Add `src/exit_codes.rs` module
   - Add `OutputFormat` enum
   - Document robot mode in AGENTS.md

2. **Phase 2 (Deprecation)**
   - Deprecate command-specific `--json` bool flags
   - Deprecate inconsistent format enums
   - Emit deprecation warnings when old flags are used
   - Old flags continue to work

3. **Phase 3 (Future)**
   - Remove deprecated flags in next major version
   - Consider gRPC/MCP native protocol

## Consequences

### Positive

- **Simpler agent integration**: Single `--robot` flag configures everything
- **Predictable behavior**: Agents know exactly what to expect
- **Stable contract**: JSON schema versioning prevents breaking changes
- **Better testing**: Golden file tests can verify robot mode output
- **Documentation**: Clear, centralized docs for agent developers

### Negative

- **More flags**: Adds another global flag to the CLI
- **Migration effort**: Existing scripts using `--json` need updates (eventually)
- **Maintenance**: Must maintain both human and robot output paths

### Neutral

- **Backward compatible**: All existing behavior continues to work
- **Opt-in**: Robot mode is not the default; humans get pretty output

## Implementation Notes

### Files to Modify

1. `src/cli.rs` - Add `--robot` flag and `OutputFormat` enum
2. `src/exit_codes.rs` - New file with exit code constants
3. `src/lib.rs` - Export exit_codes module
4. `src/main.rs` - Use exit codes, handle robot mode
5. `src/output/mod.rs` - Add robot mode output suppression
6. `docs/agents.md` - Document robot mode

### Testing Requirements

1. Golden file tests for robot mode JSON output
2. E2E tests verifying stderr suppression
3. Exit code verification tests
4. Environment variable tests (`DCG_ROBOT`)

## Related Beads

- `bd-7373`: Implement unified --robot global CLI flag
- `bd-87tn`: Standardize exit codes across all dcg commands
- `bd-1mvw`: Create unified OutputFormat enum for all CLI commands
- `bd-2s08`: Verify stdout/stderr separation
- `bd-z3h5`: E2E test script for agent workflow
- `bd-taet`: Golden file tests for JSON stability

## References

- [Claude Code Hook Protocol](https://docs.anthropic.com/claude-code/hooks)
- [Gemini CLI BeforeTool Hook](https://github.com/google-gemini/gemini-cli)
- [12-Factor App: Treat logs as event streams](https://12factor.net/logs)
- [Unix Philosophy: Write programs that do one thing well](https://en.wikipedia.org/wiki/Unix_philosophy)
