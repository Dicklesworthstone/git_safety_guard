# RESEARCH_FINDINGS: TOON Integration for dcg (destructive_command_guard)

Last updated: 2026-01-24

## Executive Summary

dcg is a Rust CLI with two distinct machine-facing surfaces:

1. **Hook protocol** (Claude Code `PreToolUse`): stdin JSON, stdout **JSON** (camelCase fields).
2. **Robot mode** (`--robot` or `DCG_ROBOT=1`): stdout **JSON**, stderr silent, standardized exit codes.

Because these are integration contracts, TOON support should be scoped to **CLI-only**
structured outputs (commands that already support `--format json`) and must be implemented
via the **toon_rust crate** (never the Node.js `toon` CLI).

## Code Map (Where JSON Is Emitted / Consumed)

### Hook protocol (JSON-only; protocol constraint)

- `src/hook.rs`
  - `HookInput` / `ToolInput` (stdin JSON)
  - `HookOutput` / `HookSpecificOutput` (stdout JSON; camelCase via `serde(rename = "...")`)
  - Must remain JSON (agent hook protocol requirement).

- `src/main.rs`
  - Detects hook mode (no subcommand) and parses stdin JSON.
  - Note: main.rs comments explicitly call out hook input/output types in `hook` module.

- `src/cli.rs`
  - `dcg hook --batch`: JSONL input, JSONL output
  - `BatchHookOutput` is the line-by-line schema.

### CLI JSON outputs (potential TOON targets)

- `src/cli.rs`
  - `dcg test`:
    - `TestFormat::{Pretty, Json}`
    - `TestOutput` schema (decision, rule_id, agent info, etc.)
    - `test_command(...)` prints JSON via `serde_json::to_string_pretty(&TestOutput)`
  - `dcg packs`: `PacksFormat::{Pretty, Json}` and `PacksOutput`
  - Many other commands have local `Format` enums (often `{Pretty, Json}`).
  - Robot mode currently forces JSON in command handlers (format overrides).

- `src/scan.rs`
  - `ScanFormat::{Pretty, Json, Markdown, Sarif}` and scan report structs.

## Recommended TOON Scope

### Non-regression constraints

- Hook protocol: **JSON / JSONL only**, regardless of env vars.
- Robot mode: **JSON only by default**, regardless of env vars.

### Phase 1 (minimal, safe)

Add TOON output only for CLI commands that already have JSON output and are not part
of the hook protocol:

- `dcg test --format toon`
- (Optional) `dcg scan --format toon` (if scan payload is useful; outputs can be large)

### Phase 2 (optional)

If we later support TOON in robot mode, require explicit opt-in (e.g., `--format toon`)
and keep hook protocol ignoring env overrides.

## Implementation Plan (Rust: crate-based, no subprocess)

1. Add `toon_rust` dependency to `Cargo.toml`:
   - Local dev path: `toon_rust = { path = \"../toon_rust\" }`
   - Or git dependency for releases.

2. Add a small helper:
   - Convert payload structs to `serde_json::Value` and encode with `toon_rust::encode(...)`.

3. Extend relevant format enums to include `toon`.

4. For `--format toon`, print encoded TOON string to stdout.

## Env / Flag Precedence (Proposed)

For CLI-only commands:

1. `--format`
2. `DCG_OUTPUT_FORMAT` (new) or keep existing `DCG_FORMAT`
3. `TOON_DEFAULT_FORMAT`
4. Default per-command (usually `pretty`)

For hook protocol and robot mode:

- Ignore `DCG_OUTPUT_FORMAT` / `TOON_DEFAULT_FORMAT`; keep JSON contract.

## Fixtures / Sample Outputs

Use `dcg test` for side-effect-free fixtures:

- Allow: `dcg test \"git status\" --format json`
- Deny: `dcg test \"rm -rf /\" --format json`
- TOON: same payloads encoded via `toon_rust::encode`

## Related Document

- `TOON_INTEGRATION_BRIEF.md` (more detailed plan + sample payloads + test design).

