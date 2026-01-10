# Pack Expansion Guide

This guide details the process, tools, and standards for adding new packs to `destructive_command_guard`.

## Prerequisites

- Rust nightly toolchain
- `cargo-nextest` (recommended for faster tests)
- `jq` (for processing test output)

## 1. Create the Pack Module

1.  Identify the category (e.g., `containers`, `database`). If it's new, create `src/packs/<category>/mod.rs`.
2.  Create `src/packs/<category>/<tool>.rs`.
3.  Implement the `create_pack()` function returning a `Pack`.

```rust
use crate::packs::{Pack, Pattern, destructive};
use std::sync::LazyLock;
use fancy_regex::Regex;

pub fn create_pack() -> Pack {
    Pack {
        id: "category.tool".to_string(),
        name: "Tool Name".to_string(),
        description: "Blocks destructive Tool commands".to_string(),
        keywords: vec!["tool".to_string()],
        safe_patterns: vec![
            pattern!("list", r"tool\s+list"),
        ],
        destructive_patterns: vec![
            destructive!(r"tool\s+delete", "deletes resources"),
        ],
    }
}
```

## 2. Unit Testing (Required)

We use a standardized template for unit tests to ensure coverage of edge cases, severity, and performance.

1.  Open `src/packs/test_template.rs`.
2.  Copy the `mod tests { ... }` block.
3.  Paste it at the bottom of your new pack file.
4.  Adapt the tests:
    *   Change `example_pack` to `super`.
    *   Update destructive/safe test cases.
    *   Keep the edge case/performance tests (adapt inputs if needed).

```bash
# Run unit tests
cargo test packs::category::tool
```

## 3. E2E Testing (Required)

Every pack must have a dedicated shell script for verification in a real environment.

1.  Copy the template:
    ```bash
    cp scripts/templates/test_pack.sh scripts/test_pack_tool.sh
    chmod +x scripts/test_pack_tool.sh
    ```
2.  Edit `scripts/test_pack_tool.sh`:
    *   Set `PACK_NAME` (e.g., "category.tool").
    *   Add `test_cmd` calls for your destructive and safe patterns.
3.  Run it:
    ```bash
    ./scripts/test_pack_tool.sh --verbose
    ```

## 4. Test Fixtures

Add your destructive commands to the central database. This allows global regression testing.

1.  Open `tests/fixtures/destructive_commands.yaml`.
2.  Add a new section for your pack:

```yaml
category.tool:
  - command: "tool delete prod"
    reason: "deletes production resources"
  - command: "tool nuke --force"
    reason: "wipes everything"
```

## 5. Registration

1.  Add `pub mod tool;` to `src/packs/<category>/mod.rs`.
2.  Add `category::tool::create_pack` to `PACK_ENTRIES` in `src/packs/mod.rs`.

## 6. Validation

Run the full suite to ensure no regressions:

```bash
# Unit tests
cargo test

# Global E2E
./scripts/e2e_test.sh

# Your pack E2E
./scripts/test_pack_tool.sh
```
