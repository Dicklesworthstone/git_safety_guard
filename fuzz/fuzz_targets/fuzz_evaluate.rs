//! Fuzz target for the main evaluator entry point.
//!
//! This fuzzes `evaluate_command` with arbitrary command strings to find:
//! - Panics from unexpected input
//! - Regex catastrophic backtracking
//! - Memory issues from adversarial input

#![no_main]

use libfuzzer_sys::fuzz_target;

use destructive_command_guard::LayeredAllowlist;
use destructive_command_guard::config::Config;
use destructive_command_guard::config::CompiledOverrides;
use destructive_command_guard::evaluator::evaluate_command;
use std::sync::LazyLock;

static EMPTY_ALLOWLISTS: LazyLock<LayeredAllowlist> = LazyLock::new(LayeredAllowlist::default);
static DEFAULT_CONFIG_AND_OVERRIDES: LazyLock<(Config, CompiledOverrides)> = LazyLock::new(|| {
    let config = Config::default();
    let compiled_overrides = config.overrides.compile();
    (config, compiled_overrides)
});

fuzz_target!(|data: &[u8]| {
    // Try to interpret the bytes as UTF-8
    if let Ok(command) = std::str::from_utf8(data) {
        // Skip extremely large inputs to avoid timeout (not a real bug)
        if command.len() > 10_000 {
            return;
        }

        // Use default config for consistent behavior (cached for fuzzing throughput).
        let (config, compiled_overrides) = &*DEFAULT_CONFIG_AND_OVERRIDES;
        let allowlists = &EMPTY_ALLOWLISTS;

        // Test with various keyword combinations
        let all_keywords = &[
            "git",
            "rm",
            "docker",
            "kubectl",
            "psql",
            "mysql",
            "mongosh",
            "redis-cli",
        ];

        // Evaluate - this should never panic
        let _ = evaluate_command(
            command,
            config,
            all_keywords,
            compiled_overrides,
            allowlists,
        );

        // Also test with empty keywords (triggers different code paths)
        let _ = evaluate_command(command, config, &[], compiled_overrides, allowlists);
    }
});
