//! CLI argument parsing and command handling.
//!
//! This module provides the command-line interface for dcg (`destructive_command_guard`),
//! including subcommands for configuration management and pack information.

use clap::{Parser, Subcommand};

use crate::config::Config;
use crate::evaluator::{EvaluationDecision, MatchSource, evaluate_command};
use crate::load_default_allowlists;
use crate::packs::REGISTRY;

/// High-performance Claude Code hook for blocking destructive commands.
///
/// dcg (`destructive_command_guard`) protects against accidental execution of
/// destructive commands by AI coding agents. It blocks dangerous git commands,
/// filesystem operations, database queries, and more.
#[derive(Parser, Debug)]
#[command(name = "dcg")]
#[command(version, about, long_about = None)]
#[command(after_help = "Run 'dcg doctor' to verify your installation.")]
pub struct Cli {
    /// Subcommand to run (omit to run in hook mode)
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Available subcommands
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Check installation, configuration, and hook registration
    #[command(name = "doctor")]
    Doctor {
        /// Attempt to fix any issues found
        #[arg(long)]
        fix: bool,
    },

    /// Install the hook into Claude Code settings
    #[command(name = "install")]
    Install {
        /// Force overwrite existing hook configuration
        #[arg(long)]
        force: bool,
    },

    /// Remove the hook from Claude Code settings
    #[command(name = "uninstall")]
    Uninstall {
        /// Also remove configuration files
        #[arg(long)]
        purge: bool,
    },

    /// List all available packs and their status
    #[command(name = "packs")]
    ListPacks {
        /// Show only enabled packs
        #[arg(long)]
        enabled: bool,

        /// Show detailed information including pattern counts
        #[arg(short, long)]
        verbose: bool,
    },

    /// Show information about a specific pack
    #[command(name = "pack")]
    PackInfo {
        /// Pack ID (e.g., "database.postgresql", "core.git")
        pack_id: String,

        /// Show all patterns in the pack
        #[arg(long)]
        patterns: bool,
    },

    /// Test a command against enabled packs
    #[command(name = "test")]
    TestCommand {
        /// Command to test
        command: String,

        /// Additional packs to enable for this test
        #[arg(long, value_delimiter = ',')]
        with_packs: Option<Vec<String>>,
    },

    /// Generate a sample configuration file
    #[command(name = "init")]
    Init {
        /// Output path (defaults to stdout)
        #[arg(short, long)]
        output: Option<String>,

        /// Overwrite existing file
        #[arg(long)]
        force: bool,
    },

    /// Show current configuration
    #[command(name = "config")]
    ShowConfig,
}

/// Run the CLI command.
///
/// # Errors
///
/// Returns an error when no subcommand is provided (hook mode), or when a
/// subcommand that performs I/O fails.
pub fn run_command(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load();

    match cli.command {
        Some(Command::Doctor { fix }) => {
            doctor(fix);
        }
        Some(Command::Install { force }) => {
            install_hook(force)?;
        }
        Some(Command::Uninstall { purge }) => {
            uninstall_hook(purge)?;
        }
        Some(Command::ListPacks { enabled, verbose }) => {
            list_packs(&config, enabled, verbose);
        }
        Some(Command::PackInfo { pack_id, patterns }) => {
            pack_info(&pack_id, patterns)?;
        }
        Some(Command::TestCommand {
            command,
            with_packs,
        }) => {
            test_command(&config, &command, with_packs);
        }
        Some(Command::Init { output, force }) => {
            init_config(output, force)?;
        }
        Some(Command::ShowConfig) => {
            show_config(&config);
        }
        None => {
            // No subcommand - run in hook mode (default behavior)
            // This is handled by main.rs
            return Err("No subcommand provided. Running in hook mode.".into());
        }
    }

    Ok(())
}

/// List all packs and their status
fn list_packs(config: &Config, enabled_only: bool, verbose: bool) {
    let enabled_packs = config.enabled_pack_ids();
    let infos = REGISTRY.list_packs(&enabled_packs);

    println!("Available packs:");
    println!();

    // Group by category
    let mut by_category: std::collections::BTreeMap<&str, Vec<_>> =
        std::collections::BTreeMap::new();
    for info in &infos {
        let category = info.id.split('.').next().unwrap_or(&info.id);
        by_category.entry(category).or_default().push(info);
    }

    for (category, packs) in by_category {
        println!("  {category}:");
        for info in packs {
            if enabled_only && !info.enabled {
                continue;
            }

            let status = if info.enabled { "✓" } else { "○" };
            if verbose {
                println!(
                    "    {} {} - {} ({} safe, {} destructive)",
                    status,
                    info.id,
                    info.description,
                    info.safe_pattern_count,
                    info.destructive_pattern_count
                );
            } else {
                println!("    {} {} - {}", status, info.id, info.name);
            }
        }
        println!();
    }

    println!("Legend: ✓ = enabled, ○ = disabled");
    println!();
    println!("Enable packs in ~/.config/dcg/config.toml");
}

/// Show detailed information about a pack
fn pack_info(pack_id: &str, show_patterns: bool) -> Result<(), Box<dyn std::error::Error>> {
    let pack = REGISTRY
        .get(pack_id)
        .ok_or_else(|| format!("Pack not found: {pack_id}"))?;

    println!("Pack: {}", pack.name);
    println!("ID: {}", pack.id);
    println!("Description: {}", pack.description);
    println!("Keywords: {}", pack.keywords.join(", "));
    println!();
    println!("Patterns:");
    println!("  Safe patterns: {}", pack.safe_patterns.len());
    println!(
        "  Destructive patterns: {}",
        pack.destructive_patterns.len()
    );

    if show_patterns {
        println!();
        println!("Safe patterns:");
        for pattern in &pack.safe_patterns {
            println!("  - {} : {}", pattern.name, pattern.regex.as_str());
        }

        println!();
        println!("Destructive patterns:");
        for pattern in &pack.destructive_patterns {
            let name = pattern.name.unwrap_or("unnamed");
            println!("  - {} : {}", name, pattern.regex.as_str());
            println!("    Reason: {}", pattern.reason);
        }
    }

    Ok(())
}

/// Test a command against the configured packs using the shared evaluator.
///
/// This ensures parity with hook mode by using the same evaluation logic:
/// 1. Config allow overrides
/// 2. Config block overrides
/// 3. Quick rejection (keyword filtering)
/// 4. Command normalization
/// 5. Pack pattern matching
#[allow(clippy::needless_pass_by_value)] // Value is consumed from CLI args
fn test_command(config: &Config, command: &str, extra_packs: Option<Vec<String>>) {
    // Build effective config with extra packs if specified
    let effective_config = extra_packs.map_or_else(
        || config.clone(),
        |packs| {
            let mut modified = config.clone();
            modified.packs.enabled.extend(packs);
            modified
        },
    );

    // Get enabled packs and collect keywords for quick rejection
    let enabled_packs = effective_config.enabled_pack_ids();
    let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);

    // Compile overrides once (not per-command)
    let compiled_overrides = effective_config.overrides.compile();

    // Load allowlists (project/user/system) for parity with hook mode.
    // This is a small file read and only affects decisions when a rule matches.
    let allowlists = load_default_allowlists();

    // Use shared evaluator for consistent behavior with hook mode
    let result = evaluate_command(
        command,
        &effective_config,
        &enabled_keywords,
        &compiled_overrides,
        &allowlists,
    );

    println!("Command: {command}");
    println!();

    match result.decision {
        EvaluationDecision::Allow => {
            if let Some(override_info) = &result.allowlist_override {
                println!(
                    "Result: ALLOWED (allowlisted by {})",
                    override_info.layer.label()
                );
                println!("Allowlist reason: {}", override_info.reason);
            } else {
                println!("Result: ALLOWED");
            }
        }
        EvaluationDecision::Deny => {
            println!("Result: BLOCKED");
            if let Some(ref info) = result.pattern_info {
                if let Some(ref pack_id) = info.pack_id {
                    println!("Pack: {pack_id}");
                }
                if let Some(ref pattern_name) = info.pattern_name {
                    println!("Pattern: {pattern_name}");
                }
                println!("Reason: {}", info.reason);
                let source = match info.source {
                    MatchSource::ConfigOverride => "config override",
                    MatchSource::LegacyPattern => "legacy pattern",
                    MatchSource::Pack => "pack",
                    MatchSource::HeredocAst => "heredoc/inline script (AST)",
                };
                println!("Source: {source}");
            }
        }
    }
}

/// Generate a sample configuration file
fn init_config(output: Option<String>, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    let sample = Config::generate_sample_config();

    match output {
        Some(path) => {
            let path = std::path::Path::new(&path);
            if path.exists() && !force {
                return Err(
                    format!("File exists: {}. Use --force to overwrite.", path.display()).into(),
                );
            }

            // Create parent directories if needed
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            std::fs::write(path, sample)?;
            println!("Configuration written to: {}", path.display());
        }
        None => {
            println!("{sample}");
        }
    }

    Ok(())
}

/// Show the current configuration
fn show_config(config: &Config) {
    println!("Current configuration:");
    println!();
    println!("General:");
    println!("  Color: {}", config.general.color);
    println!("  Verbose: {}", config.general.verbose);
    println!("  Log file: {:?}", config.general.log_file);
    println!();
    println!("Enabled packs:");
    for pack in config.enabled_pack_ids() {
        println!("  - {pack}");
    }
    println!();
    println!("Disabled packs:");
    for pack in &config.packs.disabled {
        println!("  - {pack}");
    }
}

/// Check installation, configuration, and hook registration
fn doctor(fix: bool) {
    use colored::Colorize;

    println!("{}", "dcg doctor".green().bold());
    println!();

    let mut issues = 0;
    let mut fixed = 0;

    // Check 1: Binary in PATH
    print!("Checking binary in PATH... ");
    if which_dcg().is_some() {
        println!("{}", "OK".green());
    } else {
        println!("{}", "NOT FOUND".red());
        issues += 1;
        println!("  dcg binary not found in PATH");
        println!("  Run the install script or add to PATH manually");
    }

    // Check 2: Claude Code settings file exists
    print!("Checking Claude Code settings... ");
    let settings_path = claude_settings_path();
    if settings_path.exists() {
        println!("{}", "OK".green());
    } else {
        println!("{}", "NOT FOUND".yellow());
        println!("  ~/.claude/settings.json not found");
        println!("  This is normal if Claude Code hasn't been configured yet");
    }

    // Check 3: Hook is registered
    print!("Checking hook registration... ");
    match check_hook_registered() {
        Ok(true) => println!("{}", "OK".green()),
        Ok(false) => {
            println!("{}", "NOT REGISTERED".red());
            issues += 1;
            if fix {
                println!("  Attempting to register hook...");
                if install_hook(false).is_ok() {
                    println!("  {}", "Fixed!".green());
                    fixed += 1;
                } else {
                    println!("  {}", "Failed to fix".red());
                }
            } else {
                println!("  Run 'dcg install' to register the hook");
            }
        }
        Err(e) => {
            println!("{}", "ERROR".red());
            println!("  {e}");
        }
    }

    // Check 4: Config file
    print!("Checking configuration... ");
    let config_path = config_path();
    if config_path.exists() {
        println!("{} ({})", "OK".green(), config_path.display());
    } else {
        println!("{}", "USING DEFAULTS".yellow());
        println!("  No config file found, using defaults");
        println!("  Run 'dcg init -o ~/.config/dcg/config.toml' to create one");
    }

    // Check 5: Pattern packs
    print!("Checking pattern packs... ");
    let config = Config::load();
    let enabled = config.enabled_pack_ids();
    println!("{} ({} enabled)", "OK".green(), enabled.len());

    println!();
    if issues == 0 {
        println!("{}", "All checks passed!".green().bold());
    } else if fix && fixed == issues {
        println!("{}", "All issues fixed!".green().bold());
    } else {
        println!(
            "{} issue(s) found{}",
            issues.to_string().red().bold(),
            if fix {
                format!(", {fixed} fixed")
            } else {
                String::new()
            }
        );
    }
}

fn is_dcg_command(cmd: &str) -> bool {
    cmd == "dcg" || cmd.ends_with("/dcg")
}

fn is_dcg_hook_entry(entry: &serde_json::Value) -> bool {
    entry
        .get("matcher")
        .and_then(|m| m.as_str())
        .is_some_and(|m| m == "Bash")
        && entry
            .get("hooks")
            .and_then(|h| h.as_array())
            .is_some_and(|hooks| {
                hooks.iter().any(|hook| {
                    hook.get("command")
                        .and_then(|c| c.as_str())
                        .is_some_and(is_dcg_command)
                })
            })
}

/// Install the hook into Claude Code settings
fn install_hook(force: bool) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    let settings_path = claude_settings_path();

    // Read existing settings or create new
    let mut settings: serde_json::Value = if settings_path.exists() {
        let content = std::fs::read_to_string(&settings_path)?;
        serde_json::from_str(&content)?
    } else {
        // Create parent directory if needed
        if let Some(parent) = settings_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        serde_json::json!({})
    };

    // Check if hook already exists
    let hook_exists = settings
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(|arr| arr.as_array())
        .is_some_and(|a| a.iter().any(is_dcg_hook_entry));

    if hook_exists && !force {
        println!("{}", "Hook already installed!".yellow());
        println!("Use --force to reinstall");
        return Ok(());
    }

    // Build the hook configuration
    let hook_config = serde_json::json!({
        "matcher": "Bash",
        "hooks": [{
            "type": "command",
            "command": "dcg"
        }]
    });

    // Add or update the hook
    let hooks = settings
        .as_object_mut()
        .ok_or("Invalid settings format")?
        .entry("hooks")
        .or_insert(serde_json::json!({}));

    let pre_tool_use = hooks
        .as_object_mut()
        .ok_or("Invalid hooks format")?
        .entry("PreToolUse")
        .or_insert(serde_json::json!([]));

    // Remove existing dcg hooks if force
    if force {
        if let Some(arr) = pre_tool_use.as_array_mut() {
            arr.retain(|h| !is_dcg_hook_entry(h));
        }
    }

    // Add the new hook
    if let Some(arr) = pre_tool_use.as_array_mut() {
        arr.push(hook_config);
    }

    // Write back
    let content = serde_json::to_string_pretty(&settings)?;
    std::fs::write(&settings_path, content)?;

    println!("{}", "Hook installed successfully!".green().bold());
    println!("Settings updated: {}", settings_path.display());
    println!();
    println!(
        "{}",
        "Restart Claude Code for the changes to take effect.".yellow()
    );

    Ok(())
}

/// Remove the hook from Claude Code settings
fn uninstall_hook(purge: bool) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    let settings_path = claude_settings_path();

    if !settings_path.exists() {
        println!("{}", "No Claude Code settings found.".yellow());
        return Ok(());
    }

    // Read existing settings
    let content = std::fs::read_to_string(&settings_path)?;
    let mut settings: serde_json::Value = serde_json::from_str(&content)?;

    // Remove dcg hooks
    let mut removed = false;
    if let Some(hooks) = settings.get_mut("hooks") {
        if let Some(pre_tool_use) = hooks.get_mut("PreToolUse") {
            if let Some(arr) = pre_tool_use.as_array_mut() {
                let before = arr.len();
                arr.retain(|h| !is_dcg_hook_entry(h));
                removed = arr.len() < before;
            }
        }
    }

    if removed {
        // Write back
        let content = serde_json::to_string_pretty(&settings)?;
        std::fs::write(&settings_path, content)?;
        println!("{}", "Hook removed successfully!".green().bold());
    } else {
        println!("{}", "No dcg hook found in settings.".yellow());
    }

    // Purge config files if requested
    if purge {
        let config_dir = config_dir();
        if config_dir.exists() {
            std::fs::remove_dir_all(&config_dir)?;
            println!("Removed configuration directory: {}", config_dir.display());
        }
    }

    println!();
    println!(
        "{}",
        "Restart Claude Code for the changes to take effect.".yellow()
    );

    Ok(())
}

/// Get the path to Claude Code settings
fn claude_settings_path() -> std::path::PathBuf {
    dirs::home_dir()
        .unwrap_or_default()
        .join(".claude")
        .join("settings.json")
}

/// Get the path to dcg config directory
fn config_dir() -> std::path::PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".config"))
        .join("dcg")
}

/// Get the path to dcg config file
fn config_path() -> std::path::PathBuf {
    config_dir().join("config.toml")
}

/// Check if dcg is in PATH
fn which_dcg() -> Option<std::path::PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let path = dir.join("dcg");
            if path.is_file() { Some(path) } else { None }
        })
    })
}

/// Check if the hook is registered in Claude Code settings
fn check_hook_registered() -> Result<bool, Box<dyn std::error::Error>> {
    let settings_path = claude_settings_path();
    if !settings_path.exists() {
        return Ok(false);
    }

    let content = std::fs::read_to_string(&settings_path)?;
    let settings: serde_json::Value = serde_json::from_str(&content)?;

    let registered = settings
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(|arr| arr.as_array())
        .is_some_and(|a| a.iter().any(is_dcg_hook_entry));

    Ok(registered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parse_no_args() {
        let cli = Cli::parse_from(["dcg"]);
        assert!(cli.command.is_none());
    }

    #[test]
    fn test_cli_parse_packs() {
        let cli = Cli::parse_from(["dcg", "packs"]);
        assert!(matches!(cli.command, Some(Command::ListPacks { .. })));
    }

    #[test]
    fn test_cli_parse_packs_verbose() {
        let cli = Cli::parse_from(["dcg", "packs", "--verbose"]);
        if let Some(Command::ListPacks { verbose, .. }) = cli.command {
            assert!(verbose);
        } else {
            panic!("Expected ListPacks command");
        }
    }

    #[test]
    fn test_cli_parse_pack_info() {
        let cli = Cli::parse_from(["dcg", "pack", "core.git"]);
        if let Some(Command::PackInfo { pack_id, .. }) = cli.command {
            assert_eq!(pack_id, "core.git");
        } else {
            panic!("Expected PackInfo command");
        }
    }

    #[test]
    fn test_cli_parse_test() {
        let cli = Cli::parse_from(["dcg", "test", "git reset --hard"]);
        if let Some(Command::TestCommand { command, .. }) = cli.command {
            assert_eq!(command, "git reset --hard");
        } else {
            panic!("Expected TestCommand command");
        }
    }

    #[test]
    fn test_cli_parse_init() {
        let cli = Cli::parse_from(["dcg", "init"]);
        assert!(matches!(cli.command, Some(Command::Init { .. })));
    }
}
