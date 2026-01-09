//! Configuration system for dcg.
//!
//! Supports layered configuration from multiple sources:
//! 1. Environment variables (highest priority)
//! 2. Project config (.dcg.toml in repo root)
//! 3. User config (~/.config/dcg/config.toml)
//! 4. System config (/etc/dcg/config.toml)
//! 5. Compiled defaults (lowest priority)

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Environment variable prefix for all config options.
const ENV_PREFIX: &str = "DCG";

/// Default config file name.
const CONFIG_FILE_NAME: &str = "config.toml";

/// Project-level config file name.
const PROJECT_CONFIG_NAME: &str = ".dcg.toml";

/// Main configuration structure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// General settings.
    pub general: GeneralConfig,

    /// Pack configuration.
    pub packs: PacksConfig,

    /// Decision mode policy configuration.
    pub policy: PolicyConfig,

    /// Custom overrides.
    pub overrides: OverridesConfig,

    /// Heredoc/inline-script scanning configuration.
    pub heredoc: HeredocConfig,

    /// Project-specific configurations (keyed by absolute path).
    #[serde(default)]
    pub projects: std::collections::HashMap<String, ProjectConfig>,
}

/// Heredoc and inline-script scanning configuration.
///
/// This configuration controls Tier 1/2/3 heredoc scanning behavior. Because the
/// hook is performance- and UX-sensitive, defaults are conservative and fail-open
/// on extraction/parse errors.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HeredocConfig {
    /// Enable heredoc/inline-script scanning.
    pub enabled: Option<bool>,

    /// Timeout budget for Tier 2 extraction (milliseconds).
    pub timeout_ms: Option<u64>,

    /// Maximum bytes extracted from heredoc bodies.
    pub max_body_bytes: Option<usize>,

    /// Maximum number of lines extracted from heredoc bodies.
    pub max_body_lines: Option<usize>,

    /// Maximum number of heredocs to process per command.
    pub max_heredocs: Option<usize>,

    /// Optional allowlist of languages to scan.
    ///
    /// Values are case-insensitive and may include aliases:
    /// - bash: bash, sh, shell
    /// - javascript: javascript, js, node
    /// - typescript: typescript, ts
    pub languages: Option<Vec<String>>,

    /// Fail-open when AST parsing fails for embedded code.
    pub fallback_on_parse_error: Option<bool>,

    /// Fail-open when extraction/parsing exceeds the timeout budget.
    pub fallback_on_timeout: Option<bool>,
}

/// Effective heredoc scanning settings used by the evaluator.
#[derive(Debug, Clone)]
pub struct HeredocSettings {
    pub enabled: bool,
    pub limits: crate::heredoc::ExtractionLimits,
    pub allowed_languages: Option<Vec<crate::heredoc::ScriptLanguage>>,
    pub fallback_on_parse_error: bool,
    pub fallback_on_timeout: bool,
}

impl HeredocConfig {
    #[must_use]
    pub fn settings(&self) -> HeredocSettings {
        let mut limits = crate::heredoc::ExtractionLimits::default();
        if let Some(timeout_ms) = self.timeout_ms {
            limits.timeout_ms = timeout_ms;
        }
        if let Some(max_body_bytes) = self.max_body_bytes {
            limits.max_body_bytes = max_body_bytes;
        }
        if let Some(max_body_lines) = self.max_body_lines {
            limits.max_body_lines = max_body_lines;
        }
        if let Some(max_heredocs) = self.max_heredocs {
            limits.max_heredocs = max_heredocs;
        }

        let allowed_languages = self.languages.as_ref().and_then(|langs| {
            let mut parsed: Vec<crate::heredoc::ScriptLanguage> = Vec::new();
            for raw in langs {
                let raw = raw.trim();
                if raw.is_empty() {
                    continue;
                }

                if raw.eq_ignore_ascii_case("all") {
                    return None;
                }

                let lang = match raw.to_ascii_lowercase().as_str() {
                    "bash" | "sh" | "shell" => Some(crate::heredoc::ScriptLanguage::Bash),
                    "python" => Some(crate::heredoc::ScriptLanguage::Python),
                    "ruby" => Some(crate::heredoc::ScriptLanguage::Ruby),
                    "perl" => Some(crate::heredoc::ScriptLanguage::Perl),
                    "javascript" | "js" | "node" => {
                        Some(crate::heredoc::ScriptLanguage::JavaScript)
                    }
                    "typescript" | "ts" => Some(crate::heredoc::ScriptLanguage::TypeScript),
                    "unknown" => Some(crate::heredoc::ScriptLanguage::Unknown),
                    _ => None,
                };

                if let Some(lang) = lang {
                    if !parsed.contains(&lang) {
                        parsed.push(lang);
                    }
                }
            }

            if parsed.is_empty() {
                // Avoid accidental full-disable due to typos: treat as "all".
                None
            } else {
                Some(parsed)
            }
        });

        HeredocSettings {
            enabled: self.enabled.unwrap_or(true),
            limits,
            allowed_languages,
            fallback_on_parse_error: self.fallback_on_parse_error.unwrap_or(true),
            fallback_on_timeout: self.fallback_on_timeout.unwrap_or(true),
        }
    }
}

/// General configuration options.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    /// Color output mode: "auto", "always", "never".
    pub color: String,

    /// Path to log file for blocked commands (optional).
    pub log_file: Option<String>,

    /// Whether to show verbose output.
    pub verbose: bool,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            color: "auto".to_string(),
            log_file: None,
            verbose: false,
        }
    }
}

/// Pack enablement configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PacksConfig {
    /// List of enabled packs (e.g., `["database.postgresql", "kubernetes"]`).
    pub enabled: Vec<String>,

    /// List of explicitly disabled packs (for disabling sub-packs of enabled categories).
    pub disabled: Vec<String>,
}

/// Decision mode policy configuration.
///
/// Controls how matched patterns are handled: deny (block), warn (allow with warning),
/// or log (silent allow with optional logging).
///
/// Defaults respect severity: Critical/High → deny, Medium → warn, Low → log.
/// This config allows overriding the default behavior per pack or per specific rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyConfig {
    /// Global default mode (overrides severity-based defaults).
    /// If not set, severity-based defaults apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_mode: Option<PolicyMode>,

    /// Optional observe-mode window end timestamp.
    ///
    /// When set and the current time is **before** this timestamp:
    /// - `default_mode` applies, but defaults to `"warn"` when unset.
    ///
    /// When set and the current time is **at/after** this timestamp:
    /// - `default_mode` is ignored and dcg reverts to severity-based defaults.
    ///
    /// Accepted formats:
    /// - RFC 3339: `2026-02-01T00:00:00Z`
    /// - ISO 8601 without timezone (treated as UTC): `2026-02-01T00:00:00`
    /// - Date only (treated as end of day UTC): `2026-02-01`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observe_until: Option<ObserveUntil>,

    /// Per-pack mode overrides.
    /// Key is `pack_id` (e.g., "core.git", "database.postgresql").
    /// Value is the mode to use for all patterns in that pack.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub packs: std::collections::HashMap<String, PolicyMode>,

    /// Per-rule mode overrides.
    /// Key is `rule_id` (e.g., "core.git:reset-hard", "core.filesystem:rm-rf-root").
    /// Value is the mode to use for that specific rule.
    /// Takes precedence over pack-level and global overrides.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub rules: std::collections::HashMap<String, PolicyMode>,
}

/// Policy mode for overriding default decision behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    /// Block the command (output JSON deny, print warning).
    Deny,
    /// Warn but allow (print warning to stderr, no JSON deny).
    Warn,
    /// Log only (silent allow, record for telemetry).
    Log,
}

impl PolicyMode {
    /// Convert to the internal `DecisionMode`.
    #[must_use]
    pub const fn to_decision_mode(self) -> crate::packs::DecisionMode {
        match self {
            Self::Deny => crate::packs::DecisionMode::Deny,
            Self::Warn => crate::packs::DecisionMode::Warn,
            Self::Log => crate::packs::DecisionMode::Log,
        }
    }
}

impl PolicyConfig {
    /// Resolve the effective decision mode for a given rule.
    ///
    /// Priority (highest to lowest):
    /// 1. Rule-specific override (via `rules["pack_id:pattern_name"]`)
    /// 2. Pack-specific override (via `packs["pack_id"]`)
    /// 3. Global default (`default_mode`)
    /// 4. Severity-based default (from pattern's severity)
    #[must_use]
    pub fn resolve_mode(
        &self,
        pack_id: Option<&str>,
        pattern_name: Option<&str>,
        severity: Option<crate::packs::Severity>,
    ) -> crate::packs::DecisionMode {
        self.resolve_mode_at(Utc::now(), pack_id, pattern_name, severity)
    }

    #[must_use]
    pub fn resolve_mode_at(
        &self,
        now: DateTime<Utc>,
        pack_id: Option<&str>,
        pattern_name: Option<&str>,
        severity: Option<crate::packs::Severity>,
    ) -> crate::packs::DecisionMode {
        // 1. Rule-specific override
        if let (Some(pack), Some(pattern)) = (pack_id, pattern_name) {
            let rule_id = format!("{pack}:{pattern}");
            if let Some(mode) = self.rules.get(&rule_id) {
                return mode.to_decision_mode();
            }
        }

        // Safety constraint: Critical rules may only be loosened via an explicit per-rule override.
        // Pack-level/global defaults must never downgrade Critical to warn/log.
        if matches!(severity, Some(crate::packs::Severity::Critical)) {
            return crate::packs::DecisionMode::Deny;
        }

        // 2. Pack-specific override
        if let Some(pack) = pack_id {
            if let Some(mode) = self.packs.get(pack) {
                return mode.to_decision_mode();
            }
        }

        // 3. Global default (optionally gated by observe_until)
        let effective_default_mode = self
            .observe_until
            .as_ref()
            .and_then(ObserveUntil::parsed_utc)
            .map_or(self.default_mode, |until| {
                if &now < until {
                    Some(self.default_mode.unwrap_or(PolicyMode::Warn))
                } else {
                    None
                }
            });

        if let Some(mode) = effective_default_mode {
            return mode.to_decision_mode();
        }

        // 4. Severity-based default
        severity.map_or(crate::packs::DecisionMode::Deny, |s| s.default_mode())
    }
}

/// Custom pattern overrides.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OverridesConfig {
    /// Patterns to allow that would otherwise be blocked.
    #[serde(default)]
    pub allow: Vec<AllowOverride>,

    /// Additional patterns to block.
    #[serde(default)]
    pub block: Vec<BlockOverride>,
}

/// An allow override - patterns that should be permitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AllowOverride {
    /// Simple pattern string.
    Simple(String),
    /// Conditional override with optional `when` clause.
    Conditional {
        pattern: String,
        /// Optional condition (e.g., "CI=true").
        when: Option<String>,
    },
}

impl AllowOverride {
    /// Get the pattern string.
    #[must_use]
    pub fn pattern(&self) -> &str {
        match self {
            Self::Simple(p) => p,
            Self::Conditional { pattern, .. } => pattern,
        }
    }

    /// Check if the condition is met (if any).
    #[must_use]
    pub fn condition_met(&self) -> bool {
        match self {
            Self::Simple(_) | Self::Conditional { when: None, .. } => true,
            Self::Conditional {
                when: Some(condition),
                ..
            } => {
                // Parse condition like "CI=true"
                if let Some((var, expected)) = condition.split_once('=') {
                    env::var(var).map(|v| v == expected).unwrap_or(false)
                } else {
                    // Just check if the env var is set
                    env::var(condition).is_ok()
                }
            }
        }
    }
}

/// A block override - additional patterns to block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockOverride {
    /// The regex pattern to match.
    pub pattern: String,
    /// Human-readable reason for blocking.
    pub reason: String,
}

// ============================================================================
// Compiled Overrides (Runtime-Only, Pre-compiled Regexes)
// ============================================================================

use fancy_regex::Regex;

/// A compiled allow override with precompiled regex.
///
/// This is the runtime representation used for evaluation.
/// Created once at config load time, not per-command.
#[derive(Debug)]
pub struct CompiledAllowOverride {
    /// The precompiled regex pattern.
    pub regex: Regex,
    /// The original pattern string (for diagnostics).
    pub pattern: String,
    /// The condition evaluator (returns true if condition is met).
    /// For simple overrides, this always returns true.
    /// For conditional overrides, this checks the environment.
    condition: ConditionCheck,
}

/// Condition check type - either always true or checks an env var.
#[derive(Debug)]
enum ConditionCheck {
    /// Always allow (no condition).
    Always,
    /// Check if env var equals expected value.
    EnvEquals { var: String, expected: String },
    /// Check if env var is set (any value).
    EnvSet { var: String },
}

impl ConditionCheck {
    /// Check if the condition is met.
    fn is_met(&self) -> bool {
        match self {
            Self::Always => true,
            Self::EnvEquals { var, expected } => {
                std::env::var(var).map(|v| v == *expected).unwrap_or(false)
            }
            Self::EnvSet { var } => std::env::var(var).is_ok(),
        }
    }
}

impl CompiledAllowOverride {
    /// Check if this override matches and its condition is met.
    ///
    /// Returns true if the command matches and should be allowed.
    #[inline]
    #[must_use]
    pub fn matches(&self, command: &str) -> bool {
        self.condition.is_met() && self.regex.is_match(command).unwrap_or(false)
    }
}

/// A compiled block override with precompiled regex.
#[derive(Debug)]
pub struct CompiledBlockOverride {
    /// The precompiled regex pattern.
    pub regex: Regex,
    /// The original pattern string (for diagnostics).
    pub pattern: String,
    /// Human-readable reason for blocking.
    pub reason: String,
}

impl CompiledBlockOverride {
    /// Check if this override matches.
    ///
    /// Returns the reason if blocked.
    #[inline]
    #[must_use]
    pub fn matches(&self, command: &str) -> Option<&str> {
        if self.regex.is_match(command).unwrap_or(false) {
            Some(&self.reason)
        } else {
            None
        }
    }
}

/// Compiled overrides - runtime representation with precompiled regexes.
///
/// This struct is created once per config load and reused for all command
/// evaluations. It eliminates per-command regex compilation overhead.
#[derive(Debug, Default)]
pub struct CompiledOverrides {
    /// Compiled allow overrides.
    pub allow: Vec<CompiledAllowOverride>,
    /// Compiled block overrides.
    pub block: Vec<CompiledBlockOverride>,
    /// Patterns that failed to compile (for diagnostics).
    pub invalid_patterns: Vec<InvalidPattern>,
}

/// Record of a pattern that failed to compile.
#[derive(Debug, Clone)]
pub struct InvalidPattern {
    /// The original pattern string.
    pub pattern: String,
    /// The compilation error message.
    pub error: String,
    /// Whether this was an allow or block pattern.
    pub kind: PatternKind,
}

/// Kind of override pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternKind {
    Allow,
    Block,
}

impl CompiledOverrides {
    /// Check allow overrides. Returns true if command should be allowed.
    #[inline]
    #[must_use]
    pub fn check_allow(&self, command: &str) -> bool {
        self.allow.iter().any(|o| o.matches(command))
    }

    /// Check block overrides. Returns the reason if command should be blocked.
    #[inline]
    #[must_use]
    pub fn check_block(&self, command: &str) -> Option<&str> {
        self.block.iter().find_map(|o| o.matches(command))
    }

    /// Check if there are any invalid patterns.
    #[must_use]
    pub fn has_invalid_patterns(&self) -> bool {
        !self.invalid_patterns.is_empty()
    }
}

impl OverridesConfig {
    /// Compile all override patterns into precompiled regexes.
    ///
    /// Invalid patterns are collected but do not cause errors (fail-open).
    /// Use `CompiledOverrides::invalid_patterns` to check for issues.
    #[must_use]
    pub fn compile(&self) -> CompiledOverrides {
        let mut compiled = CompiledOverrides::default();

        // Compile allow overrides
        for allow in &self.allow {
            match Regex::new(allow.pattern()) {
                Ok(regex) => {
                    let condition = match allow {
                        AllowOverride::Simple(_)
                        | AllowOverride::Conditional { when: None, .. } => ConditionCheck::Always,
                        AllowOverride::Conditional {
                            when: Some(condition),
                            ..
                        } => {
                            if let Some((var, expected)) = condition.split_once('=') {
                                ConditionCheck::EnvEquals {
                                    var: var.to_string(),
                                    expected: expected.to_string(),
                                }
                            } else {
                                ConditionCheck::EnvSet {
                                    var: condition.clone(),
                                }
                            }
                        }
                    };
                    compiled.allow.push(CompiledAllowOverride {
                        regex,
                        pattern: allow.pattern().to_string(),
                        condition,
                    });
                }
                Err(e) => {
                    compiled.invalid_patterns.push(InvalidPattern {
                        pattern: allow.pattern().to_string(),
                        error: e.to_string(),
                        kind: PatternKind::Allow,
                    });
                }
            }
        }

        // Compile block overrides
        for block in &self.block {
            match Regex::new(&block.pattern) {
                Ok(regex) => {
                    compiled.block.push(CompiledBlockOverride {
                        regex,
                        pattern: block.pattern.clone(),
                        reason: block.reason.clone(),
                    });
                }
                Err(e) => {
                    compiled.invalid_patterns.push(InvalidPattern {
                        pattern: block.pattern.clone(),
                        error: e.to_string(),
                        kind: PatternKind::Block,
                    });
                }
            }
        }

        compiled
    }
}

/// Project-specific configuration overrides.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProjectConfig {
    /// Pack configuration for this project.
    pub packs: Option<PacksConfig>,

    /// Overrides for this project.
    pub overrides: Option<OverridesConfig>,
}

impl Config {
    /// Load configuration from all sources, merging them in priority order.
    ///
    /// Priority (highest to lowest):
    /// 1. Environment variables
    /// 2. Project config (.dcg.toml)
    /// 3. User config (~/.config/dcg/config.toml)
    /// 4. System config (/etc/dcg/config.toml)
    /// 5. Compiled defaults
    #[must_use]
    pub fn load() -> Self {
        let mut config = Self::default();

        // Load system config (lowest priority of file configs)
        if let Some(system_config) = Self::load_system_config() {
            config.merge(system_config);
        }

        // Load user config
        if let Some(user_config) = Self::load_user_config() {
            config.merge(user_config);
        }

        // Load project config (if in a git repo)
        if let Some(project_config) = Self::load_project_config() {
            config.merge(project_config);
        }

        // Apply environment variable overrides (highest priority)
        config.apply_env_overrides();

        config
    }

    /// Load configuration from a specific file.
    #[must_use]
    pub fn load_from_file(path: &Path) -> Option<Self> {
        let content = fs::read_to_string(path).ok()?;
        toml::from_str(&content).ok()
    }

    /// Load system-wide configuration.
    fn load_system_config() -> Option<Self> {
        let path = PathBuf::from("/etc/dcg").join(CONFIG_FILE_NAME);
        Self::load_from_file(&path)
    }

    /// Load user configuration.
    fn load_user_config() -> Option<Self> {
        let config_dir = dirs::config_dir()?;
        let path = config_dir.join("dcg").join(CONFIG_FILE_NAME);
        Self::load_from_file(&path)
    }

    /// Load project-level configuration.
    fn load_project_config() -> Option<Self> {
        // Try to find .dcg.toml in current dir or parent dirs
        let mut current = env::current_dir().ok()?;

        loop {
            let config_path = current.join(PROJECT_CONFIG_NAME);
            if config_path.exists() {
                return Self::load_from_file(&config_path);
            }

            // Also check for .git directory to find repo root
            let git_dir = current.join(".git");
            if git_dir.exists() {
                // We're at the repo root, check for config here
                let config_path = current.join(PROJECT_CONFIG_NAME);
                return Self::load_from_file(&config_path);
            }

            // Move to parent directory
            if !current.pop() {
                break;
            }
        }

        None
    }

    /// Merge another config into this one (other takes priority).
    fn merge(&mut self, other: Self) {
        // Merge general settings
        if other.general.color != "auto" {
            self.general.color = other.general.color;
        }
        if other.general.log_file.is_some() {
            self.general.log_file = other.general.log_file;
        }
        if other.general.verbose {
            self.general.verbose = true;
        }

        // Merge packs (append, don't replace)
        self.packs.enabled.extend(other.packs.enabled);
        self.packs.disabled.extend(other.packs.disabled);

        // Merge policy config (other takes priority)
        if other.policy.default_mode.is_some() {
            self.policy.default_mode = other.policy.default_mode;
        }
        if other.policy.observe_until.is_some() {
            self.policy.observe_until = other.policy.observe_until;
        }
        self.policy.packs.extend(other.policy.packs);
        self.policy.rules.extend(other.policy.rules);

        // Merge overrides (append)
        self.overrides.allow.extend(other.overrides.allow);
        self.overrides.block.extend(other.overrides.block);

        // Merge heredoc config (field-wise; other wins when set)
        if other.heredoc.enabled.is_some() {
            self.heredoc.enabled = other.heredoc.enabled;
        }
        if other.heredoc.timeout_ms.is_some() {
            self.heredoc.timeout_ms = other.heredoc.timeout_ms;
        }
        if other.heredoc.max_body_bytes.is_some() {
            self.heredoc.max_body_bytes = other.heredoc.max_body_bytes;
        }
        if other.heredoc.max_body_lines.is_some() {
            self.heredoc.max_body_lines = other.heredoc.max_body_lines;
        }
        if other.heredoc.max_heredocs.is_some() {
            self.heredoc.max_heredocs = other.heredoc.max_heredocs;
        }
        if other.heredoc.languages.is_some() {
            self.heredoc.languages = other.heredoc.languages;
        }
        if other.heredoc.fallback_on_parse_error.is_some() {
            self.heredoc.fallback_on_parse_error = other.heredoc.fallback_on_parse_error;
        }
        if other.heredoc.fallback_on_timeout.is_some() {
            self.heredoc.fallback_on_timeout = other.heredoc.fallback_on_timeout;
        }

        // Merge project configs
        self.projects.extend(other.projects);
    }

    /// Apply environment variable overrides.
    fn apply_env_overrides(&mut self) {
        self.apply_env_overrides_from(|key| env::var(key).ok());
    }

    fn apply_env_overrides_from<F>(&mut self, mut get_env: F)
    where
        F: FnMut(&str) -> Option<String>,
    {
        // DCG_PACKS="core,database.postgresql,kubernetes"
        if let Some(packs) = get_env(&format!("{ENV_PREFIX}_PACKS")) {
            self.packs.enabled = packs.split(',').map(|s| s.trim().to_string()).collect();
        }

        // DCG_DISABLE="kubernetes.helm"
        if let Some(disable) = get_env(&format!("{ENV_PREFIX}_DISABLE")) {
            self.packs.disabled = disable.split(',').map(|s| s.trim().to_string()).collect();
        }

        // DCG_VERBOSE=1
        if get_env(&format!("{ENV_PREFIX}_VERBOSE")).is_some() {
            self.general.verbose = true;
        }

        // DCG_COLOR=never
        if let Some(color) = get_env(&format!("{ENV_PREFIX}_COLOR")) {
            self.general.color = color;
        }

        // -----------------------------------------------------------------
        // Heredoc scanning (env overrides)
        // -----------------------------------------------------------------

        // DCG_HEREDOC_ENABLED=true|false|1|0
        if let Some(enabled) = get_env(&format!("{ENV_PREFIX}_HEREDOC_ENABLED")) {
            if let Some(parsed) = parse_env_bool(&enabled) {
                self.heredoc.enabled = Some(parsed);
            }
        }

        // DCG_HEREDOC_TIMEOUT=50 (ms)
        let timeout_var = format!("{ENV_PREFIX}_HEREDOC_TIMEOUT");
        let timeout_ms_var = format!("{ENV_PREFIX}_HEREDOC_TIMEOUT_MS");
        if let Some(timeout_ms) = get_env(&timeout_ms_var).or_else(|| get_env(&timeout_var)) {
            if let Ok(parsed) = timeout_ms.trim().parse::<u64>() {
                self.heredoc.timeout_ms = Some(parsed);
            }
        }

        // DCG_HEREDOC_LANGUAGES=python,bash,javascript
        if let Some(langs) = get_env(&format!("{ENV_PREFIX}_HEREDOC_LANGUAGES")) {
            let parsed: Vec<String> = langs
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !parsed.is_empty() {
                self.heredoc.languages = Some(parsed);
            }
        }

        // -----------------------------------------------------------------
        // Policy config (env overrides)
        // -----------------------------------------------------------------

        // DCG_POLICY_DEFAULT_MODE=deny|warn|log
        if let Some(mode) = get_env(&format!("{ENV_PREFIX}_POLICY_DEFAULT_MODE")) {
            if let Some(parsed) = parse_policy_mode(&mode) {
                self.policy.default_mode = Some(parsed);
            }
        }

        // DCG_POLICY_OBSERVE_UNTIL=2030-01-01T00:00:00Z
        if let Some(observe_until) = get_env(&format!("{ENV_PREFIX}_POLICY_OBSERVE_UNTIL")) {
            self.policy.observe_until = ObserveUntil::parse(&observe_until);
        }
    }

    /// Get a reference to the policy config.
    #[must_use]
    pub const fn policy(&self) -> &PolicyConfig {
        &self.policy
    }

    /// Check if the bypass flag is set (escape hatch).
    #[must_use]
    pub fn is_bypassed() -> bool {
        env::var(format!("{ENV_PREFIX}_BYPASS")).is_ok()
    }

    /// Get the effective pack configuration for a specific project path.
    #[must_use]
    pub fn effective_packs_for_project(&self, project_path: &Path) -> PacksConfig {
        // Check if there's a project-specific config
        let path_str = project_path.to_string_lossy();

        for (project_pattern, project_config) in &self.projects {
            if path_str.starts_with(project_pattern) {
                if let Some(packs) = &project_config.packs {
                    return packs.clone();
                }
            }
        }

        // Fall back to global config
        self.packs.clone()
    }

    /// Get enabled pack IDs as a deduplicated set.
    #[must_use]
    pub fn enabled_pack_ids(&self) -> HashSet<String> {
        let mut enabled: HashSet<String> = self.packs.enabled.iter().cloned().collect();

        // Remove explicitly disabled packs
        for disabled in &self.packs.disabled {
            enabled.remove(disabled);
            // Also remove sub-packs if a category is disabled
            enabled.retain(|p| !p.starts_with(&format!("{disabled}.")));
        }

        // Core is always enabled
        enabled.insert("core".to_string());

        enabled
    }

    /// Get effective heredoc scanning settings for evaluation.
    #[must_use]
    pub fn heredoc_settings(&self) -> HeredocSettings {
        self.heredoc.settings()
    }

    /// Get the path to the user config file (creates dir if needed).
    #[must_use]
    pub fn user_config_path() -> Option<PathBuf> {
        let config_dir = dirs::config_dir()?;
        let guard_dir = config_dir.join("dcg");

        // Create directory if it doesn't exist
        if !guard_dir.exists() {
            fs::create_dir_all(&guard_dir).ok()?;
        }

        Some(guard_dir.join(CONFIG_FILE_NAME))
    }

    /// Save configuration to the user config file.
    ///
    /// # Errors
    ///
    /// Returns an error if the config directory cannot be determined/created,
    /// serialization fails, or the config file cannot be written.
    pub fn save_to_user_config(&self) -> Result<PathBuf, String> {
        let path = Self::user_config_path().ok_or("Could not determine config directory")?;

        let content =
            toml::to_string_pretty(self).map_err(|e| format!("Failed to serialize config: {e}"))?;

        fs::write(&path, content).map_err(|e| format!("Failed to write config: {e}"))?;

        Ok(path)
    }

    /// Generate a default configuration with common packs enabled.
    #[must_use]
    pub fn generate_default() -> Self {
        Self {
            general: GeneralConfig::default(),
            packs: PacksConfig {
                enabled: vec![
                    // Core is implicit, but list common ones
                    "database.postgresql".to_string(),
                    "containers.docker".to_string(),
                ],
                disabled: vec![],
            },
            policy: PolicyConfig::default(),
            overrides: OverridesConfig::default(),
            heredoc: HeredocConfig::default(),
            projects: std::collections::HashMap::new(),
        }
    }

    /// Generate a sample configuration string with comments.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn generate_sample_config() -> String {
        r#"# dcg configuration
# https://github.com/Dicklesworthstone/destructive_command_guard

[general]
# Color output: "auto" | "always" | "never"
color = "auto"

# Log blocked commands to file (optional)
# log_file = "~/.local/share/dcg/blocked.log"

# Verbose output
verbose = false

#─────────────────────────────────────────────────────────────
# PACK CONFIGURATION
#─────────────────────────────────────────────────────────────

[packs]
# Enable entire categories or specific sub-packs.
# Core pack is always enabled implicitly.
#
# Available packs:
#   core                  - Git and filesystem protections (always on)
#   database.postgresql   - PostgreSQL destructive commands
#   database.mysql        - MySQL destructive commands
#   database.mongodb      - MongoDB destructive commands
#   database.redis        - Redis FLUSH commands
#   database.sqlite       - SQLite destructive commands
#   containers.docker     - Docker destructive commands
#   containers.compose    - Docker Compose destructive commands
#   containers.podman     - Podman destructive commands
#   kubernetes.kubectl    - kubectl delete commands
#   kubernetes.helm       - Helm uninstall commands
#   kubernetes.kustomize  - Kustomize delete commands
#   cloud.aws             - AWS CLI destructive commands
#   cloud.gcp             - GCP CLI destructive commands
#   cloud.azure           - Azure CLI destructive commands
#   infrastructure.terraform - Terraform destroy commands
#   infrastructure.ansible   - Ansible state=absent patterns
#   infrastructure.pulumi    - Pulumi destroy commands
#   system.disk           - Disk operations (dd, mkfs, fdisk)
#   system.permissions    - Dangerous permission changes
#   system.services       - Service management commands
#   strict_git            - Extra paranoid git protections
#   package_managers      - npm unpublish, cargo yank, etc.

enabled = [
    "database.postgresql",
    "containers.docker",
    # "kubernetes",         # Uncomment to enable all kubernetes sub-packs
    # "cloud.aws",
]

# Explicitly disable specific sub-packs
disabled = [
    # "kubernetes.kustomize",  # Example: disable kustomize if you don't use it
]

#─────────────────────────────────────────────────────────────
# DECISION MODE POLICY
#─────────────────────────────────────────────────────────────

[policy]
# Optional global override for how matched rules are handled:
# - "deny": block (default)
# - "warn": allow but print a warning to stderr (no hook JSON deny)
# - "log": allow silently (no stderr/stdout; optional log_file telemetry)
#
# If unset, dcg uses severity defaults:
# - critical/high => deny
# - medium => warn
# - low => log
#
# default_mode = "deny"
#
# Optional observe-mode window end timestamp.
# When set and before the timestamp, `default_mode` applies (defaulting to "warn" when unset).
# When set and after the timestamp, `default_mode` is ignored and severity defaults apply.
# observe_until = "2026-02-01T00:00:00Z"

[policy.packs]
# Override mode for an entire pack (pack_id => mode).
# Examples:
# "core.git" = "warn"                # warn-first rollout for git pack
# "containers.docker" = "deny"       # keep docker destructive ops as hard blocks

[policy.rules]
# Override mode for a specific rule (rule_id => mode).
# Examples:
# "core.git:push-force-long" = "warn"
# "core.git:reset-hard" = "deny"     # keep critical rules as hard blocks
#
# Safety: Critical rules are only loosened via explicit per-rule overrides.

#─────────────────────────────────────────────────────────────
# CUSTOM OVERRIDES
#─────────────────────────────────────────────────────────────

[overrides]
# Allow specific patterns that would otherwise be blocked.
# Supports simple strings or conditional objects.
allow = [
    # Example: Allow deleting test namespaces
    # "kubectl delete namespace test-.*",

    # Example: Allow dropping test databases
    # "dropdb test_.*",

    # Example: Conditional - only in CI
    # { pattern = "docker system prune", when = "CI=true" },
]

# Block additional patterns not covered by any pack.
block = [
    # Example: Block a custom dangerous script
    # { pattern = "deploy-to-prod\\.sh.*--force", reason = "Never force-deploy to production" },

    # Example: Block piping curl to shell
    # { pattern = "curl.*\\| ?sh", reason = "Piping curl to shell is dangerous" },
]

#─────────────────────────────────────────────────────────────
# HEREDOC / INLINE SCRIPT SCANNING
#─────────────────────────────────────────────────────────────

[heredoc]
# Enable scanning for heredocs and inline scripts (python -c, bash -c, etc.).
enabled = true

# Extraction timeout budget (milliseconds). Parsing/matching has its own budget.
timeout_ms = 50

# Resource limits for extracted bodies (Tier 2).
max_body_bytes = 1048576
max_body_lines = 10000
max_heredocs = 10

# Optional language filter (scan only these languages). Omit for "all".
# languages = ["python", "bash", "javascript", "typescript", "ruby", "perl"]

# Graceful degradation (hook defaults are fail-open).
fallback_on_parse_error = true
fallback_on_timeout = true

#─────────────────────────────────────────────────────────────
# PROJECT-SPECIFIC OVERRIDES
#─────────────────────────────────────────────────────────────

# Override settings for specific project directories.
# The key is the absolute path to the project.

# [projects."/path/to/database-project"]
# packs.enabled = ["database"]
# packs.disabled = []
# overrides.allow = ["dropdb test_.*"]

# [projects."/path/to/k8s-infra"]
# packs.enabled = ["kubernetes", "cloud.aws", "infrastructure.terraform"]
"#
        .to_string()
    }
}

fn parse_env_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "y" | "on" => Some(true),
        "0" | "false" | "no" | "n" | "off" => Some(false),
        _ => None,
    }
}

fn parse_policy_mode(value: &str) -> Option<PolicyMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "deny" | "block" => Some(PolicyMode::Deny),
        "warn" | "warning" => Some(PolicyMode::Warn),
        "log" | "log-only" | "logonly" => Some(PolicyMode::Log),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObserveUntil {
    raw: String,
    parsed_utc: Option<DateTime<Utc>>,
}

impl ObserveUntil {
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }
        Some(Self {
            raw: trimmed.to_string(),
            parsed_utc: parse_timestamp_as_utc(trimmed),
        })
    }

    #[must_use]
    pub const fn parsed_utc(&self) -> Option<&DateTime<Utc>> {
        self.parsed_utc.as_ref()
    }
}

impl std::ops::Deref for ObserveUntil {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

impl Serialize for ObserveUntil {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for ObserveUntil {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        let trimmed = raw.trim();
        Ok(Self {
            raw: trimmed.to_string(),
            parsed_utc: parse_timestamp_as_utc(trimmed),
        })
    }
}

fn parse_timestamp_as_utc(value: &str) -> Option<DateTime<Utc>> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    // RFC 3339 (e.g., "2030-01-01T00:00:00Z" or "2030-01-01T00:00:00+00:00")
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(value) {
        return Some(dt.with_timezone(&Utc));
    }

    // ISO 8601 without timezone (treat as UTC)
    if let Ok(dt) = NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S") {
        return Some(dt.and_utc());
    }

    // Date only (YYYY-MM-DD) - treat as end of day UTC (23:59:59)
    if let Ok(date) = NaiveDate::parse_from_str(value, "%Y-%m-%d") {
        let end_of_day = date.and_hms_opt(23, 59, 59).expect("valid time").and_utc();
        return Some(end_of_day);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.general.color, "auto");
        assert!(config.packs.enabled.is_empty());
    }

    #[test]
    fn test_enabled_pack_ids_includes_core() {
        let config = Config::default();
        let enabled = config.enabled_pack_ids();
        assert!(enabled.contains("core"));
    }

    #[test]
    fn test_enabled_pack_ids_respects_disabled() {
        let config = Config {
            packs: PacksConfig {
                enabled: vec!["kubernetes".to_string(), "kubernetes.helm".to_string()],
                disabled: vec!["kubernetes.helm".to_string()],
            },
            ..Default::default()
        };
        let enabled = config.enabled_pack_ids();
        assert!(enabled.contains("kubernetes"));
        assert!(!enabled.contains("kubernetes.helm"));
    }

    #[test]
    fn test_allow_override_simple() {
        let override_ = AllowOverride::Simple("test pattern".to_string());
        assert_eq!(override_.pattern(), "test pattern");
        assert!(override_.condition_met());
    }

    #[test]
    fn test_allow_override_conditional_no_condition() {
        let override_ = AllowOverride::Conditional {
            pattern: "test pattern".to_string(),
            when: None,
        };
        assert!(override_.condition_met());
    }

    #[test]
    fn test_sample_config_parses() {
        let sample = Config::generate_sample_config();
        // Remove comment lines for parsing test
        let _config: Result<Config, _> = toml::from_str(&sample);
        // Note: The sample has comments which toml handles fine
    }

    #[test]
    fn test_config_merge() {
        let mut base = Config::default();
        let other = Config {
            packs: PacksConfig {
                enabled: vec!["database.postgresql".to_string()],
                disabled: vec![],
            },
            ..Default::default()
        };
        base.merge(other);
        assert!(
            base.packs
                .enabled
                .contains(&"database.postgresql".to_string())
        );
    }

    #[test]
    fn test_heredoc_settings_defaults() {
        let config = Config::default();
        let settings = config.heredoc_settings();
        assert!(settings.enabled);
        assert_eq!(settings.limits.timeout_ms, 50);
        assert!(settings.allowed_languages.is_none());
        assert!(settings.fallback_on_parse_error);
        assert!(settings.fallback_on_timeout);
    }

    #[test]
    fn test_heredoc_env_overrides_enabled_timeout_languages() {
        let env_map: std::collections::HashMap<&str, &str> = std::collections::HashMap::from([
            ("DCG_HEREDOC_ENABLED", "0"),
            ("DCG_HEREDOC_TIMEOUT_MS", "123"),
            ("DCG_HEREDOC_LANGUAGES", "python, bash, js, unknown_value"),
        ]);
        let mut config = Config::default();
        config.apply_env_overrides_from(|key| env_map.get(key).map(|v| (*v).to_string()));

        let settings = config.heredoc_settings();
        assert!(!settings.enabled);
        assert_eq!(settings.limits.timeout_ms, 123);
        assert_eq!(
            settings.allowed_languages,
            Some(vec![
                crate::heredoc::ScriptLanguage::Python,
                crate::heredoc::ScriptLanguage::Bash,
                crate::heredoc::ScriptLanguage::JavaScript
            ])
        );
    }

    #[test]
    fn test_heredoc_language_filter_all_is_treated_as_unfiltered() {
        let mut config = Config::default();
        config.heredoc.languages = Some(vec!["all".to_string(), "python".to_string()]);
        let settings = config.heredoc_settings();
        assert!(settings.allowed_languages.is_none());
    }

    #[test]
    fn test_heredoc_language_filter_invalid_only_falls_back_to_all() {
        let mut config = Config::default();
        config.heredoc.languages = Some(vec!["definitely_not_a_language".to_string()]);
        let settings = config.heredoc_settings();
        assert!(settings.allowed_languages.is_none());
    }

    // ========================================================================
    // CompiledOverrides Tests (git_safety_guard-99e.4.1)
    // ========================================================================

    #[test]
    fn test_compile_simple_allow_override() {
        let overrides = OverridesConfig {
            allow: vec![AllowOverride::Simple("git reset --hard".to_string())],
            block: vec![],
        };
        let compiled = overrides.compile();

        assert_eq!(compiled.allow.len(), 1);
        assert!(compiled.invalid_patterns.is_empty());
        assert!(compiled.check_allow("git reset --hard"));
        assert!(!compiled.check_allow("git status"));
    }

    #[test]
    fn test_compile_block_override() {
        let overrides = OverridesConfig {
            allow: vec![],
            block: vec![BlockOverride {
                pattern: "dangerous-command".to_string(),
                reason: "This is dangerous!".to_string(),
            }],
        };
        let compiled = overrides.compile();

        assert_eq!(compiled.block.len(), 1);
        assert!(compiled.invalid_patterns.is_empty());
        assert_eq!(
            compiled.check_block("dangerous-command --force"),
            Some("This is dangerous!")
        );
        assert_eq!(compiled.check_block("safe-command"), None);
    }

    #[test]
    fn test_compile_invalid_regex_fails_open() {
        let overrides = OverridesConfig {
            allow: vec![AllowOverride::Simple("[invalid regex".to_string())],
            block: vec![BlockOverride {
                pattern: "[also invalid".to_string(),
                reason: "Won't compile".to_string(),
            }],
        };
        let compiled = overrides.compile();

        // Invalid patterns should NOT be in the compiled lists
        assert!(compiled.allow.is_empty());
        assert!(compiled.block.is_empty());

        // But they should be recorded in invalid_patterns
        assert_eq!(compiled.invalid_patterns.len(), 2);
        assert!(compiled.has_invalid_patterns());

        // Check that we recorded the right kinds
        assert!(
            compiled
                .invalid_patterns
                .iter()
                .any(|p| p.kind == PatternKind::Allow)
        );
        assert!(
            compiled
                .invalid_patterns
                .iter()
                .any(|p| p.kind == PatternKind::Block)
        );
    }

    #[test]
    fn test_compile_conditional_override_always() {
        let overrides = OverridesConfig {
            allow: vec![AllowOverride::Conditional {
                pattern: "test-pattern".to_string(),
                when: None,
            }],
            block: vec![],
        };
        let compiled = overrides.compile();

        assert_eq!(compiled.allow.len(), 1);
        // With no condition, it should always match
        assert!(compiled.check_allow("test-pattern"));
    }

    #[test]
    fn test_compile_regex_pattern() {
        let overrides = OverridesConfig {
            allow: vec![AllowOverride::Simple(
                r"kubectl delete namespace test-\d+".to_string(),
            )],
            block: vec![],
        };
        let compiled = overrides.compile();

        assert!(compiled.check_allow("kubectl delete namespace test-123"));
        assert!(compiled.check_allow("kubectl delete namespace test-999"));
        assert!(!compiled.check_allow("kubectl delete namespace production"));
    }

    #[test]
    fn test_compiled_overrides_check_order() {
        // Allow takes precedence (checked first in evaluator)
        let overrides = OverridesConfig {
            allow: vec![AllowOverride::Simple("test-command".to_string())],
            block: vec![BlockOverride {
                pattern: "test-command".to_string(),
                reason: "Blocked!".to_string(),
            }],
        };
        let compiled = overrides.compile();

        // Both patterns match
        assert!(compiled.check_allow("test-command"));
        assert!(compiled.check_block("test-command").is_some());

        // In the evaluator, allow is checked first, so command would be allowed
    }

    #[test]
    fn test_compiled_overrides_empty() {
        let overrides = OverridesConfig::default();
        let compiled = overrides.compile();

        assert!(compiled.allow.is_empty());
        assert!(compiled.block.is_empty());
        assert!(!compiled.has_invalid_patterns());
        assert!(!compiled.check_allow("anything"));
        assert!(compiled.check_block("anything").is_none());
    }

    #[test]
    fn test_compiled_overrides_multiple_patterns() {
        let overrides = OverridesConfig {
            allow: vec![
                AllowOverride::Simple("pattern-a".to_string()),
                AllowOverride::Simple("pattern-b".to_string()),
            ],
            block: vec![
                BlockOverride {
                    pattern: "block-1".to_string(),
                    reason: "Reason 1".to_string(),
                },
                BlockOverride {
                    pattern: "block-2".to_string(),
                    reason: "Reason 2".to_string(),
                },
            ],
        };
        let compiled = overrides.compile();

        assert!(compiled.check_allow("pattern-a"));
        assert!(compiled.check_allow("pattern-b"));
        assert!(!compiled.check_allow("pattern-c"));

        assert_eq!(compiled.check_block("block-1"), Some("Reason 1"));
        assert_eq!(compiled.check_block("block-2"), Some("Reason 2"));
        assert_eq!(compiled.check_block("block-3"), None);
    }

    // ========================================================================
    // PolicyConfig Tests (git_safety_guard-1gt.3)
    // ========================================================================

    #[test]
    fn test_policy_mode_to_decision_mode() {
        assert_eq!(
            PolicyMode::Deny.to_decision_mode(),
            crate::packs::DecisionMode::Deny
        );
        assert_eq!(
            PolicyMode::Warn.to_decision_mode(),
            crate::packs::DecisionMode::Warn
        );
        assert_eq!(
            PolicyMode::Log.to_decision_mode(),
            crate::packs::DecisionMode::Log
        );
    }

    #[test]
    fn test_policy_resolve_mode_rule_override_takes_precedence() {
        let policy = PolicyConfig {
            default_mode: Some(PolicyMode::Deny),
            observe_until: None,
            packs: std::collections::HashMap::from([("core.git".to_string(), PolicyMode::Warn)]),
            rules: std::collections::HashMap::from([(
                "core.git:reset-hard".to_string(),
                PolicyMode::Log,
            )]),
        };

        // Rule-specific override should win
        let mode = policy.resolve_mode(
            Some("core.git"),
            Some("reset-hard"),
            Some(crate::packs::Severity::High),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Log);
    }

    #[test]
    fn test_policy_resolve_mode_pack_override_when_no_rule() {
        let policy = PolicyConfig {
            default_mode: Some(PolicyMode::Deny),
            packs: std::collections::HashMap::from([("core.git".to_string(), PolicyMode::Warn)]),
            ..Default::default()
        };

        // No rule override, so pack override wins
        let mode = policy.resolve_mode(
            Some("core.git"),
            Some("push-force"),
            Some(crate::packs::Severity::High),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Warn);
    }

    #[test]
    fn test_policy_resolve_mode_global_default_when_no_pack() {
        let policy = PolicyConfig {
            default_mode: Some(PolicyMode::Log),
            ..Default::default()
        };

        // No pack override, so global default wins
        let mode = policy.resolve_mode(
            Some("containers.docker"),
            Some("prune"),
            Some(crate::packs::Severity::Medium),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Log);
    }

    #[test]
    fn test_policy_resolve_mode_severity_default_when_nothing_set() {
        let policy = PolicyConfig::default();

        // High severity defaults to Deny
        let mode_high = policy.resolve_mode(
            Some("core.git"),
            Some("reset-hard"),
            Some(crate::packs::Severity::High),
        );
        assert_eq!(mode_high, crate::packs::DecisionMode::Deny);

        // Medium severity defaults to Warn
        let mode_medium = policy.resolve_mode(
            Some("core.git"),
            Some("something"),
            Some(crate::packs::Severity::Medium),
        );
        assert_eq!(mode_medium, crate::packs::DecisionMode::Warn);

        // Low severity defaults to Log
        let mode_low = policy.resolve_mode(
            Some("core.git"),
            Some("something"),
            Some(crate::packs::Severity::Low),
        );
        assert_eq!(mode_low, crate::packs::DecisionMode::Log);
    }

    #[test]
    fn test_policy_resolve_mode_critical_cannot_be_loosened_by_pack() {
        let mut policy = PolicyConfig::default();
        policy
            .packs
            .insert("core.git".to_string(), PolicyMode::Warn);

        // Critical severity should ALWAYS be Deny, even with pack override
        let mode = policy.resolve_mode(
            Some("core.git"),
            Some("reset-hard"),
            Some(crate::packs::Severity::Critical),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Deny);
    }

    #[test]
    fn test_policy_resolve_mode_critical_cannot_be_loosened_by_global() {
        let policy = PolicyConfig {
            default_mode: Some(PolicyMode::Log),
            ..Default::default()
        };

        // Critical severity should ALWAYS be Deny, even with global override
        let mode = policy.resolve_mode(
            Some("core.git"),
            Some("reset-hard"),
            Some(crate::packs::Severity::Critical),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Deny);
    }

    #[test]
    fn test_policy_resolve_mode_critical_can_be_loosened_by_rule() {
        let mut policy = PolicyConfig::default();
        policy
            .rules
            .insert("core.git:reset-hard".to_string(), PolicyMode::Warn);

        // Critical CAN be loosened via explicit per-rule override
        let mode = policy.resolve_mode(
            Some("core.git"),
            Some("reset-hard"),
            Some(crate::packs::Severity::Critical),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Warn);
    }

    #[test]
    fn test_policy_resolve_mode_no_severity_defaults_to_deny() {
        let policy = PolicyConfig::default();

        // No severity provided should default to Deny
        let mode = policy.resolve_mode(Some("core.git"), Some("pattern"), None);
        assert_eq!(mode, crate::packs::DecisionMode::Deny);
    }

    #[test]
    fn test_policy_env_override_default_mode() {
        let env_map: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::from([("DCG_POLICY_DEFAULT_MODE", "warn")]);

        let mut config = Config::default();
        config.apply_env_overrides_from(|key| env_map.get(key).map(|v| (*v).to_string()));

        assert_eq!(config.policy.default_mode, Some(PolicyMode::Warn));
    }

    #[test]
    fn test_policy_env_override_observe_until() {
        let env_map: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::from([("DCG_POLICY_OBSERVE_UNTIL", "2030-01-01T00:00:00Z")]);

        let mut config = Config::default();
        config.apply_env_overrides_from(|key| env_map.get(key).map(|v| (*v).to_string()));

        assert_eq!(
            config.policy.observe_until.as_deref(),
            Some("2030-01-01T00:00:00Z")
        );
    }

    #[test]
    fn test_policy_env_override_parses_all_modes() {
        for (input, expected) in [
            ("deny", Some(PolicyMode::Deny)),
            ("block", Some(PolicyMode::Deny)),
            ("warn", Some(PolicyMode::Warn)),
            ("warning", Some(PolicyMode::Warn)),
            ("log", Some(PolicyMode::Log)),
            ("log-only", Some(PolicyMode::Log)),
            ("logonly", Some(PolicyMode::Log)),
            ("DENY", Some(PolicyMode::Deny)), // case-insensitive
            ("invalid", None),
        ] {
            let result = parse_policy_mode(input);
            assert_eq!(result, expected, "parse_policy_mode({input:?}) mismatch");
        }
    }

    #[test]
    fn test_policy_config_merge() {
        let mut base = Config::default();
        base.policy.default_mode = Some(PolicyMode::Deny);
        base.policy.observe_until = ObserveUntil::parse("2000-01-01T00:00:00Z");
        base.policy
            .packs
            .insert("core.git".to_string(), PolicyMode::Deny);

        let other = Config {
            policy: PolicyConfig {
                default_mode: Some(PolicyMode::Warn),
                observe_until: ObserveUntil::parse("2030-01-01T00:00:00Z"),
                packs: std::collections::HashMap::from([(
                    "containers.docker".to_string(),
                    PolicyMode::Log,
                )]),
                rules: std::collections::HashMap::from([(
                    "core.git:reset-hard".to_string(),
                    PolicyMode::Log,
                )]),
            },
            ..Default::default()
        };

        base.merge(other);

        // Other's default_mode should win
        assert_eq!(base.policy.default_mode, Some(PolicyMode::Warn));
        // Other's observe_until should win
        assert_eq!(
            base.policy.observe_until.as_deref(),
            Some("2030-01-01T00:00:00Z")
        );
        // Both packs should be present
        assert_eq!(base.policy.packs.get("core.git"), Some(&PolicyMode::Deny));
        assert_eq!(
            base.policy.packs.get("containers.docker"),
            Some(&PolicyMode::Log)
        );
        // Rules should be merged
        assert_eq!(
            base.policy.rules.get("core.git:reset-hard"),
            Some(&PolicyMode::Log)
        );
    }

    #[test]
    fn test_sample_config_includes_policy_section() {
        let sample = Config::generate_sample_config();
        assert!(
            sample.contains("[policy]"),
            "Sample config should have [policy] section"
        );
        assert!(
            sample.contains("default_mode"),
            "Sample config should mention default_mode"
        );
        assert!(
            sample.contains("observe_until"),
            "Sample config should mention observe_until"
        );
        assert!(
            sample.contains("[policy.packs]"),
            "Sample config should have [policy.packs]"
        );
        assert!(
            sample.contains("[policy.rules]"),
            "Sample config should have [policy.rules]"
        );
    }

    // ========================================================================
    // Observe mode tests (git_safety_guard-1gt.3.3)
    // ========================================================================

    #[test]
    fn test_policy_observe_window_active_defaults_to_warn_when_unset() {
        let policy = PolicyConfig {
            observe_until: ObserveUntil::parse("2030-01-01T00:00:00Z"),
            ..Default::default()
        };

        let now = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&Utc);

        let mode = policy.resolve_mode_at(
            now,
            Some("core.git"),
            Some("push-force-long"),
            Some(crate::packs::Severity::High),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Warn);
    }

    #[test]
    fn test_policy_observe_window_expired_ignores_default_mode() {
        let policy = PolicyConfig {
            default_mode: Some(PolicyMode::Warn),
            observe_until: ObserveUntil::parse("2026-01-01T00:00:00Z"),
            ..Default::default()
        };

        let now = chrono::DateTime::parse_from_rfc3339("2026-01-02T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&Utc);

        let mode = policy.resolve_mode_at(
            now,
            Some("core.git"),
            Some("push-force-long"),
            Some(crate::packs::Severity::High),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Deny);
    }

    #[test]
    fn test_policy_observe_window_active_does_not_loosen_critical_without_rule_override() {
        let policy = PolicyConfig {
            default_mode: Some(PolicyMode::Warn),
            observe_until: ObserveUntil::parse("2030-01-01T00:00:00Z"),
            ..Default::default()
        };

        let now = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&Utc);

        let mode = policy.resolve_mode_at(
            now,
            Some("core.git"),
            Some("reset-hard"),
            Some(crate::packs::Severity::Critical),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Deny);
    }
}
