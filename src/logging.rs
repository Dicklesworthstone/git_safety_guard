//! Structured logging for allow/deny decisions.
//!
//! This module provides structured logging for command evaluation decisions,
//! supporting both text and JSON output formats with optional redaction.

use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::SystemTime;

use crate::evaluator::{EvaluationDecision, EvaluationResult};
use crate::packs::DecisionMode;

// ============================================================================
// Configuration Types
// ============================================================================

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Whether structured logging is enabled.
    pub enabled: bool,
    /// Path to log file. Supports ~ expansion.
    pub file: Option<String>,
    /// Output format: "text" or "json".
    pub format: LogFormat,
    /// Redaction settings.
    pub redaction: RedactionConfig,
    /// Events to log.
    pub events: LogEventFilter,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            file: None,
            format: LogFormat::Text,
            redaction: RedactionConfig::default(),
            events: LogEventFilter::default(),
        }
    }
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

/// Redaction configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RedactionConfig {
    pub enabled: bool,
    pub mode: RedactionMode,
    pub max_argument_len: usize,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: RedactionMode::Arguments,
            max_argument_len: 50,
        }
    }
}

/// Redaction mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RedactionMode {
    None,
    #[default]
    Arguments,
    Full,
}

/// Filter for which events to log.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LogEventFilter {
    pub deny: bool,
    pub warn: bool,
    pub allow: bool,
}

impl Default for LogEventFilter {
    fn default() -> Self {
        Self {
            deny: true,
            warn: true,
            allow: false,
        }
    }
}

// ============================================================================
// Log Entry
// ============================================================================

/// A structured log entry for a command evaluation.
#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub decision: String,
    pub mode: String,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalized_command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pack_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_skip: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowlist_layer: Option<String>,
}

impl LogEntry {
    /// Create a new log entry from an evaluation result.
    #[must_use]
    pub fn from_result(
        result: &EvaluationResult,
        command: &str,
        normalized: Option<&str>,
        mode: DecisionMode,
        redaction: &RedactionConfig,
        elapsed_us: Option<u64>,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or_else(
                |_| "1970-01-01T00:00:00Z".to_string(),
                |d| time_to_iso8601(d.as_secs()),
            );

        let decision_str = match result.decision {
            EvaluationDecision::Allow => "allow",
            EvaluationDecision::Deny => match mode {
                DecisionMode::Deny => "deny",
                DecisionMode::Warn => "warn",
                DecisionMode::Log => "log",
            },
        };

        let mode_str = match mode {
            DecisionMode::Deny => "deny",
            DecisionMode::Warn => "warn",
            DecisionMode::Log => "log",
        };

        let (pack_id, pattern_name, rule_id, reason) =
            result
                .pattern_info
                .as_ref()
                .map_or((None, None, None, None), |pm| {
                    let pack = pm.pack_id.as_deref().map(String::from);
                    let pattern = pm.pattern_name.as_deref().map(String::from);
                    // Construct rule_id as "pack_id:pattern_name" if both are present
                    let rule = match (&pm.pack_id, &pm.pattern_name) {
                        (Some(p), Some(n)) => Some(format!("{p}:{n}")),
                        _ => None,
                    };
                    let r = Some(pm.reason.clone());
                    (pack, pattern, rule, r)
                });

        let allowlist_layer = result
            .allowlist_override
            .as_ref()
            .map(|o| o.layer.label().to_string());

        let redacted_command = redact_command(command, redaction);
        let redacted_normalized = normalized.map(|n| redact_command(n, redaction));

        Self {
            timestamp,
            decision: decision_str.to_string(),
            mode: mode_str.to_string(),
            command: redacted_command,
            normalized_command: redacted_normalized,
            pack_id,
            pattern_name,
            rule_id,
            reason,
            elapsed_us,
            budget_skip: if result.skipped_due_to_budget {
                Some(true)
            } else {
                None
            },
            allowlist_layer,
        }
    }

    /// Format as text log line.
    #[must_use]
    pub fn format_text(&self) -> String {
        let mut parts = Vec::with_capacity(8);
        parts.push(format!("[{}]", self.timestamp));
        parts.push(self.decision.to_uppercase());
        if let Some(ref rule_id) = self.rule_id {
            parts.push(rule_id.clone());
        }
        parts.push(format!("\"{}\"", self.command));
        if let Some(ref reason) = self.reason {
            parts.push(format!("-- {reason}"));
        }
        if let Some(us) = self.elapsed_us {
            parts.push(format!("({us}us)"));
        }
        if self.budget_skip.unwrap_or(false) {
            parts.push("[budget-skip]".to_string());
        }
        if let Some(ref layer) = self.allowlist_layer {
            parts.push(format!("[allowlist:{layer}]"));
        }
        parts.join(" ")
    }

    /// Format as JSON line.
    #[must_use]
    pub fn format_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

// ============================================================================
// Logger
// ============================================================================

/// A structured logger for command evaluation decisions.
pub struct DecisionLogger {
    config: LoggingConfig,
    writer: Option<Mutex<BufWriter<File>>>,
}

impl DecisionLogger {
    /// Create a new logger from configuration.
    #[must_use]
    pub fn new(config: &LoggingConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        let writer = config.file.as_ref().and_then(|path| {
            let expanded = expand_tilde(path);
            open_log_file(&expanded)
                .ok()
                .map(|f| Mutex::new(BufWriter::new(f)))
        });
        Some(Self {
            config: config.clone(),
            writer,
        })
    }

    /// Log an evaluation result.
    pub fn log(
        &self,
        result: &EvaluationResult,
        command: &str,
        normalized: Option<&str>,
        mode: DecisionMode,
        elapsed_us: Option<u64>,
    ) {
        if !self.should_log(result, mode) {
            return;
        }
        let entry = LogEntry::from_result(
            result,
            command,
            normalized,
            mode,
            &self.config.redaction,
            elapsed_us,
        );
        let line = match self.config.format {
            LogFormat::Text => entry.format_text(),
            LogFormat::Json => entry.format_json(),
        };
        if let Some(ref writer) = self.writer {
            if let Ok(mut w) = writer.lock() {
                let _ = writeln!(w, "{line}");
                let _ = w.flush();
            }
        }
    }

    /// Determine if this result should be logged based on event filters.
    ///
    /// When a command matches a destructive pattern (Deny decision), we use the deny
    /// filter regardless of mode. Log mode means "don't block, just observe" - but
    /// the pattern still matched, so users who enable deny logging should see it.
    const fn should_log(&self, result: &EvaluationResult, mode: DecisionMode) -> bool {
        match result.decision {
            EvaluationDecision::Allow => self.config.events.allow,
            EvaluationDecision::Deny => match mode {
                DecisionMode::Warn => self.config.events.warn,
                // Log mode: pattern matched but we're just observing. Use deny filter
                // since a destructive pattern did match, even if we're not blocking.
                DecisionMode::Deny | DecisionMode::Log => self.config.events.deny,
            },
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn expand_tilde(path: &str) -> String {
    if path.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return format!("{}{}", home.to_string_lossy(), &path[1..]);
        }
    }
    path.to_string()
}

fn open_log_file(path: &str) -> std::io::Result<File> {
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    OpenOptions::new().create(true).append(true).open(path)
}

fn redact_command(command: &str, config: &RedactionConfig) -> String {
    if !config.enabled {
        return command.to_string();
    }
    match config.mode {
        RedactionMode::None => command.to_string(),
        RedactionMode::Full => "[REDACTED]".to_string(),
        RedactionMode::Arguments => redact_arguments(command, config.max_argument_len),
    }
}

fn redact_arguments(command: &str, max_len: usize) -> String {
    let mut result = String::with_capacity(command.len());
    let mut in_quote = false;
    let mut quote_char = '"';
    let mut arg_len = 0;
    let mut escaped = false;

    for c in command.chars() {
        if escaped {
            if in_quote && arg_len < max_len {
                result.push(c);
                arg_len += 1;
            }
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            if !in_quote || arg_len < max_len {
                result.push(c);
                if in_quote {
                    arg_len += 1;
                }
            }
            continue;
        }
        if !in_quote && (c == '"' || c == '\'') {
            in_quote = true;
            quote_char = c;
            arg_len = 0;
            result.push(c);
            continue;
        }
        if in_quote && c == quote_char {
            in_quote = false;
            if arg_len > max_len {
                result.push_str("...");
            }
            result.push(c);
            continue;
        }
        if in_quote {
            if arg_len < max_len {
                result.push(c);
            }
            arg_len += 1;
        } else {
            result.push(c);
        }
    }
    result
}

fn time_to_iso8601(secs: u64) -> String {
    const SECS_PER_DAY: u64 = 86400;
    const DAYS_PER_YEAR: u64 = 365;
    const DAYS_PER_4YEARS: u64 = 1461;
    const DAYS_PER_100YEARS: u64 = 36524;
    const DAYS_PER_400YEARS: u64 = 146_097;

    let mut days = secs / SECS_PER_DAY;
    let time_of_day = secs % SECS_PER_DAY;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    days += 719_468;
    let era = days / DAYS_PER_400YEARS;
    let doe = days % DAYS_PER_400YEARS;
    let yoe = (doe - doe / DAYS_PER_4YEARS + doe / DAYS_PER_100YEARS - doe / DAYS_PER_400YEARS)
        / DAYS_PER_YEAR;
    let year = yoe + era * 400;
    let doy = doe - (DAYS_PER_YEAR * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logging_config_defaults() {
        let config = LoggingConfig::default();
        assert!(!config.enabled);
        assert!(config.file.is_none());
        assert_eq!(config.format, LogFormat::Text);
    }

    #[test]
    fn redact_full_mode() {
        let config = RedactionConfig {
            enabled: true,
            mode: RedactionMode::Full,
            max_argument_len: 50,
        };
        let result = redact_command("git reset --hard HEAD", &config);
        assert_eq!(result, "[REDACTED]");
    }

    #[test]
    fn redact_disabled() {
        let config = RedactionConfig {
            enabled: false,
            mode: RedactionMode::Full,
            max_argument_len: 50,
        };
        let result = redact_command("git reset --hard HEAD", &config);
        assert_eq!(result, "git reset --hard HEAD");
    }

    #[test]
    fn time_to_iso8601_epoch() {
        assert_eq!(time_to_iso8601(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn time_to_iso8601_known_date() {
        // 2024-01-15 12:30:45 UTC = 1705321845 seconds since epoch
        let result = time_to_iso8601(1_705_321_845);
        assert_eq!(result, "2024-01-15T12:30:45Z");
    }

    #[test]
    fn redact_none_mode() {
        let config = RedactionConfig {
            enabled: true,
            mode: RedactionMode::None,
            max_argument_len: 50,
        };
        let result = redact_command("git reset --hard HEAD", &config);
        assert_eq!(result, "git reset --hard HEAD");
    }

    #[test]
    fn redact_arguments_truncates_long_strings() {
        let config = RedactionConfig {
            enabled: true,
            mode: RedactionMode::Arguments,
            max_argument_len: 10,
        };
        let result = redact_command(
            r#"echo "this is a very long string that should be truncated""#,
            &config,
        );
        assert_eq!(result, r#"echo "this is a ...""#);
    }

    #[test]
    fn redact_arguments_preserves_short_strings() {
        let config = RedactionConfig {
            enabled: true,
            mode: RedactionMode::Arguments,
            max_argument_len: 50,
        };
        let result = redact_command(r#"echo "short""#, &config);
        assert_eq!(result, r#"echo "short""#);
    }

    #[test]
    fn expand_tilde_with_home() {
        if std::env::var_os("HOME").is_some() {
            let result = expand_tilde("~/test/path");
            assert!(!result.starts_with("~/"));
            assert!(result.ends_with("/test/path"));
        }
    }

    #[test]
    fn expand_tilde_without_tilde() {
        let result = expand_tilde("/absolute/path");
        assert_eq!(result, "/absolute/path");
    }

    #[test]
    fn log_event_filter_defaults() {
        let filter = LogEventFilter::default();
        assert!(filter.deny);
        assert!(filter.warn);
        assert!(!filter.allow);
    }
}
