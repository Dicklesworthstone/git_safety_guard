//! Repository scanning (`dcg scan`) for destructive commands.
//!
//! This module is intentionally **extractor-based** (not naive substring grep).
//! The core idea is to extract only *executable contexts* from files, then
//! evaluate extracted commands using the shared evaluator pipeline.
//!
//! # Extraction contract
//!
//! Each extractor returns `ExtractedCommand` entries:
//!
//! - `file`, `line`, optional `col`
//! - `extractor_id` identifying the execution context (e.g. `shell.script`)
//! - `command` (the extracted executable command text)
//! - optional `metadata` (structured context for debugging / future UX)
//!
//! Extractors MUST be conservative: if unsure whether something is executed,
//! prefer returning no extraction rather than producing false positives.
//!
//! # Output schema (v1)
//!
//! `dcg scan --format json` emits a `ScanReport` containing:
//! - stable ordering of findings (deterministic output for CI / PR comments)
//! - `decision` in {allow,warn,deny}
//! - `severity` in {info,warning,error}
//! - stable `rule_id` (`pack_id:pattern_name`) when available
//!
//! Note: the shared evaluator currently only blocks deny-by-default pack rules.
//! Scan output uses this evaluator behavior for parity.

use crate::config::{Config, HeredocSettings};
use crate::evaluator::{EvaluationDecision, PatternMatch, evaluate_command_with_pack_order};
use crate::packs::{DecisionMode, REGISTRY, Severity};
use crate::suggestions::{SuggestionKind, get_suggestion_by_kind};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

/// Scan output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ScanFormat {
    Pretty,
    Json,
}

/// Controls scan failure behavior (CI integration).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ScanFailOn {
    None,
    Warning,
    Error,
}

impl ScanFailOn {
    #[must_use]
    pub const fn blocks(&self, severity: ScanSeverity) -> bool {
        match self {
            Self::None => false,
            Self::Warning => matches!(severity, ScanSeverity::Warning | ScanSeverity::Error),
            Self::Error => matches!(severity, ScanSeverity::Error),
        }
    }
}

/// Scan decision for an extracted command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanDecision {
    Allow,
    Warn,
    Deny,
}

/// Scan severity (used for `--fail-on` policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanSeverity {
    Info,
    Warning,
    Error,
}

impl ScanSeverity {
    #[must_use]
    pub const fn rank(&self) -> u8 {
        match self {
            Self::Error => 3,
            Self::Warning => 2,
            Self::Info => 1,
        }
    }
}

/// Extracted executable command from a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedCommand {
    pub file: String,
    pub line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub col: Option<usize>,
    pub extractor_id: String,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// A scan finding produced by evaluating an extracted command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    pub file: String,
    pub line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub col: Option<usize>,
    pub extractor_id: String,
    pub extracted_command: String,
    pub decision: ScanDecision,
    pub severity: ScanSeverity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
}

/// Summary statistics for a scan run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub files_considered: usize,
    pub files_scanned: usize,
    pub commands_extracted: usize,
    pub findings: usize,
    pub blocked: usize,
    pub warned: usize,
    pub max_findings_reached: bool,
}

/// Complete scan output (stable JSON schema).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub findings: Vec<ScanFinding>,
    pub summary: ScanSummary,
}

/// In-memory scan configuration (CLI + defaults).
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub format: ScanFormat,
    pub fail_on: ScanFailOn,
    pub max_file_size_bytes: u64,
    pub max_findings: usize,
}

/// Precomputed evaluator context for scanning.
#[derive(Debug)]
pub struct ScanEvalContext {
    pub enabled_keywords: Vec<&'static str>,
    pub ordered_packs: Vec<String>,
    pub compiled_overrides: crate::config::CompiledOverrides,
    pub allowlists: crate::allowlist::LayeredAllowlist,
    pub heredoc_settings: HeredocSettings,
}

impl ScanEvalContext {
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        let enabled_packs: HashSet<String> = config.enabled_pack_ids();
        let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
        let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
        let compiled_overrides = config.overrides.compile();
        let allowlists = crate::load_default_allowlists();
        let heredoc_settings = config.heredoc_settings();

        Self {
            enabled_keywords,
            ordered_packs,
            compiled_overrides,
            allowlists,
            heredoc_settings,
        }
    }
}

#[must_use]
pub fn should_fail(report: &ScanReport, fail_on: ScanFailOn) -> bool {
    report.findings.iter().any(|f| fail_on.blocks(f.severity))
}

pub fn sort_findings(findings: &mut [ScanFinding]) {
    findings.sort_by(|a, b| {
        let key_a = (
            std::cmp::Reverse(a.severity.rank()),
            a.rule_id.as_deref().unwrap_or(""),
            a.file.as_str(),
            a.line,
            a.col.unwrap_or(0),
            a.extractor_id.as_str(),
            a.extracted_command.as_str(),
        );
        let key_b = (
            std::cmp::Reverse(b.severity.rank()),
            b.rule_id.as_deref().unwrap_or(""),
            b.file.as_str(),
            b.line,
            b.col.unwrap_or(0),
            b.extractor_id.as_str(),
            b.extracted_command.as_str(),
        );
        key_a.cmp(&key_b)
    });
}

#[must_use]
pub fn evaluate_extracted_command(
    extracted: &ExtractedCommand,
    _config: &Config,
    ctx: &ScanEvalContext,
) -> Option<ScanFinding> {
    let result = evaluate_command_with_pack_order(
        &extracted.command,
        &ctx.enabled_keywords,
        &ctx.ordered_packs,
        &ctx.compiled_overrides,
        &ctx.allowlists,
        &ctx.heredoc_settings,
    );

    if result.decision == EvaluationDecision::Allow {
        return None;
    }

    let Some(pattern) = result.pattern_info else {
        return Some(ScanFinding {
            file: extracted.file.clone(),
            line: extracted.line,
            col: extracted.col,
            extractor_id: extracted.extractor_id.clone(),
            extracted_command: extracted.command.clone(),
            decision: ScanDecision::Deny,
            severity: ScanSeverity::Error,
            rule_id: None,
            reason: Some("Blocked (missing match metadata)".to_string()),
            suggestion: None,
        });
    };

    let (rule_id, severity, decision_mode) = resolve_severity_and_rule_id(&pattern);

    let scan_decision = match decision_mode {
        Some(DecisionMode::Deny) | None => ScanDecision::Deny,
        Some(DecisionMode::Warn) => ScanDecision::Warn,
        Some(DecisionMode::Log) => ScanDecision::Allow,
    };

    let scan_severity = match severity {
        Some(Severity::Medium) => ScanSeverity::Warning,
        Some(Severity::Low) => ScanSeverity::Info,
        Some(Severity::Critical | Severity::High) | None => ScanSeverity::Error,
    };

    let suggestion = rule_id
        .as_deref()
        .and_then(|id| get_suggestion_by_kind(id, SuggestionKind::SaferAlternative))
        .map(|s| s.text.clone());

    Some(ScanFinding {
        file: extracted.file.clone(),
        line: extracted.line,
        col: extracted.col,
        extractor_id: extracted.extractor_id.clone(),
        extracted_command: extracted.command.clone(),
        decision: scan_decision,
        severity: scan_severity,
        rule_id,
        reason: Some(pattern.reason),
        suggestion,
    })
}

fn resolve_severity_and_rule_id(
    pattern: &PatternMatch,
) -> (Option<String>, Option<Severity>, Option<DecisionMode>) {
    let Some(pack_id) = pattern.pack_id.as_deref() else {
        return (None, None, None);
    };

    let Some(pattern_name) = pattern.pattern_name.as_deref() else {
        return (None, None, None);
    };

    let rule_id = Some(format!("{pack_id}:{pattern_name}"));

    let Some(pack) = REGISTRY.get(pack_id) else {
        return (rule_id, None, None);
    };

    let Some(found) = pack
        .destructive_patterns
        .iter()
        .find(|p| p.name.is_some_and(|n| n == pattern_name))
    else {
        return (rule_id, None, None);
    };

    (
        rule_id,
        Some(found.severity),
        Some(found.severity.default_mode()),
    )
}

/// Scan file paths (directories are expanded recursively).
///
/// This is a small, conservative implementation intended to support the `scan`
/// epic without pulling in heavy parsing dependencies. Extraction is delegated
/// to extractor modules (implemented in follow-up tasks).
///
/// Currently this function does **not** implement extractors; it is a framework
/// for deterministic output and evaluator integration.
#[allow(clippy::missing_errors_doc)]
#[allow(clippy::missing_const_for_fn)] // Can't be const: returns Result with Vec::new()
pub fn scan_paths(
    _paths: &[PathBuf],
    _options: &ScanOptions,
    _config: &Config,
    _ctx: &ScanEvalContext,
) -> Result<ScanReport, String> {
    Ok(ScanReport {
        findings: Vec::new(),
        summary: ScanSummary {
            files_considered: 0,
            files_scanned: 0,
            commands_extracted: 0,
            findings: 0,
            blocked: 0,
            warned: 0,
            max_findings_reached: false,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> Config {
        Config::default()
    }

    #[test]
    fn fail_on_policy_blocks_as_expected() {
        let report = ScanReport {
            findings: vec![
                ScanFinding {
                    file: "a".to_string(),
                    line: 1,
                    col: None,
                    extractor_id: "x".to_string(),
                    extracted_command: "rm -rf /".to_string(),
                    decision: ScanDecision::Deny,
                    severity: ScanSeverity::Error,
                    rule_id: Some("core.filesystem:rm-rf-general".to_string()),
                    reason: Some("blocked".to_string()),
                    suggestion: None,
                },
                ScanFinding {
                    file: "b".to_string(),
                    line: 1,
                    col: None,
                    extractor_id: "x".to_string(),
                    extracted_command: "echo hi".to_string(),
                    decision: ScanDecision::Warn,
                    severity: ScanSeverity::Warning,
                    rule_id: None,
                    reason: Some("warn".to_string()),
                    suggestion: None,
                },
            ],
            summary: ScanSummary {
                files_considered: 2,
                files_scanned: 2,
                commands_extracted: 2,
                findings: 2,
                blocked: 1,
                warned: 1,
                max_findings_reached: false,
            },
        };

        assert!(should_fail(&report, ScanFailOn::Error));
        assert!(should_fail(&report, ScanFailOn::Warning));
        assert!(!should_fail(&report, ScanFailOn::None));
    }

    #[test]
    fn finding_order_is_deterministic() {
        let mut findings = vec![
            ScanFinding {
                file: "b".to_string(),
                line: 2,
                col: None,
                extractor_id: "x".to_string(),
                extracted_command: "cmd".to_string(),
                decision: ScanDecision::Warn,
                severity: ScanSeverity::Warning,
                rule_id: Some("pack:rule".to_string()),
                reason: None,
                suggestion: None,
            },
            ScanFinding {
                file: "a".to_string(),
                line: 1,
                col: None,
                extractor_id: "x".to_string(),
                extracted_command: "cmd".to_string(),
                decision: ScanDecision::Deny,
                severity: ScanSeverity::Error,
                rule_id: Some("pack:rule".to_string()),
                reason: None,
                suggestion: None,
            },
        ];

        sort_findings(&mut findings);
        assert_eq!(findings[0].file, "a");
        assert_eq!(findings[0].severity, ScanSeverity::Error);
    }

    #[test]
    fn evaluator_integration_maps_pack_rule_to_rule_id() {
        let config = default_config();
        let ctx = ScanEvalContext::from_config(&config);
        let extracted = ExtractedCommand {
            file: "test".to_string(),
            line: 1,
            col: None,
            extractor_id: "shell.script".to_string(),
            command: "git reset --hard".to_string(),
            metadata: None,
        };

        let finding = evaluate_extracted_command(&extracted, &config, &ctx)
            .expect("git reset --hard should be blocked");
        assert_eq!(finding.decision, ScanDecision::Deny);
        assert_eq!(finding.severity, ScanSeverity::Error);
        assert_eq!(finding.rule_id.as_deref(), Some("core.git:reset-hard"));
        assert!(finding.reason.is_some());
    }
}
