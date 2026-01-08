//! Explain trace data model for `dcg explain` mode.
//!
//! This module provides opt-in instrumentation for tracing command evaluation,
//! enabling detailed decision explanations without impacting hook mode performance.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      TraceCollector                             │
//! │  (opt-in, passed as Option<&mut TraceCollector> to evaluator)   │
//! └─────────────────────────────────────────────────────────────────┘
//!                                  │
//!                                  ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                       ExplainTrace                              │
//! │  (complete decision trace with steps, match info, timing)       │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Performance
//!
//! When tracing is disabled (`None`), the evaluator avoids allocations and
//! expensive string formatting. The trace collection is truly opt-in.
//!
//! # Example
//!
//! ```ignore
//! use destructive_command_guard::trace::TraceCollector;
//!
//! let mut collector = TraceCollector::new();
//! // ... pass &mut collector to evaluator ...
//! let trace = collector.finish();
//!
//! println!("Decision: {:?}", trace.decision);
//! println!("Total time: {}us", trace.total_duration_us);
//! for step in &trace.steps {
//!     println!("  {} ({}us)", step.name, step.duration_us);
//! }
//! ```

use crate::allowlist::AllowlistLayer;
use crate::evaluator::{EvaluationDecision, MatchSource};
use std::time::Instant;

/// A complete trace of a command evaluation.
///
/// Contains all information needed for `dcg explain` output formatting.
#[derive(Debug, Clone)]
pub struct ExplainTrace {
    /// The original command that was evaluated.
    pub command: String,
    /// The normalized command (after path stripping, etc.).
    pub normalized_command: Option<String>,
    /// The sanitized command (after masking safe string arguments).
    pub sanitized_command: Option<String>,
    /// The final decision (Allow or Deny).
    pub decision: EvaluationDecision,
    /// Total evaluation duration in microseconds.
    pub total_duration_us: u64,
    /// Individual trace steps in chronological order.
    pub steps: Vec<TraceStep>,
    /// Match information (when command was denied or allowlisted).
    pub match_info: Option<MatchInfo>,
    /// Allowlist override information (when a deny was overridden).
    pub allowlist_info: Option<AllowlistInfo>,
    /// Summary of packs that were evaluated.
    pub pack_summary: Option<PackSummary>,
}

/// A single step in the evaluation trace.
#[derive(Debug, Clone)]
pub struct TraceStep {
    /// Human-readable step name.
    pub name: &'static str,
    /// Step duration in microseconds.
    pub duration_us: u64,
    /// Step-specific details.
    pub details: TraceDetails,
}

/// Step-specific details for different evaluation stages.
#[derive(Debug, Clone)]
pub enum TraceDetails {
    /// Input parsing (hook JSON vs CLI input).
    InputParsing {
        /// Whether input was from hook (JSON) or CLI.
        is_hook_input: bool,
        /// Command length in bytes.
        command_len: usize,
    },

    /// Keyword gating (quick reject).
    KeywordGating {
        /// Whether the command was quick-rejected (no keywords found).
        quick_rejected: bool,
        /// Keywords that were checked.
        keywords_checked: Vec<String>,
        /// First keyword that matched (if any).
        first_match: Option<String>,
    },

    /// Command normalization.
    Normalization {
        /// Whether the command was modified.
        was_modified: bool,
        /// Original prefix that was stripped (if any).
        stripped_prefix: Option<String>,
    },

    /// Context sanitization (false positive immunity).
    Sanitization {
        /// Whether the command was modified.
        was_modified: bool,
        /// Number of spans that were masked.
        spans_masked: usize,
    },

    /// Heredoc/inline script detection.
    HeredocDetection {
        /// Whether heredoc triggers were found.
        triggered: bool,
        /// Number of scripts extracted.
        scripts_extracted: usize,
        /// Languages detected.
        languages: Vec<String>,
    },

    /// Allowlist check.
    AllowlistCheck {
        /// Number of layers checked.
        layers_checked: usize,
        /// Whether a match was found.
        matched: bool,
        /// The layer that matched (if any).
        matched_layer: Option<AllowlistLayer>,
    },

    /// Pack evaluation.
    PackEvaluation {
        /// Packs that were evaluated (not skipped).
        packs_evaluated: Vec<String>,
        /// Packs that were skipped (keyword gating).
        packs_skipped: Vec<String>,
        /// The pack that matched (if any).
        matched_pack: Option<String>,
        /// The pattern name that matched (if any).
        matched_pattern: Option<String>,
    },

    /// Config override check.
    ConfigOverride {
        /// Whether an allow override matched.
        allow_matched: bool,
        /// Whether a block override matched.
        block_matched: bool,
        /// The override reason (if blocked).
        reason: Option<String>,
    },

    /// Final policy decision.
    PolicyDecision {
        /// The decision made.
        decision: EvaluationDecision,
        /// Whether the decision was due to allowlist override.
        allowlisted: bool,
    },
}

/// Information about a pattern match (for denials or allowlist overrides).
#[derive(Debug, Clone)]
pub struct MatchInfo {
    /// Stable rule ID (e.g., `core.git:reset-hard`).
    pub rule_id: Option<String>,
    /// Pack ID that matched.
    pub pack_id: Option<String>,
    /// Pattern name that matched.
    pub pattern_name: Option<String>,
    /// Human-readable reason.
    pub reason: String,
    /// Source of the match.
    pub source: MatchSource,
    /// Byte offset where match starts in the command.
    pub match_start: Option<usize>,
    /// Byte offset where match ends in the command.
    pub match_end: Option<usize>,
    /// Preview of matched text (truncated if too long).
    pub matched_text_preview: Option<String>,
}

/// Information about an allowlist override.
#[derive(Debug, Clone)]
pub struct AllowlistInfo {
    /// The layer that matched.
    pub layer: AllowlistLayer,
    /// The allowlist entry reason.
    pub entry_reason: String,
    /// The original match that was overridden.
    pub original_match: MatchInfo,
}

/// Summary of pack evaluation.
#[derive(Debug, Clone)]
pub struct PackSummary {
    /// Total number of enabled packs.
    pub enabled_count: usize,
    /// Packs that were evaluated (not skipped by keyword gating).
    pub evaluated: Vec<String>,
    /// Packs that were skipped (keyword gating).
    pub skipped: Vec<String>,
}

/// Collector for building a trace during evaluation.
///
/// This is the opt-in instrumentation hook. Pass `Some(&mut collector)` to
/// the evaluator to enable tracing, or `None` to disable.
#[derive(Debug)]
pub struct TraceCollector {
    /// Start time of the evaluation.
    start_time: Instant,
    /// Current step start time.
    step_start: Instant,
    /// Steps collected so far.
    steps: Vec<TraceStep>,
    /// The original command.
    command: String,
    /// Normalized command (set during evaluation).
    normalized_command: Option<String>,
    /// Sanitized command (set during evaluation).
    sanitized_command: Option<String>,
    /// Match information (set during evaluation).
    match_info: Option<MatchInfo>,
    /// Allowlist information (set during evaluation).
    allowlist_info: Option<AllowlistInfo>,
    /// Pack summary (set during evaluation).
    pack_summary: Option<PackSummary>,
}

impl TraceCollector {
    /// Create a new trace collector.
    #[must_use]
    pub fn new(command: &str) -> Self {
        let now = Instant::now();
        Self {
            start_time: now,
            step_start: now,
            steps: Vec::with_capacity(8), // Typical number of steps
            command: command.to_string(),
            normalized_command: None,
            sanitized_command: None,
            match_info: None,
            allowlist_info: None,
            pack_summary: None,
        }
    }

    /// Start timing a new step.
    pub fn begin_step(&mut self) {
        self.step_start = Instant::now();
    }

    /// End the current step and record it.
    #[allow(clippy::cast_possible_truncation)] // Microseconds fit in u64
    pub fn end_step(&mut self, name: &'static str, details: TraceDetails) {
        let duration_us = self.step_start.elapsed().as_micros() as u64;
        self.steps.push(TraceStep {
            name,
            duration_us,
            details,
        });
    }

    /// Record a step with explicit duration (for when step wasn't timed with begin/end).
    pub fn record_step(&mut self, name: &'static str, duration_us: u64, details: TraceDetails) {
        self.steps.push(TraceStep {
            name,
            duration_us,
            details,
        });
    }

    /// Set the normalized command.
    pub fn set_normalized(&mut self, normalized: &str) {
        self.normalized_command = Some(normalized.to_string());
    }

    /// Set the sanitized command.
    pub fn set_sanitized(&mut self, sanitized: &str) {
        self.sanitized_command = Some(sanitized.to_string());
    }

    /// Set match information.
    pub fn set_match(&mut self, info: MatchInfo) {
        self.match_info = Some(info);
    }

    /// Set allowlist override information.
    pub fn set_allowlist(&mut self, info: AllowlistInfo) {
        self.allowlist_info = Some(info);
    }

    /// Set pack summary.
    pub fn set_pack_summary(&mut self, summary: PackSummary) {
        self.pack_summary = Some(summary);
    }

    /// Finish collection and produce the final trace.
    #[allow(clippy::cast_possible_truncation)] // Microseconds fit in u64
    #[must_use]
    pub fn finish(self, decision: EvaluationDecision) -> ExplainTrace {
        let total_duration_us = self.start_time.elapsed().as_micros() as u64;
        ExplainTrace {
            command: self.command,
            normalized_command: self.normalized_command,
            sanitized_command: self.sanitized_command,
            decision,
            total_duration_us,
            steps: self.steps,
            match_info: self.match_info,
            allowlist_info: self.allowlist_info,
            pack_summary: self.pack_summary,
        }
    }
}

impl ExplainTrace {
    /// Get the stable rule ID (if a match occurred).
    #[must_use]
    pub fn rule_id(&self) -> Option<&str> {
        self.match_info.as_ref().and_then(|m| m.rule_id.as_deref())
    }

    /// Check if the command was allowed due to an allowlist override.
    #[must_use]
    pub const fn was_allowlisted(&self) -> bool {
        self.allowlist_info.is_some()
    }

    /// Get the first match (either from denial or allowlist).
    #[must_use]
    pub fn first_match(&self) -> Option<&MatchInfo> {
        self.match_info.as_ref().or_else(|| {
            self.allowlist_info
                .as_ref()
                .map(|a| &a.original_match)
        })
    }

    /// Find a step by name.
    #[must_use]
    pub fn find_step(&self, name: &str) -> Option<&TraceStep> {
        self.steps.iter().find(|s| s.name == name)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_collector_basic_flow() {
        let mut collector = TraceCollector::new("git reset --hard");

        collector.begin_step();
        std::thread::sleep(std::time::Duration::from_micros(10));
        collector.end_step(
            "keyword_gating",
            TraceDetails::KeywordGating {
                quick_rejected: false,
                keywords_checked: vec!["git".to_string()],
                first_match: Some("git".to_string()),
            },
        );

        collector.set_normalized("git reset --hard");
        collector.set_match(MatchInfo {
            rule_id: Some("core.git:reset-hard".to_string()),
            pack_id: Some("core.git".to_string()),
            pattern_name: Some("reset-hard".to_string()),
            reason: "destroys uncommitted changes".to_string(),
            source: MatchSource::Pack,
            match_start: Some(0),
            match_end: Some(15),
            matched_text_preview: Some("git reset --hard".to_string()),
        });

        let trace = collector.finish(EvaluationDecision::Deny);

        assert_eq!(trace.decision, EvaluationDecision::Deny);
        assert_eq!(trace.command, "git reset --hard");
        assert!(trace.total_duration_us > 0);
        assert_eq!(trace.steps.len(), 1);
        assert_eq!(trace.steps[0].name, "keyword_gating");
        assert!(trace.match_info.is_some());
        assert_eq!(
            trace.rule_id(),
            Some("core.git:reset-hard")
        );
    }

    #[test]
    fn trace_collector_allowed_flow() {
        let mut collector = TraceCollector::new("git status");

        collector.begin_step();
        collector.end_step(
            "keyword_gating",
            TraceDetails::KeywordGating {
                quick_rejected: false,
                keywords_checked: vec!["git".to_string()],
                first_match: Some("git".to_string()),
            },
        );

        let trace = collector.finish(EvaluationDecision::Allow);

        assert_eq!(trace.decision, EvaluationDecision::Allow);
        assert!(trace.match_info.is_none());
        assert!(!trace.was_allowlisted());
    }

    #[test]
    fn trace_collector_allowlist_override() {
        let mut collector = TraceCollector::new("git reset --hard");

        let original_match = MatchInfo {
            rule_id: Some("core.git:reset-hard".to_string()),
            pack_id: Some("core.git".to_string()),
            pattern_name: Some("reset-hard".to_string()),
            reason: "destroys uncommitted changes".to_string(),
            source: MatchSource::Pack,
            match_start: Some(0),
            match_end: Some(15),
            matched_text_preview: Some("git reset --hard".to_string()),
        };

        collector.set_allowlist(AllowlistInfo {
            layer: AllowlistLayer::Project,
            entry_reason: "Allowed for release automation".to_string(),
            original_match,
        });

        let trace = collector.finish(EvaluationDecision::Allow);

        assert_eq!(trace.decision, EvaluationDecision::Allow);
        assert!(trace.was_allowlisted());
        assert!(trace.allowlist_info.is_some());
        assert_eq!(
            trace.allowlist_info.as_ref().unwrap().layer,
            AllowlistLayer::Project
        );
    }

    #[test]
    fn trace_step_ordering_preserved() {
        let mut collector = TraceCollector::new("test");

        collector.record_step("step1", 10, TraceDetails::InputParsing {
            is_hook_input: false,
            command_len: 4,
        });
        collector.record_step("step2", 20, TraceDetails::KeywordGating {
            quick_rejected: true,
            keywords_checked: vec![],
            first_match: None,
        });
        collector.record_step("step3", 30, TraceDetails::PolicyDecision {
            decision: EvaluationDecision::Allow,
            allowlisted: false,
        });

        let trace = collector.finish(EvaluationDecision::Allow);

        assert_eq!(trace.steps.len(), 3);
        assert_eq!(trace.steps[0].name, "step1");
        assert_eq!(trace.steps[1].name, "step2");
        assert_eq!(trace.steps[2].name, "step3");
        assert_eq!(trace.steps[0].duration_us, 10);
        assert_eq!(trace.steps[1].duration_us, 20);
        assert_eq!(trace.steps[2].duration_us, 30);
    }

    #[test]
    fn trace_find_step() {
        let mut collector = TraceCollector::new("test");

        collector.record_step("keyword_gating", 10, TraceDetails::KeywordGating {
            quick_rejected: false,
            keywords_checked: vec!["git".to_string()],
            first_match: Some("git".to_string()),
        });

        let trace = collector.finish(EvaluationDecision::Allow);

        assert!(trace.find_step("keyword_gating").is_some());
        assert!(trace.find_step("nonexistent").is_none());
    }

    #[test]
    fn match_info_captures_span() {
        let info = MatchInfo {
            rule_id: Some("test:pattern".to_string()),
            pack_id: Some("test".to_string()),
            pattern_name: Some("pattern".to_string()),
            reason: "test reason".to_string(),
            source: MatchSource::Pack,
            match_start: Some(10),
            match_end: Some(25),
            matched_text_preview: Some("matched text".to_string()),
        };

        assert_eq!(info.match_start, Some(10));
        assert_eq!(info.match_end, Some(25));
        assert_eq!(info.matched_text_preview, Some("matched text".to_string()));
    }

    #[test]
    fn pack_summary_tracks_evaluation() {
        let summary = PackSummary {
            enabled_count: 5,
            evaluated: vec!["core.git".to_string(), "core.filesystem".to_string()],
            skipped: vec!["containers.docker".to_string()],
        };

        assert_eq!(summary.enabled_count, 5);
        assert_eq!(summary.evaluated.len(), 2);
        assert_eq!(summary.skipped.len(), 1);
    }
}
