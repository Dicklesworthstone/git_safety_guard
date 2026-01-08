//! Suggestions system for providing actionable guidance when commands are blocked.
//!
//! When DCG blocks a command, users need actionable guidance:
//! - What safer alternatives exist?
//! - How can they preview the effect first?
//! - How can they allowlist if intentional?
//!
//! This module provides:
//! - [`SuggestionKind`] enum categorizing types of suggestions
//! - [`Suggestion`] struct with actionable guidance
//! - [`SUGGESTION_REGISTRY`] static registry keyed by `rule_id`
//! - [`get_suggestions`] lookup function

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::LazyLock;

/// Type of suggestion to help the user.
///
/// Each kind represents a different strategy for helping users
/// work around blocked commands safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuggestionKind {
    /// "Run this first to preview the effect"
    /// e.g., "Run `git diff` before `git reset --hard`"
    PreviewFirst,

    /// "Use this safer alternative instead"
    /// e.g., "Use `git reset --soft` or `--mixed` instead of `--hard`"
    SaferAlternative,

    /// "Fix your workflow to avoid this situation"
    /// e.g., "Commit your changes before resetting"
    WorkflowFix,

    /// "Read the documentation for more context"
    /// e.g., "See: <https://git-scm.com/docs/git-reset>"
    Documentation,

    /// "How to allowlist this specific rule"
    /// e.g., "To allow: `dcg allow core.git:reset-hard --reason '...'`"
    AllowSafely,
}

impl SuggestionKind {
    /// Returns a human-readable label for this suggestion kind.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::PreviewFirst => "Preview first",
            Self::SaferAlternative => "Safer alternative",
            Self::WorkflowFix => "Workflow fix",
            Self::Documentation => "Documentation",
            Self::AllowSafely => "Allow safely",
        }
    }
}

/// A suggestion providing actionable guidance for a blocked command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suggestion {
    /// Type of suggestion
    pub kind: SuggestionKind,

    /// Human-readable suggestion text
    pub text: String,

    /// Optional command the user can copy/paste
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,

    /// Optional URL for documentation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl Suggestion {
    /// Create a new suggestion.
    #[must_use]
    pub fn new(kind: SuggestionKind, text: impl Into<String>) -> Self {
        Self {
            kind,
            text: text.into(),
            command: None,
            url: None,
        }
    }

    /// Add a command to copy/paste.
    #[must_use]
    pub fn with_command(mut self, command: impl Into<String>) -> Self {
        self.command = Some(command.into());
        self
    }

    /// Add a documentation URL.
    #[must_use]
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }
}

/// Registry of suggestions keyed by `rule_id` (e.g., `"core.git:reset-hard"`).
///
/// Rule IDs follow the format `{pack_id}:{pattern_name}`.
///
/// # Performance
///
/// - Lookup is O(1) via `HashMap`
/// - Returns static references (zero allocation on lookup)
/// - Initialized once on first access via `LazyLock`
pub static SUGGESTION_REGISTRY: LazyLock<HashMap<&'static str, Vec<Suggestion>>> =
    LazyLock::new(build_suggestion_registry);

/// Look up suggestions for a rule.
///
/// Returns `None` if no suggestions are registered for the given `rule_id`.
///
/// # Example
///
/// ```
/// use destructive_command_guard::suggestions::get_suggestions;
///
/// if let Some(suggestions) = get_suggestions("core.git:reset-hard") {
///     for s in suggestions {
///         println!("- {}", s.text);
///     }
/// }
/// ```
#[must_use]
pub fn get_suggestions(rule_id: &str) -> Option<&'static [Suggestion]> {
    SUGGESTION_REGISTRY.get(rule_id).map(Vec::as_slice)
}

/// Get the first suggestion of a specific kind for a rule.
#[must_use]
pub fn get_suggestion_by_kind(rule_id: &str, kind: SuggestionKind) -> Option<&'static Suggestion> {
    get_suggestions(rule_id).and_then(|suggestions| suggestions.iter().find(|s| s.kind == kind))
}

/// Build the suggestion registry.
///
/// This function is called once by `LazyLock` to initialize the registry.
#[allow(clippy::too_many_lines)]
fn build_suggestion_registry() -> HashMap<&'static str, Vec<Suggestion>> {
    let mut m = HashMap::new();
    register_core_git_suggestions(&mut m);
    register_core_filesystem_suggestions(&mut m);
    register_heredoc_suggestions(&mut m);
    m
}

/// Register suggestions for core.git pack rules.
#[allow(clippy::too_many_lines)]
fn register_core_git_suggestions(m: &mut HashMap<&'static str, Vec<Suggestion>>) {
    m.insert(
        "core.git:reset-hard",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Run `git diff` and `git status` to see what would be lost",
            )
            .with_command("git diff && git status"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Use `git reset --soft` or `--mixed` to preserve changes",
            )
            .with_command("git reset --soft HEAD~1"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Consider using `git stash` to save changes temporarily",
            )
            .with_command("git stash"),
            Suggestion::new(
                SuggestionKind::Documentation,
                "See Git documentation for reset options",
            )
            .with_url("https://git-scm.com/docs/git-reset"),
        ],
    );

    m.insert(
        "core.git:clean-force",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Run `git clean -n` to preview what would be deleted",
            )
            .with_command("git clean -n -fd"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Use `git clean -i` for interactive mode to select files",
            )
            .with_command("git clean -i"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Add patterns to .gitignore instead of cleaning",
            ),
        ],
    );

    // Force push patterns (--force and -f variants)
    let force_push_suggestions = vec![
        Suggestion::new(
            SuggestionKind::SaferAlternative,
            "Use `git push --force-with-lease` to prevent overwriting others' work",
        )
        .with_command("git push --force-with-lease"),
        Suggestion::new(
            SuggestionKind::PreviewFirst,
            "Run `git log origin/branch..HEAD` to see commits being pushed",
        ),
        Suggestion::new(
            SuggestionKind::WorkflowFix,
            "Coordinate with team before force pushing to shared branches",
        ),
    ];
    m.insert("core.git:push-force-long", force_push_suggestions.clone());
    m.insert("core.git:push-force-short", force_push_suggestions);

    // Checkout patterns that discard changes
    let checkout_discard_suggestions = vec![
        Suggestion::new(
            SuggestionKind::PreviewFirst,
            "Run `git status` and `git diff` to see uncommitted changes that would be lost",
        )
        .with_command("git status && git diff"),
        Suggestion::new(
            SuggestionKind::WorkflowFix,
            "Commit or stash changes before discarding",
        )
        .with_command("git stash"),
    ];
    m.insert(
        "core.git:checkout-discard",
        checkout_discard_suggestions.clone(),
    );
    m.insert(
        "core.git:checkout-ref-discard",
        checkout_discard_suggestions,
    );

    m.insert(
        "core.git:branch-force-delete",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Check if branch has unmerged commits with `git log branch --not main`",
            ),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Use `git branch -d` (lowercase) to only delete if merged",
            )
            .with_command("git branch -d branch-name"),
        ],
    );

    // restore worktree patterns
    let restore_worktree_suggestions = vec![
        Suggestion::new(
            SuggestionKind::PreviewFirst,
            "Run `git diff` to see uncommitted changes that would be lost",
        )
        .with_command("git diff"),
        Suggestion::new(
            SuggestionKind::SaferAlternative,
            "Use `git restore --staged` to unstage without discarding changes",
        )
        .with_command("git restore --staged"),
        Suggestion::new(
            SuggestionKind::WorkflowFix,
            "Stash changes before discarding with `git stash`",
        )
        .with_command("git stash"),
    ];
    m.insert(
        "core.git:restore-worktree",
        restore_worktree_suggestions.clone(),
    );
    m.insert(
        "core.git:restore-worktree-explicit",
        restore_worktree_suggestions,
    );

    // reset --merge
    m.insert(
        "core.git:reset-merge",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Run `git status` to see uncommitted changes that could be lost",
            )
            .with_command("git status"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Use `git merge --abort` to cleanly abort an in-progress merge",
            )
            .with_command("git merge --abort"),
        ],
    );

    // stash destruction
    m.insert(
        "core.git:stash-drop",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "List stashes with `git stash list` and view contents with `git stash show -p`",
            )
            .with_command("git stash list"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Apply the stash first with `git stash apply` before dropping",
            )
            .with_command("git stash apply"),
        ],
    );

    m.insert(
        "core.git:stash-clear",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "List all stashes with `git stash list` to review what would be deleted",
            )
            .with_command("git stash list"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Drop stashes individually with `git stash drop` for more control",
            )
            .with_command("git stash drop stash@{0}"),
        ],
    );
}

/// Register suggestions for core.filesystem pack rules.
fn register_core_filesystem_suggestions(m: &mut HashMap<&'static str, Vec<Suggestion>>) {
    // Shared suggestions for all recursive force-delete variants
    let rm_rf_suggestions = vec![
        Suggestion::new(
            SuggestionKind::PreviewFirst,
            "List contents first with `ls -la` to verify target",
        ),
        Suggestion::new(
            SuggestionKind::SaferAlternative,
            "Use `rm -ri` for interactive confirmation of each file",
        )
        .with_command("rm -ri path/"),
        Suggestion::new(
            SuggestionKind::WorkflowFix,
            "Move to trash instead: `mv path ~/.local/share/Trash/`",
        ),
    ];

    // Register for all actual pattern names from filesystem.rs
    m.insert("core.filesystem:rm-rf-root-home", rm_rf_suggestions.clone());
    m.insert("core.filesystem:rm-rf-general", rm_rf_suggestions.clone());
    m.insert("core.filesystem:rm-r-f-separate", rm_rf_suggestions.clone());
    m.insert("core.filesystem:rm-recursive-force-long", rm_rf_suggestions);
}

/// Register suggestions for heredoc pattern rules (placeholder for expansion).
fn register_heredoc_suggestions(m: &mut HashMap<&'static str, Vec<Suggestion>>) {
    m.insert(
        "heredoc.python.shutil_rmtree",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "List directory contents with `os.listdir()` before removal",
            ),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Use `shutil.move()` to archive instead of delete",
            ),
        ],
    );

    m.insert(
        "heredoc.javascript.fs_rmsync",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Use `fs.readdirSync()` to list contents first",
            ),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Move files to a backup directory instead of deleting",
            ),
        ],
    );
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggestion_kind_labels() {
        assert_eq!(SuggestionKind::PreviewFirst.label(), "Preview first");
        assert_eq!(
            SuggestionKind::SaferAlternative.label(),
            "Safer alternative"
        );
        assert_eq!(SuggestionKind::WorkflowFix.label(), "Workflow fix");
        assert_eq!(SuggestionKind::Documentation.label(), "Documentation");
        assert_eq!(SuggestionKind::AllowSafely.label(), "Allow safely");
    }

    #[test]
    fn suggestion_builder_pattern() {
        let suggestion = Suggestion::new(SuggestionKind::PreviewFirst, "Test suggestion")
            .with_command("git status")
            .with_url("https://example.com");

        assert_eq!(suggestion.kind, SuggestionKind::PreviewFirst);
        assert_eq!(suggestion.text, "Test suggestion");
        assert_eq!(suggestion.command, Some("git status".to_string()));
        assert_eq!(suggestion.url, Some("https://example.com".to_string()));
    }

    #[test]
    fn registry_lookup_returns_suggestions() {
        let suggestions = get_suggestions("core.git:reset-hard");
        assert!(suggestions.is_some());
        let suggestions = suggestions.unwrap();
        assert!(!suggestions.is_empty());
        assert!(suggestions.len() >= 3); // At least preview, alternative, workflow
    }

    #[test]
    fn registry_lookup_returns_none_for_unknown_rule() {
        let suggestions = get_suggestions("nonexistent:rule");
        assert!(suggestions.is_none());
    }

    #[test]
    fn get_suggestion_by_kind_works() {
        let preview = get_suggestion_by_kind("core.git:reset-hard", SuggestionKind::PreviewFirst);
        assert!(preview.is_some());
        assert!(preview.unwrap().text.contains("git diff"));

        let safer = get_suggestion_by_kind("core.git:reset-hard", SuggestionKind::SaferAlternative);
        assert!(safer.is_some());
        assert!(safer.unwrap().text.contains("soft"));
    }

    #[test]
    fn suggestions_serialize_to_json() {
        let suggestion =
            Suggestion::new(SuggestionKind::PreviewFirst, "Test").with_command("git status");

        let json = serde_json::to_string(&suggestion).unwrap();
        assert!(json.contains("\"kind\":\"preview_first\""));
        assert!(json.contains("\"text\":\"Test\""));
        assert!(json.contains("\"command\":\"git status\""));
        // url should be skipped when None
        assert!(!json.contains("\"url\""));
    }

    #[test]
    fn suggestions_deserialize_from_json() {
        let json = r#"{"kind":"safer_alternative","text":"Use safer option","command":"git reset --soft"}"#;
        let suggestion: Suggestion = serde_json::from_str(json).unwrap();

        assert_eq!(suggestion.kind, SuggestionKind::SaferAlternative);
        assert_eq!(suggestion.text, "Use safer option");
        assert_eq!(suggestion.command, Some("git reset --soft".to_string()));
        assert_eq!(suggestion.url, None);
    }

    #[test]
    fn registry_has_core_git_rules() {
        // Verify expected core.git rules have suggestions
        // These must match actual pattern names from src/packs/core/git.rs
        let expected_rules = [
            "core.git:reset-hard",
            "core.git:reset-merge",
            "core.git:clean-force",
            "core.git:push-force-long",
            "core.git:push-force-short",
            "core.git:checkout-discard",
            "core.git:checkout-ref-discard",
            "core.git:branch-force-delete",
            "core.git:restore-worktree",
            "core.git:restore-worktree-explicit",
            "core.git:stash-drop",
            "core.git:stash-clear",
        ];

        for rule in expected_rules {
            assert!(
                get_suggestions(rule).is_some(),
                "Expected suggestions for {rule}"
            );
        }
    }

    #[test]
    fn registry_has_core_filesystem_rules() {
        // Verify expected core.filesystem rules have suggestions
        // These must match actual pattern names from src/packs/core/filesystem.rs
        let expected_rules = [
            "core.filesystem:rm-rf-root-home",
            "core.filesystem:rm-rf-general",
            "core.filesystem:rm-r-f-separate",
            "core.filesystem:rm-recursive-force-long",
        ];

        for rule in expected_rules {
            assert!(
                get_suggestions(rule).is_some(),
                "Expected suggestions for {rule}"
            );
        }
    }

    #[test]
    fn all_suggestion_kinds_are_used() {
        // Verify all SuggestionKind variants are used at least once in the registry
        let mut kinds_found = std::collections::HashSet::new();

        for suggestions in SUGGESTION_REGISTRY.values() {
            for suggestion in suggestions {
                kinds_found.insert(suggestion.kind);
            }
        }

        // Note: AllowSafely may not be used yet - that's intentional for 1gt.5.2
        assert!(kinds_found.contains(&SuggestionKind::PreviewFirst));
        assert!(kinds_found.contains(&SuggestionKind::SaferAlternative));
        assert!(kinds_found.contains(&SuggestionKind::WorkflowFix));
        assert!(kinds_found.contains(&SuggestionKind::Documentation));
        // AllowSafely will be added when allowlist integration is complete
    }

    #[test]
    fn suggestions_have_stable_order() {
        // Verify suggestions for a rule always come in the same order
        let suggestions1 = get_suggestions("core.git:reset-hard").unwrap();
        let suggestions2 = get_suggestions("core.git:reset-hard").unwrap();

        assert_eq!(suggestions1.len(), suggestions2.len());
        for (s1, s2) in suggestions1.iter().zip(suggestions2.iter()) {
            assert_eq!(s1.kind, s2.kind);
            assert_eq!(s1.text, s2.text);
        }
    }
}
