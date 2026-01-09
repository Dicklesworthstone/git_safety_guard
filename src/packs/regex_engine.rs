//! Dual regex engine abstraction for safe and fast pattern matching.
//!
//! The regex safety audit (git_safety_guard-99e.11) found:
//! - ~85% of pack patterns can use the linear-time `regex` crate
//! - ~15% require lookahead/lookbehind (needs `fancy_regex`)
//!
//! This module provides [`CompiledRegex`], an abstraction that auto-selects
//! the appropriate engine based on pattern syntax, providing guaranteed O(n)
//! performance for the majority of patterns.

use std::borrow::Cow;

/// A compiled regex that auto-selects between linear-time and backtracking engines.
///
/// Use this instead of `fancy_regex::Regex` directly when the pattern may not
/// require backtracking features. The `regex` crate provides O(n) guarantees
/// but doesn't support lookahead/lookbehind.
///
/// # Example
///
/// ```ignore
/// use destructive_command_guard::packs::regex_engine::CompiledRegex;
///
/// // Auto-selects linear-time engine (no lookahead)
/// let simple = CompiledRegex::new(r"rm\s+-rf").unwrap();
/// assert!(!simple.uses_backtracking());
///
/// // Auto-selects backtracking engine (has lookahead)
/// let lookahead = CompiledRegex::new(r"git\s+push(?=.*--force)").unwrap();
/// assert!(lookahead.uses_backtracking());
/// ```
#[derive(Debug)]
pub enum CompiledRegex {
    /// Linear-time regex (O(n) guaranteed, no backtracking).
    Linear(regex::Regex),
    /// Backtracking regex (supports lookahead/lookbehind).
    Backtracking(fancy_regex::Regex),
}

impl CompiledRegex {
    /// Compile a pattern, auto-selecting the appropriate engine.
    ///
    /// Uses linear-time `regex` crate unless the pattern contains
    /// lookahead (`(?=`, `(?!`) or lookbehind (`(?<=`, `(?<!`).
    ///
    /// # Errors
    /// Returns an error if the pattern fails to compile.
    pub fn new(pattern: &str) -> Result<Self, String> {
        if needs_backtracking_engine(pattern) {
            fancy_regex::Regex::new(pattern)
                .map(Self::Backtracking)
                .map_err(|e| format!("fancy_regex compile error: {e}"))
        } else {
            regex::Regex::new(pattern)
                .map(Self::Linear)
                .map_err(|e| format!("regex compile error: {e}"))
        }
    }

    /// Compile a pattern using the linear-time engine only.
    ///
    /// # Errors
    /// Returns an error if the pattern uses features not supported by the
    /// linear-time engine (lookahead, lookbehind, backreferences).
    pub fn new_linear(pattern: &str) -> Result<Self, String> {
        regex::Regex::new(pattern)
            .map(Self::Linear)
            .map_err(|e| format!("regex compile error: {e}"))
    }

    /// Compile a pattern using the backtracking engine.
    ///
    /// # Errors
    /// Returns an error if the pattern fails to compile.
    pub fn new_backtracking(pattern: &str) -> Result<Self, String> {
        fancy_regex::Regex::new(pattern)
            .map(Self::Backtracking)
            .map_err(|e| format!("fancy_regex compile error: {e}"))
    }

    /// Check if the pattern matches the text.
    ///
    /// For backtracking engine, returns `false` on regex execution errors.
    #[must_use]
    pub fn is_match(&self, text: &str) -> bool {
        match self {
            Self::Linear(re) => re.is_match(text),
            Self::Backtracking(re) => re.is_match(text).unwrap_or(false),
        }
    }

    /// Find the first match in the text.
    ///
    /// Returns the start and end byte offsets of the match.
    #[must_use]
    pub fn find(&self, text: &str) -> Option<(usize, usize)> {
        match self {
            Self::Linear(re) => re.find(text).map(|m| (m.start(), m.end())),
            Self::Backtracking(re) => re.find(text).ok().flatten().map(|m| (m.start(), m.end())),
        }
    }

    /// Get the pattern string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Linear(re) => re.as_str(),
            Self::Backtracking(re) => re.as_str(),
        }
    }

    /// Check if this regex uses the backtracking engine.
    #[must_use]
    pub const fn uses_backtracking(&self) -> bool {
        matches!(self, Self::Backtracking(_))
    }

    /// Replace up to `limit` matches with the replacement string.
    ///
    /// Returns a `Cow::Borrowed` if no replacements were made.
    /// For backtracking engine, falls back to original text on execution errors.
    #[must_use]
    pub fn replacen<'t>(&self, text: &'t str, limit: usize, rep: &str) -> Cow<'t, str> {
        match self {
            Self::Linear(re) => re.replacen(text, limit, rep),
            // Use try_replacen to handle errors gracefully (returns Result)
            Self::Backtracking(re) => re
                .try_replacen(text, limit, rep)
                .unwrap_or(Cow::Borrowed(text)),
        }
    }
}

/// Check if a pattern requires the backtracking engine.
///
/// Returns `true` if the pattern contains lookahead or lookbehind assertions,
/// which are not supported by the linear-time `regex` crate.
#[must_use]
pub fn needs_backtracking_engine(pattern: &str) -> bool {
    // Lookahead: (?= positive, (?! negative
    // Lookbehind: (?<= positive, (?<! negative
    pattern.contains("(?=")
        || pattern.contains("(?!")
        || pattern.contains("(?<=")
        || pattern.contains("(?<!")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linear_engine_selection() {
        // Simple patterns should use linear engine
        let re = CompiledRegex::new(r"rm\s+-rf").unwrap();
        assert!(!re.uses_backtracking());
        assert!(re.is_match("rm -rf /"));
    }

    #[test]
    fn test_backtracking_engine_selection() {
        // Lookahead patterns should use backtracking engine
        let re = CompiledRegex::new(r"git\s+push(?=.*--force)").unwrap();
        assert!(re.uses_backtracking());
        assert!(re.is_match("git push --force"));
        assert!(!re.is_match("git push"));
    }

    #[test]
    fn test_lookbehind() {
        let re = CompiledRegex::new(r"(?<=drop\s)database").unwrap();
        assert!(re.uses_backtracking());
        assert!(re.is_match("drop database"));
    }

    #[test]
    fn test_negative_lookahead() {
        let re = CompiledRegex::new(r"rm(?!\s+--dry-run)").unwrap();
        assert!(re.uses_backtracking());
        assert!(re.is_match("rm -rf"));
        assert!(!re.is_match("rm --dry-run"));
    }

    #[test]
    fn test_needs_backtracking_detection() {
        assert!(!needs_backtracking_engine(r"simple"));
        assert!(!needs_backtracking_engine(r"git\s+status"));
        assert!(needs_backtracking_engine(r"(?=lookahead)"));
        assert!(needs_backtracking_engine(r"(?!negative)"));
        assert!(needs_backtracking_engine(r"(?<=lookbehind)"));
        assert!(needs_backtracking_engine(r"(?<!negative-behind)"));
    }

    #[test]
    fn test_find() {
        let re = CompiledRegex::new(r"rm").unwrap();
        assert_eq!(re.find("test rm command"), Some((5, 7)));
    }

    #[test]
    fn test_replacen() {
        let re = CompiledRegex::new(r"foo").unwrap();
        assert_eq!(re.replacen("foo bar foo", 1, "baz"), "baz bar foo");
    }

    // ==========================================================================
    // Worst-case regex input tests
    // ==========================================================================
    // These tests verify the linear-time engine handles inputs that would cause
    // exponential blowup in backtracking engines (classic ReDoS patterns).

    #[test]
    fn test_worst_case_alternation() {
        // Pattern: (a|a)+ on input "aaaa..." is O(2^n) for backtracking
        // Linear engine handles this in O(n)
        let re = CompiledRegex::new(r"(a|a)+").unwrap();
        assert!(!re.uses_backtracking()); // Should use linear engine

        // This would hang a backtracking engine but linear handles it fine
        let input = "a".repeat(100);
        assert!(re.is_match(&input));
    }

    #[test]
    fn test_worst_case_nested_quantifiers() {
        // Pattern: (a+)+ on input "aaa...!" is classic ReDoS
        // Linear engine guarantees O(n)
        let re = CompiledRegex::new(r"(a+)+$").unwrap();
        assert!(!re.uses_backtracking());

        // Input that would cause catastrophic backtracking
        let mut input = "a".repeat(50);
        input.push('!'); // Force non-match after lots of 'a's
        assert!(!re.is_match(&input)); // Should complete quickly
    }

    #[test]
    fn test_worst_case_star_quantifier() {
        // Pattern: a*a*a*...a*b on input "aaaa...a" (no b)
        let re = CompiledRegex::new(r"a*a*a*a*a*b").unwrap();
        assert!(!re.uses_backtracking());

        let input = "a".repeat(100);
        assert!(!re.is_match(&input)); // No 'b', should be quick
    }

    #[test]
    fn test_worst_case_dot_star() {
        // Pattern: .*.*.*= with non-matching long input
        let re = CompiledRegex::new(r".*.*.*=").unwrap();
        assert!(!re.uses_backtracking());

        let input = "x".repeat(100);
        assert!(!re.is_match(&input)); // No '=', should complete quickly
    }

    #[test]
    fn test_linear_engine_long_input() {
        // Verify linear engine handles long inputs efficiently
        let re = CompiledRegex::new(r"rm\s+-rf\s+/").unwrap();
        assert!(!re.uses_backtracking());

        // Embed the pattern in a very long command
        let mut cmd = "echo ".to_string();
        cmd.push_str(&"x".repeat(10_000));
        cmd.push_str(" && rm -rf / && ");
        cmd.push_str(&"y".repeat(10_000));

        assert!(re.is_match(&cmd));
    }

    #[test]
    fn test_backtracking_safety() {
        // Patterns with lookahead still need backtracking, but should be bounded
        // This test ensures we don't hang on reasonable inputs
        let re = CompiledRegex::new(r"git\s+push(?=.*--force)").unwrap();
        assert!(re.uses_backtracking());

        // Reasonable size input - should complete quickly
        let cmd = format!("git push {} --force", "branch".repeat(100));
        assert!(re.is_match(&cmd));
    }

    #[test]
    fn test_as_str_preserves_pattern() {
        let pattern = r"test\s+pattern";
        let re = CompiledRegex::new(pattern).unwrap();
        assert_eq!(re.as_str(), pattern);
    }
}
