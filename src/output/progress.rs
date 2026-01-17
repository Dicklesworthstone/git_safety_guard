//! Progress indicators for dcg using indicatif.
//!
//! Provides progress bars and spinners for long-running operations like
//! scanning and history analysis.
//!
//! # Design Principles
//!
//! - **TTY-aware**: Progress only shown when stdout is a TTY
//! - **Threshold-based**: Progress bar only appears for operations above a threshold
//! - **Non-blocking**: Progress updates are designed to be fast
//! - **Clean finish**: No visual artifacts left after completion
//!
//! # Thresholds
//!
//! - File scanning: Show progress bar when scanning >20 files
//! - Operation duration: Show spinner when operation may take >500ms
//!
//! # Usage
//!
//! ```no_run
//! use destructive_command_guard::output::progress::{ScanProgress, spinner};
//!
//! // For file scanning
//! if let Some(progress) = ScanProgress::new_if_needed(100) {
//!     for file in files {
//!         progress.tick(&file);
//!     }
//!     progress.finish("Scan complete");
//! }
//!
//! // For short operations with uncertain duration
//! let sp = spinner("Loading patterns...");
//! // ... do work ...
//! sp.finish_and_clear();
//! ```

use indicatif::{ProgressBar, ProgressStyle};
use std::borrow::Cow;
use std::time::Duration;

/// Minimum file count before showing a progress bar.
pub const SCAN_PROGRESS_THRESHOLD: u64 = 20;

/// Default tick interval for spinners.
const SPINNER_TICK_MS: u64 = 80;

/// Progress bar for file scanning operations.
#[derive(Debug)]
pub struct ScanProgress {
    bar: ProgressBar,
    show_file_names: bool,
}

impl ScanProgress {
    /// Creates a new scan progress bar for the given file count.
    ///
    /// The progress bar is always created, even if not a TTY. Use `new_if_needed`
    /// for threshold-aware creation.
    #[must_use]
    pub fn new(total_files: u64) -> Self {
        let bar = ProgressBar::new(total_files);
        bar.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} files ({eta})")
                .expect("valid progress template")
                .progress_chars("█▓░"),
        );
        bar.enable_steady_tick(Duration::from_millis(SPINNER_TICK_MS));

        Self {
            bar,
            show_file_names: true,
        }
    }

    /// Creates a progress bar only if the file count exceeds the threshold
    /// and stdout is a TTY.
    ///
    /// Returns `None` if:
    /// - `total_files` is below `SCAN_PROGRESS_THRESHOLD`
    /// - stdout is not a TTY (non-interactive environment)
    #[must_use]
    pub fn new_if_needed(total_files: u64) -> Option<Self> {
        if total_files < SCAN_PROGRESS_THRESHOLD {
            return None;
        }

        if !super::should_use_rich_output() {
            return None;
        }

        Some(Self::new(total_files))
    }

    /// Creates a progress bar with a custom style.
    #[must_use]
    pub fn with_style(total_files: u64, style: ScanProgressStyle) -> Self {
        let bar = ProgressBar::new(total_files);
        bar.set_style(style.to_indicatif_style());
        bar.enable_steady_tick(Duration::from_millis(SPINNER_TICK_MS));

        Self {
            bar,
            show_file_names: style.show_file_names,
        }
    }

    /// Disables file name display in the progress message.
    #[must_use]
    pub fn without_file_names(mut self) -> Self {
        self.show_file_names = false;
        self
    }

    /// Advances the progress bar and optionally displays the current file.
    pub fn tick(&self, file_path: &str) {
        if self.show_file_names {
            // Truncate long paths for display
            let display_path = truncate_path(file_path, 50);
            self.bar.set_message(display_path.into_owned());
        }
        self.bar.inc(1);
    }

    /// Advances the progress bar without updating the message.
    pub fn tick_silent(&self) {
        self.bar.inc(1);
    }

    /// Marks the progress bar as complete with a final message.
    pub fn finish(&self, message: &str) {
        self.bar.finish_with_message(message.to_string());
    }

    /// Finishes and clears the progress bar (no final message).
    pub fn finish_and_clear(&self) {
        self.bar.finish_and_clear();
    }

    /// Sets the total file count (useful when count isn't known upfront).
    pub fn set_length(&self, len: u64) {
        self.bar.set_length(len);
    }

    /// Returns whether the progress bar is finished.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.bar.is_finished()
    }
}

/// Style configuration for scan progress bars.
#[derive(Debug, Clone)]
pub struct ScanProgressStyle {
    /// Template string for the progress bar.
    pub template: String,
    /// Characters for the progress bar (filled, current, empty).
    pub progress_chars: String,
    /// Whether to show file names in the message.
    pub show_file_names: bool,
}

impl Default for ScanProgressStyle {
    fn default() -> Self {
        Self {
            template: "{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} files ({eta})".to_string(),
            progress_chars: "█▓░".to_string(),
            show_file_names: true,
        }
    }
}

impl ScanProgressStyle {
    /// Creates a minimal progress style (no spinner, simple bar).
    #[must_use]
    pub fn minimal() -> Self {
        Self {
            template: "[{bar:40}] {pos}/{len}".to_string(),
            progress_chars: "#>-".to_string(),
            show_file_names: false,
        }
    }

    /// Creates a verbose progress style with file name display.
    #[must_use]
    pub fn verbose() -> Self {
        Self {
            template: "{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {wide_msg}"
                .to_string(),
            progress_chars: "█▓░".to_string(),
            show_file_names: true,
        }
    }

    /// Converts to an indicatif `ProgressStyle`.
    fn to_indicatif_style(&self) -> ProgressStyle {
        ProgressStyle::default_bar()
            .template(&self.template)
            .expect("valid progress template")
            .progress_chars(&self.progress_chars)
    }
}

/// Creates a spinner for indeterminate-duration operations.
///
/// The spinner automatically ticks in the background. Call `finish_and_clear()`
/// or `finish_with_message()` when done.
///
/// # Example
///
/// ```no_run
/// use destructive_command_guard::output::progress::spinner;
///
/// let sp = spinner("Loading configuration...");
/// // ... do work ...
/// sp.finish_and_clear();
/// ```
#[must_use]
pub fn spinner(message: &str) -> ProgressBar {
    let sp = ProgressBar::new_spinner();
    sp.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
            .template("{spinner:.blue} {msg}")
            .expect("valid spinner template"),
    );
    sp.set_message(message.to_string());
    sp.enable_steady_tick(Duration::from_millis(SPINNER_TICK_MS));
    sp
}

/// Creates a spinner only if stdout is a TTY.
///
/// Returns `None` in non-interactive environments (CI, piped output).
#[must_use]
pub fn spinner_if_tty(message: &str) -> Option<ProgressBar> {
    if super::should_use_rich_output() {
        Some(spinner(message))
    } else {
        None
    }
}

/// A no-op progress tracker for when progress shouldn't be shown.
///
/// Implements the same interface as `ScanProgress` but does nothing.
/// Useful for avoiding Option checks throughout scanning code.
#[derive(Debug, Default)]
pub struct NoopProgress;

impl NoopProgress {
    /// Creates a new no-op progress tracker.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// No-op tick.
    pub fn tick(&self, _file_path: &str) {}

    /// No-op tick without message.
    pub fn tick_silent(&self) {}

    /// No-op finish.
    pub fn finish(&self, _message: &str) {}

    /// No-op finish and clear.
    pub fn finish_and_clear(&self) {}
}

/// Progress tracker that can be either real or no-op.
///
/// Use this when you want to conditionally show progress based on
/// runtime conditions without Option checks everywhere.
#[derive(Debug)]
pub enum MaybeProgress {
    /// Real progress bar.
    Real(ScanProgress),
    /// No-op progress tracker.
    Noop(NoopProgress),
}

impl MaybeProgress {
    /// Creates a progress tracker, choosing real or no-op based on threshold and TTY.
    #[must_use]
    pub fn new(total_files: u64) -> Self {
        match ScanProgress::new_if_needed(total_files) {
            Some(progress) => Self::Real(progress),
            None => Self::Noop(NoopProgress::new()),
        }
    }

    /// Advances the progress bar.
    pub fn tick(&self, file_path: &str) {
        match self {
            Self::Real(p) => p.tick(file_path),
            Self::Noop(p) => p.tick(file_path),
        }
    }

    /// Advances without updating message.
    pub fn tick_silent(&self) {
        match self {
            Self::Real(p) => p.tick_silent(),
            Self::Noop(p) => p.tick_silent(),
        }
    }

    /// Finishes with a message.
    pub fn finish(&self, message: &str) {
        match self {
            Self::Real(p) => p.finish(message),
            Self::Noop(p) => p.finish(message),
        }
    }

    /// Finishes and clears.
    pub fn finish_and_clear(&self) {
        match self {
            Self::Real(p) => p.finish_and_clear(),
            Self::Noop(p) => p.finish_and_clear(),
        }
    }
}

/// Truncates a file path to fit within `max_len` characters.
///
/// If the path is too long, it replaces the middle with "...".
fn truncate_path(path: &str, max_len: usize) -> Cow<'_, str> {
    if path.len() <= max_len {
        return Cow::Borrowed(path);
    }

    if max_len < 10 {
        // Too short to truncate meaningfully
        return Cow::Owned(path[..max_len].to_string());
    }

    // Keep beginning and end, replace middle with ...
    let keep_start = (max_len - 3) / 2;
    let keep_end = max_len - 3 - keep_start;

    let start = &path[..keep_start];
    let end = &path[path.len() - keep_end..];

    Cow::Owned(format!("{start}...{end}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_path_short() {
        let path = "src/main.rs";
        assert_eq!(truncate_path(path, 50), Cow::Borrowed(path));
    }

    #[test]
    fn test_truncate_path_long() {
        let path = "very/long/path/to/some/deeply/nested/file/structure/main.rs";
        let truncated = truncate_path(path, 30);
        assert!(truncated.len() <= 30);
        assert!(truncated.contains("..."));
    }

    #[test]
    fn test_truncate_path_preserves_extension() {
        let path = "a/very/long/path/to/file.rs";
        let truncated = truncate_path(path, 25);
        assert!(truncated.ends_with("ile.rs") || truncated.ends_with(".rs"));
    }

    #[test]
    fn test_scan_progress_creation() {
        // This test runs in a non-TTY environment, so new_if_needed should return None
        let _progress = ScanProgress::new_if_needed(100);
        // In test environment (non-TTY), this should be None
        // But new() always creates regardless of TTY
        let _progress = ScanProgress::new(100);
    }

    #[test]
    fn test_scan_progress_style_default() {
        let style = ScanProgressStyle::default();
        assert!(style.template.contains("spinner"));
        assert!(style.show_file_names);
    }

    #[test]
    fn test_scan_progress_style_minimal() {
        let style = ScanProgressStyle::minimal();
        assert!(!style.template.contains("spinner"));
        assert!(!style.show_file_names);
    }

    #[test]
    fn test_noop_progress_does_nothing() {
        let noop = NoopProgress::new();
        noop.tick("some/path");
        noop.tick_silent();
        noop.finish("done");
        noop.finish_and_clear();
        // Just verify no panics
    }

    #[test]
    fn test_maybe_progress_threshold() {
        // Below threshold should give Noop
        let progress = MaybeProgress::new(5);
        assert!(matches!(progress, MaybeProgress::Noop(_)));
    }

    #[test]
    fn test_threshold_constant() {
        assert_eq!(SCAN_PROGRESS_THRESHOLD, 20);
    }

    #[test]
    fn test_spinner_creation() {
        // spinner_if_tty returns None in test environment
        let sp = spinner_if_tty("Loading...");
        assert!(sp.is_none()); // Non-TTY test environment

        // Direct spinner creation still works
        let _sp = spinner("Loading...");
    }

    #[test]
    fn test_truncate_path_exact_length() {
        let path = "exactly20chars.rs...";
        let truncated = truncate_path(path, 20);
        assert_eq!(truncated.len(), 20);
    }

    #[test]
    fn test_truncate_path_very_short_max() {
        let path = "some/path/file.rs";
        let truncated = truncate_path(path, 5);
        assert_eq!(truncated.len(), 5);
    }
}
