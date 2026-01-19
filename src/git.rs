//! Git branch detection for branch-aware strictness.
//!
//! This module provides reliable detection of the current git branch with fallback
//! mechanisms and per-directory caching for performance.
//!
//! # Design
//!
//! - **Primary method**: `git branch --show-current` (most reliable)
//! - **Fallback method**: Read `.git/HEAD` file directly (for environments without git CLI)
//! - **Detached HEAD**: Returns `None` for branch, or commit hash with special marker
//! - **Caching**: Per working directory cache to avoid repeated subprocess/file reads
//!
//! # Usage
//!
//! ```ignore
//! use destructive_command_guard::git::get_current_branch;
//!
//! if let Some(branch) = get_current_branch() {
//!     println!("Current branch: {}", branch);
//! } else {
//!     println!("Not on a branch (detached HEAD or not in git repo)");
//! }
//! ```

use std::cell::RefCell;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

/// Cache duration before refreshing branch info.
/// 30 seconds is reasonable for a CLI tool that runs briefly.
const CACHE_TTL: Duration = Duration::from_secs(30);

/// Result of branch detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchInfo {
    /// On a named branch (e.g., "main", "feature/foo").
    Branch(String),
    /// In detached HEAD state with optional commit hash.
    DetachedHead(Option<String>),
    /// Not in a git repository.
    NotGitRepo,
}

impl BranchInfo {
    /// Returns the branch name if on a named branch, `None` otherwise.
    #[must_use]
    pub fn branch_name(&self) -> Option<&str> {
        match self {
            Self::Branch(name) => Some(name),
            Self::DetachedHead(_) | Self::NotGitRepo => None,
        }
    }

    /// Returns `true` if in a git repository (either on a branch or detached HEAD).
    #[must_use]
    pub fn is_in_git_repo(&self) -> bool {
        !matches!(self, Self::NotGitRepo)
    }

    /// Returns `true` if on a named branch.
    #[must_use]
    pub fn is_on_branch(&self) -> bool {
        matches!(self, Self::Branch(_))
    }

    /// Returns `true` if in detached HEAD state.
    #[must_use]
    pub fn is_detached(&self) -> bool {
        matches!(self, Self::DetachedHead(_))
    }
}

/// Cached branch information for a specific working directory.
#[derive(Debug)]
struct CachedBranch {
    /// The working directory this cache entry is for.
    working_dir: PathBuf,
    /// The cached branch info.
    info: BranchInfo,
    /// When this cache entry was created.
    cached_at: Instant,
}

impl CachedBranch {
    /// Returns `true` if this cache entry is still valid.
    fn is_valid(&self, current_dir: &PathBuf) -> bool {
        self.working_dir == *current_dir && self.cached_at.elapsed() < CACHE_TTL
    }
}

thread_local! {
    /// Per-thread cache for branch information.
    /// Keyed by working directory to handle directory changes.
    static BRANCH_CACHE: RefCell<Option<CachedBranch>> = const { RefCell::new(None) };
}

/// Get the current git branch, using cache if available.
///
/// Returns `None` if not on a named branch (detached HEAD) or not in a git repo.
/// Use [`get_branch_info`] for more detailed information.
///
/// # Caching
///
/// Results are cached per working directory for up to 30 seconds to avoid
/// repeated subprocess calls. The cache is automatically invalidated when
/// the working directory changes.
#[must_use]
pub fn get_current_branch() -> Option<String> {
    get_branch_info().branch_name().map(String::from)
}

/// Get detailed branch information, using cache if available.
///
/// Returns a [`BranchInfo`] enum indicating:
/// - `Branch(name)`: On a named branch
/// - `DetachedHead(hash)`: In detached HEAD state (with optional commit hash)
/// - `NotGitRepo`: Not in a git repository
#[must_use]
pub fn get_branch_info() -> BranchInfo {
    let current_dir = std::env::current_dir().unwrap_or_default();

    // Check cache first
    let cached = BRANCH_CACHE.with(|cache| {
        let borrow = cache.borrow();
        if let Some(ref entry) = *borrow {
            if entry.is_valid(&current_dir) {
                return Some(entry.info.clone());
            }
        }
        None
    });

    if let Some(info) = cached {
        return info;
    }

    // Cache miss - fetch fresh info
    let info = fetch_branch_info();

    // Update cache
    BRANCH_CACHE.with(|cache| {
        *cache.borrow_mut() = Some(CachedBranch {
            working_dir: current_dir,
            info: info.clone(),
            cached_at: Instant::now(),
        });
    });

    info
}

/// Get branch information for a specific path.
///
/// This bypasses the cache since it's for a specific path that may differ
/// from the current working directory.
#[must_use]
pub fn get_branch_info_at_path(path: &std::path::Path) -> BranchInfo {
    fetch_branch_info_at_path(path)
}

/// Clear the branch cache.
///
/// Useful for testing or when you know the branch has changed.
pub fn clear_cache() {
    BRANCH_CACHE.with(|cache| {
        *cache.borrow_mut() = None;
    });
}

/// Fetch branch info without caching.
fn fetch_branch_info() -> BranchInfo {
    // Try primary method: git command
    if let Some(info) = get_branch_from_git_command(None) {
        return info;
    }

    // Fallback: read .git/HEAD directly
    get_branch_from_head_file(None)
}

/// Fetch branch info for a specific path without caching.
fn fetch_branch_info_at_path(path: &std::path::Path) -> BranchInfo {
    // Try primary method: git command
    if let Some(info) = get_branch_from_git_command(Some(path)) {
        return info;
    }

    // Fallback: read .git/HEAD directly
    get_branch_from_head_file(Some(path))
}

/// Primary method: Use `git branch --show-current` to get the branch name.
///
/// This is the most reliable method as it handles all edge cases correctly,
/// including worktrees, submodules, and unusual repository layouts.
fn get_branch_from_git_command(working_dir: Option<&std::path::Path>) -> Option<BranchInfo> {
    let mut cmd = Command::new("git");
    cmd.args(["branch", "--show-current"]);

    if let Some(dir) = working_dir {
        cmd.current_dir(dir);
    }

    // Suppress stderr to avoid noise when not in a git repo
    cmd.stderr(std::process::Stdio::null());

    let output = cmd.output().ok()?;

    if !output.status.success() {
        // Git command failed - might not be in a repo
        return None;
    }

    let branch = String::from_utf8(output.stdout).ok()?.trim().to_string();

    if branch.is_empty() {
        // Empty output means detached HEAD
        // Try to get the commit hash
        let hash = get_detached_head_hash(working_dir);
        Some(BranchInfo::DetachedHead(hash))
    } else {
        Some(BranchInfo::Branch(branch))
    }
}

/// Get the commit hash when in detached HEAD state.
fn get_detached_head_hash(working_dir: Option<&std::path::Path>) -> Option<String> {
    let mut cmd = Command::new("git");
    cmd.args(["rev-parse", "--short", "HEAD"]);

    if let Some(dir) = working_dir {
        cmd.current_dir(dir);
    }

    cmd.stderr(std::process::Stdio::null());

    let output = cmd.output().ok()?;

    if output.status.success() {
        let hash = String::from_utf8(output.stdout).ok()?.trim().to_string();
        if !hash.is_empty() {
            return Some(hash);
        }
    }

    None
}

/// Fallback method: Read `.git/HEAD` file directly.
///
/// Format: `ref: refs/heads/<branch-name>` for branches
/// or a commit hash for detached HEAD.
fn get_branch_from_head_file(working_dir: Option<&std::path::Path>) -> BranchInfo {
    let git_dir = find_git_dir(working_dir);
    let head_path = match git_dir {
        Some(dir) => dir.join("HEAD"),
        None => return BranchInfo::NotGitRepo,
    };

    let head_content = match std::fs::read_to_string(&head_path) {
        Ok(content) => content,
        Err(_) => return BranchInfo::NotGitRepo,
    };

    let trimmed = head_content.trim();

    // Check if it's a symbolic reference: "ref: refs/heads/<branch>"
    if let Some(ref_path) = trimmed.strip_prefix("ref: refs/heads/") {
        return BranchInfo::Branch(ref_path.to_string());
    }

    // It's a commit hash (detached HEAD)
    // Validate it looks like a hash (40 hex chars for full, or shorter for abbreviated)
    if trimmed.len() >= 7 && trimmed.len() <= 40 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        // Return abbreviated hash (first 7 chars)
        let short_hash = if trimmed.len() > 7 {
            trimmed[..7].to_string()
        } else {
            trimmed.to_string()
        };
        return BranchInfo::DetachedHead(Some(short_hash));
    }

    // Couldn't parse HEAD - might be corrupted or unusual format
    BranchInfo::NotGitRepo
}

/// Find the .git directory for a repository.
///
/// Handles both regular repositories (.git as directory) and worktrees
/// (.git as file pointing to the actual git directory).
fn find_git_dir(working_dir: Option<&std::path::Path>) -> Option<PathBuf> {
    let start_dir = working_dir
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())?;

    let mut current = start_dir.as_path();

    loop {
        let git_path = current.join(".git");

        if git_path.is_dir() {
            // Regular git directory
            return Some(git_path);
        }

        if git_path.is_file() {
            // Worktree: .git file contains "gitdir: <path>"
            if let Ok(content) = std::fs::read_to_string(&git_path) {
                if let Some(gitdir) = content.trim().strip_prefix("gitdir: ") {
                    let gitdir_path = PathBuf::from(gitdir);
                    // Handle relative paths
                    let resolved = if gitdir_path.is_absolute() {
                        gitdir_path
                    } else {
                        current.join(gitdir_path)
                    };
                    if resolved.is_dir() {
                        return Some(resolved);
                    }
                }
            }
        }

        // Move up to parent directory
        current = current.parent()?;
    }
}

/// Check if the current directory is in a git repository.
#[must_use]
pub fn is_in_git_repo() -> bool {
    get_branch_info().is_in_git_repo()
}

/// Check if the specified path is in a git repository.
#[must_use]
pub fn is_in_git_repo_at_path(path: &std::path::Path) -> bool {
    get_branch_info_at_path(path).is_in_git_repo()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_branch_info_methods() {
        let branch = BranchInfo::Branch("main".to_string());
        assert_eq!(branch.branch_name(), Some("main"));
        assert!(branch.is_in_git_repo());
        assert!(branch.is_on_branch());
        assert!(!branch.is_detached());

        let detached = BranchInfo::DetachedHead(Some("abc1234".to_string()));
        assert_eq!(detached.branch_name(), None);
        assert!(detached.is_in_git_repo());
        assert!(!detached.is_on_branch());
        assert!(detached.is_detached());

        let not_repo = BranchInfo::NotGitRepo;
        assert_eq!(not_repo.branch_name(), None);
        assert!(!not_repo.is_in_git_repo());
        assert!(!not_repo.is_on_branch());
        assert!(!not_repo.is_detached());
    }

    #[test]
    fn test_cache_validity() {
        let current_dir = PathBuf::from("/test/path");
        let other_dir = PathBuf::from("/other/path");

        let cache = CachedBranch {
            working_dir: current_dir.clone(),
            info: BranchInfo::Branch("main".to_string()),
            cached_at: Instant::now(),
        };

        // Same directory, fresh cache
        assert!(cache.is_valid(&current_dir));

        // Different directory
        assert!(!cache.is_valid(&other_dir));
    }

    #[test]
    fn test_head_file_parsing_branch() {
        // Test the branch parsing logic without actually reading files
        let content = "ref: refs/heads/feature/my-branch";
        let trimmed = content.trim();

        if let Some(branch) = trimmed.strip_prefix("ref: refs/heads/") {
            assert_eq!(branch, "feature/my-branch");
        } else {
            panic!("Expected branch reference");
        }
    }

    #[test]
    fn test_head_file_parsing_detached() {
        // Test commit hash detection
        let hash = "abc1234def5678";
        assert!(hash.len() >= 7 && hash.len() <= 40);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_clear_cache() {
        // Just verify clear_cache doesn't panic
        clear_cache();

        // And that we can still get branch info after clearing
        let _ = get_branch_info();
    }

    #[test]
    fn test_get_current_branch_returns_some_in_git_repo() {
        // This test runs in the dcg repo, so should return a branch
        // unless we're in a weird CI state
        let result = get_current_branch();
        // We don't assert the specific value since it could be any branch
        // Just verify the function doesn't panic
        drop(result);
    }

    #[test]
    fn test_is_in_git_repo() {
        // This test runs in the dcg repo
        let result = is_in_git_repo();
        // Should be true since we're in a git repo
        assert!(result, "Expected to be in a git repo");
    }

    #[test]
    fn test_branch_info_at_temp_path() {
        // Test with a path that's definitely not a git repo
        let temp_dir = std::env::temp_dir();
        let result = get_branch_info_at_path(&temp_dir);
        // Temp dir might or might not be in a git repo depending on system
        // Just verify it doesn't panic
        drop(result);
    }
}
