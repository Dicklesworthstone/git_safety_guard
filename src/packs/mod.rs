//! Pack system for modular command blocking.
//!
//! This module provides the infrastructure for organizing patterns into "packs"
//! that can be enabled or disabled based on user configuration.
//!
//! # Pack Hierarchy
//!
//! Packs are organized in a two-level hierarchy:
//! - Category (e.g., "database", "kubernetes")
//! - Sub-pack (e.g., "database.postgresql", "kubernetes.kubectl")
//!
//! Enabling a category enables all its sub-packs. Sub-packs can be individually
//! disabled even if their parent category is enabled.

pub mod cloud;
pub mod containers;
pub mod core;
pub mod database;
pub mod infrastructure;
pub mod kubernetes;
pub mod package_managers;
pub mod strict_git;
pub mod system;

use fancy_regex::Regex;
use memchr::memmem;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

/// Unique identifier for a pack (e.g., "core", "database.postgresql").
pub type PackId = String;

/// A safe pattern that, when matched, allows the command immediately.
#[derive(Debug)]
pub struct SafePattern {
    /// Compiled regex pattern.
    pub regex: Regex,
    /// Debug name for the pattern.
    pub name: &'static str,
}

/// A destructive pattern that, when matched, blocks the command.
#[derive(Debug)]
pub struct DestructivePattern {
    /// Compiled regex pattern.
    pub regex: Regex,
    /// Human-readable explanation of why this command is blocked.
    pub reason: &'static str,
    /// Optional pattern name for debugging.
    pub name: Option<&'static str>,
}

/// Macro to create a safe pattern with compile-time name checking.
#[macro_export]
macro_rules! safe_pattern {
    ($name:literal, $re:literal) => {
        $crate::packs::SafePattern {
            regex: ::fancy_regex::Regex::new($re).expect(concat!(
                "safe pattern '",
                $name,
                "' should compile"
            )),
            name: $name,
        }
    };
}

/// Macro to create a destructive pattern with reason.
#[macro_export]
macro_rules! destructive_pattern {
    ($re:literal, $reason:literal) => {
        $crate::packs::DestructivePattern {
            regex: ::fancy_regex::Regex::new($re)
                .expect(concat!("destructive pattern should compile: ", $re)),
            reason: $reason,
            name: None,
        }
    };
    ($name:literal, $re:literal, $reason:literal) => {
        $crate::packs::DestructivePattern {
            regex: ::fancy_regex::Regex::new($re).expect(concat!(
                "destructive pattern '",
                $name,
                "' should compile"
            )),
            reason: $reason,
            name: Some($name),
        }
    };
}

/// A pack of patterns for a specific category of commands.
#[derive(Debug)]
pub struct Pack {
    /// Unique identifier (e.g., "database.postgresql").
    pub id: PackId,

    /// Human-readable name (e.g., "PostgreSQL").
    pub name: &'static str,

    /// Description of what this pack protects against.
    pub description: &'static str,

    /// Keywords for quick-reject filtering (e.g., ["psql", "dropdb", "DROP"]).
    /// Commands without any of these keywords skip pattern matching for this pack.
    pub keywords: &'static [&'static str],

    /// Safe patterns (whitelist) - checked first.
    pub safe_patterns: Vec<SafePattern>,

    /// Destructive patterns (blacklist) - checked if no safe pattern matches.
    pub destructive_patterns: Vec<DestructivePattern>,
}

impl Pack {
    /// Check if a command contains any of this pack's keywords.
    /// Returns false if the command doesn't contain any keywords (quick reject).
    pub fn might_match(&self, cmd: &str) -> bool {
        if self.keywords.is_empty() {
            return true; // No keywords = always check patterns
        }

        let bytes = cmd.as_bytes();
        self.keywords
            .iter()
            .any(|kw| memmem::find(bytes, kw.as_bytes()).is_some())
    }

    /// Check if a command matches any safe pattern.
    pub fn matches_safe(&self, cmd: &str) -> bool {
        self.safe_patterns
            .iter()
            .any(|p| p.regex.is_match(cmd).unwrap_or(false))
    }

    /// Check if a command matches any destructive pattern.
    /// Returns the reason if matched.
    pub fn matches_destructive(&self, cmd: &str) -> Option<&'static str> {
        self.destructive_patterns
            .iter()
            .find(|p| p.regex.is_match(cmd).unwrap_or(false))
            .map(|p| p.reason)
    }

    /// Check a command against this pack.
    /// Returns Some(reason) if blocked, None if allowed.
    pub fn check(&self, cmd: &str) -> Option<&'static str> {
        // Quick reject if no keywords match
        if !self.might_match(cmd) {
            return None;
        }

        // Check safe patterns first (whitelist)
        if self.matches_safe(cmd) {
            return None;
        }

        // Check destructive patterns (blacklist)
        self.matches_destructive(cmd)
    }
}

/// Result of checking a command against all packs.
#[derive(Debug)]
pub struct CheckResult {
    /// Whether the command should be blocked.
    pub blocked: bool,
    /// The reason for blocking (if blocked).
    pub reason: Option<String>,
    /// Which pack blocked it (if blocked).
    pub pack_id: Option<PackId>,
}

impl CheckResult {
    /// Create an "allowed" result.
    pub fn allowed() -> Self {
        Self {
            blocked: false,
            reason: None,
            pack_id: None,
        }
    }

    /// Create a "blocked" result.
    pub fn blocked(reason: &str, pack_id: &str) -> Self {
        Self {
            blocked: true,
            reason: Some(reason.to_string()),
            pack_id: Some(pack_id.to_string()),
        }
    }
}

/// Registry of all available packs.
pub struct PackRegistry {
    /// All registered packs, keyed by ID.
    packs: HashMap<PackId, Pack>,

    /// Pack IDs organized by category for hierarchical enablement.
    categories: HashMap<String, Vec<PackId>>,
}

impl PackRegistry {
    /// Collect all keywords from enabled packs.
    ///
    /// This returns a deduplicated list of keywords that can be used for
    /// pack-aware quick rejection. If a command contains none of these keywords,
    /// it can safely skip pack checking.
    #[must_use]
    pub fn collect_enabled_keywords(&self, enabled_packs: &HashSet<String>) -> Vec<&'static str> {
        let expanded = self.expand_enabled(enabled_packs);
        let mut keywords = Vec::new();

        for pack_id in &expanded {
            if let Some(pack) = self.packs.get(pack_id) {
                keywords.extend(pack.keywords.iter().copied());
            }
        }

        // Deduplicate while preserving order (first occurrence wins)
        let mut seen = HashSet::new();
        keywords.retain(|kw| seen.insert(*kw));

        keywords
    }

    /// Create a new registry with all built-in packs.
    pub fn new() -> Self {
        let mut registry = Self {
            packs: HashMap::new(),
            categories: HashMap::new(),
        };

        // Register all built-in packs
        registry.register_pack(core::git::create_pack());
        registry.register_pack(core::filesystem::create_pack());
        registry.register_pack(database::postgresql::create_pack());
        registry.register_pack(database::mysql::create_pack());
        registry.register_pack(database::mongodb::create_pack());
        registry.register_pack(database::redis::create_pack());
        registry.register_pack(database::sqlite::create_pack());
        registry.register_pack(containers::docker::create_pack());
        registry.register_pack(containers::compose::create_pack());
        registry.register_pack(containers::podman::create_pack());
        registry.register_pack(kubernetes::kubectl::create_pack());
        registry.register_pack(kubernetes::helm::create_pack());
        registry.register_pack(kubernetes::kustomize::create_pack());
        registry.register_pack(cloud::aws::create_pack());
        registry.register_pack(cloud::gcp::create_pack());
        registry.register_pack(cloud::azure::create_pack());
        registry.register_pack(infrastructure::terraform::create_pack());
        registry.register_pack(infrastructure::ansible::create_pack());
        registry.register_pack(infrastructure::pulumi::create_pack());
        registry.register_pack(system::disk::create_pack());
        registry.register_pack(system::permissions::create_pack());
        registry.register_pack(system::services::create_pack());
        registry.register_pack(strict_git::create_pack());
        registry.register_pack(package_managers::create_pack());

        registry
    }

    /// Register a pack in the registry.
    fn register_pack(&mut self, pack: Pack) {
        let id = pack.id.clone();

        // Extract category from ID (e.g., "database" from "database.postgresql")
        let category = id.split('.').next().unwrap_or(&id).to_string();

        // Add to categories map
        self.categories
            .entry(category)
            .or_default()
            .push(id.clone());

        // Add to packs map
        self.packs.insert(id, pack);
    }

    /// Get a pack by ID.
    pub fn get(&self, id: &str) -> Option<&Pack> {
        self.packs.get(id)
    }

    /// Get all pack IDs.
    pub fn all_pack_ids(&self) -> Vec<&PackId> {
        self.packs.keys().collect()
    }

    /// Get all categories.
    pub fn all_categories(&self) -> Vec<&String> {
        self.categories.keys().collect()
    }

    /// Get pack IDs in a category.
    pub fn packs_in_category(&self, category: &str) -> Vec<&PackId> {
        self.categories
            .get(category)
            .map(|ids| ids.iter().collect())
            .unwrap_or_default()
    }

    /// Expand enabled pack IDs to include sub-packs when a category is enabled.
    pub fn expand_enabled(&self, enabled: &HashSet<String>) -> HashSet<String> {
        let mut expanded = HashSet::new();

        for id in enabled {
            // Check if this is a category
            if let Some(sub_packs) = self.categories.get(id) {
                // Add all sub-packs in the category
                for sub_pack in sub_packs {
                    expanded.insert(sub_pack.clone());
                }
            }
            // Also add the ID itself (in case it's a specific pack)
            expanded.insert(id.clone());
        }

        expanded
    }

    /// Check a command against all enabled packs.
    pub fn check_command(&self, cmd: &str, enabled_packs: &HashSet<String>) -> CheckResult {
        // Expand category IDs to include all sub-packs
        let expanded = self.expand_enabled(enabled_packs);

        for pack_id in &expanded {
            if let Some(pack) = self.packs.get(pack_id) {
                if let Some(reason) = pack.check(cmd) {
                    return CheckResult::blocked(reason, pack_id);
                }
            }
        }

        CheckResult::allowed()
    }

    /// List all packs with their status.
    pub fn list_packs(&self, enabled: &HashSet<String>) -> Vec<PackInfo> {
        let expanded = self.expand_enabled(enabled);

        let mut infos: Vec<_> = self
            .packs
            .values()
            .map(|pack| PackInfo {
                id: pack.id.clone(),
                name: pack.name,
                description: pack.description,
                enabled: expanded.contains(&pack.id),
                safe_pattern_count: pack.safe_patterns.len(),
                destructive_pattern_count: pack.destructive_patterns.len(),
            })
            .collect();

        // Sort by ID for consistent output
        infos.sort_by(|a, b| a.id.cmp(&b.id));
        infos
    }
}

impl Default for PackRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about a pack for display.
#[derive(Debug)]
pub struct PackInfo {
    /// Pack ID.
    pub id: PackId,
    /// Human-readable name.
    pub name: &'static str,
    /// Description.
    pub description: &'static str,
    /// Whether the pack is enabled.
    pub enabled: bool,
    /// Number of safe patterns.
    pub safe_pattern_count: usize,
    /// Number of destructive patterns.
    pub destructive_pattern_count: usize,
}

/// Global pack registry (lazily initialized).
pub static REGISTRY: LazyLock<PackRegistry> = LazyLock::new(PackRegistry::new);

/// Regex to strip absolute paths from git/rm binaries.
static PATH_NORMALIZER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/(?:\S*/)*s?bin/(rm|git)(?=\s|$)").unwrap());

/// Normalize a command by stripping absolute paths from common binaries.
#[inline]
pub fn normalize_command(cmd: &str) -> Cow<'_, str> {
    if !cmd.starts_with('/') {
        return Cow::Borrowed(cmd);
    }
    PATH_NORMALIZER.replace(cmd, "$1")
}

/// Pre-compiled finders for core quick rejection (git/rm).
static GIT_FINDER: LazyLock<memmem::Finder<'static>> = LazyLock::new(|| memmem::Finder::new("git"));
static RM_FINDER: LazyLock<memmem::Finder<'static>> = LazyLock::new(|| memmem::Finder::new("rm"));

/// Core quick-reject filter (legacy - only checks git/rm).
/// Returns true if command definitely doesn't need core checking (no "git" or "rm").
///
/// NOTE: This only checks core keywords. Use `pack_aware_quick_reject` for
/// commands that need to be checked against enabled packs.
#[inline]
pub fn global_quick_reject(cmd: &str) -> bool {
    let bytes = cmd.as_bytes();
    GIT_FINDER.find(bytes).is_none() && RM_FINDER.find(bytes).is_none()
}

/// Pack-aware quick-reject filter.
///
/// Returns true if the command can be safely skipped (contains none of the
/// provided keywords from enabled packs).
///
/// This is the correct function to use when non-core packs are enabled.
/// It checks all keywords from enabled packs, not just "git" and "rm".
///
/// # Performance
///
/// Uses SIMD-accelerated substring search via memchr for each keyword.
/// For typical command lengths and keyword counts, this is sub-microsecond.
///
/// # Arguments
///
/// * `cmd` - The command string to check
/// * `enabled_keywords` - Keywords from all enabled packs (from `PackRegistry::collect_enabled_keywords`)
///
/// # Returns
///
/// `true` if the command contains NO keywords (safe to skip pack checking)
/// `false` if the command contains at least one keyword (must check packs)
#[inline]
#[must_use]
pub fn pack_aware_quick_reject(cmd: &str, enabled_keywords: &[&str]) -> bool {
    let bytes = cmd.as_bytes();

    // Fast path: if no keywords are configured, nothing to check
    if enabled_keywords.is_empty() {
        return true;
    }

    // Check if any keyword appears in the command
    // Using memchr::memmem::find for SIMD-accelerated search
    for keyword in enabled_keywords {
        if memmem::find(bytes, keyword.as_bytes()).is_some() {
            return false; // Keyword found, must evaluate packs
        }
    }

    true // No keywords found, safe to skip pack checking
}
