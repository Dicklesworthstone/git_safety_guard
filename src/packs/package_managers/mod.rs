//! Package Managers pack - protections for package manager commands.
//!
//! This pack provides protection against dangerous package manager operations:
//! - npm/yarn/pnpm publish without verification
//! - pip install from untrusted sources
//! - apt/yum remove critical packages
//! - cargo publish

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Package Managers pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "package_managers".to_string(),
        name: "Package Managers",
        description: "Protects against dangerous package manager operations like publishing \
                      packages and removing critical system packages",
        keywords: &[
            "npm", "yarn", "pnpm", "pip", "apt", "yum", "dnf", "cargo", "gem", "brew", "poetry",
            "mvn", "mvnw", "gradle", "gradlew", "publish",
        ],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // npm/yarn/pnpm install are generally safe
        safe_pattern!("npm-install", r"npm\s+(?:install|i|ci)\b"),
        safe_pattern!("yarn-add", r"yarn\s+(?:add|install)\b"),
        safe_pattern!("pnpm-install", r"pnpm\s+(?:add|install|i)\b"),
        // list/info commands are safe
        safe_pattern!("npm-list", r"npm\s+(?:list|ls|info|view)\b"),
        safe_pattern!("yarn-list", r"yarn\s+(?:list|info|why)\b"),
        // audit is safe
        safe_pattern!("npm-audit", r"npm\s+audit"),
        safe_pattern!("yarn-audit", r"yarn\s+audit"),
        // pip list/show are safe
        safe_pattern!("pip-list", r"pip\s+(?:list|show|freeze)\b"),
        // poetry show/info are safe
        safe_pattern!("poetry-show", r"poetry\s+show\b"),
        safe_pattern!("poetry-env-list", r"poetry\s+env\s+list\b"),
        // cargo build/test/check are safe
        safe_pattern!(
            "cargo-safe",
            r"cargo\s+(?:build|test|check|clippy|fmt|doc|bench)\b"
        ),
        // apt list/show are safe
        safe_pattern!("apt-list", r"apt\s+(?:list|show|search)\b"),
        safe_pattern!("apt-get-list", r"apt-get\s+(?:update|upgrade)(?!\s+.*-y)"),
        // dry-run flags
        safe_pattern!("npm-dry-run", r"npm\s+.*--dry-run"),
        safe_pattern!("cargo-dry-run", r"cargo\s+.*--dry-run"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // npm/yarn/pnpm publish
        destructive_pattern!(
            "npm-publish",
            r"npm\s+publish\b(?!.*--dry-run)",
            "npm publish releases a package publicly. Use --dry-run first."
        ),
        destructive_pattern!(
            "yarn-publish",
            r"yarn\s+publish\b(?!.*--dry-run)",
            "yarn publish releases a package publicly. Verify package.json first."
        ),
        destructive_pattern!(
            "pnpm-publish",
            r"pnpm\s+publish\b(?!.*--dry-run)",
            "pnpm publish releases a package publicly."
        ),
        // npm unpublish
        destructive_pattern!(
            "npm-unpublish",
            r"npm\s+unpublish\b",
            "npm unpublish removes a published package. This can break dependent projects."
        ),
        // pip uninstall
        destructive_pattern!(
            "pip-uninstall",
            r"pip(?:3)?\s+uninstall\b",
            "pip uninstall removes installed packages. Verify dependencies before removing."
        ),
        // pip install from URL (potential security risk)
        destructive_pattern!(
            "pip-url",
            r"pip\s+install\s+(?:https?://|git\+)",
            "pip install from URL can install unvetted code. Verify the source first."
        ),
        // pip install --user or --system
        destructive_pattern!(
            "pip-system",
            r"pip\s+install\s+.*--(?:system|target\s*/usr)",
            "pip install to system directories requires careful review."
        ),
        // apt remove/purge
        destructive_pattern!(
            "apt-remove",
            r"apt(?:-get)?\s+(?:remove|purge|autoremove)\b",
            "apt remove/purge removes packages. Verify no critical packages are affected."
        ),
        // yum/dnf remove
        destructive_pattern!(
            "yum-remove",
            r"(?:yum|dnf)\s+(?:remove|erase|autoremove)\b",
            "yum/dnf remove removes packages. Verify no critical packages are affected."
        ),
        // cargo publish
        destructive_pattern!(
            "cargo-publish",
            r"cargo\s+publish\b(?!.*--dry-run)",
            "cargo publish releases a crate to crates.io. Use --dry-run first."
        ),
        // cargo yank
        destructive_pattern!(
            "cargo-yank",
            r"cargo\s+yank\b",
            "cargo yank marks a version as unavailable. This can break dependent projects."
        ),
        // gem push
        destructive_pattern!(
            "gem-push",
            r"gem\s+push\b",
            "gem push releases a gem to rubygems.org. Verify before publishing."
        ),
        // brew uninstall
        destructive_pattern!(
            "brew-uninstall",
            r"brew\s+(?:uninstall|remove)\b",
            "brew uninstall removes packages. Verify no dependent packages are affected."
        ),
        // poetry publish/remove
        destructive_pattern!(
            "poetry-publish",
            r"poetry\s+publish\b(?!.*--dry-run)",
            "poetry publish releases a package. Use --dry-run first."
        ),
        destructive_pattern!(
            "poetry-remove",
            r"poetry\s+remove\b",
            "poetry remove uninstalls a dependency. Verify no critical packages are affected."
        ),
        // maven deploy / release
        destructive_pattern!(
            "maven-deploy",
            r"(?:mvn|mvnw)\s+deploy\b",
            "mvn deploy publishes artifacts to a remote repository. Verify target repository."
        ),
        destructive_pattern!(
            "maven-release-perform",
            r"(?:mvn|mvnw)\s+.*release:perform\b",
            "mvn release:perform publishes a release. Verify version and repository."
        ),
        // gradle publish / release
        destructive_pattern!(
            "gradle-publish",
            r"(?:gradle|gradlew)\s+.*\bpublish\b",
            "gradle publish uploads artifacts. Use --dry-run first when possible."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::test_helpers::assert_blocks;

    #[test]
    fn brew_uninstall_is_reachable_via_keywords() {
        let pack = create_pack();
        assert!(
            pack.might_match("brew uninstall wget"),
            "brew should be included in pack keywords to prevent false negatives"
        );
        let matched = pack
            .check("brew uninstall wget")
            .expect("brew uninstall should be blocked by package managers pack");
        assert_eq!(matched.name, Some("brew-uninstall"));
    }

    #[test]
    fn poetry_maven_gradle_and_pip_uninstall_block() {
        let pack = create_pack();
        assert_blocks(&pack, "poetry publish", "poetry publish");
        assert_blocks(&pack, "poetry remove requests", "poetry remove");
        assert_blocks(&pack, "mvn deploy", "mvn deploy");
        assert_blocks(&pack, "./mvnw release:perform", "release:perform");
        assert_blocks(&pack, "gradle publish", "gradle publish");
        assert_blocks(&pack, "./gradlew publish", "gradle publish");
        assert_blocks(&pack, "pip uninstall boto3", "pip uninstall");
        assert_blocks(&pack, "pip3 uninstall requests", "pip uninstall");
    }

    #[test]
    fn keyword_absent_skips_pack() {
        let pack = create_pack();
        assert!(!pack.might_match("echo hello"));
        assert!(pack.check("echo hello").is_none());
    }
}
