//! nginx load balancer pack - protections for destructive nginx operations.
//!
//! Covers destructive operations:
//! - nginx stop/quit signals
//! - systemctl/service stop for nginx
//! - removing nginx config files in /etc/nginx

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the nginx load balancer pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "loadbalancer.nginx".to_string(),
        name: "nginx",
        description: "Protects against destructive nginx load balancer operations like stopping \
                      the service or deleting config files.",
        keywords: &["nginx", "/etc/nginx"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!("nginx-config-test", r"nginx\s+-t\b"),
        safe_pattern!("nginx-config-dump", r"nginx\s+-T\b"),
        safe_pattern!("nginx-version", r"nginx\s+-v\b"),
        safe_pattern!("nginx-version-full", r"nginx\s+-V\b"),
        safe_pattern!("nginx-reload", r"nginx\s+-s\s+reload\b"),
        safe_pattern!(
            "systemctl-status-nginx",
            r"systemctl\s+status\s+nginx(?:\.service)?\b"
        ),
        safe_pattern!("service-status-nginx", r"service\s+nginx\s+status\b"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "nginx-stop",
            r"nginx\s+-s\s+stop\b",
            "nginx -s stop shuts down nginx and stops the load balancer."
        ),
        destructive_pattern!(
            "nginx-quit",
            r"nginx\s+-s\s+quit\b",
            "nginx -s quit gracefully stops nginx and halts traffic handling."
        ),
        destructive_pattern!(
            "systemctl-stop-nginx",
            r"systemctl\s+stop\s+nginx(?:\.service)?\b",
            "systemctl stop nginx stops the nginx service and disrupts traffic."
        ),
        destructive_pattern!(
            "service-stop-nginx",
            r"service\s+nginx\s+stop\b",
            "service nginx stop stops the nginx service and disrupts traffic."
        ),
        destructive_pattern!(
            "nginx-config-delete",
            r"\brm\b.*\s+/etc/nginx(?:/|\b)",
            "Removing files from /etc/nginx deletes nginx configuration."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::test_helpers::*;

    #[test]
    fn test_pack_creation() {
        let pack = create_pack();
        assert_eq!(pack.id, "loadbalancer.nginx");
        assert_eq!(pack.name, "nginx");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"nginx"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "nginx -t");
        assert_safe_pattern_matches(&pack, "nginx -T");
        assert_safe_pattern_matches(&pack, "nginx -v");
        assert_safe_pattern_matches(&pack, "nginx -V");
        assert_safe_pattern_matches(&pack, "nginx -s reload");
        assert_safe_pattern_matches(&pack, "systemctl status nginx");
        assert_safe_pattern_matches(&pack, "service nginx status");
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "nginx -s stop", "nginx-stop");
        assert_blocks_with_pattern(&pack, "nginx -s quit", "nginx-quit");
        assert_blocks_with_pattern(&pack, "systemctl stop nginx", "systemctl-stop-nginx");
        assert_blocks_with_pattern(&pack, "service nginx stop", "service-stop-nginx");
        assert_blocks_with_pattern(&pack, "rm -f /etc/nginx/nginx.conf", "nginx-config-delete");
    }
}
