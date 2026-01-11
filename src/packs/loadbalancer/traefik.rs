//! Traefik load balancer pack - protections for destructive Traefik operations.
//!
//! Covers destructive operations:
//! - Stopping/removing Traefik containers
//! - Deleting Traefik configuration files
//! - Traefik API DELETE operations
//! - Removing Traefik `IngressRoute` CRDs

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Traefik load balancer pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "loadbalancer.traefik".to_string(),
        name: "Traefik",
        description: "Protects against destructive Traefik load balancer operations like stopping \
                      containers, deleting config, or API deletions.",
        keywords: &["traefik", "ingressroute"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // Version and health checks
        safe_pattern!("traefik-version", r"\btraefik\s+version\b"),
        safe_pattern!("traefik-healthcheck", r"\btraefik\s+healthcheck\b"),
        // API GET operations (read-only)
        safe_pattern!(
            "traefik-api-get",
            r"curl\b.*\s-X\s*GET\b.*\btraefik\b.*\b/api/"
        ),
        safe_pattern!(
            "traefik-api-read",
            r"curl\b.*\btraefik\b.*\b/api/(?:overview|entrypoints|routers|services|middlewares|version|rawdata)"
        ),
        // Docker inspect/logs (read-only)
        safe_pattern!(
            "docker-traefik-inspect",
            r"docker\s+(?:inspect|logs)\s+.*\btraefik\b"
        ),
        // Kubectl get/describe (read-only)
        safe_pattern!(
            "kubectl-traefik-get",
            r"kubectl\s+(?:get|describe)\s+.*\bingressroute"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // Docker container operations
        destructive_pattern!(
            "traefik-docker-stop",
            r"docker\s+(?:stop|kill)\s+.*\btraefik\b",
            "Stopping the Traefik container halts all traffic routing."
        ),
        destructive_pattern!(
            "traefik-docker-rm",
            r"docker\s+rm\s+.*\btraefik\b",
            "Removing the Traefik container destroys the load balancer."
        ),
        destructive_pattern!(
            "traefik-compose-down",
            r"docker[\s-]compose\s+.*\bdown\b.*\btraefik\b",
            "docker-compose down on Traefik stops and removes the load balancer."
        ),
        // Kubernetes operations
        destructive_pattern!(
            "traefik-kubectl-delete-pod",
            r"kubectl\s+delete\s+(?:pod|deployment|daemonset)\s+.*\btraefik\b",
            "Deleting Traefik pods/deployments disrupts traffic routing."
        ),
        destructive_pattern!(
            "traefik-kubectl-delete-ingressroute",
            r"kubectl\s+delete\s+ingressroute\b",
            "Deleting IngressRoute CRDs removes Traefik routing rules."
        ),
        // Config file deletion
        destructive_pattern!(
            "traefik-config-delete",
            r"\brm\b.*\btraefik\b.*\.(?:ya?ml|toml)\b",
            "Removing Traefik config files disrupts load balancer configuration."
        ),
        // API DELETE operations
        destructive_pattern!(
            "traefik-api-delete",
            r"curl\b.*\s-X\s*DELETE\b.*\btraefik\b.*\b/api/",
            "DELETE operations against Traefik API can remove routing configuration."
        ),
        // Systemctl/service operations
        destructive_pattern!(
            "traefik-systemctl-stop",
            r"systemctl\s+stop\s+traefik(?:\.service)?\b",
            "systemctl stop traefik stops the Traefik service."
        ),
        destructive_pattern!(
            "traefik-service-stop",
            r"service\s+traefik\s+stop\b",
            "service traefik stop stops the Traefik service."
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
        assert_eq!(pack.id, "loadbalancer.traefik");
        assert_eq!(pack.name, "Traefik");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"traefik"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "traefik version");
        assert_safe_pattern_matches(&pack, "traefik healthcheck");
        assert_safe_pattern_matches(&pack, "docker inspect traefik");
        assert_safe_pattern_matches(&pack, "docker logs traefik");
        assert_safe_pattern_matches(&pack, "kubectl get ingressroute");
        assert_safe_pattern_matches(&pack, "kubectl describe ingressroute my-route");
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "docker stop traefik", "traefik-docker-stop");
        assert_blocks_with_pattern(&pack, "docker kill traefik", "traefik-docker-stop");
        assert_blocks_with_pattern(&pack, "docker rm traefik", "traefik-docker-rm");
        assert_blocks_with_pattern(
            &pack,
            "kubectl delete pod traefik-abc123",
            "traefik-kubectl-delete-pod",
        );
        assert_blocks_with_pattern(
            &pack,
            "kubectl delete ingressroute my-route",
            "traefik-kubectl-delete-ingressroute",
        );
        assert_blocks_with_pattern(
            &pack,
            "rm /etc/traefik/traefik.yml",
            "traefik-config-delete",
        );
        assert_blocks_with_pattern(&pack, "systemctl stop traefik", "traefik-systemctl-stop");
    }
}
