//! AWS Route53 DNS pack - protections for destructive Route53 operations.
//!
//! Covers destructive CLI operations:
//! - Hosted zone deletion
//! - DNS record set deletion via change-resource-record-sets
//! - Health check deletion
//! - Query logging config deletion
//! - Traffic policy deletion
//! - Reusable delegation set deletion

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the AWS Route53 DNS pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "dns.route53".to_string(),
        name: "AWS Route53",
        description: "Protects against destructive AWS Route53 DNS operations like hosted zone deletion \
                      and record set DELETE changes.",
        keywords: &["aws", "route53"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!(
            "route53-list-hosted-zones",
            r"aws\s+route53\s+list-hosted-zones\b"
        ),
        safe_pattern!(
            "route53-list-resource-record-sets",
            r"aws\s+route53\s+list-resource-record-sets\b"
        ),
        safe_pattern!(
            "route53-get-hosted-zone",
            r"aws\s+route53\s+get-hosted-zone\b"
        ),
        safe_pattern!(
            "route53-test-dns-answer",
            r"aws\s+route53\s+test-dns-answer\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "route53-delete-hosted-zone",
            r"aws\s+route53\s+delete-hosted-zone\b",
            "aws route53 delete-hosted-zone permanently deletes a Route53 hosted zone."
        ),
        destructive_pattern!(
            "route53-change-resource-record-sets-delete",
            r"aws\s+route53\s+change-resource-record-sets\b.*\bDELETE\b",
            "aws route53 change-resource-record-sets with DELETE removes DNS records."
        ),
        destructive_pattern!(
            "route53-delete-health-check",
            r"aws\s+route53\s+delete-health-check\b",
            "aws route53 delete-health-check permanently deletes a Route53 health check."
        ),
        destructive_pattern!(
            "route53-delete-query-logging-config",
            r"aws\s+route53\s+delete-query-logging-config\b",
            "aws route53 delete-query-logging-config removes a Route53 query logging configuration."
        ),
        destructive_pattern!(
            "route53-delete-traffic-policy",
            r"aws\s+route53\s+delete-traffic-policy\b",
            "aws route53 delete-traffic-policy permanently deletes a Route53 traffic policy."
        ),
        destructive_pattern!(
            "route53-delete-reusable-delegation-set",
            r"aws\s+route53\s+delete-reusable-delegation-set\b",
            "aws route53 delete-reusable-delegation-set permanently deletes a reusable delegation set."
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
        assert_eq!(pack.id, "dns.route53");
        assert_eq!(pack.name, "AWS Route53");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"aws"));
        assert!(pack.keywords.contains(&"route53"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "aws route53 list-hosted-zones");
        assert_safe_pattern_matches(
            &pack,
            "aws route53 list-resource-record-sets --hosted-zone-id Z123",
        );
        assert_safe_pattern_matches(&pack, "aws route53 get-hosted-zone --id Z123");
        assert_safe_pattern_matches(
            &pack,
            "aws route53 test-dns-answer --hosted-zone-id Z123 --record-name example.com",
        );
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "aws route53 delete-hosted-zone --id Z123",
            "route53-delete-hosted-zone",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws route53 change-resource-record-sets --hosted-zone-id Z123 --change-batch '{\"Changes\":[{\"Action\":\"DELETE\"}]}'",
            "route53-change-resource-record-sets-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws route53 delete-health-check --health-check-id abc",
            "route53-delete-health-check",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws route53 delete-query-logging-config --id abc",
            "route53-delete-query-logging-config",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws route53 delete-traffic-policy --id abc --version 1",
            "route53-delete-traffic-policy",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws route53 delete-reusable-delegation-set --id N123",
            "route53-delete-reusable-delegation-set",
        );
    }
}
