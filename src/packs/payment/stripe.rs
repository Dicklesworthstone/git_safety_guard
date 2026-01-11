//! `Stripe` payment pack - protections for destructive `Stripe` operations.
//!
//! Covers destructive CLI/API operations:
//! - `stripe ... delete` for resources like webhook endpoints, customers, products, prices, coupons
//! - `stripe api_keys roll` (key rotation without coordination)
//! - `Stripe` API DELETE calls for `/v1/...` endpoints

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `Stripe` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "payment.stripe".to_string(),
        name: "Stripe",
        description: "Protects against destructive Stripe CLI/API operations like deleting webhook endpoints \
                      and customers, or rotating API keys without coordination.",
        keywords: &["stripe", "api.stripe.com"],
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
            "stripe-listen",
            r"\bstripe\b(?:\s+--?\S+(?:\s+\S+)?)*\s+listen\b"
        ),
        safe_pattern!(
            "stripe-customers-list",
            r"\bstripe\b(?:\s+--?\S+(?:\s+\S+)?)*\s+customers\s+list\b"
        ),
        safe_pattern!(
            "stripe-products-list",
            r"\bstripe\b(?:\s+--?\S+(?:\s+\S+)?)*\s+products\s+list\b"
        ),
        safe_pattern!(
            "stripe-payments-list",
            r"\bstripe\b(?:\s+--?\S+(?:\s+\S+)?)*\s+payments\s+list\b"
        ),
        safe_pattern!(
            "stripe-logs-tail",
            r"\bstripe\b(?:\s+--?\S+(?:\s+\S+)?)*\s+logs\s+tail\b"
        ),
        safe_pattern!(
            "stripe-api-get",
            r"(?i)curl\s+.*(?:-X|--request)\s+GET\b.*api\.stripe\.com.*\/v1\/"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "stripe-webhook-endpoints-delete",
            r"\bstripe\b(?:\s+--?\S+(?:\s+\S+)?)*\s+webhook[_-]endpoints\s+delete\b",
            "stripe webhook_endpoints delete removes a Stripe webhook endpoint, breaking notifications."
        ),
        destructive_pattern!(
            "stripe-customers-delete",
            r"\bstripe\b(?:\s+--?\S+(?:\s+\S+)?)*\s+customers\s+delete\b",
            "stripe customers delete permanently deletes a customer."
        ),
        destructive_pattern!(
            "stripe-products-delete",
            r"\bstripe\b(?:\s+--?\S+(?:\s+\S+)?)*\s+products\s+delete\b",
            "stripe products delete permanently deletes a product."
        ),
        destructive_pattern!(
            "stripe-prices-delete",
            r"\bstripe\b(?:\s+--?\S+(?:\s+\S+)?)*\s+prices\s+delete\b",
            "stripe prices delete permanently deletes a price."
        ),
        destructive_pattern!(
            "stripe-coupons-delete",
            r"\bstripe\b(?:\s+--?\S+(?:\s+\S+)?)*\s+coupons\s+delete\b",
            "stripe coupons delete permanently deletes a coupon."
        ),
        destructive_pattern!(
            "stripe-api-keys-roll",
            r"\bstripe\b(?:\s+--?\S+(?:\s+\S+)?)*\s+api[_-]keys\s+roll\b",
            "stripe api_keys roll rotates API keys; coordinate to avoid outages.",
            Medium
        ),
        destructive_pattern!(
            "stripe-api-delete",
            r"(?i)curl\s+.*(?:-X|--request)\s+DELETE\b.*api\.stripe\.com.*\/v1\/",
            "Stripe API DELETE calls remove Stripe resources."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn test_pack_creation() {
        let pack = create_pack();
        assert_eq!(pack.id, "payment.stripe");
        assert_eq!(pack.name, "Stripe");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"stripe"));
        assert!(pack.keywords.contains(&"api.stripe.com"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "stripe listen");
        assert_safe_pattern_matches(&pack, "stripe customers list");
        assert_safe_pattern_matches(&pack, "stripe products list");
        assert_safe_pattern_matches(&pack, "stripe payments list");
        assert_safe_pattern_matches(&pack, "stripe logs tail");
        assert_safe_pattern_matches(&pack, "curl -X GET https://api.stripe.com/v1/customers");
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "stripe webhook_endpoints delete we_123",
            "stripe-webhook-endpoints-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "stripe customers delete cus_123",
            "stripe-customers-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "stripe products delete prod_123",
            "stripe-products-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "stripe prices delete price_123",
            "stripe-prices-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "stripe coupons delete coupon_123",
            "stripe-coupons-delete",
        );
        assert_blocks_with_pattern(&pack, "stripe api_keys roll", "stripe-api-keys-roll");
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.stripe.com/v1/customers/cus_123",
            "stripe-api-delete",
        );
    }

    #[test]
    fn key_rotation_is_medium_severity() {
        let pack = create_pack();
        let Some(matched) = pack.matches_destructive("stripe api_keys roll") else {
            panic!("expected stripe api_keys roll to match a destructive pattern");
        };
        assert_eq!(matched.severity, Severity::Medium);
    }
}
