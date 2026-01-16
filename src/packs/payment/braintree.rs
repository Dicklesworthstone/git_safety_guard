//! `Braintree` payment pack - protections for destructive `Braintree` operations.
//!
//! Covers destructive API/SDK operations:
//! - `curl -X DELETE` to `braintreegateway.com` endpoints (customers, webhooks, etc.)
//! - SDK delete/cancel calls in scripts (e.g., `braintree.Customer.delete`, `gateway.customer.delete`)
//!
//! Note: Many `Braintree` workflows run via SDK calls embedded in scripts; this pack aims to
//! catch obvious deletion/cancellation primitives in command strings.

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `Braintree` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "payment.braintree".to_string(),
        name: "Braintree",
        description: "Protects against destructive Braintree/PayPal payment operations like deleting customers \
                      or cancelling subscriptions via API/SDK calls.",
        keywords: &[
            "braintree",
            "braintreegateway.com",
            "braintree.",
            "gateway.customer.",
            "gateway.merchant_account.",
            "gateway.payment_method.",
            "gateway.subscription.",
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
        safe_pattern!("braintree-customer-find", r"\bbraintree\.Customer\.find\b"),
        safe_pattern!(
            "braintree-customer-search",
            r"\bgateway\.customer\.search\b"
        ),
        safe_pattern!(
            "braintree-api-get",
            r"(?i)curl\s+.*(?:-X|--request)\s+GET\b.*braintreegateway\.com"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "braintree-api-delete",
            r"(?i)curl\s+.*(?:-X|--request)\s+DELETE\b.*braintreegateway\.com",
            "Braintree API DELETE calls remove payment resources (customers, webhooks, etc.)."
        ),
        destructive_pattern!(
            "braintree-customer-delete",
            r"\bbraintree\.Customer\.delete\b",
            "braintree.Customer.delete permanently deletes a Braintree customer."
        ),
        destructive_pattern!(
            "braintree-gateway-customer-delete",
            r"\bgateway\.customer\.delete\b",
            "gateway.customer.delete permanently deletes a Braintree customer."
        ),
        destructive_pattern!(
            "braintree-merchant-account-delete",
            r"\bgateway\.merchant_account\.delete\b",
            "gateway.merchant_account.delete removes a Braintree merchant account."
        ),
        destructive_pattern!(
            "braintree-payment-method-delete",
            r"\bgateway\.payment_method\.delete\b",
            "gateway.payment_method.delete removes a stored payment method."
        ),
        destructive_pattern!(
            "braintree-subscription-cancel",
            r"\bgateway\.subscription\.cancel\b",
            "gateway.subscription.cancel cancels a subscription, impacting billing."
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
        assert_eq!(pack.id, "payment.braintree");
        assert_eq!(pack.name, "Braintree");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"braintree"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "braintree.Customer.find('cust_123')");
        assert_safe_pattern_matches(&pack, "gateway.customer.search({:email => 'a@b.com'})");
        assert_safe_pattern_matches(
            &pack,
            "curl -X GET https://api.braintreegateway.com/merchants/abc/customers/cust_123",
        );
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.braintreegateway.com/merchants/abc/customers/cust_123",
            "braintree-api-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "braintree.Customer.delete('cust_123')",
            "braintree-customer-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "gateway.customer.delete('cust_123')",
            "braintree-gateway-customer-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "gateway.merchant_account.delete('ma_123')",
            "braintree-merchant-account-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "gateway.payment_method.delete('pm_123')",
            "braintree-payment-method-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "gateway.subscription.cancel('sub_123')",
            "braintree-subscription-cancel",
        );
    }
}
