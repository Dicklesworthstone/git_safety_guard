//! `Square` payment pack - protections for destructive `Square` operations.
//!
//! Covers destructive CLI/API operations:
//! - `square catalog delete`
//! - `curl -X DELETE` to `api.squareup.com/v2/...` endpoints (catalog objects, customers, locations, webhooks)

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `Square` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "payment.square".to_string(),
        name: "Square",
        description: "Protects against destructive Square CLI/API operations like deleting catalog objects \
                      or customers (which can break payment flows).",
        keywords: &["square", "api.squareup.com"],
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
            "square-catalog-list",
            r"\bsquare\b(?:\s+--?\S+(?:\s+\S+)?)*\s+catalog\s+list\b"
        ),
        safe_pattern!(
            "square-customers-list",
            r"\bsquare\b(?:\s+--?\S+(?:\s+\S+)?)*\s+customers\s+list\b"
        ),
        safe_pattern!(
            "square-api-get",
            r"(?i)curl\s+.*(?:-X|--request)\s+GET\b.*api\.squareup\.com"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "square-catalog-delete",
            r"\bsquare\b(?:\s+--?\S+(?:\s+\S+)?)*\s+catalog\s+delete\b",
            "square catalog delete removes catalog objects, impacting products and inventory.",
            High,
            "Deleting catalog objects removes products, variations, modifiers, or categories \
             from your Square catalog. POS systems, online stores, and invoicing that \
             reference these items will show errors or missing products.\n\n\
             Safer alternatives:\n\
             - square catalog list to review items first\n\
             - Set item visibility to hidden instead of deleting\n\
             - Export catalog backup before bulk deletions"
        ),
        destructive_pattern!(
            "square-api-delete-catalog-object",
            r"(?i)curl\s+.*(?:-X|--request)\s+DELETE\b.*api\.squareup\.com[^\s]*?/v2/catalog/object/[^\s]+",
            "Square API DELETE /v2/catalog/object/{id} deletes a catalog object.",
            High,
            "Direct API deletion of catalog objects bypasses CLI safety checks. Products, \
             categories, taxes, discounts, and modifiers can be permanently removed, \
             breaking POS workflows and e-commerce integrations.\n\n\
             Safer alternatives:\n\
             - GET /v2/catalog/object/{id} to verify before deletion\n\
             - Use batch operations with careful ID validation\n\
             - Test in Square sandbox environment first"
        ),
        destructive_pattern!(
            "square-api-delete-customer",
            r"(?i)curl\s+.*(?:-X|--request)\s+DELETE\b.*api\.squareup\.com[^\s]*?/v2/customers/[^\s]+",
            "Square API DELETE /v2/customers/{id} deletes a customer.",
            Critical,
            "Deleting a Square customer removes their profile, cards on file, and loyalty \
             data. Transaction history loses customer context, affecting reporting and \
             CRM. Repeat customers will need to re-register.\n\n\
             Safer alternatives:\n\
             - GET /v2/customers/{id} to verify customer before deletion\n\
             - Remove cards on file instead of full deletion\n\
             - Export customer data before deletion for compliance"
        ),
        destructive_pattern!(
            "square-api-delete-location",
            r"(?i)curl\s+.*(?:-X|--request)\s+DELETE\b.*api\.squareup\.com[^\s]*?/v2/locations/[^\s]+",
            "Square API DELETE /v2/locations/{id} deletes a location.",
            Critical,
            "Deleting a location removes a business location from Square. This affects \
             payment processing, inventory tracking, and employee management for that \
             location. Transactions cannot be processed at a deleted location.\n\n\
             Safer alternatives:\n\
             - Set location status to inactive instead of deleting\n\
             - GET /v2/locations/{id} to verify location details first\n\
             - Transfer inventory and employees before deletion"
        ),
        destructive_pattern!(
            "square-api-delete-webhook-subscription",
            r"(?i)curl\s+.*(?:-X|--request)\s+DELETE\b.*api\.squareup\.com[^\s]*?/v2/webhooks/subscriptions/[^\s]+",
            "Square API DELETE /v2/webhooks/subscriptions/{id} deletes a webhook subscription.",
            High,
            "Deleting a webhook subscription stops event notifications for payments, \
             refunds, inventory changes, and other business events. Your application \
             will miss critical updates until the subscription is recreated.\n\n\
             Safer alternatives:\n\
             - Disable the webhook subscription instead of deleting\n\
             - GET /v2/webhooks/subscriptions to verify subscription ID\n\
             - Set up backup notification channels before removal"
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
        assert_eq!(pack.id, "payment.square");
        assert_eq!(pack.name, "Square");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"square"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "square catalog list");
        assert_safe_pattern_matches(&pack, "square customers list");
        assert_safe_pattern_matches(&pack, "curl -X GET https://api.squareup.com/v2/locations");
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "square catalog delete obj_123",
            "square-catalog-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.squareup.com/v2/catalog/object/obj_123",
            "square-api-delete-catalog-object",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.squareup.com/v2/customers/cus_123",
            "square-api-delete-customer",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.squareup.com/v2/locations/loc_123",
            "square-api-delete-location",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.squareup.com/v2/webhooks/subscriptions/sub_123",
            "square-api-delete-webhook-subscription",
        );
    }
}
