#[test]
fn test_rm_quoted_root_is_critical() {
    use destructive_command_guard::packs::core::filesystem::{parse_rm_command, RmParseDecision};
    use destructive_command_guard::packs::Severity;

    // rm -rf / -> Critical (Correct)
    if let RmParseDecision::Deny(hit) = parse_rm_command("rm -rf /") {
        assert_eq!(hit.severity, Severity::Critical, "Unquoted / should be Critical");
    } else {
        panic!("rm -rf / should be denied");
    }

    // rm -rf "/" -> Currently High (Bug), Should be Critical
    if let RmParseDecision::Deny(hit) = parse_rm_command("rm -rf \"/\"") {
        assert_eq!(hit.severity, Severity::Critical, "Quoted \"/\" should be Critical");
    } else {
        panic!("rm -rf \"/\" should be denied");
    }
}

