use crate::rules::parser::CustomRule;

/// Check if a function body matches the rule's pattern.
/// Returns the matching line number (1-based) if found, None otherwise.
pub fn matches_rule(
    source: &str,
    fn_body: &str,
    fn_line: usize,
    rule: &CustomRule,
) -> Option<usize> {
    // Check if the pattern exists in the function body source
    // We check the raw source lines around the function for the pattern
    // since tokenized source may alter formatting
    let lines: Vec<&str> = source.lines().collect();
    let start = fn_line.saturating_sub(1);

    for (i, line) in lines[start..].iter().enumerate() {
        if line.contains(&rule.pattern) {
            return Some(start + i + 1);
        }
    }

    // Also check tokenized body as fallback
    if fn_body.contains(&rule.pattern) {
        return Some(fn_line);
    }

    None
}

/// Check if a function name looks like a test function.
pub fn is_test_function(fn_name: &str, fn_source: &str) -> bool {
    fn_name.contains("test")
        || fn_source.contains("# [test]")
        || fn_source.contains("#[test]")
        || fn_source.contains("cfg (test")
        || fn_source.contains("cfg(test")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::parser::CustomRule;

    fn make_rule(pattern: &str) -> CustomRule {
        CustomRule {
            id: "TEST-001".to_string(),
            name: "test-rule".to_string(),
            severity: "medium".to_string(),
            confidence: "medium".to_string(),
            chain: None,
            pattern: pattern.to_string(),
            message: "test".to_string(),
            recommendation: "test".to_string(),
            exclude_tests: true,
        }
    }

    #[test]
    fn test_matches_pattern_in_source() {
        let source = "fn foo() {\n    unsafe { do_thing(); }\n}\n";
        let rule = make_rule("unsafe {");
        assert!(matches_rule(source, "", 1, &rule).is_some());
    }

    #[test]
    fn test_no_match() {
        let source = "fn foo() {\n    safe_thing();\n}\n";
        let rule = make_rule("unsafe {");
        assert!(matches_rule(source, "", 1, &rule).is_none());
    }

    #[test]
    fn test_is_test_function() {
        assert!(is_test_function("test_foo", "fn test_foo() {}"));
        assert!(is_test_function("foo", "#[test]\nfn foo() {}"));
        assert!(!is_test_function("foo", "fn foo() {}"));
    }
}
