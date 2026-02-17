use quote::ToTokens;
use syn::visit::Visit;
use syn::ImplItemFn;

use crate::detectors::Detector;
use crate::scanner::context::ScanContext;
use crate::scanner::finding::*;
use crate::utils::ast_helpers::*;

pub struct MissingCallerCheckDetector;

impl Detector for MissingCallerCheckDetector {
    fn id(&self) -> &'static str {
        "INK-003"
    }
    fn name(&self) -> &'static str {
        "ink-missing-caller-check"
    }
    fn description(&self) -> &'static str {
        "Detects #[ink(message)] functions that write storage without caller check"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }
    fn chain(&self) -> Chain {
        Chain::Ink
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut visitor = CallerVisitor {
            findings: &mut findings,
            ctx,
        };
        visitor.visit_file(&ctx.ast);
        findings
    }
}

struct CallerVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    ctx: &'a ScanContext,
}

impl<'ast, 'a> Visit<'ast> for CallerVisitor<'a> {
    fn visit_impl_item_fn(&mut self, method: &'ast ImplItemFn) {
        // Check for #[ink(message)] attribute
        let mut has_ink_message = false;
        let mut is_payable = false;
        for attr in &method.attrs {
            let tokens = attr.meta.to_token_stream().to_string();
            if tokens.contains("ink") && tokens.contains("message") {
                has_ink_message = true;
                if tokens.contains("payable") {
                    is_payable = true;
                }
            }
        }

        if !has_ink_message {
            return;
        }

        // Only check methods that take &mut self (can actually write storage)
        let sig_src = method.sig.to_token_stream().to_string();
        if !sig_src.contains("& mut self") && !sig_src.contains("&mut self") {
            return;
        }

        let method_name = method.sig.ident.to_string();
        let name_lower = method_name.to_lowercase();

        // Skip known permissionless patterns — standard interface methods and trivial operations
        if name_lower == "flip"
            || name_lower == "inc"
            || name_lower == "increment"
            || name_lower == "decrement"
            || name_lower == "vote"
            || name_lower == "register"
            || name_lower == "new"
            || name_lower.starts_with("get_")
            || name_lower.starts_with("is_")
            || name_lower.starts_with("has_")
        {
            return;
        }

        // Skip PSP22/PSP34 (ERC-20/721 equivalent) standard interface methods
        if name_lower == "transfer"
            || name_lower == "transfer_from"
            || name_lower == "approve"
            || name_lower == "increase_allowance"
            || name_lower == "decrease_allowance"
        {
            return;
        }

        let body_src = method.block.to_token_stream().to_string();

        // Check for actual storage mutation patterns:
        // self.field = value  (assignment to self field)
        let has_storage_write = has_self_field_assignment(&body_src);

        if !has_storage_write {
            return;
        }

        // Check for caller verification
        // Note: "owner" and "admin" alone are not sufficient — they could be
        // the field being written to. Require them in an access-control context:
        // comparison (==), assertion, or function call pattern.
        let has_caller_check = body_src.contains("caller")
            || body_src.contains("ensure !")
            || body_src.contains("ensure!")
            || body_src.contains("assert !")
            || body_src.contains("assert!")
            || body_src.contains("only_owner")
            || body_src.contains("authorize")
            || (body_src.contains("owner")
                && (body_src.contains("== ") || body_src.contains("!= ")))
            || (body_src.contains("admin")
                && (body_src.contains("== ") || body_src.contains("!= ")));

        if has_caller_check {
            return;
        }

        // Determine risk level based on what's being written and method context
        let has_value_transfer = body_src.contains("transfer (")
            || body_src.contains("transfer(")
            || body_src.contains("transferred_value");

        // High-risk field writes: admin/owner/config fields
        let written_fields = extract_self_field_names(&body_src);
        let has_sensitive_write = written_fields.iter().any(|f| {
            let fl = f.to_lowercase();
            fl.contains("owner")
                || fl.contains("admin")
                || fl.contains("authority")
                || fl.contains("manager")
                || fl.contains("controller")
                || fl.contains("paused")
                || fl.contains("frozen")
                || fl.contains("config")
                || fl.contains("operator")
        });

        // Caller-scoped writes: mapping insert keyed by caller
        let has_caller_scoped_write = body_src.contains("env () . caller")
            || body_src.contains("env() . caller")
            || body_src.contains("env().caller");

        // Determine severity and confidence based on risk signals
        let (severity, confidence, extra_context) = if has_value_transfer {
            // Transferring value without auth is always Critical
            (Severity::Critical, Confidence::High, " (transfers value)")
        } else if has_sensitive_write {
            // Writing to admin/owner fields without auth is Critical
            (
                Severity::Critical,
                Confidence::High,
                " (modifies sensitive field)",
            )
        } else if has_caller_scoped_write || is_payable {
            // Caller-scoped or payable methods are low risk
            (
                Severity::Medium,
                Confidence::Low,
                " (likely permissionless by design)",
            )
        } else {
            // General storage write — flag but at reduced confidence
            (Severity::High, Confidence::Medium, "")
        };

        let line = span_to_line(&method.sig.ident.span());
        self.findings.push(Finding {
            detector_id: "INK-003".to_string(),
            name: "ink-missing-caller-check".to_string(),
            severity,
            confidence,
            message: format!(
                "#[ink(message)] '{}' writes to storage without verifying caller{}",
                method_name, extra_context
            ),
            file: self.ctx.file_path.clone(),
            line,
            column: span_to_column(&method.sig.ident.span()),
            snippet: snippet_at_line(&self.ctx.source, line),
            recommendation: "Add `assert_eq!(self.env().caller(), self.owner)` or similar caller verification before storage writes".to_string(),
            chain: Chain::Ink,
        });
    }
}

/// Extract field names from `self.field = ...` patterns
fn extract_self_field_names(body: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let bytes = body.as_bytes();
    let pat = b"self .";
    let mut i = 0;
    while i + pat.len() < bytes.len() {
        if &bytes[i..i + pat.len()] == pat {
            let rest = &body[i + pat.len()..].trim_start();
            // Extract the field name (alphanumeric + underscore)
            let field_end = rest
                .find(|c: char| !c.is_alphanumeric() && c != '_')
                .unwrap_or(rest.len());
            let field_name = &rest[..field_end];
            if !field_name.is_empty() {
                // Check if this is an assignment (not comparison, not method call)
                let after_field = rest[field_end..].trim_start();
                if after_field.starts_with('=') && !after_field.starts_with("==") {
                    let prefix = &body[..i];
                    let trimmed = prefix.trim_end();
                    if !trimmed.ends_with("let") && !trimmed.ends_with("=") {
                        fields.push(field_name.to_string());
                    }
                }
            }
        }
        i += 1;
    }
    fields
}

/// Check for `self.field = ...` patterns (actual assignment, not comparison)
fn has_self_field_assignment(body: &str) -> bool {
    // In tokenized form: "self . field = expr" but NOT "self . field == expr"
    // Look for "self ." followed by an ident and then " = " (single equals, not double)
    let bytes = body.as_bytes();
    let pat = b"self .";
    let mut i = 0;
    while i + pat.len() < bytes.len() {
        if &bytes[i..i + pat.len()] == pat {
            // Skip past "self . <ident>"
            let rest = &body[i + pat.len()..];
            // Find next '=' character
            if let Some(eq_pos) = rest.find('=') {
                let before_eq = &rest[..eq_pos];
                // Should be just whitespace + identifier before the =
                let after_eq = rest.get(eq_pos + 1..eq_pos + 2).unwrap_or("");
                // Make sure it's not == or !=
                if after_eq != "=" && !before_eq.ends_with('!') {
                    // Make sure we're not in a let binding (let x = self.field)
                    // Check characters before "self"
                    let prefix = &body[..i];
                    let trimmed = prefix.trim_end();
                    if !trimmed.ends_with("let") && !trimmed.ends_with("=") {
                        return true;
                    }
                }
            }
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_detector(source: &str) -> Vec<Finding> {
        let ast = syn::parse_file(source).unwrap();
        let ctx = ScanContext::new(
            std::path::PathBuf::from("test.rs"),
            source.to_string(),
            ast,
            Chain::Ink,
        );
        MissingCallerCheckDetector.detect(&ctx)
    }

    #[test]
    fn test_detects_missing_caller() {
        let source = r#"
            impl MyContract {
                #[ink(message)]
                pub fn set_value(&mut self, value: u32) {
                    self.value = value;
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect missing caller check");
    }

    #[test]
    fn test_no_finding_readonly_method() {
        let source = r#"
            impl MyContract {
                #[ink(message)]
                pub fn get_value(&self) -> u32 {
                    let x = self.value;
                    x
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag read-only &self methods"
        );
    }

    #[test]
    fn test_no_finding_with_caller_check() {
        let source = r#"
            impl MyContract {
                #[ink(message)]
                pub fn set_value(&mut self, value: u32) {
                    assert_eq!(self.env().caller(), self.owner);
                    self.value = value;
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(findings.is_empty(), "Should not flag with caller check");
    }

    #[test]
    fn test_critical_for_owner_write() {
        let source = r#"
            impl MyContract {
                #[ink(message)]
                pub fn set_owner(&mut self, new_owner: AccountId) {
                    self.owner = new_owner;
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(
            !findings.is_empty(),
            "Should detect missing caller check on owner write"
        );
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_reduced_severity_for_general_write() {
        let source = r#"
            impl MyContract {
                #[ink(message)]
                pub fn set_value(&mut self, value: u32) {
                    self.value = value;
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty(), "Should detect missing caller check");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_low_confidence_for_payable() {
        let source = r#"
            impl MyContract {
                #[ink(message, payable)]
                pub fn deposit(&mut self) {
                    self.balance = 100;
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].confidence, Confidence::Low);
    }

    #[test]
    fn test_no_finding_for_flip() {
        let source = r#"
            impl Flipper {
                #[ink(message)]
                pub fn flip(&mut self) {
                    self.value = !self.value;
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag known permissionless patterns like flip"
        );
    }

    #[test]
    fn test_no_finding_for_standard_transfer() {
        let source = r#"
            impl Erc20 {
                #[ink(message)]
                pub fn transfer(&mut self, to: AccountId, value: Balance) {
                    self.balances = value;
                }
            }
        "#;
        let findings = run_detector(source);
        assert!(
            findings.is_empty(),
            "Should not flag PSP22/ERC20 standard transfer method"
        );
    }
}
