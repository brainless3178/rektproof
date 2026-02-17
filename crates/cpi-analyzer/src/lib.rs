pub mod enhanced;
pub mod graph;

pub use enhanced::{CPISeverity, EnhancedCPIAnalyzer, EnhancedCPIFinding, EnhancedCPIReport, EnhancedCPIVulnerability};
pub use graph::{CPIDependencyGraph, CPICallType, CPIEdge, ProgramNode, RiskPropagation, GraphSummary};

pub struct CPIAnalyzer;

impl Default for CPIAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl CPIAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Analyse Solana source code for unsafe Cross-Program Invocation patterns.
    ///
    /// Detects:
    /// - `invoke()` / `invoke_signed()` calls without prior program ID validation
    /// - Raw `AccountInfo` used as CPI target without owner/key checks
    /// - Missing `Program<'info, T>` type safety on CPI targets
    /// - Privilege escalation via unchecked signer propagation
    pub fn analyze_source(
        &self,
        source: &str,
        filename: &str,
    ) -> Result<Vec<CPIFinding>, String> {
        let mut findings = Vec::new();

        // Parse the source into an AST
        let file = match syn::parse_file(source) {
            Ok(f) => f,
            Err(_) => return Ok(Vec::new()), // Unparseable source — skip gracefully
        };

        let source_lines: Vec<&str> = source.lines().collect();

        // Walk all function items looking for CPI patterns
        for item in &file.items {
            if let syn::Item::Fn(func) = item {
                self.analyze_function(func, filename, &source_lines, &mut findings);
            }
            // Also check impl blocks
            if let syn::Item::Impl(impl_block) = item {
                for impl_item in &impl_block.items {
                    if let syn::ImplItem::Fn(method) = impl_item {
                        self.analyze_method(method, filename, &source_lines, &mut findings);
                    }
                }
            }
        }

        // Fallback: source-level text scan for CPI patterns the AST walk may miss
        // (e.g. macro-heavy code, inline closures, or non-standard function sigs)
        if findings.is_empty() {
            self.scan_body_for_cpi(source, "<file>", filename, &source_lines, &mut findings);
        }

        Ok(findings)
    }

    fn analyze_function(
        &self,
        func: &syn::ItemFn,
        filename: &str,
        source_lines: &[&str],
        findings: &mut Vec<CPIFinding>,
    ) {
        let fn_name = func.sig.ident.to_string();
        let body = quote::quote!(#func.block).to_string();
        self.scan_body_for_cpi(&body, &fn_name, filename, source_lines, findings);
    }

    fn analyze_method(
        &self,
        method: &syn::ImplItemFn,
        filename: &str,
        source_lines: &[&str],
        findings: &mut Vec<CPIFinding>,
    ) {
        let fn_name = method.sig.ident.to_string();
        let body = quote::quote!(#method.block).to_string();
        self.scan_body_for_cpi(&body, &fn_name, filename, source_lines, findings);
    }

    fn scan_body_for_cpi(
        &self,
        body: &str,
        fn_name: &str,
        filename: &str,
        source_lines: &[&str],
        findings: &mut Vec<CPIFinding>,
    ) {
        let has_invoke = body.contains("invoke(") || body.contains("invoke_signed(");
        let has_cpi_call = body.contains("CpiContext") || body.contains("cpi::");

        if !has_invoke && !has_cpi_call {
            return;
        }

        // Check 1: invoke/invoke_signed without program ID validation
        if has_invoke {
            let has_program_id_check = body.contains("program_id")
                || body.contains("key()")
                || body.contains("require_keys_eq")
                || body.contains("constraint =")
                || body.contains("Program<");

            if !has_program_id_check {
                let line_num = self.find_line_number(source_lines, "invoke");
                findings.push(CPIFinding {
                    vulnerability_type: EnhancedCPIVulnerability::ArbitraryCPI,
                    severity: CPISeverity::Critical,
                    description: format!(
                        "[{}:{}] Function `{}` calls invoke/invoke_signed without validating the target \
                         program ID. An attacker can substitute a malicious program that mimics the expected \
                         interface but drains funds. Use `Program<'info, T>` or `require_keys_eq!()` to \
                         validate the CPI target.",
                        filename, line_num, fn_name
                    ),
                    location: format!("{}:{}", filename, line_num),
                    cpi_chain: vec![fn_name.to_string()],
                });
            }
        }

        // Check 2: CPI with raw AccountInfo target (no type safety)
        if has_cpi_call && body.contains("AccountInfo") && !body.contains("Program<") {
            let line_num = self.find_line_number(source_lines, "CpiContext");
            findings.push(CPIFinding {
                vulnerability_type: EnhancedCPIVulnerability::PrivilegeEscalation,
                severity: CPISeverity::High,
                description: format!(
                    "[{}:{}] Function `{}` constructs a CPI context using raw AccountInfo instead of \
                     typed `Program<'info, T>`. This bypasses Anchor's automatic program ID validation. \
                     An attacker can pass any program account, enabling privilege escalation.",
                    filename, line_num, fn_name
                ),
                location: format!("{}:{}", filename, line_num),
                cpi_chain: vec![fn_name.to_string()],
            });
        }

        // Check 3: Signer propagation without validation
        if has_invoke && body.contains("is_signer") && !body.contains("require!") {
            let line_num = self.find_line_number(source_lines, "is_signer");
            findings.push(CPIFinding {
                vulnerability_type: EnhancedCPIVulnerability::PrivilegeEscalation,
                severity: CPISeverity::High,
                description: format!(
                    "[{}:{}] Function `{}` propagates signer privileges in a CPI without explicit \
                     validation. Ensure the signer account is actually authorized before forwarding \
                     its privileges to another program.",
                    filename, line_num, fn_name
                ),
                location: format!("{}:{}", filename, line_num),
                cpi_chain: vec![fn_name.to_string()],
            });
        }
    }

    fn find_line_number(&self, source_lines: &[&str], pattern: &str) -> usize {
        source_lines
            .iter()
            .position(|line| line.contains(pattern))
            .map(|i| i + 1) // 1-indexed
            .unwrap_or(0)
    }
}

pub type CPIFinding = EnhancedCPIFinding;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpi_analyzer_creation() {
        let analyzer = CPIAnalyzer::new();
        let result = analyzer.analyze_source("", "test.rs");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_detects_unvalidated_invoke() {
        let analyzer = CPIAnalyzer::new();
        let code = r#"
            fn transfer_tokens(accounts: &[AccountInfo]) -> ProgramResult {
                let ix = spl_token::instruction::transfer(
                    &spl_token::id(), &src, &dst, &auth, &[], amount
                )?;
                invoke(&ix, accounts)?;
                Ok(())
            }
        "#;
        let result = analyzer.analyze_source(code, "program.rs");
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert!(
            findings.iter().any(|f| matches!(f.vulnerability_type, EnhancedCPIVulnerability::ArbitraryCPI)),
            "Should detect unvalidated invoke() call"
        );
    }

    #[test]
    fn test_no_finding_for_validated_cpi() {
        let analyzer = CPIAnalyzer::new();
        let code = r#"
            fn safe_transfer(ctx: Context<SafeTransfer>) -> Result<()> {
                let cpi_program: Program<'info, Token> = ctx.accounts.token_program;
                let cpi_ctx = CpiContext::new(cpi_program.to_account_info(), transfer_accounts);
                token::transfer(cpi_ctx, amount)?;
                Ok(())
            }
        "#;
        let result = analyzer.analyze_source(code, "program.rs");
        assert!(result.is_ok());
        // With Program<'info, T> validation, no ArbitraryCPI finding should exist
        let findings = result.unwrap();
        assert!(
            !findings.iter().any(|f| matches!(f.vulnerability_type, EnhancedCPIVulnerability::ArbitraryCPI)),
            "Should NOT flag validated CPI with Program<> type"
        );
    }

    #[test]
    fn test_enhanced_cpi_analyzer_creation() {
        let mut analyzer = EnhancedCPIAnalyzer::new();
        let report = analyzer.analyze_source("", "test.rs");
        assert!(report.is_ok());
        let report = report.unwrap();
        assert!(report.findings.is_empty());
        assert!(report.program_id_sources.is_empty());
        assert!(report.high_risk_paths.is_empty());
    }

    #[test]
    fn test_enhanced_cpi_report_default() {
        let report = EnhancedCPIReport::default();
        assert!(report.findings.is_empty());
        assert!(report.whitelist_checks.is_empty());
        assert!(report.ownership_checks.is_empty());
    }

    #[test]
    fn test_cpi_severity_equality() {
        assert_eq!(CPISeverity::Critical, CPISeverity::Critical);
        assert_ne!(CPISeverity::Critical, CPISeverity::Low);
    }
}
