use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedCPIFinding {
    pub vulnerability_type: EnhancedCPIVulnerability,
    pub severity: CPISeverity,
    pub description: String,
    pub location: String,
    pub cpi_chain: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnhancedCPIVulnerability {
    ArbitraryCPI,
    PrivilegeEscalation,
    UnvalidatedProgramId,
    ReentrancyRisk,
    UncheckedReturnValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CPISeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnhancedCPIReport {
    pub findings: Vec<EnhancedCPIFinding>,
    pub program_id_sources: Vec<String>,
    pub whitelist_checks: Vec<String>,
    pub ownership_checks: Vec<String>,
    pub high_risk_paths: Vec<String>,
    pub cpi_call_count: usize,
    pub validated_cpi_count: usize,
}

pub struct EnhancedCPIAnalyzer {
    /// Functions that contain CPI calls
    cpi_functions: Vec<CPICallSite>,
    /// Call graph: caller → callees
    call_graph: std::collections::HashMap<String, Vec<String>>,
}

/// A CPI call site found in source
#[derive(Debug, Clone)]
struct CPICallSite {
    caller_function: String,
    cpi_target: String,
    line_number: usize,
    has_program_id_check: bool,
    has_signer_check: bool,
    has_return_check: bool,
    is_invoke_signed: bool,
}

impl Default for EnhancedCPIAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl EnhancedCPIAnalyzer {
    pub fn new() -> Self {
        Self {
            cpi_functions: Vec::new(),
            call_graph: std::collections::HashMap::new(),
        }
    }

    pub fn analyze_source(
        &mut self,
        source: &str,
        filename: &str,
    ) -> Result<EnhancedCPIReport, String> {
        self.cpi_functions.clear();
        self.call_graph.clear();

        // Phase 1: Parse the source and build the call graph
        if let Ok(file) = syn::parse_file(source) {
            self.build_call_graph(&file);
            self.extract_cpi_sites(&file, filename, source);
        } else {
            // Fallback to text scan
            self.text_scan(source, filename);
        }

        // Phase 2: Analyze CPI patterns
        let mut findings = Vec::new();
        let mut program_id_sources = Vec::new();
        let mut whitelist_checks = Vec::new();
        let mut ownership_checks = Vec::new();
        let mut high_risk_paths = Vec::new();
        let mut validated_count = 0;

        for site in &self.cpi_functions {
            // Check for unvalidated program ID
            if !site.has_program_id_check {
                findings.push(EnhancedCPIFinding {
                    vulnerability_type: EnhancedCPIVulnerability::UnvalidatedProgramId,
                    severity: CPISeverity::Critical,
                    description: format!(
                        "CPI call to '{}' in function '{}' at line {} lacks program ID validation. \
                         An attacker could substitute a malicious program.",
                        site.cpi_target, site.caller_function, site.line_number
                    ),
                    location: format!("{}:{}", filename, site.line_number),
                    cpi_chain: self.trace_callers(&site.caller_function),
                });
                high_risk_paths.push(format!(
                    "{} → {} (no program ID check)", site.caller_function, site.cpi_target
                ));
            } else {
                validated_count += 1;
                program_id_sources.push(format!(
                    "{}: validated CPI to {}", site.caller_function, site.cpi_target
                ));
            }

            // Check for privilege escalation via invoke_signed without signer checks
            if site.is_invoke_signed && !site.has_signer_check {
                findings.push(EnhancedCPIFinding {
                    vulnerability_type: EnhancedCPIVulnerability::PrivilegeEscalation,
                    severity: CPISeverity::Critical,
                    description: format!(
                        "invoke_signed() in function '{}' at line {} signs without verifying \
                         the incoming signer authority. An attacker may trick the PDA into \
                         signing for unintended operations.",
                        site.caller_function, site.line_number
                    ),
                    location: format!("{}:{}", filename, site.line_number),
                    cpi_chain: self.trace_callers(&site.caller_function),
                });
            }

            // Check for unchecked return values
            if !site.has_return_check {
                findings.push(EnhancedCPIFinding {
                    vulnerability_type: EnhancedCPIVulnerability::UncheckedReturnValue,
                    severity: CPISeverity::Medium,
                    description: format!(
                        "CPI call in function '{}' at line {} does not check the return value. \
                         A failed CPI could go unnoticed.",
                        site.caller_function, site.line_number
                    ),
                    location: format!("{}:{}", filename, site.line_number),
                    cpi_chain: vec![site.caller_function.clone()],
                });
            }

            // Detect reentrancy risk: function calls CPI and then writes state
            let callers = self.trace_callers(&site.caller_function);
            if callers.len() > 2 {
                // Deep call chain = higher reentrancy risk
                findings.push(EnhancedCPIFinding {
                    vulnerability_type: EnhancedCPIVulnerability::ReentrancyRisk,
                    severity: CPISeverity::High,
                    description: format!(
                        "CPI call in function '{}' is reachable through a deep call chain ({}). \
                         Consider checks-effects-interactions pattern.",
                        site.caller_function, callers.join(" → ")
                    ),
                    location: format!("{}:{}", filename, site.line_number),
                    cpi_chain: callers,
                });
            }
        }

        // Scan for ownership checks
        for line in source.lines() {
            let trimmed = line.trim();
            if trimmed.contains("owner ==") || trimmed.contains(".owner") && trimmed.contains("key()") {
                ownership_checks.push(trimmed.to_string());
            }
            if trimmed.contains("program_id") && (trimmed.contains("==") || trimmed.contains("require")) {
                whitelist_checks.push(trimmed.to_string());
            }
        }

        Ok(EnhancedCPIReport {
            cpi_call_count: self.cpi_functions.len(),
            validated_cpi_count: validated_count,
            findings,
            program_id_sources,
            whitelist_checks,
            ownership_checks,
            high_risk_paths,
        })
    }

    /// Build call graph from parsed AST
    fn build_call_graph(&mut self, file: &syn::File) {
        use syn::visit::Visit;

        struct CallGraphVisitor<'a> {
            graph: &'a mut std::collections::HashMap<String, Vec<String>>,
            current_fn: String,
        }

        impl<'a> Visit<'_> for CallGraphVisitor<'a> {
            fn visit_item_fn(&mut self, func: &syn::ItemFn) {
                let name = func.sig.ident.to_string();
                self.current_fn = name.clone();
                self.graph.entry(name).or_default();
                syn::visit::visit_item_fn(self, func);
            }

            fn visit_expr_call(&mut self, call: &syn::ExprCall) {
                if !self.current_fn.is_empty() {
                    let callee = quote::quote!(#call.func).to_string()
                        .split("::")
                        .last()
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    if !callee.is_empty() {
                        self.graph
                            .entry(self.current_fn.clone())
                            .or_default()
                            .push(callee);
                    }
                }
                syn::visit::visit_expr_call(self, call);
            }

            fn visit_expr_method_call(&mut self, mc: &syn::ExprMethodCall) {
                if !self.current_fn.is_empty() {
                    let callee = mc.method.to_string();
                    self.graph
                        .entry(self.current_fn.clone())
                        .or_default()
                        .push(callee);
                }
                syn::visit::visit_expr_method_call(self, mc);
            }
        }

        let mut visitor = CallGraphVisitor {
            graph: &mut self.call_graph,
            current_fn: String::new(),
        };
        visitor.visit_file(file);
    }

    /// Extract CPI call sites from AST
    fn extract_cpi_sites(&mut self, file: &syn::File, _filename: &str, source: &str) {
        use syn::visit::Visit;

        let lines: Vec<&str> = source.lines().collect();

        struct CPIVisitor<'a> {
            sites: &'a mut Vec<CPICallSite>,
            current_fn: String,
            lines: &'a [&'a str],
        }

        impl<'a> Visit<'_> for CPIVisitor<'a> {
            fn visit_item_fn(&mut self, func: &syn::ItemFn) {
                self.current_fn = func.sig.ident.to_string();
                syn::visit::visit_item_fn(self, func);
            }

            fn visit_expr_call(&mut self, call: &syn::ExprCall) {
                let func_str = quote::quote!(#call).to_string();

                let is_invoke = func_str.contains("invoke");
                let is_invoke_signed = func_str.contains("invoke_signed");

                if is_invoke || is_invoke_signed {
                    // Determine approximate line number
                    let line_number = self.lines.iter()
                        .position(|l| l.contains("invoke"))
                        .map(|p| p + 1)
                        .unwrap_or(0);

                    // Check if there's a program ID validation nearby
                    let context_start = line_number.saturating_sub(10);
                    let context_end = (line_number + 5).min(self.lines.len());
                    let context: String = self.lines[context_start..context_end].join("\n");

                    let has_program_id_check = context.contains("program_id")
                        && (context.contains("==") || context.contains("require"))
                        || context.contains("Program<")
                        || context.contains("Interface<");

                    let has_signer_check = context.contains("Signer<")
                        || context.contains("is_signer")
                        || context.contains("has_one");

                    let has_return_check = func_str.contains("?")
                        || context.contains("expect(")
                        || context.contains("unwrap()");

                    let cpi_target = if func_str.contains("spl_token") {
                        "spl_token".to_string()
                    } else if func_str.contains("system_program") {
                        "system_program".to_string()
                    } else {
                        "unknown_program".to_string()
                    };

                    self.sites.push(CPICallSite {
                        caller_function: self.current_fn.clone(),
                        cpi_target,
                        line_number,
                        has_program_id_check,
                        has_signer_check,
                        has_return_check,
                        is_invoke_signed,
                    });
                }

                syn::visit::visit_expr_call(self, call);
            }
        }

        let mut visitor = CPIVisitor {
            sites: &mut self.cpi_functions,
            current_fn: String::new(),
            lines: &lines,
        };
        visitor.visit_file(file);
    }

    /// Text-based fallback scan for CPI patterns
    fn text_scan(&mut self, source: &str, _filename: &str) {
        let lines: Vec<&str> = source.lines().collect();
        let mut current_fn = String::new();

        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Track current function
            if trimmed.starts_with("pub fn ") || trimmed.starts_with("fn ") {
                if let Some(name) = trimmed.split('(').next() {
                    current_fn = name
                        .replace("pub fn ", "")
                        .replace("fn ", "")
                        .trim()
                        .to_string();
                }
            }

            // Detect CPI calls
            if trimmed.contains("invoke(") || trimmed.contains("invoke_signed(") {
                let is_invoke_signed = trimmed.contains("invoke_signed");

                let context_start = i.saturating_sub(10);
                let context_end = (i + 5).min(lines.len());
                let context: String = lines[context_start..context_end].join("\n");

                let has_program_id_check = context.contains("program_id")
                    && (context.contains("==") || context.contains("require"));
                let has_signer_check = context.contains("Signer<")
                    || context.contains("is_signer");
                let has_return_check = trimmed.contains("?") || trimmed.contains("expect(");

                self.cpi_functions.push(CPICallSite {
                    caller_function: current_fn.clone(),
                    cpi_target: "unknown_program".to_string(),
                    line_number: i + 1,
                    has_program_id_check,
                    has_signer_check,
                    has_return_check,
                    is_invoke_signed,
                });
            }
        }
    }

    /// Trace callers of a function through the call graph
    fn trace_callers(&self, target: &str) -> Vec<String> {
        let mut chain = vec![target.to_string()];
        let mut visited = std::collections::HashSet::new();
        visited.insert(target.to_string());

        // Reverse search: find who calls `target`
        let mut current = target.to_string();
        for _ in 0..10 {
            // max depth to prevent infinite loops
            let mut found_caller = false;
            for (caller, callees) in &self.call_graph {
                if callees.contains(&current) && !visited.contains(caller) {
                    chain.push(caller.clone());
                    visited.insert(caller.clone());
                    current = caller.clone();
                    found_caller = true;
                    break;
                }
            }
            if !found_caller {
                break;
            }
        }

        chain.reverse();
        chain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_unvalidated_invoke() {
        let mut analyzer = EnhancedCPIAnalyzer::new();
        let code = r#"
            pub fn do_transfer(accounts: &[AccountInfo]) -> ProgramResult {
                let ix = spl_token::instruction::transfer(
                    &spl_token::id(), &src, &dst, &auth, &[], amount
                )?;
                invoke(&ix, accounts)?;
                Ok(())
            }
        "#;
        let report = analyzer.analyze_source(code, "test.rs").unwrap();
        assert!(report.cpi_call_count > 0, "Should find CPI calls");
    }

    #[test]
    fn test_empty_source() {
        let mut analyzer = EnhancedCPIAnalyzer::new();
        let report = analyzer.analyze_source("", "empty.rs").unwrap();
        assert_eq!(report.cpi_call_count, 0);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn test_safe_cpi_no_findings() {
        let mut analyzer = EnhancedCPIAnalyzer::new();
        let code = r#"
            pub fn safe_fn() -> Result<()> {
                let x = 1 + 2;
                Ok(())
            }
        "#;
        let report = analyzer.analyze_source(code, "safe.rs").unwrap();
        assert!(report.findings.is_empty(), "Safe code should produce no CPI findings");
    }
}
