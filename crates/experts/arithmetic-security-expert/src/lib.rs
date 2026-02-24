#![allow(dead_code)]
//! Arithmetic Security Expert — Static Analysis for Numeric Vulnerabilities
//!
//! Performs AST-level analysis of Rust source code to detect arithmetic
//! vulnerabilities common in Solana programs: unchecked +/-/*/÷, precision
//! loss (div-before-mul), lossy integer casts, and shift overflows.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use syn::spanned::Spanned;
use syn::{
    visit::{self, Visit},
    BinOp, Expr,
};

pub struct ArithmeticSecurityExpert;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArithmeticInsight {
    pub id: String,
    pub name: String,
    pub risk_assessment: String,
    pub attack_vectors: Vec<String>,
    pub secure_pattern: String,
    pub precision_rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ArithmeticIssueKind {
    DivisionBeforeMultiplication,
    UncheckedArithmetic,
    PotentialPrecisionLoss,
    IntegerCastingRisk,
    ShiftOverflow,
    PotentialDivisionByZero,
    ModuloByZero,
}

impl ArithmeticIssueKind {
    /// Return a CVSS-like severity score (0-10).
    pub fn severity(&self) -> u8 {
        match self {
            ArithmeticIssueKind::UncheckedArithmetic => 9,
            ArithmeticIssueKind::PotentialDivisionByZero => 9,
            ArithmeticIssueKind::DivisionBeforeMultiplication => 7,
            ArithmeticIssueKind::IntegerCastingRisk => 7,
            ArithmeticIssueKind::ShiftOverflow => 6,
            ArithmeticIssueKind::PotentialPrecisionLoss => 5,
            ArithmeticIssueKind::ModuloByZero => 4,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArithmeticIssue {
    pub kind: ArithmeticIssueKind,
    pub line: usize,
    pub snippet: String,
    pub recommendation: String,
}

impl ArithmeticSecurityExpert {
    pub fn get_insight_for_id(id: &str) -> Option<ArithmeticInsight> {
        match id {
            "2.1" | "SOL-002" => Some(ArithmeticInsight {
                id: "SOL-002".into(),
                name: "Integer Overflow/Underflow".into(),
                risk_assessment: "Critical. Allows manipulation of balances and shares.".into(),
                attack_vectors: vec![
                    "Large deposit amount causing overflow in total assets".into(),
                    "Small deposit/withdraw causing precision loss in share calculation".into(),
                    "Subtraction underflow wrapping to MAX value".into(),
                ],
                secure_pattern:
                    "amount.checked_mul(total_shares).ok_or(Error::Overflow)? / total_assets"
                        .into(),
                precision_rules: vec![
                    "Always multiply before dividing".into(),
                    "Use checked arithmetic for all user-controlled inputs".into(),
                    "Enable overflow-checks = true in release profile".into(),
                ],
            }),
            "2.2" | "SOL-031" => Some(ArithmeticInsight {
                id: "SOL-031".into(),
                name: "Division Before Multiplication (Precision Loss)".into(),
                risk_assessment: "High. Integer truncation cascades across operations.".into(),
                attack_vectors: vec![
                    "Repeated rounding-down extracts value over many transactions".into(),
                    "Share calculation yields 0 when amount * shares < total_assets".into(),
                ],
                secure_pattern: "amount.checked_mul(rate).ok_or(...)?.checked_div(scale)".into(),
                precision_rules: vec![
                    "Always multiply before dividing".into(),
                    "Use WAD (1e18) or RAY (1e27) scaling for fixed-point".into(),
                    "Verify result > 0 after division".into(),
                ],
            }),
            "2.3" | "SOL-032" => Some(ArithmeticInsight {
                id: "SOL-032".into(),
                name: "Lossy Integer Casting".into(),
                risk_assessment: "High. Silent truncation can halve or zero critical values."
                    .into(),
                attack_vectors: vec![
                    "u128 price cast to u64 silently truncates high bits".into(),
                    "i64 timestamp cast to u32 wraps in year 2038".into(),
                ],
                secure_pattern:
                    "let val: u64 = big_val.try_into().map_err(|_| Error::CastOverflow)?"
                        .into(),
                precision_rules: vec![
                    "Never use 'as' for numeric conversions".into(),
                    "Use TryInto with explicit error handling".into(),
                    "Validate range before casting".into(),
                ],
            }),
            _ => None,
        }
    }

    /// Analyze a source file for arithmetic vulnerabilities.
    ///
    /// Returns all detected issues sorted by severity (highest first).
    pub fn analyze_source(source: &str) -> Result<Vec<ArithmeticIssue>> {
        let file = syn::parse_file(source)?;
        let mut visitor = ArithmeticVisitor { issues: Vec::new() };
        visitor.visit_file(&file);
        // Sort by severity descending
        visitor
            .issues
            .sort_by(|a, b| b.kind.severity().cmp(&a.kind.severity()));
        Ok(visitor.issues)
    }

    /// Convenience: return only Critical/High issues (severity >= 7).
    pub fn analyze_critical(source: &str) -> Result<Vec<ArithmeticIssue>> {
        Ok(Self::analyze_source(source)?
            .into_iter()
            .filter(|i| i.kind.severity() >= 7)
            .collect())
    }
}

struct ArithmeticVisitor {
    issues: Vec<ArithmeticIssue>,
}

impl ArithmeticVisitor {
    fn is_div_op(expr: &Expr) -> bool {
        match expr {
            Expr::Binary(eb) => matches!(eb.op, BinOp::Div(_)),
            Expr::Paren(ep) => Self::is_div_op(&ep.expr),
            _ => false,
        }
    }

    /// Check if an expression is a literal zero.
    fn is_zero_literal(expr: &Expr) -> bool {
        match expr {
            Expr::Lit(lit) => {
                if let syn::Lit::Int(int_lit) = &lit.lit {
                    int_lit.base10_parse::<u64>().map_or(false, |v| v == 0)
                } else {
                    false
                }
            }
            Expr::Paren(p) => Self::is_zero_literal(&p.expr),
            _ => false,
        }
    }

    /// Check whether the expression is inside a checked_* or saturating_* call.
    fn is_likely_checked_context(expr: &Expr) -> bool {
        let s = quote::quote!(#expr).to_string();
        s.contains("checked_") || s.contains("saturating_") || s.contains("overflowing_")
    }
}

impl<'ast> Visit<'ast> for ArithmeticVisitor {
    fn visit_expr_binary(&mut self, i: &'ast syn::ExprBinary) {
        let line = i.op.span().start().line;

        match i.op {
            // ── Division before multiplication: (a / b) * c ──────────
            BinOp::Mul(_) => {
                if Self::is_div_op(&i.left) {
                    self.issues.push(ArithmeticIssue {
                        kind: ArithmeticIssueKind::DivisionBeforeMultiplication,
                        line,
                        snippet: "Division before multiplication detected".into(),
                        recommendation: "Reorder to multiply first: (a * c) / b. This \
                            preserves maximum precision by avoiding premature truncation."
                            .into(),
                    });
                }
            }

            // ── Unchecked addition (potential overflow) ──────────────
            BinOp::Add(_) => {
                if !Self::is_likely_checked_context(&Expr::Binary(i.clone())) {
                    self.issues.push(ArithmeticIssue {
                        kind: ArithmeticIssueKind::UncheckedArithmetic,
                        line,
                        snippet: "Unchecked addition (+) operator".into(),
                        recommendation: "Use .checked_add() to detect overflow, or \
                            .saturating_add() if clamping is acceptable."
                            .into(),
                    });
                }
            }

            // ── Unchecked subtraction (potential underflow) ──────────
            BinOp::Sub(_) => {
                if !Self::is_likely_checked_context(&Expr::Binary(i.clone())) {
                    self.issues.push(ArithmeticIssue {
                        kind: ArithmeticIssueKind::UncheckedArithmetic,
                        line,
                        snippet: "Unchecked subtraction (-) operator".into(),
                        recommendation: "Use .checked_sub() to detect underflow. For unsigned \
                            types, a - b panics or wraps if b > a."
                            .into(),
                    });
                }
            }

            // ── Division: precision loss + possible div-by-zero ─────
            BinOp::Div(_) => {
                self.issues.push(ArithmeticIssue {
                    kind: ArithmeticIssueKind::PotentialPrecisionLoss,
                    line,
                    snippet: "Division operator used".into(),
                    recommendation: "Ensure the denominator cannot be zero. Use \
                        .checked_div() and verify the result is non-zero after division."
                        .into(),
                });
                // Explicit zero divisor check
                if Self::is_zero_literal(&i.right) {
                    self.issues.push(ArithmeticIssue {
                        kind: ArithmeticIssueKind::PotentialDivisionByZero,
                        line,
                        snippet: "Division by literal zero".into(),
                        recommendation: "This will always panic. Remove or guard with a \
                            conditional check."
                            .into(),
                    });
                }
            }

            // ── Modulo: div-by-zero risk ─────────────────────────────
            BinOp::Rem(_) => {
                if Self::is_zero_literal(&i.right) {
                    self.issues.push(ArithmeticIssue {
                        kind: ArithmeticIssueKind::ModuloByZero,
                        line,
                        snippet: "Modulo by literal zero".into(),
                        recommendation: "This will always panic. Use checked_rem() or \
                            validate the divisor."
                            .into(),
                    });
                }
            }

            // ── Shift: overflow if shift amount >= bit width ─────────
            BinOp::Shl(_) | BinOp::Shr(_) => {
                self.issues.push(ArithmeticIssue {
                    kind: ArithmeticIssueKind::ShiftOverflow,
                    line,
                    snippet: "Shift operator used".into(),
                    recommendation: "Ensure shift amount is < bit width (e.g., < 64 for u64). \
                        Use .checked_shl() / .checked_shr() to avoid panics on over-shift."
                        .into(),
                });
            }

            _ => {}
        }

        visit::visit_expr_binary(self, i);
    }

    fn visit_expr_cast(&mut self, i: &'ast syn::ExprCast) {
        let line = i.as_token.span().start().line;
        let type_name = quote::quote!(#i.ty).to_string();

        // Check for potentially lossy casts: wider → narrower
        let narrowing_targets = ["u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "usize"];
        if narrowing_targets.iter().any(|t| type_name.contains(t)) {
            self.issues.push(ArithmeticIssue {
                kind: ArithmeticIssueKind::IntegerCastingRisk,
                line,
                snippet: format!("Cast to {}", type_name),
                recommendation: "Use .try_into().map_err(|_| Error::CastOverflow)? instead \
                    of 'as' for potentially lossy type conversions. The 'as' keyword silently \
                    truncates, which can lead to critical balance/price errors."
                    .into(),
            });
        }
        visit::visit_expr_cast(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_div_before_mul_detection() {
        let source = r#"
            pub fn calculate_yield(amount: u64, rate: u64, precision: u64) -> u64 {
                let result = (amount / precision) * rate;
                result
            }
        "#;
        let issues = ArithmeticSecurityExpert::analyze_source(source).unwrap();
        assert!(issues
            .iter()
            .any(|i| i.kind == ArithmeticIssueKind::DivisionBeforeMultiplication));
    }

    #[test]
    fn test_unchecked_addition_detection() {
        let source = r#"
            pub fn deposit(vault: &mut Vault, amount: u64) {
                vault.total = vault.total + amount;
            }
        "#;
        let issues = ArithmeticSecurityExpert::analyze_source(source).unwrap();
        assert!(issues
            .iter()
            .any(|i| i.kind == ArithmeticIssueKind::UncheckedArithmetic));
    }

    #[test]
    fn test_unchecked_subtraction_detection() {
        let source = r#"
            pub fn withdraw(vault: &mut Vault, amount: u64) {
                vault.total = vault.total - amount;
            }
        "#;
        let issues = ArithmeticSecurityExpert::analyze_source(source).unwrap();
        assert!(
            issues
                .iter()
                .any(|i| i.kind == ArithmeticIssueKind::UncheckedArithmetic),
            "Should detect unchecked subtraction"
        );
    }

    #[test]
    fn test_division_precision_loss() {
        let source = r#"
            pub fn calc(a: u64, b: u64) -> u64 {
                a / b
            }
        "#;
        let issues = ArithmeticSecurityExpert::analyze_source(source).unwrap();
        assert!(issues
            .iter()
            .any(|i| i.kind == ArithmeticIssueKind::PotentialPrecisionLoss));
    }

    #[test]
    fn test_lossy_cast_detection() {
        let source = r#"
            pub fn process(val: u128) -> u64 {
                let x = val as u64;
                x
            }
        "#;
        let issues = ArithmeticSecurityExpert::analyze_source(source).unwrap();
        assert!(issues
            .iter()
            .any(|i| i.kind == ArithmeticIssueKind::IntegerCastingRisk));
    }

    #[test]
    fn test_shift_overflow_detection() {
        let source = r#"
            pub fn scale(val: u64, shift: u32) -> u64 {
                val << shift
            }
        "#;
        let issues = ArithmeticSecurityExpert::analyze_source(source).unwrap();
        assert!(issues
            .iter()
            .any(|i| i.kind == ArithmeticIssueKind::ShiftOverflow));
    }

    #[test]
    fn test_severity_ordering() {
        let source = r#"
            pub fn complex(a: u64, b: u64, c: u128) -> u64 {
                let x = (a / b) * c as u64;
                x + a
            }
        "#;
        let issues = ArithmeticSecurityExpert::analyze_source(source).unwrap();
        // Verify issues are sorted by severity descending
        for window in issues.windows(2) {
            assert!(window[0].kind.severity() >= window[1].kind.severity());
        }
    }

    #[test]
    fn test_analyze_critical_filters() {
        let source = r#"
            pub fn calc(a: u64, b: u64) -> u64 {
                a + b
            }
        "#;
        let critical = ArithmeticSecurityExpert::analyze_critical(source).unwrap();
        for issue in &critical {
            assert!(issue.kind.severity() >= 7);
        }
    }

    #[test]
    fn test_insight_database() {
        let insight = ArithmeticSecurityExpert::get_insight_for_id("2.1").unwrap();
        assert_eq!(insight.name, "Integer Overflow/Underflow");
        assert!(!insight.attack_vectors.is_empty());

        let insight2 = ArithmeticSecurityExpert::get_insight_for_id("SOL-002").unwrap();
        assert_eq!(insight.name, insight2.name);
    }

    #[test]
    fn test_insight_for_unknown_returns_none() {
        assert!(ArithmeticSecurityExpert::get_insight_for_id("99").is_none());
    }
}
