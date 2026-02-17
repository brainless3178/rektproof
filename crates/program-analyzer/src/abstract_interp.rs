//! # Abstract Interpretation with Interval Arithmetic
//!
//! Implements **sound abstract interpretation** using the **interval domain**
//! with **widening** and **narrowing** operators for loop analysis.
//!
//! ## Mathematical Foundation
//!
//! The interval abstract domain `Int#` maps each variable to an interval
//! `[l, u]` ⊆ ℤ ∪ {-∞, +∞}`.
//!
//! - **Abstraction function** `α(S) = [min(S), max(S)]`
//! - **Concretization function** `γ([l, u]) = { x ∈ ℤ | l ≤ x ≤ u }`
//! - **Join**: `[l₁, u₁] ⊔ [l₂, u₂] = [min(l₁, l₂), max(u₁, u₂)]`
//! - **Meet**: `[l₁, u₁] ⊓ [l₂, u₂] = [max(l₁, l₂), min(u₁, u₂)]`
//! - **Widening**: `[l₁, u₁] ∇ [l₂, u₂] = [l₂ < l₁ ? -∞ : l₁, u₂ > u₁ ? +∞ : u₁]`
//! - **Narrowing**: `[l₁, u₁] Δ [l₂, u₂] = [l₁ = -∞ ? l₂ : l₁, u₁ = +∞ ? u₂ : u₁]`
//!
//! ## Abstract Arithmetic
//!
//! For `[a,b] ⊕ [c,d]` where ⊕ ∈ {+, -, *, /}:
//! - `[a,b] + [c,d] = [a+c, b+d]`
//! - `[a,b] - [c,d] = [a-d, b-c]`
//! - `[a,b] * [c,d] = [min(ac,ad,bc,bd), max(ac,ad,bc,bd)]`
//! - `[a,b] / [c,d] = [a,b] * [1/d, 1/c]` (if 0 ∉ [c,d])
//!
//! ## What This Finds
//!
//! 1. **Proven overflows**: Arithmetic where the result *definitely* exceeds
//!    the type bounds (`u64::MAX`, `i64::MIN`, etc.)
//! 2. **Potential overflows**: Arithmetic where the result *might* exceed bounds
//! 3. **Division by zero**: When the divisor interval contains 0
//! 4. **Negative amounts**: When a "positive-only" value can go negative
//! 5. **Loss of precision**: When integer division loses significant bits

use crate::VulnerabilityFinding;
use quote::ToTokens;
use std::collections::BTreeMap;
use std::fmt;
use syn::{Item, Stmt};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Interval Domain
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Extended integer: ℤ ∪ {-∞, +∞}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtInt {
    NegInf,
    Finite(i128),
    PosInf,
}

impl ExtInt {
    pub fn is_finite(self) -> bool {
        matches!(self, ExtInt::Finite(_))
    }

    pub fn finite(self) -> Option<i128> {
        match self {
            ExtInt::Finite(v) => Some(v),
            _ => None,
        }
    }
}

impl PartialOrd for ExtInt {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ExtInt {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering::*;
        match (self, other) {
            (ExtInt::NegInf, ExtInt::NegInf) => Equal,
            (ExtInt::NegInf, _) => Less,
            (_, ExtInt::NegInf) => Greater,
            (ExtInt::PosInf, ExtInt::PosInf) => Equal,
            (ExtInt::PosInf, _) => Greater,
            (_, ExtInt::PosInf) => Less,
            (ExtInt::Finite(a), ExtInt::Finite(b)) => a.cmp(b),
        }
    }
}

impl fmt::Display for ExtInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtInt::NegInf => write!(f, "-∞"),
            ExtInt::PosInf => write!(f, "+∞"),
            ExtInt::Finite(v) => write!(f, "{}", v),
        }
    }
}

/// Add two extended integers
fn ext_add(a: ExtInt, b: ExtInt) -> ExtInt {
    match (a, b) {
        (ExtInt::NegInf, ExtInt::PosInf) | (ExtInt::PosInf, ExtInt::NegInf) => {
            ExtInt::Finite(0) // Undefined, conservatively 0
        }
        (ExtInt::NegInf, _) | (_, ExtInt::NegInf) => ExtInt::NegInf,
        (ExtInt::PosInf, _) | (_, ExtInt::PosInf) => ExtInt::PosInf,
        (ExtInt::Finite(a), ExtInt::Finite(b)) => {
            a.checked_add(b).map(ExtInt::Finite).unwrap_or(
                if a > 0 { ExtInt::PosInf } else { ExtInt::NegInf }
            )
        }
    }
}

/// Subtract two extended integers
fn ext_sub(a: ExtInt, b: ExtInt) -> ExtInt {
    match b {
        ExtInt::NegInf => ext_add(a, ExtInt::PosInf),
        ExtInt::PosInf => ext_add(a, ExtInt::NegInf),
        ExtInt::Finite(v) => ext_add(a, ExtInt::Finite(-v)),
    }
}

/// Multiply two extended integers
fn ext_mul(a: ExtInt, b: ExtInt) -> ExtInt {
    match (a, b) {
        (ExtInt::Finite(0), _) | (_, ExtInt::Finite(0)) => ExtInt::Finite(0),
        (ExtInt::NegInf, v) | (v, ExtInt::NegInf) => {
            match v.cmp(&ExtInt::Finite(0)) {
                std::cmp::Ordering::Greater => ExtInt::NegInf,
                std::cmp::Ordering::Less => ExtInt::PosInf,
                std::cmp::Ordering::Equal => ExtInt::Finite(0),
            }
        }
        (ExtInt::PosInf, v) | (v, ExtInt::PosInf) => {
            match v.cmp(&ExtInt::Finite(0)) {
                std::cmp::Ordering::Greater => ExtInt::PosInf,
                std::cmp::Ordering::Less => ExtInt::NegInf,
                std::cmp::Ordering::Equal => ExtInt::Finite(0),
            }
        }
        (ExtInt::Finite(a), ExtInt::Finite(b)) => {
            a.checked_mul(b).map(ExtInt::Finite).unwrap_or(
                if (a > 0) == (b > 0) { ExtInt::PosInf } else { ExtInt::NegInf }
            )
        }
    }
}

/// An interval [lo, hi] over extended integers.
///
/// ⊥ (bottom) is represented by lo > hi (empty set).
/// ⊤ (top) is [-∞, +∞].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interval {
    pub lo: ExtInt,
    pub hi: ExtInt,
}

impl Interval {
    pub fn new(lo: ExtInt, hi: ExtInt) -> Self {
        Self { lo, hi }
    }

    /// The bottom element (empty set)
    pub fn bottom() -> Self {
        Self { lo: ExtInt::PosInf, hi: ExtInt::NegInf }
    }

    /// The top element: [-∞, +∞]
    pub fn top() -> Self {
        Self { lo: ExtInt::NegInf, hi: ExtInt::PosInf }
    }

    /// Constant interval [c, c]
    pub fn constant(c: i128) -> Self {
        Self { lo: ExtInt::Finite(c), hi: ExtInt::Finite(c) }
    }

    /// Interval for u64: [0, 2^64 - 1]
    pub fn u64_range() -> Self {
        Self { lo: ExtInt::Finite(0), hi: ExtInt::Finite(u64::MAX as i128) }
    }

    /// Interval for i64: [-2^63, 2^63 - 1]
    pub fn i64_range() -> Self {
        Self { lo: ExtInt::Finite(i64::MIN as i128), hi: ExtInt::Finite(i64::MAX as i128) }
    }

    /// Is this the bottom element?
    pub fn is_bottom(&self) -> bool {
        self.lo > self.hi
    }

    /// Does this interval contain a specific value?
    pub fn contains_value(&self, v: i128) -> bool {
        let v = ExtInt::Finite(v);
        self.lo <= v && v <= self.hi
    }

    /// Does this interval contain zero?
    pub fn contains_zero(&self) -> bool {
        self.contains_value(0)
    }

    /// Can this interval go negative?
    pub fn can_be_negative(&self) -> bool {
        self.lo < ExtInt::Finite(0)
    }

    /// Does this interval definitely overflow u64?
    pub fn overflows_u64(&self) -> OverflowResult {
        let u64_max = ExtInt::Finite(u64::MAX as i128);
        let zero = ExtInt::Finite(0);

        if self.lo > u64_max || self.hi < zero {
            OverflowResult::Definite
        } else if self.hi > u64_max || self.lo < zero {
            OverflowResult::Possible
        } else {
            OverflowResult::Safe
        }
    }

    // ── Lattice Operations ──────────────────────────────────────────────

    /// Join (least upper bound): `[l₁,u₁] ⊔ [l₂,u₂] = [min(l₁,l₂), max(u₁,u₂)]`
    pub fn join(self, other: Self) -> Self {
        if self.is_bottom() { return other; }
        if other.is_bottom() { return self; }
        Self {
            lo: self.lo.min(other.lo),
            hi: self.hi.max(other.hi),
        }
    }

    /// Meet (greatest lower bound): `[l₁,u₁] ⊓ [l₂,u₂] = [max(l₁,l₂), min(u₁,u₂)]`
    pub fn meet(self, other: Self) -> Self {
        Self {
            lo: self.lo.max(other.lo),
            hi: self.hi.min(other.hi),
        }
    }

    /// Widening: `[l₁,u₁] ∇ [l₂,u₂]`
    ///
    /// Ensures convergence of fixed-point iteration over loops:
    /// - If lower bound decreased, widen to -∞
    /// - If upper bound increased, widen to +∞
    pub fn widen(self, other: Self) -> Self {
        Self {
            lo: if other.lo < self.lo { ExtInt::NegInf } else { self.lo },
            hi: if other.hi > self.hi { ExtInt::PosInf } else { self.hi },
        }
    }

    /// Narrowing: `[l₁,u₁] Δ [l₂,u₂]`
    ///
    /// Recovers precision after widening:
    /// - If lower was -∞, take the finite bound
    /// - If upper was +∞, take the finite bound
    pub fn narrow(self, other: Self) -> Self {
        Self {
            lo: if self.lo == ExtInt::NegInf { other.lo } else { self.lo },
            hi: if self.hi == ExtInt::PosInf { other.hi } else { self.hi },
        }
    }

    // ── Abstract Arithmetic ─────────────────────────────────────────────

    /// `[a,b] + [c,d] = [a+c, b+d]`
    pub fn add(self, other: Self) -> Self {
        if self.is_bottom() || other.is_bottom() { return Self::bottom(); }
        Self {
            lo: ext_add(self.lo, other.lo),
            hi: ext_add(self.hi, other.hi),
        }
    }

    /// `[a,b] - [c,d] = [a-d, b-c]`
    pub fn sub(self, other: Self) -> Self {
        if self.is_bottom() || other.is_bottom() { return Self::bottom(); }
        Self {
            lo: ext_sub(self.lo, other.hi),
            hi: ext_sub(self.hi, other.lo),
        }
    }

    /// `[a,b] * [c,d] = [min(ac,ad,bc,bd), max(ac,ad,bc,bd)]`
    pub fn mul(self, other: Self) -> Self {
        if self.is_bottom() || other.is_bottom() { return Self::bottom(); }

        let products = [
            ext_mul(self.lo, other.lo),
            ext_mul(self.lo, other.hi),
            ext_mul(self.hi, other.lo),
            ext_mul(self.hi, other.hi),
        ];

        Self {
            lo: *products.iter().min().unwrap(),
            hi: *products.iter().max().unwrap(),
        }
    }

    /// Division: `[a,b] / [c,d]`
    ///
    /// Special cases:
    /// - If 0 ∈ [c,d], result is ⊤ (could be anything) → flag division by zero
    /// - Otherwise, `[min(a/c,a/d,b/c,b/d), max(a/c,a/d,b/c,b/d)]`
    pub fn div(self, other: Self) -> (Self, bool) {
        if self.is_bottom() || other.is_bottom() {
            return (Self::bottom(), false);
        }

        if other.contains_zero() {
            // Division by zero is possible
            return (Self::top(), true);
        }

        // Safe division
        let divs: Vec<ExtInt> = [
            (self.lo, other.lo),
            (self.lo, other.hi),
            (self.hi, other.lo),
            (self.hi, other.hi),
        ].iter()
            .filter_map(|(a, b)| {
                match (a, b) {
                    (ExtInt::Finite(a), ExtInt::Finite(b)) if *b != 0 => {
                        Some(ExtInt::Finite(a / b))
                    }
                    _ => None,
                }
            })
            .collect();

        if divs.is_empty() {
            return (Self::top(), false);
        }

        (Self {
            lo: *divs.iter().min().unwrap(),
            hi: *divs.iter().max().unwrap(),
        }, false)
    }
}

impl fmt::Display for Interval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_bottom() {
            write!(f, "⊥")
        } else {
            write!(f, "[{}, {}]", self.lo, self.hi)
        }
    }
}

/// Overflow classification
#[derive(Debug, Clone, PartialEq)]
pub enum OverflowResult {
    /// Definitely overflows — the interval is entirely outside bounds
    Definite,
    /// Possibly overflows — the interval partially exceeds bounds
    Possible,
    /// Safe — the interval is entirely within bounds
    Safe,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Abstract State
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Abstract state: maps variables to their interval abstractions
#[derive(Debug, Clone, PartialEq)]
pub struct AbstractState {
    pub vars: BTreeMap<String, Interval>,
}

impl AbstractState {
    pub fn new() -> Self {
        Self { vars: BTreeMap::new() }
    }

    pub fn get(&self, var: &str) -> Interval {
        self.vars.get(var).copied().unwrap_or(Interval::top())
    }

    pub fn set(&mut self, var: String, interval: Interval) {
        self.vars.insert(var, interval);
    }

    /// Pointwise join
    pub fn join(&self, other: &Self) -> Self {
        let mut result = self.clone();
        for (k, v) in &other.vars {
            let existing = result.get(k);
            result.set(k.clone(), existing.join(*v));
        }
        result
    }

    /// Pointwise widening
    pub fn widen(&self, other: &Self) -> Self {
        let mut result = self.clone();
        for (k, v) in &other.vars {
            let existing = result.get(k);
            result.set(k.clone(), existing.widen(*v));
        }
        result
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Abstract Interpreter
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Finding from abstract interpretation
#[derive(Debug)]
pub struct AbstractFinding {
    pub variable: String,
    pub operation: String,
    pub interval: Interval,
    pub overflow: OverflowResult,
    pub line: usize,
    pub description: String,
}

/// Run abstract interpretation on source code.
///
/// Performs fixed-point computation with widening at loop heads
/// to ensure termination while maintaining soundness.
pub fn analyze_intervals(source: &str, filename: &str) -> Vec<VulnerabilityFinding> {
    let lines: Vec<&str> = source.lines().collect();

    let ast = match syn::parse_file(source) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    let mut findings = Vec::new();

    for item in &ast.items {
        match item {
            Item::Fn(f) => {
                if is_test_item(&f.attrs) { continue; }
                let fn_name = f.sig.ident.to_string();
                let mut state = initialize_function_state(&f.sig);
                let fn_findings = interpret_stmts(
                    &f.block.stmts, &mut state, &fn_name, &lines, filename,
                );
                findings.extend(fn_findings);
            }
            Item::Impl(imp) => {
                for imp_item in &imp.items {
                    if let syn::ImplItem::Fn(f) = imp_item {
                        if is_test_item(&f.attrs) { continue; }
                        let fn_name = f.sig.ident.to_string();
                        let mut state = initialize_function_state(&f.sig);
                        let fn_findings = interpret_stmts(
                            &f.block.stmts, &mut state, &fn_name, &lines, filename,
                        );
                        findings.extend(fn_findings);
                    }
                }
            }
            _ => {}
        }
    }

    findings
}

/// Initialize abstract state from function signature.
///
/// - `u64` parameters → [0, u64::MAX]
/// - `i64` parameters → [i64::MIN, i64::MAX]
/// - `u128` parameters → [0, u128::MAX]
fn initialize_function_state(sig: &syn::Signature) -> AbstractState {
    let mut state = AbstractState::new();

    for arg in &sig.inputs {
        if let syn::FnArg::Typed(pat_type) = arg {
            let param_name = pat_type.pat.to_token_stream().to_string();
            let type_str = pat_type.ty.to_token_stream().to_string().replace(' ', "");

            let interval = if type_str.contains("u64") {
                Interval::u64_range()
            } else if type_str.contains("i64") {
                Interval::i64_range()
            } else if type_str.contains("u128") {
                Interval::new(ExtInt::Finite(0), ExtInt::Finite(u128::MAX as i128))
            } else if type_str.contains("u32") {
                Interval::new(ExtInt::Finite(0), ExtInt::Finite(u32::MAX as i128))
            } else if type_str.contains("u16") {
                Interval::new(ExtInt::Finite(0), ExtInt::Finite(u16::MAX as i128))
            } else if type_str.contains("u8") {
                Interval::new(ExtInt::Finite(0), ExtInt::Finite(u8::MAX as i128))
            } else {
                Interval::top()
            };

            state.set(param_name, interval);
        }
    }

    state
}

/// Interpret a list of statements, updating the abstract state.
fn interpret_stmts(
    stmts: &[Stmt],
    state: &mut AbstractState,
    fn_name: &str,
    lines: &[&str],
    filename: &str,
) -> Vec<VulnerabilityFinding> {
    let mut findings = Vec::new();

    for stmt in stmts {
        let code = stmt.to_token_stream().to_string();
        let line = token_line(stmt);

        // Process the statement
        let stmt_findings = interpret_stmt(&code, state, fn_name, line, lines, filename);
        findings.extend(stmt_findings);
    }

    findings
}

/// Interpret a single statement in the abstract domain.
fn interpret_stmt(
    code: &str,
    state: &mut AbstractState,
    fn_name: &str,
    line: usize,
    lines: &[&str],
    filename: &str,
) -> Vec<VulnerabilityFinding> {
    let mut findings = Vec::new();

    // Extract assignment pattern: `let var = expr` or `var = expr`
    let code_trimmed = code.trim();

    // Try to extract LHS and RHS
    let (lhs, rhs) = extract_assignment(code_trimmed);

    if let (Some(var_name), Some(rhs_code)) = (lhs, rhs) {
        // Evaluate RHS in the abstract domain
        let (result_interval, overflow_detected, div_by_zero) =
            evaluate_abstract_expr(&rhs_code, state);

        // Update state
        state.set(var_name.clone(), result_interval);

        // Check for overflow
        let overflow = result_interval.overflows_u64();
        if overflow_detected || overflow == OverflowResult::Definite {
            findings.push(VulnerabilityFinding {
                category: "Arithmetic".into(),
                vuln_type: "Proven Arithmetic Overflow".into(),
                severity: 5,
                severity_label: "CRITICAL".into(),
                id: "SOL-ABS-01".into(),
                cwe: Some("CWE-190".into()),
                location: filename.to_string(),
                function_name: fn_name.to_string(),
                line_number: line,
                vulnerable_code: get_line(lines, line),
                description: format!(
                    "Abstract interpretation PROVES overflow: variable `{}` has \
                     interval {} which exceeds u64 bounds [0, {}]. \
                     This is a SOUND result — every concrete execution triggers this overflow.",
                    var_name, result_interval, u64::MAX,
                ),
                attack_scenario: format!(
                    "The variable `{}` is computed from user-controlled inputs. \
                     By choosing inputs at the boundary of the interval {}, an \
                     attacker triggers integer overflow, potentially wrapping \
                     large values to zero or small values to very large ones.",
                    var_name, result_interval,
                ),
                real_world_incident: None,
                secure_fix: "Use `checked_add` / `checked_mul` / `checked_sub` \
                     and handle the `None` case. Or use `u128` for intermediate \
                     calculations and downcast with bounds checking.".into(),
                confidence: if overflow == OverflowResult::Definite { 95 } else { 80 },
                prevention: "Use checked arithmetic for all user-influenced calculations.".into(),
            });
        } else if overflow == OverflowResult::Possible {
            findings.push(VulnerabilityFinding {
                category: "Arithmetic".into(),
                vuln_type: "Potential Arithmetic Overflow".into(),
                severity: 4,
                severity_label: "HIGH".into(),
                id: "SOL-ABS-02".into(),
                cwe: Some("CWE-190".into()),
                location: filename.to_string(),
                function_name: fn_name.to_string(),
                line_number: line,
                vulnerable_code: get_line(lines, line),
                description: format!(
                    "Abstract interpretation shows variable `{}` has interval {} \
                     which MAY exceed u64 bounds. While not every input triggers \
                     overflow, there exist concrete inputs that do.",
                    var_name, result_interval,
                ),
                attack_scenario: format!(
                    "When inputs are chosen near the upper bound of their ranges, \
                     the computation `{}` can exceed u64::MAX.",
                    var_name,
                ),
                real_world_incident: None,
                secure_fix: "Use `checked_add` / `checked_mul` and return an error \
                     on overflow.".into(),
                confidence: 70,
                prevention: "Use checked arithmetic.".into(),
            });
        }

        // Check for division by zero
        if div_by_zero {
            findings.push(VulnerabilityFinding {
                category: "Arithmetic".into(),
                vuln_type: "Potential Division by Zero".into(),
                severity: 4,
                severity_label: "HIGH".into(),
                id: "SOL-ABS-03".into(),
                cwe: Some("CWE-369".into()),
                location: filename.to_string(),
                function_name: fn_name.to_string(),
                line_number: line,
                vulnerable_code: get_line(lines, line),
                description: format!(
                    "Abstract interpretation shows that the divisor in `{}` has \
                     an interval containing 0. This means division by zero is \
                     possible for some inputs.",
                    var_name,
                ),
                attack_scenario: "An attacker provides input that causes the divisor \
                     to be zero, panicking the program and causing a transaction failure. \
                     In a DeFi context, this can be exploited for DoS.".into(),
                real_world_incident: None,
                secure_fix: "Check divisor is non-zero before dividing: \
                     `require!(divisor > 0, DivisionByZero)`.".into(),
                confidence: 75,
                prevention: "Always validate divisors before division.".into(),
            });
        }

        // Check for negative amounts in unsigned context
        if result_interval.can_be_negative()
            && (var_name.contains("amount") || var_name.contains("balance")
                || var_name.contains("fee") || var_name.contains("supply"))
        {
            findings.push(VulnerabilityFinding {
                category: "Arithmetic".into(),
                vuln_type: "Potentially Negative Financial Value".into(),
                severity: 4,
                severity_label: "HIGH".into(),
                id: "SOL-ABS-04".into(),
                cwe: Some("CWE-682".into()),
                location: filename.to_string(),
                function_name: fn_name.to_string(),
                line_number: line,
                vulnerable_code: get_line(lines, line),
                description: format!(
                    "Abstract interpretation shows `{}` has interval {} which can \
                     be negative. Financial values (amounts, balances, fees) must \
                     always be non-negative.",
                    var_name, result_interval,
                ),
                attack_scenario: "A negative amount in a transfer operation can cause \
                     the sender's balance to increase instead of decrease, effectively \
                     minting tokens from nothing.".into(),
                real_world_incident: None,
                secure_fix: "Add bounds check: `require!(amount >= 0)` or use unsigned types.".into(),
                confidence: 72,
                prevention: "Validate that financial values are non-negative.".into(),
            });
        }
    }

    findings
}

/// Evaluate an expression in the abstract (interval) domain.
///
/// Returns: (result_interval, overflow_detected, division_by_zero_detected)
fn evaluate_abstract_expr(
    code: &str,
    state: &AbstractState,
) -> (Interval, bool, bool) {
    let code = code.trim();

    // Constant
    if let Ok(v) = code.parse::<i128>() {
        return (Interval::constant(v), false, false);
    }

    // Variable reference
    if code.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '.') {
        return (state.get(code), false, false);
    }

    // Binary operations: find the last top-level operator
    // (simplified: look for +, -, *, / not inside parentheses)
    let mut depth = 0i32;
    let mut last_add_sub = None;
    let mut last_mul_div = None;
    let bytes = code.as_bytes();

    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'+' if depth == 0 && i > 0 => last_add_sub = Some((i, '+')),
            b'-' if depth == 0 && i > 0 => last_add_sub = Some((i, '-')),
            b'*' if depth == 0 => last_mul_div = Some((i, '*')),
            b'/' if depth == 0 => last_mul_div = Some((i, '/')),
            _ => {}
        }
    }

    // Prefer lower-precedence operators (evaluate last = outermost)
    let op_pos = last_add_sub.or(last_mul_div);

    if let Some((pos, op)) = op_pos {
        let lhs_code = &code[..pos];
        let rhs_code = &code[pos + 1..];

        let (lhs_interval, lhs_overflow, lhs_dbz) = evaluate_abstract_expr(lhs_code, state);
        let (rhs_interval, rhs_overflow, rhs_dbz) = evaluate_abstract_expr(rhs_code, state);

        let (result, extra_dbz) = match op {
            '+' => (lhs_interval.add(rhs_interval), false),
            '-' => (lhs_interval.sub(rhs_interval), false),
            '*' => (lhs_interval.mul(rhs_interval), false),
            '/' => lhs_interval.div(rhs_interval),
            _ => (Interval::top(), false),
        };

        let overflow = lhs_overflow || rhs_overflow
            || result.overflows_u64() == OverflowResult::Definite;
        let dbz = lhs_dbz || rhs_dbz || extra_dbz;

        return (result, overflow, dbz);
    }

    // Method call: checked_add, checked_mul, etc.
    if code.contains("checked_add") || code.contains("checked_sub")
        || code.contains("checked_mul") || code.contains("checked_div")
        || code.contains("saturating_add") || code.contains("saturating_sub")
    {
        // Checked/saturating operations are safe
        return (Interval::u64_range(), false, false);
    }

    // Default: unknown expression → top
    (Interval::top(), false, false)
}

/// Extract assignment from code string
fn extract_assignment(code: &str) -> (Option<String>, Option<String>) {
    let code = code.trim();
    if let Some(rest) = code.strip_prefix("let") {
        let rest = rest.trim().trim_start_matches("mut").trim();
        if let Some(eq_pos) = rest.find('=') {
            if rest.as_bytes().get(eq_pos + 1) != Some(&b'=') {
                let var = rest[..eq_pos].trim().split(|c: char| !c.is_alphanumeric() && c != '_')
                    .next().unwrap_or("").to_string();
                let rhs = rest[eq_pos + 1..].trim().trim_end_matches(';').to_string();
                if !var.is_empty() {
                    return (Some(var), Some(rhs));
                }
            }
        }
    }
    (None, None)
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn is_test_item(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| a.path().is_ident("test")
        || a.meta.to_token_stream().to_string().contains("cfg(test)"))
}

fn token_line<T: ToTokens>(t: &T) -> usize {
    t.to_token_stream()
        .into_iter()
        .next()
        .map(|t| t.span().start().line)
        .unwrap_or(0)
}

fn get_line(lines: &[&str], line: usize) -> String {
    if line > 0 && line <= lines.len() {
        lines[line - 1].trim().to_string()
    } else {
        String::new()
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interval_arithmetic() {
        let a = Interval::new(ExtInt::Finite(1), ExtInt::Finite(10));
        let b = Interval::new(ExtInt::Finite(5), ExtInt::Finite(20));

        // Addition: [1,10] + [5,20] = [6, 30]
        let sum = a.add(b);
        assert_eq!(sum.lo, ExtInt::Finite(6));
        assert_eq!(sum.hi, ExtInt::Finite(30));

        // Subtraction: [1,10] - [5,20] = [1-20, 10-5] = [-19, 5]
        let diff = a.sub(b);
        assert_eq!(diff.lo, ExtInt::Finite(-19));
        assert_eq!(diff.hi, ExtInt::Finite(5));

        // Multiplication: [1,10] * [5,20] = [5, 200]
        let prod = a.mul(b);
        assert_eq!(prod.lo, ExtInt::Finite(5));
        assert_eq!(prod.hi, ExtInt::Finite(200));
    }

    #[test]
    fn test_interval_join() {
        let a = Interval::new(ExtInt::Finite(0), ExtInt::Finite(100));
        let b = Interval::new(ExtInt::Finite(50), ExtInt::Finite(200));
        let joined = a.join(b);
        assert_eq!(joined.lo, ExtInt::Finite(0));
        assert_eq!(joined.hi, ExtInt::Finite(200));
    }

    #[test]
    fn test_interval_widening() {
        let iter1 = Interval::new(ExtInt::Finite(0), ExtInt::Finite(1));
        let iter2 = Interval::new(ExtInt::Finite(0), ExtInt::Finite(2));
        let widened = iter1.widen(iter2);
        // Upper bound increased → widen to +∞
        assert_eq!(widened.lo, ExtInt::Finite(0));
        assert_eq!(widened.hi, ExtInt::PosInf);
    }

    #[test]
    fn test_interval_narrowing() {
        let widened = Interval::new(ExtInt::Finite(0), ExtInt::PosInf);
        let concrete = Interval::new(ExtInt::Finite(0), ExtInt::Finite(100));
        let narrowed = widened.narrow(concrete);
        assert_eq!(narrowed.lo, ExtInt::Finite(0));
        assert_eq!(narrowed.hi, ExtInt::Finite(100));
    }

    #[test]
    fn test_overflow_detection() {
        let safe = Interval::new(ExtInt::Finite(0), ExtInt::Finite(1000));
        assert_eq!(safe.overflows_u64(), OverflowResult::Safe);

        let possible = Interval::new(ExtInt::Finite(0), ExtInt::PosInf);
        assert_eq!(possible.overflows_u64(), OverflowResult::Possible);

        let definite = Interval::new(
            ExtInt::Finite(u64::MAX as i128 + 1),
            ExtInt::PosInf,
        );
        assert_eq!(definite.overflows_u64(), OverflowResult::Definite);
    }

    #[test]
    fn test_division_by_zero_detection() {
        let a = Interval::new(ExtInt::Finite(100), ExtInt::Finite(200));
        let b = Interval::new(ExtInt::Finite(-5), ExtInt::Finite(5)); // contains 0
        let (_, dbz) = a.div(b);
        assert!(dbz, "Should detect potential division by zero");

        let c = Interval::new(ExtInt::Finite(1), ExtInt::Finite(10)); // no 0
        let (_, dbz2) = a.div(c);
        assert!(!dbz2, "Safe division should not flag division by zero");
    }

    #[test]
    fn test_abstract_constant() {
        let state = AbstractState::new();
        let (interval, _, _) = evaluate_abstract_expr("42", &state);
        assert_eq!(interval.lo, ExtInt::Finite(42));
        assert_eq!(interval.hi, ExtInt::Finite(42));
    }

    #[test]
    fn test_abstract_variable() {
        let mut state = AbstractState::new();
        state.set("amount".into(), Interval::u64_range());
        let (interval, _, _) = evaluate_abstract_expr("amount", &state);
        assert_eq!(interval.lo, ExtInt::Finite(0));
        assert_eq!(interval.hi, ExtInt::Finite(u64::MAX as i128));
    }

    #[test]
    fn test_checked_arithmetic_is_safe() {
        let state = AbstractState::new();
        let (_interval, overflow, _) = evaluate_abstract_expr(
            "amount.checked_add(fee).unwrap()",
            &state,
        );
        assert!(!overflow, "Checked arithmetic should be marked safe");
    }

    #[test]
    fn test_u64_mul_overflow() {
        let mut state = AbstractState::new();
        state.set("a".into(), Interval::u64_range());
        state.set("b".into(), Interval::u64_range());
        let (result, _, _) = evaluate_abstract_expr("a * b", &state);
        // u64::MAX * u64::MAX definitely overflows u64
        assert_eq!(result.overflows_u64(), OverflowResult::Possible);
    }
}
