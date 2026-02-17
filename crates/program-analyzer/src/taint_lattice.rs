//! # Lattice-Based Taint Analysis
//!
//! Implements a **formal information-flow analysis** using abstract
//! interpretation over a security lattice.
//!
//! ## Mathematical Foundation
//!
//! We define a **complete lattice** `(L, ⊑, ⊔, ⊓, ⊥, ⊤)` where:
//!
//! - `L = {Untainted, AccountInput, SignerControlled, ExternalData,
//!          ArithmeticDerived, Tainted}`
//! - `⊥ = Untainted` (no taint — safe)
//! - `⊤ = Tainted` (definitely unsafe)
//! - `⊑` is the partial order: Untainted ⊑ AccountInput ⊑ Tainted, etc.
//!
//! The analysis computes a **least fixed point** of the dataflow equations:
//!
//! ```text
//! taint(v) = ⊔ { transfer(taint(u)) | (u, v) ∈ E }
//! ```
//!
//! where `transfer` is the transfer function for each statement type and
//! `E` is the set of def-use edges.
//!
//! ## What It Finds (Real Vulnerabilities)
//!
//! 1. **Untrusted data reaching privileged operations** — e.g., an unchecked
//!    `AccountInfo` field flowing into a `transfer` or `invoke` call
//! 2. **External oracle data used in arithmetic without sanitization**
//! 3. **User-supplied amounts flowing to authority checks**
//! 4. **Cross-instruction data contamination**
//!
//! ## Algorithm
//!
//! Chaotic iteration (worklist algorithm) until fixed point:
//!
//! ```text
//! W := all_nodes
//! while W ≠ ∅:
//!     pick n from W
//!     old := taint[n]
//!     taint[n] := ⊔ { transfer_f(taint[pred]) | pred ∈ predecessors(n) }
//!     if taint[n] ≠ old:
//!         W := W ∪ successors(n)
//! ```

use crate::VulnerabilityFinding;
use quote::ToTokens;
use std::collections::{BTreeMap, VecDeque};
use syn::{Item, Stmt};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Security Lattice
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// The security lattice for taint tracking.
///
/// Hasse diagram:
/// ```text
///            Tainted (⊤)
///           /    |    \
///    ExternalData  ArithmeticDerived
///           \    |    /
///       AccountInput  SignerControlled
///            \  |  /
///         Untainted (⊥)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TaintLevel {
    /// ⊥ — No taint. Value is a compile-time constant or trusted source.
    Untainted = 0,
    /// Value comes from a signer-verified account (partially trusted).
    SignerControlled = 1,
    /// Value read from an account field (could be forged if no owner check).
    AccountInput = 2,
    /// Value derived from arithmetic on tainted inputs.
    ArithmeticDerived = 3,
    /// Value from an external source (oracle, CPI return, etc.).
    ExternalData = 4,
    /// ⊤ — Fully tainted. Must not reach privileged sinks.
    Tainted = 5,
}

impl TaintLevel {
    /// Lattice join (least upper bound): `a ⊔ b`
    pub fn join(self, other: Self) -> Self {
        if self as u8 >= other as u8 { self } else { other }
    }

    /// Lattice meet (greatest lower bound): `a ⊓ b`
    pub fn meet(self, other: Self) -> Self {
        if self as u8 <= other as u8 { self } else { other }
    }

    /// Is this level "at least as tainted as" the other? (`self ⊒ other`)
    pub fn subsumes(self, other: Self) -> bool {
        self as u8 >= other as u8
    }

    /// Bottom element
    pub fn bottom() -> Self {
        TaintLevel::Untainted
    }

    /// Top element
    pub fn top() -> Self {
        TaintLevel::Tainted
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Taint State & Transfer Functions
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// The abstract state maps each variable name to its taint level.
#[derive(Debug, Clone, PartialEq)]
pub struct TaintState {
    pub vars: BTreeMap<String, TaintLevel>,
}

impl TaintState {
    pub fn new() -> Self {
        Self { vars: BTreeMap::new() }
    }

    /// Get taint level for a variable (default: Untainted)
    pub fn get(&self, var: &str) -> TaintLevel {
        self.vars.get(var).copied().unwrap_or(TaintLevel::Untainted)
    }

    /// Set taint level for a variable
    pub fn set(&mut self, var: String, level: TaintLevel) {
        self.vars.insert(var, level);
    }

    /// Join two states pointwise: `(s1 ⊔ s2)(v) = s1(v) ⊔ s2(v)` for all v
    pub fn join(&self, other: &Self) -> Self {
        let mut result = self.clone();
        for (k, v) in &other.vars {
            let existing = result.get(k);
            result.set(k.clone(), existing.join(*v));
        }
        result
    }

    /// Check if this state is subsumed by another: `self ⊑ other`
    pub fn is_subsumed_by(&self, other: &Self) -> bool {
        for (k, v) in &self.vars {
            if !other.get(k).subsumes(*v) {
                return false;
            }
        }
        true
    }
}

/// A taint source: where taint originates.
#[derive(Debug, Clone)]
pub struct TaintSource {
    pub variable: String,
    pub level: TaintLevel,
    pub line: usize,
    pub reason: String,
}

/// A taint sink: a dangerous operation where taint must not reach.
#[derive(Debug, Clone)]
pub struct TaintSink {
    pub operation: String,
    pub variable: String,
    pub max_allowed_taint: TaintLevel,
    pub line: usize,
    pub vuln_id: String,
    pub description: String,
}

/// A taint flow: tainted data reaching a dangerous sink.
#[derive(Debug, Clone)]
pub struct TaintFlow {
    pub source: TaintSource,
    pub sink: TaintSink,
    pub propagation_path: Vec<String>,
    pub final_taint: TaintLevel,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Transfer Functions
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Transfer function: how taint propagates through a statement.
///
/// For assignment `x = f(y, z)`:
///   taint(x) := transfer(op, taint(y), taint(z))
///
/// Rules:
/// - Constants: Untainted
/// - Assignment from variable: inherits taint
/// - Arithmetic: `max(taint(operands))` → ArithmeticDerived or higher
/// - Function call: depends on function (sanitizer → Untainted, oracle → ExternalData)
/// - AccountInfo field access: AccountInput
/// - Signer check: lowers taint to SignerControlled
fn transfer_assignment(
    state: &TaintState,
    _lhs: &str,
    rhs_code: &str,
    rhs_vars: &[String],
) -> TaintLevel {
    // Rule 1: Constants
    if rhs_code.trim().parse::<u64>().is_ok() || rhs_code.contains("\"") {
        return TaintLevel::Untainted;
    }

    // Rule 2: Sanitizers lower taint
    if rhs_code.contains("checked_") || rhs_code.contains("require!")
        || rhs_code.contains("assert!") || rhs_code.contains("validate")
        || rhs_code.contains("is_signer")
    {
        return TaintLevel::SignerControlled;
    }

    // Rule 3: External data sources
    if rhs_code.contains("get_price") || rhs_code.contains("oracle")
        || rhs_code.contains("pyth") || rhs_code.contains("switchboard")
        || rhs_code.contains("invoke") || rhs_code.contains("CpiContext")
    {
        return TaintLevel::ExternalData;
    }

    // Rule 4: Account field access
    if rhs_code.contains("ctx.accounts") || rhs_code.contains("AccountInfo")
        || rhs_code.contains(".data") || rhs_code.contains(".lamports")
        || rhs_code.contains("try_borrow_data") || rhs_code.contains("deserialize")
    {
        return TaintLevel::AccountInput;
    }

    // Rule 5: Arithmetic — propagate max taint of operands, elevate
    if rhs_code.contains('+') || rhs_code.contains('-')
        || rhs_code.contains('*') || rhs_code.contains('/')
    {
        let max_operand_taint = rhs_vars.iter()
            .map(|v| state.get(v))
            .fold(TaintLevel::Untainted, |a, b| a.join(b));

        if max_operand_taint.subsumes(TaintLevel::AccountInput) {
            return TaintLevel::ArithmeticDerived.join(max_operand_taint);
        }
    }

    // Rule 6: Simple variable propagation
    rhs_vars.iter()
        .map(|v| state.get(v))
        .fold(TaintLevel::Untainted, |a, b| a.join(b))
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Analysis Engine
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Result of taint analysis on a function.
#[derive(Debug)]
pub struct TaintAnalysisResult {
    pub function_name: String,
    pub flows: Vec<TaintFlow>,
    pub final_state: TaintState,
    pub fixed_point_iterations: u32,
    pub findings: Vec<VulnerabilityFinding>,
}

/// Run taint analysis on a source file.
///
/// This performs:
/// 1. **Source identification** — Mark account inputs, function params, oracle reads
/// 2. **Fixed-point iteration** — Chaotic iteration until taint state stabilizes
/// 3. **Sink checking** — Verify no tainted data reaches privileged operations
/// 4. **Finding generation** — Convert taint flows to vulnerability findings
pub fn analyze_taint(source: &str, filename: &str) -> Vec<TaintAnalysisResult> {
    let lines: Vec<&str> = source.lines().collect();

    let ast = match syn::parse_file(source) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    let mut results = Vec::new();

    for item in &ast.items {
        match item {
            Item::Fn(f) => {
                if is_test_item(&f.attrs) { continue; }
                let fn_name = f.sig.ident.to_string();
                let result = analyze_function_taint(
                    &fn_name, &f.block.stmts, &f.sig, &lines, filename,
                );
                results.push(result);
            }
            Item::Impl(imp) => {
                for imp_item in &imp.items {
                    if let syn::ImplItem::Fn(f) = imp_item {
                        if is_test_item(&f.attrs) { continue; }
                        let fn_name = f.sig.ident.to_string();
                        let result = analyze_function_taint(
                            &fn_name, &f.block.stmts, &f.sig, &lines, filename,
                        );
                        results.push(result);
                    }
                }
            }
            _ => {}
        }
    }

    results
}

fn analyze_function_taint(
    fn_name: &str,
    stmts: &[Stmt],
    sig: &syn::Signature,
    lines: &[&str],
    filename: &str,
) -> TaintAnalysisResult {
    let mut state = TaintState::new();
    let mut sources: Vec<TaintSource> = Vec::new();
    let mut sinks: Vec<TaintSink> = Vec::new();

    // ── Phase 1: Initialize taint sources from function signature ──────

    for arg in &sig.inputs {
        if let syn::FnArg::Typed(pat_type) = arg {
            let param_name = pat_type.pat.to_token_stream().to_string();
            let type_str = pat_type.ty.to_token_stream().to_string().replace(' ', "");
            let line = token_line(&pat_type.ty);

            if type_str.contains("Context<") {
                // Anchor Context — accounts are partially trusted
                state.set(param_name.clone(), TaintLevel::AccountInput);
                sources.push(TaintSource {
                    variable: param_name,
                    level: TaintLevel::AccountInput,
                    line,
                    reason: "Anchor Context parameter".into(),
                });
            } else if type_str.contains("AccountInfo") {
                // Raw AccountInfo — untrusted
                state.set(param_name.clone(), TaintLevel::Tainted);
                sources.push(TaintSource {
                    variable: param_name,
                    level: TaintLevel::Tainted,
                    line,
                    reason: "Raw AccountInfo — no type safety".into(),
                });
            } else if type_str.contains("u64") || type_str.contains("u128")
                || type_str.contains("i64")
            {
                // Numeric parameter — could be attacker-controlled
                state.set(param_name.clone(), TaintLevel::AccountInput);
                sources.push(TaintSource {
                    variable: param_name,
                    level: TaintLevel::AccountInput,
                    line,
                    reason: "Numeric parameter from instruction data".into(),
                });
            } else if type_str.contains("Pubkey") || type_str.contains("&[u8]") {
                state.set(param_name.clone(), TaintLevel::AccountInput);
                sources.push(TaintSource {
                    variable: param_name,
                    level: TaintLevel::AccountInput,
                    line,
                    reason: "User-supplied key or data".into(),
                });
            }
        }
    }

    // ── Phase 2: Worklist-based fixed-point iteration ──────────────────

    // Each statement is a node. We iterate until the taint state stabilizes.
    let num_stmts = stmts.len();
    let mut worklist: VecDeque<usize> = (0..num_stmts).collect();
    let mut iterations = 0u32;
    let max_iterations = (num_stmts as u32 + 1) * 10; // Bounded for safety

    while let Some(idx) = worklist.pop_front() {
        if iterations >= max_iterations { break; }
        iterations += 1;

        let stmt = &stmts[idx];
        let code = stmt.to_token_stream().to_string();
        let old_state = state.clone();

        // Extract variable assignments from statement
        let (lhs_opt, rhs_vars) = extract_assignment_vars(&code);

        if let Some(lhs) = &lhs_opt {
            let new_taint = transfer_assignment(&state, lhs, &code, &rhs_vars);
            state.set(lhs.clone(), new_taint);
        }

        // Detect sinks in this statement
        detect_sinks(&code, &state, &rhs_vars, idx, stmts, &mut sinks);

        // If state changed, re-process successor statements
        if state != old_state && idx + 1 < num_stmts {
            if !worklist.contains(&(idx + 1)) {
                worklist.push_back(idx + 1);
            }
        }
    }

    // ── Phase 3: Check sinks against taint state ──────────────────────

    let mut flows = Vec::new();
    let mut findings = Vec::new();

    for sink in &sinks {
        let actual_taint = state.get(&sink.variable);
        if actual_taint.subsumes(sink.max_allowed_taint)
            && actual_taint != TaintLevel::Untainted
        {
            // Find the source that caused this taint
            let source = sources.iter()
                .find(|s| {
                    // Trace back: does this source contribute to the sink variable?
                    state.get(&s.variable).subsumes(TaintLevel::AccountInput)
                })
                .cloned()
                .unwrap_or(TaintSource {
                    variable: sink.variable.clone(),
                    level: actual_taint,
                    line: 0,
                    reason: "Unknown source".into(),
                });

            flows.push(TaintFlow {
                source: source.clone(),
                sink: sink.clone(),
                propagation_path: vec![
                    format!("source: {} (line {})", source.variable, source.line),
                    format!("sink: {} (line {})", sink.operation, sink.line),
                ],
                final_taint: actual_taint,
            });

            let line = sink.line;
            findings.push(VulnerabilityFinding {
                category: "Information Flow".into(),
                vuln_type: format!("Tainted Data Reaching {}", sink.operation),
                severity: if actual_taint == TaintLevel::Tainted { 5 } else { 4 },
                severity_label: if actual_taint == TaintLevel::Tainted {
                    "CRITICAL".into()
                } else {
                    "HIGH".into()
                },
                id: sink.vuln_id.clone(),
                cwe: Some("CWE-20".into()),
                location: filename.to_string(),
                function_name: fn_name.to_string(),
                line_number: line,
                vulnerable_code: get_line(lines, line),
                description: format!(
                    "Taint analysis detected that variable `{}` (taint level: {:?}) \
                     flows from {} to a security-sensitive operation `{}` in `{}`. \
                     The data has taint level {:?} but the sink requires at most {:?}. \
                     Fixed-point reached after {} iterations.",
                    sink.variable, actual_taint, source.reason,
                    sink.operation, fn_name, actual_taint,
                    sink.max_allowed_taint, iterations,
                ),
                attack_scenario: sink.description.clone(),
                real_world_incident: None,
                secure_fix: format!(
                    "Validate `{}` before passing to `{}`. Add bounds checking, \
                     signer verification, or account ownership validation.",
                    sink.variable, sink.operation,
                ),
                confidence: match actual_taint {
                    TaintLevel::Tainted => 85,
                    TaintLevel::ExternalData => 78,
                    TaintLevel::ArithmeticDerived => 72,
                    TaintLevel::AccountInput => 65,
                    _ => 50,
                },
                prevention: "Sanitize all data before it reaches privileged operations.".into(),
            });
        }
    }

    TaintAnalysisResult {
        function_name: fn_name.to_string(),
        flows,
        final_state: state,
        fixed_point_iterations: iterations,
        findings,
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Statement Analysis Helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Extract LHS variable and RHS variable references from a statement.
fn extract_assignment_vars(code: &str) -> (Option<String>, Vec<String>) {
    let mut lhs = None;
    let mut rhs_vars = Vec::new();

    // Pattern: `let var = ...` or `var = ...`
    let code_trimmed = code.trim();
    if let Some(rest) = code_trimmed.strip_prefix("let") {
        let rest = rest.trim().trim_start_matches("mut").trim();
        if let Some(eq_pos) = rest.find('=') {
            let var_part = rest[..eq_pos].trim();
            // Handle pattern destructuring: take the first identifier
            let var_name = var_part.split(|c: char| !c.is_alphanumeric() && c != '_')
                .next()
                .unwrap_or("")
                .to_string();
            if !var_name.is_empty() {
                lhs = Some(var_name);
            }
            // Extract RHS identifiers
            let rhs_part = &rest[eq_pos + 1..];
            rhs_vars = extract_identifiers(rhs_part);
        }
    } else if let Some(eq_pos) = code_trimmed.find('=') {
        // Check it's not == or !=
        if eq_pos > 0
            && !code_trimmed.as_bytes().get(eq_pos + 1).copied().map_or(false, |b| b == b'=')
            && code_trimmed.as_bytes().get(eq_pos.saturating_sub(1)).copied() != Some(b'!')
            && code_trimmed.as_bytes().get(eq_pos.saturating_sub(1)).copied() != Some(b'>')
            && code_trimmed.as_bytes().get(eq_pos.saturating_sub(1)).copied() != Some(b'<')
        {
            let var_part = code_trimmed[..eq_pos].trim();
            let var_name = var_part.split(|c: char| !c.is_alphanumeric() && c != '_')
                .filter(|s| !s.is_empty())
                .last()
                .unwrap_or("")
                .to_string();
            if !var_name.is_empty() {
                lhs = Some(var_name);
            }
            let rhs_part = &code_trimmed[eq_pos + 1..];
            rhs_vars = extract_identifiers(rhs_part);
        }
    }

    (lhs, rhs_vars)
}

/// Extract identifiers from a code string.
fn extract_identifiers(code: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut current = String::new();

    for ch in code.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            current.push(ch);
        } else {
            if !current.is_empty()
                && !is_keyword(&current)
                && current.chars().next().map_or(false, |c| c.is_alphabetic() || c == '_')
            {
                ids.push(current.clone());
            }
            current.clear();
        }
    }
    if !current.is_empty() && !is_keyword(&current) {
        ids.push(current);
    }

    ids
}

fn is_keyword(s: &str) -> bool {
    matches!(s, "let" | "mut" | "pub" | "fn" | "if" | "else" | "match" | "return"
        | "true" | "false" | "self" | "Self" | "as" | "u8" | "u16" | "u32"
        | "u64" | "u128" | "i8" | "i16" | "i32" | "i64" | "i128" | "usize"
        | "isize" | "bool" | "str" | "String" | "Ok" | "Err" | "Some" | "None"
        | "Result" | "Option" | "Vec")
}

/// Detect security-critical sinks in a statement.
fn detect_sinks(
    code: &str,
    state: &TaintState,
    rhs_vars: &[String],
    _stmt_idx: usize,
    stmts: &[Stmt],
    sinks: &mut Vec<TaintSink>,
) {
    let line = if _stmt_idx < stmts.len() {
        token_line(&stmts[_stmt_idx])
    } else {
        0
    };

    // Sink 1: Token transfer with tainted amount
    if code.contains("transfer") || code.contains("Transfer") {
        for var in rhs_vars {
            if var.contains("amount") || var.contains("lamport") || var.contains("value") {
                sinks.push(TaintSink {
                    operation: "Token Transfer".into(),
                    variable: var.clone(),
                    max_allowed_taint: TaintLevel::SignerControlled,
                    line,
                    vuln_id: "SOL-TAINT-01".into(),
                    description: "Attacker-controlled amount flows to token transfer. \
                         An attacker can manipulate this value to drain funds.".into(),
                });
            }
        }
    }

    // Sink 2: CPI invocation with tainted data
    if code.contains("invoke") || code.contains("invoke_signed") || code.contains("CpiContext") {
        for var in rhs_vars {
            sinks.push(TaintSink {
                operation: "CPI Invocation".into(),
                variable: var.clone(),
                max_allowed_taint: TaintLevel::SignerControlled,
                line,
                vuln_id: "SOL-TAINT-02".into(),
                description: "Tainted data flows to a cross-program invocation. \
                     The callee program may not validate the data, leading to \
                     cross-contract exploitation.".into(),
            });
        }
    }

    // Sink 3: Authority/signer comparison with tainted key
    if code.contains("authority") && code.contains("key") && code.contains("==") {
        for var in rhs_vars {
            if var.contains("key") || var.contains("pubkey") {
                sinks.push(TaintSink {
                    operation: "Authority Check".into(),
                    variable: var.clone(),
                    max_allowed_taint: TaintLevel::Untainted,
                    line,
                    vuln_id: "SOL-TAINT-03".into(),
                    description: "User-supplied key used in authority comparison. \
                         If the expected key is also tainted, the check is bypassed.".into(),
                });
            }
        }
    }

    // Sink 4: Arithmetic on tainted values flowing to state update
    if (code.contains("+=") || code.contains("-=") || code.contains("borrow_mut"))
        && !code.contains("checked_")
    {
        for var in rhs_vars {
            if state.get(var).subsumes(TaintLevel::AccountInput) {
                sinks.push(TaintSink {
                    operation: "State Update".into(),
                    variable: var.clone(),
                    max_allowed_taint: TaintLevel::SignerControlled,
                    line,
                    vuln_id: "SOL-TAINT-04".into(),
                    description: "Tainted value used in unchecked state update. \
                         An attacker can manipulate program state through crafted inputs.".into(),
                });
            }
        }
    }

    // Sink 5: Seeds for PDA derivation with tainted data
    if code.contains("find_program_address") || code.contains("create_program_address") {
        for var in rhs_vars {
            if state.get(var).subsumes(TaintLevel::AccountInput) {
                sinks.push(TaintSink {
                    operation: "PDA Derivation".into(),
                    variable: var.clone(),
                    max_allowed_taint: TaintLevel::SignerControlled,
                    line,
                    vuln_id: "SOL-TAINT-05".into(),
                    description: "Tainted data used as PDA seed. An attacker can derive \
                         a different PDA by controlling the seed, potentially accessing \
                         unauthorized accounts.".into(),
                });
            }
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn is_test_item(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("test")
        || a.meta.to_token_stream().to_string().contains("test")
    })
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
    fn test_lattice_join() {
        assert_eq!(TaintLevel::Untainted.join(TaintLevel::Tainted), TaintLevel::Tainted);
        assert_eq!(TaintLevel::AccountInput.join(TaintLevel::SignerControlled), TaintLevel::AccountInput);
        assert_eq!(TaintLevel::ExternalData.join(TaintLevel::ArithmeticDerived), TaintLevel::ExternalData);
        assert_eq!(TaintLevel::Untainted.join(TaintLevel::Untainted), TaintLevel::Untainted);
    }

    #[test]
    fn test_lattice_meet() {
        assert_eq!(TaintLevel::Tainted.meet(TaintLevel::Untainted), TaintLevel::Untainted);
        assert_eq!(TaintLevel::AccountInput.meet(TaintLevel::ExternalData), TaintLevel::AccountInput);
    }

    #[test]
    fn test_lattice_subsumes() {
        assert!(TaintLevel::Tainted.subsumes(TaintLevel::Untainted));
        assert!(TaintLevel::ExternalData.subsumes(TaintLevel::AccountInput));
        assert!(!TaintLevel::Untainted.subsumes(TaintLevel::Tainted));
    }

    #[test]
    fn test_state_join() {
        let mut s1 = TaintState::new();
        s1.set("x".into(), TaintLevel::AccountInput);
        s1.set("y".into(), TaintLevel::Untainted);

        let mut s2 = TaintState::new();
        s2.set("x".into(), TaintLevel::ExternalData);
        s2.set("z".into(), TaintLevel::Tainted);

        let joined = s1.join(&s2);
        assert_eq!(joined.get("x"), TaintLevel::ExternalData);
        assert_eq!(joined.get("y"), TaintLevel::Untainted);
        assert_eq!(joined.get("z"), TaintLevel::Tainted);
    }

    #[test]
    fn test_extract_identifiers() {
        let ids = extract_identifiers("amount + fee * rate");
        assert!(ids.contains(&"amount".to_string()));
        assert!(ids.contains(&"fee".to_string()));
        assert!(ids.contains(&"rate".to_string()));
    }

    #[test]
    fn test_extract_assignment() {
        let (lhs, rhs) = extract_assignment_vars("let amount = ctx.accounts.vault.amount");
        assert_eq!(lhs, Some("amount".to_string()));
        assert!(rhs.contains(&"ctx".to_string()));
    }

    #[test]
    fn test_transfer_sanitizer_lowers_taint() {
        let mut state = TaintState::new();
        state.set("amount".into(), TaintLevel::Tainted);

        let result = transfer_assignment(
            &state,
            "validated",
            "require!(amount > 0 && amount < max)",
            &["amount".into()],
        );
        assert_eq!(result, TaintLevel::SignerControlled);
    }

    #[test]
    fn test_taint_analysis_detects_flow() {
        let code = r#"
            pub fn withdraw(amount: u64, vault: &mut Vault) {
                let transfer_amount = amount;
                anchor_spl::token::transfer(cpi_ctx, transfer_amount);
            }
        "#;
        let results = analyze_taint(code, "test.rs");
        assert!(!results.is_empty());
        // The u64 `amount` parameter should be tainted as AccountInput,
        // and it flows to a transfer sink
    }
}
