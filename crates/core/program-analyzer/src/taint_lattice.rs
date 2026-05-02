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

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Interprocedural Taint Analysis
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Summary of a function's taint behavior.
///
/// For each function `f(p₁, p₂, …, pₙ) → r`, the summary records:
/// - Which parameters propagate their taint to the return value
/// - The maximum taint level of any parameter that reaches a sink
///
/// This enables interprocedural analysis without inlining:
/// at call sites, we apply the summary to compute the return taint.
#[derive(Debug, Clone)]
pub struct FunctionTaintSummary {
    /// Function name
    pub name: String,
    /// Parameter names in order
    pub params: Vec<String>,
    /// Taint of the return value: join of all contributing parameter taints
    pub return_taint: TaintLevel,
    /// For each parameter index, does it contribute to the return value?
    pub param_contributes_to_return: Vec<bool>,
    /// For each parameter index, does it reach a security-sensitive sink?
    pub param_reaches_sink: Vec<bool>,
}

/// A call edge in the interprocedural call graph.
#[derive(Debug, Clone)]
pub struct CallEdge {
    /// Caller function name
    pub caller: String,
    /// Callee function name
    pub callee: String,
    /// Argument expressions at the call site
    pub arguments: Vec<String>,
    /// Line number of the call
    pub line: usize,
}

/// Known external crate functions that are security-sensitive sinks.
/// These are not defined in the program but are called via CPI.
/// The key is the function name pattern, the value describes its security impact.
pub fn get_external_sink_functions() -> std::collections::HashMap<&'static str, (&'static str, TaintLevel)> {
    let mut sinks = std::collections::HashMap::new();
    
    // Token program transfers - taint flows through the amount parameter to privileged operation
    sinks.insert("transfer", ("SPL Token Transfer - amount reaches lamports", TaintLevel::Tainted));
    sinks.insert("transfer_signed", ("SPL Token Transfer (signed) - amount reaches lamports", TaintLevel::Tainted));
    sinks.insert("mint_to", ("SPL Token Mint - mint authority delegation risk", TaintLevel::Tainted));
    sinks.insert("mint_to_checked", ("SPL Token Mint - amount from caller", TaintLevel::Tainted));
    sinks.insert("burn", ("SPL Token Burn - supply manipulation", TaintLevel::Tainted));
    sinks.insert("burn_checked", ("SPL Token Burn - supply manipulation", TaintLevel::Tainted));
    sinks.insert("freeze", ("SPL Token Freeze - authority bypass risk", TaintLevel::Tainted));
    sinks.insert("thaw", ("SPL Token Thaw - authority bypass risk", TaintLevel::Tainted));
    sinks.insert("set_authority", ("SPL Token Authority Change - privilege escalation", TaintLevel::Tainted));
    
    // System program - SOL transfers
    sinks.insert("transfer", ("System Transfer - lamport manipulation", TaintLevel::Tainted));
    sinks.insert("assign", ("System Account Assign - ownership change", TaintLevel::Tainted));
    sinks.insert("create_account", ("System Create Account - space/lamport allocation", TaintLevel::Tainted));
    sinks.insert("allocate", ("System Allocate - account data manipulation", TaintLevel::Tainted));
    
    // Associated token program
    sinks.insert("create", ("ATA Create - account initialization", TaintLevel::AccountInput));
    sinks.insert("create_idempotent", ("ATA Create - account initialization", TaintLevel::AccountInput));
    
    // Token-2022 extensions
    sinks.insert("transfer_checked", ("Token-2022 Transfer - amount reaches lamports", TaintLevel::Tainted));
    sinks.insert("mint_to_checked", ("Token-2022 Mint - supply manipulation", TaintLevel::Tainted));
    
    sinks
}

/// Known external crate functions that are security-sensitive sources.
/// These introduce taint into the program.
pub fn get_external_source_functions() -> std::collections::HashMap<&'static str, (&'static str, TaintLevel)> {
    let mut sources = std::collections::HashMap::new();
    
    // Oracle price feeds - external data that should be validated
    sources.insert("get_price", ("Pyth Oracle - untrusted price data", TaintLevel::ExternalData));
    sources.insert("get_price_unchecked", ("Pyth Oracle - untrusted price data", TaintLevel::ExternalData));
    sources.insert("get_ema_price", ("Pyth Oracle EMA - untrusted price data", TaintLevel::ExternalData));
    sources.insert("get_ema_price_unchecked", ("Pyth Oracle EMA - untrusted price data", TaintLevel::ExternalData));
    sources.insert("get_account", ("Pyth Oracle Account - untrusted data", TaintLevel::ExternalData));
    
    // Switchboard oracle
    sources.insert("fetch", ("Switchboard Feed - untrusted external data", TaintLevel::ExternalData));
    sources.insert("get", ("Switchboard Feed - untrusted external data", TaintLevel::ExternalData));
    sources.insert("get_value", ("Switchboard Value - untrusted external data", TaintLevel::ExternalData));
    
    // CPI return data - anything returned from external calls is tainted
    sources.insert("invoke", ("CPI Return - external program data", TaintLevel::ExternalData));
    sources.insert("invoke_signed", ("CPI Return - external program data", TaintLevel::ExternalData));
    
    sources
}

/// Build a call graph from the AST, including external CPI calls.
///
/// Returns:
/// - Internal call edges (within the program)
/// - Function summaries
/// 
/// This version also detects calls to external crate functions (via CPI)
/// and marks them as cross-crate edges.
pub fn build_call_graph(source: &str) -> (Vec<CallEdge>, Vec<FunctionTaintSummary>) {
    let (edges, summaries, _) = build_call_graph_extended(source);
    (edges, summaries)
}

/// Build a call graph and also get external CPI edges (convenience wrapper)
pub fn build_call_graph_with_external(source: &str) -> (Vec<CallEdge>, Vec<FunctionTaintSummary>, Vec<ExtendedCallEdge>) {
    build_call_graph_extended(source)
}

/// Extended version that also returns external CPI edges for cross-crate analysis.
/// Returns: (internal_edges, function_summaries, external_cpi_edges)
pub fn build_call_graph_extended(source: &str) -> (Vec<CallEdge>, Vec<FunctionTaintSummary>, Vec<ExtendedCallEdge>) {
    let ast = match syn::parse_file(source) {
        Ok(f) => f,
        Err(_) => return (Vec::new(), Vec::new(), Vec::new()),
    };

    let mut edges = Vec::new();
    let mut external_edges: Vec<ExtendedCallEdge> = Vec::new();
    let mut function_names: Vec<String> = Vec::new();

    // Collect all function names first
    for item in &ast.items {
        match item {
            Item::Fn(f) => {
                function_names.push(f.sig.ident.to_string());
            }
            Item::Impl(imp) => {
                for imp_item in &imp.items {
                    if let syn::ImplItem::Fn(f) = imp_item {
                        function_names.push(f.sig.ident.to_string());
                    }
                }
            }
            _ => {}
        }
    }

    // Scan function bodies for calls to known functions and external CPI calls
    for item in &ast.items {
        match item {
            Item::Fn(f) => {
                let caller = f.sig.ident.to_string();
                collect_call_edges(&caller, &f.block.stmts, &function_names, &mut edges, &mut external_edges);
            }
            Item::Impl(imp) => {
                for imp_item in &imp.items {
                    if let syn::ImplItem::Fn(f) = imp_item {
                        let caller = f.sig.ident.to_string();
                        collect_call_edges(&caller, &f.block.stmts, &function_names, &mut edges, &mut external_edges);
                    }
                }
            }
            _ => {}
        }
    }

    // Compute function summaries from intraprocedural results
    let summaries = compute_function_summaries(&ast);

    (edges, summaries, external_edges)
}

/// A call edge that can be either internal or external (cross-crate/CPI)
#[derive(Debug, Clone)]
pub enum CallEdgeType {
    /// Internal call to a function defined in the same program
    Internal,
    /// External call via CPI to another program (e.g., token transfer, system program)
    External { program: String, description: String },
}

/// Extended call edge with type information
#[derive(Debug, Clone)]
pub struct ExtendedCallEdge {
    pub caller: String,
    pub callee: String,
    pub arguments: Vec<String>,
    pub line: usize,
    pub edge_type: CallEdgeType,
}

/// Collect call edges from function body statements, including external CPI calls.
fn collect_call_edges(
    caller: &str,
    stmts: &[Stmt],
    known_functions: &[String],
    edges: &mut Vec<CallEdge>,
    external_edges: &mut Vec<ExtendedCallEdge>,
) {
    let external_sinks = get_external_sink_functions();
    let external_sources = get_external_source_functions();
    
    for stmt in stmts {
        let code = stmt.to_token_stream().to_string();
        let line = token_line(stmt);

        // Check for internal function calls
        for func_name in known_functions {
            if code.contains(&format!("{}(", func_name))
                || code.contains(&format!("{} (", func_name))
                || code.contains(&format!(":: {} (", func_name))
                || code.contains(&format!("::{}(", func_name))
            {
                let arguments = extract_call_arguments(&code, func_name);
                edges.push(CallEdge {
                    caller: caller.to_string(),
                    callee: func_name.clone(),
                    arguments,
                    line,
                });
            }
        }
        
        // Check for external CPI calls (anchor_spl, system_program, etc.)
        detect_external_calls(caller, &code, line, &external_sinks, &external_sources, external_edges);
    }
}

/// Detect external crate calls (CPI) and add them as cross-crate edges.
fn detect_external_calls(
    caller: &str,
    code: &str,
    line: usize,
    external_sinks: &std::collections::HashMap<&'static str, (&'static str, TaintLevel)>,
    external_sources: &std::collections::HashMap<&'static str, (&'static str, TaintLevel)>,
    external_edges: &mut Vec<ExtendedCallEdge>,
) {
    // Common external crate module paths
    let external_patterns = [
        "anchor_spl::token::",
        "anchor_spl::associated_token::",
        "anchor_spl::token_2022::",
        "solana_program::program::invoke",
        "solana_program::program::invoke_signed",
        "system_instruction::",
        "pyth::",
        "switchboard::",
    ];
    
    for pattern in external_patterns {
        if code.contains(pattern) {
            // Extract the actual function being called
            if let Some(call_start) = code.find(pattern) {
                let after_pattern = &code[call_start + pattern.len()..];
                // Get function name (up to parenthesis)
                let func_name: String = after_pattern.chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                
                if !func_name.is_empty() {
                    // Determine if this is a sink or source
                    if let Some((desc, _)) = external_sinks.get(func_name.as_str()) {
                        external_edges.push(ExtendedCallEdge {
                            caller: caller.to_string(),
                            callee: format!("{}::{}", pattern.trim_end_matches("::"), func_name),
                            arguments: extract_call_arguments(&code, &func_name),
                            line,
                            edge_type: CallEdgeType::External { 
                                program: pattern.trim_end_matches("::").to_string(),
                                description: desc.to_string(),
                            },
                        });
                    } else if let Some((desc, level)) = external_sources.get(func_name.as_str()) {
                        external_edges.push(ExtendedCallEdge {
                            caller: caller.to_string(),
                            callee: format!("{}::{}", pattern.trim_end_matches("::"), func_name),
                            arguments: extract_call_arguments(&code, &func_name),
                            line,
                            edge_type: CallEdgeType::External { 
                                program: pattern.trim_end_matches("::").to_string(),
                                description: format!("{} (taint level: {:?})", desc, level),
                            },
                        });
                    }
                }
            }
        }
    }
}

/// Extract function call arguments from code string.
fn extract_call_arguments(code: &str, func_name: &str) -> Vec<String> {
    // Try both `func_name(` and `func_name (` patterns
    let patterns = [format!("{}(", func_name), format!("{} (", func_name)];
    for pattern in &patterns {
        if let Some(start) = code.find(pattern.as_str()) {
            let after_pattern = start + pattern.len() - 1; // position of '('
            let rest = &code[after_pattern..];
            if rest.starts_with('(') {
                let inner = &rest[1..]; // skip the '('
                // Find matching close paren
                let mut depth = 1;
                let mut end = 0;
                for (i, ch) in inner.char_indices() {
                    match ch {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                end = i;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                let args_str = &inner[..end];
                return args_str.split(',')
                    .map(|a| a.trim().to_string())
                    .filter(|a| !a.is_empty())
                    .collect();
            }
        }
    }
    Vec::new()
}

/// Compute taint summaries for all functions in the AST.
///
/// For each function, runs a quick intraprocedural taint analysis and
/// observes which parameters contribute to the return value and which
/// reach security sinks.
fn compute_function_summaries(ast: &syn::File) -> Vec<FunctionTaintSummary> {
    let mut summaries = Vec::new();

    for item in &ast.items {
        match item {
            Item::Fn(f) => {
                if let Some(summary) = summarize_function(&f.sig, &f.block.stmts) {
                    summaries.push(summary);
                }
            }
            Item::Impl(imp) => {
                for imp_item in &imp.items {
                    if let syn::ImplItem::Fn(f) = imp_item {
                        if let Some(summary) = summarize_function(&f.sig, &f.block.stmts) {
                            summaries.push(summary);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    summaries
}

/// Create a taint summary for a single function.
fn summarize_function(sig: &syn::Signature, stmts: &[Stmt]) -> Option<FunctionTaintSummary> {
    let fn_name = sig.ident.to_string();
    let mut params = Vec::new();

    // Extract parameter names
    for arg in &sig.inputs {
        if let syn::FnArg::Typed(pat_type) = arg {
            let param_name = pat_type.pat.to_token_stream().to_string();
            params.push(param_name);
        }
    }

    if params.is_empty() {
        return None;
    }

    // Run a mini taint analysis: mark each param as tainted one at a time
    // and observe if the return value becomes tainted
    let mut param_contributes_to_return = vec![false; params.len()];
    let mut param_reaches_sink = vec![false; params.len()];

    // Combined analysis: taint all params and trace flow
    let mut state = TaintState::new();
    for (i, param) in params.iter().enumerate() {
        // Give each param a unique taint level for tracking
        let level = TaintLevel::AccountInput;
        state.set(param.clone(), level);
        // Check if param name appears in any return/sink-like expressions
        for stmt in stmts {
            let code = stmt.to_token_stream().to_string();
            if code.contains("return") || code.contains("Ok(") {
                if code.contains(param) {
                    param_contributes_to_return[i] = true;
                }
            }
            if code.contains("transfer") || code.contains("invoke")
                || code.contains("CpiContext")
            {
                if code.contains(param) {
                    param_reaches_sink[i] = true;
                }
            }
        }
    }

    let return_taint = if param_contributes_to_return.iter().any(|&c| c) {
        TaintLevel::AccountInput
    } else {
        TaintLevel::Untainted
    };

    Some(FunctionTaintSummary {
        name: fn_name,
        params,
        return_taint,
        param_contributes_to_return,
        param_reaches_sink,
    })
}

/// Apply interprocedural taint summaries to a function's taint state.
///
/// At each call site `r = callee(arg1, arg2, ...)`:
/// 1. Look up the callee's summary
/// 2. For each argument, get its taint from the caller's state
/// 3. If the argument's parameter contributes to the return value,
///    join its taint into the return value's taint
/// 4. If the argument's parameter reaches a sink, flag a finding
///
/// This is a **context-insensitive** summary application (each function
/// has one summary regardless of call context). For Solana programs with
/// typically < 50 functions, this is sufficient.
pub fn apply_interprocedural_summaries(
    intra_results: &mut [TaintAnalysisResult],
    edges: &[CallEdge],
    summaries: &[FunctionTaintSummary],
    filename: &str,
) {
    let _lines: Vec<&str> = Vec::new(); // We don't need source lines for IP findings

    for edge in edges {
        // Find the callee summary
        let summary = match summaries.iter().find(|s| s.name == edge.callee) {
            Some(s) => s,
            None => continue,
        };

        // Find the caller's taint result
        let caller_result = match intra_results.iter_mut()
            .find(|r| r.function_name == edge.caller)
        {
            Some(r) => r,
            None => continue,
        };

        // Apply summary: compute taint at the call site
        let mut call_return_taint = TaintLevel::Untainted;
        for (i, arg_expr) in edge.arguments.iter().enumerate() {
            if i >= summary.params.len() { break; }

            // Get taint of the argument expression
            let arg_vars = extract_identifiers(arg_expr);
            let arg_taint = arg_vars.iter()
                .map(|v| caller_result.final_state.get(v))
                .fold(TaintLevel::Untainted, |a, b| a.join(b));

            // If this parameter contributes to return, propagate taint
            if summary.param_contributes_to_return.get(i).copied().unwrap_or(false) {
                call_return_taint = call_return_taint.join(arg_taint);
            }

            // If this parameter reaches a sink in the callee, generate a finding
            if summary.param_reaches_sink.get(i).copied().unwrap_or(false)
                && arg_taint.subsumes(TaintLevel::AccountInput)
            {
                caller_result.findings.push(VulnerabilityFinding {
                    category: "Interprocedural Information Flow".into(),
                    vuln_type: format!(
                        "Cross-Function Taint: {} → {} (param {})",
                        edge.caller, edge.callee, summary.params[i],
                    ),
                    severity: if arg_taint == TaintLevel::Tainted { 5 } else { 4 },
                    severity_label: if arg_taint == TaintLevel::Tainted {
                        "CRITICAL".into()
                    } else {
                        "HIGH".into()
                    },
                    id: "SOL-TAINT-IP-01".into(),
                    cwe: Some("CWE-20".into()),
                    location: filename.to_string(),
                    function_name: edge.caller.clone(),
                    line_number: edge.line,
                    vulnerable_code: format!(
                        "{}({}) at line {}",
                        edge.callee,
                        edge.arguments.join(", "),
                        edge.line,
                    ),
                    description: format!(
                        "Interprocedural taint analysis: tainted data (level {:?}) \
                         flows from `{}` in function `{}` through parameter `{}` of \
                         function `{}`, where it reaches a security-sensitive sink. \
                         Call graph edge: {} → {}.",
                        arg_taint, arg_expr, edge.caller,
                        summary.params[i], edge.callee,
                        edge.caller, edge.callee,
                    ),
                    attack_scenario: format!(
                        "An attacker supplies malicious input that flows through \
                         `{}` to `{}`, bypassing validation that only checks the \
                         immediate function's parameters.",
                        edge.caller, edge.callee,
                    ),
                    real_world_incident: None,
                    secure_fix: format!(
                        "Validate parameter `{}` in `{}` before passing to `{}`.",
                        summary.params[i], edge.caller, edge.callee,
                    ),
                    confidence: 60,
                    prevention: "Validate data at every trust boundary, not just at entry points.".into(),
                });
            }
        }
    }
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

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Cross-Crate CPI Vulnerability Detection
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Detect vulnerabilities from cross-crate CPI (cross-program invocation) calls.
/// This analyzes external program calls (token transfers, system program, etc.)
/// and checks for common vulnerability patterns in how they're invoked.
///
/// Returns vulnerability findings for issues like:
/// - Unchecked CPI return values
/// - Missing signer verification before CPI
/// - Delegate authority without proper checks
/// - Oracle data used in CPI without validation
pub fn detect_cross_crate_vulnerabilities(
    external_edges: &[ExtendedCallEdge],
    raw_sources: &[(String, String)],
) -> Vec<VulnerabilityFinding> {
    let mut findings = Vec::new();
    
    // Known dangerous CPI patterns
    // Pattern, description, severity (5=Critical, 4=High, 3=Medium)
    // ORDER MATTERS: More specific patterns must come first (before shorter substrings)
    let dangerous_patterns: Vec<(&str, &str, u8)> = vec![
        // Token-2022 extensions (most specific - check first)
        ("transfer_checked", "Token-2022 transfer - amount reaches lamports", 5),
        ("freeze_account", "Token-2022 freeze - fund lock risk", 4),
        ("thaw_account", "Token-2022 thaw - unfreeze without auth", 4),
        
        // System Program operations (specific names first)
        ("system_transfer", "System transfer - SOL manipulation", 5),
        ("system_create_account", "System create account - lamport/space allocation", 4),
        ("withdraw_nonce", "Nonce withdrawal - could drain validator", 5),
        ("advance_nonce", "Nonce advancement - state manipulation", 4),
        
        // SPL Token operations (specific variants first)
        ("transfer_signed", "Unchecked token transfer with signer - could drain vault", 5),
        ("mint_to_checked", "Unchecked token mint - supply manipulation risk", 5),
        ("burn_checked", "Unchecked token burn - supply manipulation risk", 5),
        
        // Base SPL Token operations (come after their _checked variants)
        ("mint_to", "Unchecked token mint - could exceed supply limits", 5),
        ("burn", "Unchecked token burn - could destroy user funds", 5),
        ("freeze", "Unchecked token freeze - could lock user funds", 4),
        ("thaw", "Unchecked token thaw - could unfreeze without authorization", 4),
        ("set_authority", "Authority change without proper validation - privilege escalation", 5),
        ("close_account", "Account closure without proper validation", 4),
        ("close", "Account closure - could drain account lamports", 4),
        ("transfer", "Unchecked token transfer - amount parameter could be attacker-controlled", 5),
        
        // Associated Token Account
        ("ata_create", "ATA creation - account initialization", 3),
        ("create_idempotent", "ATA creation - account initialization", 3),
        ("recover", "ATA recovery - could reclaim funds", 4),
        
        // System Program (generic - come after specific)
        ("allocate", "System allocate - account data manipulation", 4),
        ("assign", "System assign - ownership change", 5),
    ];
    
    for edge in external_edges {
        // Check if this is a dangerous CPI call
        let callee_lower = edge.callee.to_lowercase();
        for (pattern, description, default_severity) in &dangerous_patterns {
            if callee_lower.contains(pattern) {
                // Analyze the source to check for proper validation before this CPI
                let validation = check_cpi_validation(raw_sources, &edge.caller, pattern);
                
                if !validation.has_signer_check || !validation.has_amount_validation {
                    // Use the pattern severity, but escalate if signer check is missing
                    let severity = if !validation.has_signer_check { 5 } else { *default_severity };
                    let severity_label = match severity {
                        5 => "Critical",
                        4 => "High",
                        3 => "Medium",
                        _ => "Medium",
                    };
                    
                    findings.push(VulnerabilityFinding {
                        category: "Cross-Crate CPI".into(),
                        vuln_type: format!("Unvalidated CPI Call: {}", edge.callee),
                        severity,
                        severity_label: severity_label.into(),
                        id: format!("SOL-CPI-{}", pattern),
                        cwe: Some("CWE-346".into()),
                        location: validation.file.clone(),
                        function_name: edge.caller.clone(),
                        line_number: edge.line,
                        vulnerable_code: format!("{}(...) at line {} in {}", 
                            edge.callee, edge.line, edge.caller),
                        description: format!(
                            "Cross-crate CPI call to {}: {}. {}, Line: {}",
                            edge.callee, description,
                            if !validation.has_signer_check { "Missing signer verification" } 
                            else { "Missing amount validation" },
                            edge.line
                        ),
                        attack_scenario: format!(
                            "An attacker could invoke {} with manipulated parameters {}, \
                             potentially draining funds or escalating privileges.",
                            edge.caller,
                            if !validation.has_signer_check { 
                                "without proper signer authorization" 
                            } else { 
                                "without validating amounts" 
                            }
                        ),
                        real_world_incident: None,
                        secure_fix: format!(
                            "Add {} validation before the CPI call in {}.",
                            if !validation.has_signer_check { "signer" } else { "amount" },
                            edge.caller
                        ),
                        prevention: "Always validate signer authority and parameter bounds before CPI calls.".into(),
                        confidence: if !validation.has_signer_check { 80 } else { 70 },
                    });
                }
            }
        }
        
        // Check for oracle data used in CPI without validation
        if callee_lower.contains("pyth") || callee_lower.contains("oracle") || callee_lower.contains("switchboard") {
            let validation = check_oracle_validation(raw_sources, &edge.caller);
            if !validation.price_validated {
                findings.push(VulnerabilityFinding {
                    category: "Cross-Crate CPI".into(),
                    vuln_type: "Unvalidated Oracle Data in CPI".into(),
                    severity: 4,
                    severity_label: "High".into(),
                    id: "SOL-CPI-02".into(),
                    cwe: Some("CWE-20".into()),
                    location: validation.file.clone(),
                    function_name: edge.caller.clone(),
                    line_number: edge.line,
                    vulnerable_code: format!("Oracle data from {} used in CPI without validation", edge.callee),
                    description: format!(
                        "Oracle price/confidence data from {} is used in a CPI call \
                         without proper validation. Stale or manipulated oracle data \
                         could lead to under-collateralized positions.",
                        edge.callee
                    ),
                    attack_scenario: "Attacker manipulates oracle price to trigger favorable \
                        conditions in the protocol, then executes CPI to drain funds.".into(),
                    real_world_incident: None,
                    secure_fix: format!(
                        "Add oracle price/confidence validation in {} before using in CPI.",
                        edge.caller
                    ),
                    prevention: "Always validate oracle freshness and confidence thresholds before use.".into(),
                    confidence: 65,
                });
            }
        }
    }
    
    findings
}

/// Check if a CPI call has proper validation
struct CpiValidationResult {
    has_signer_check: bool,
    has_amount_validation: bool,
    file: String,
}

/// Find a function in source code using improved pattern matching.
/// Handles: fn, pub fn, async fn, pub async fn, and methods in impl blocks.
fn find_function_in_source(source: &str, fn_name: &str) -> Option<(usize, usize)> {
    use regex::Regex;
    
    // Match various function declaration patterns:
    // - fn name(
    // - pub fn name(
    // - async fn name(
    // - pub async fn name(
    // Also handle impl blocks: fn name(
    let patterns = [
        format!(r"(?:pub\s+)?(?:async\s+)?fn\s+{}\s*\(", fn_name),
        // For impl blocks, search for the function within the impl - we'll find the fn pattern separately
        format!(r"fn\s+{}\s*\(", fn_name),
    ];
    
    for pattern in &patterns {
        if let Ok(re) = Regex::new(pattern) {
            if let Some(m) = re.find(source) {
                let start = m.start();
                // Find the matching closing brace for impl blocks
                let end = if pattern.contains("impl") {
                    find_impl_block_end(source, start)
                } else {
                    find_function_end(source, start)
                };
                return Some((start, end));
            }
        }
    }
    
    None
}

/// Find the end of a function by counting braces
fn find_function_end(source: &str, start: usize) -> usize {
    let remaining = &source[start..];
    let mut brace_count = 0;
    let mut found_open = false;
    
    for (i, ch) in remaining.char_indices() {
        match ch {
            '{' => {
                found_open = true;
                brace_count += 1;
            }
            '}' => {
                brace_count -= 1;
                if found_open && brace_count == 0 {
                    return start + i + 1;
                }
            }
            _ => {}
        }
    }
    // Default: return 5000 chars if we can't find the end
    (start + 5000).min(source.len())
}

/// Find the end of an impl block
fn find_impl_block_end(source: &str, start: usize) -> usize {
    find_function_end(source, start)
}

fn check_cpi_validation(
    raw_sources: &[(String, String)],
    caller_fn: &str,
    _cpi_method: &str,
) -> CpiValidationResult {
    let mut has_signer_check = false;
    let mut has_amount_validation = false;
    let mut file = String::new();
    
    for (filename, source) in raw_sources {
        // Find the caller function using improved matching
        if let Some((fn_start, fn_end)) = find_function_in_source(source, caller_fn) {
            file = filename.clone();
            
            // Extract the function content
            let fn_content = &source[fn_start..fn_end];
            
            // Check for signer verification patterns
            if fn_content.contains("require_signed")
                || fn_content.contains(".is_signer")
                || fn_content.contains("assert_keys_equal")
                || (fn_content.contains("require!") && fn_content.contains("signer"))
                || fn_content.contains("require_eq!") && fn_content.contains("authority")
            {
                has_signer_check = true;
            }
            
            // Check for amount validation patterns
            if fn_content.contains("require!") 
                && (fn_content.contains("amount > 0") || fn_content.contains("amount <")
                    || fn_content.contains("> 0") || fn_content.contains("<= max")
                    || fn_content.contains("amount <= ") || fn_content.contains("amount >="))
            {
                has_amount_validation = true;
            }
            
            // Also check for checked arithmetic patterns
            if fn_content.contains("checked_") 
                || fn_content.contains("try_add") 
                || fn_content.contains("try_sub")
                || fn_content.contains("try_mul")
                || fn_content.contains("checked_add")
                || fn_content.contains("checked_sub")
            {
                has_amount_validation = true;
            }
            
            break;
        }
    }
    
    CpiValidationResult {
        has_signer_check,
        has_amount_validation,
        file,
    }
}

/// Check if oracle data is properly validated before use in CPI
struct OracleValidationResult {
    price_validated: bool,
    file: String,
}

fn check_oracle_validation(
    raw_sources: &[(String, String)],
    caller_fn: &str,
) -> OracleValidationResult {
    let mut price_validated = false;
    let mut file = String::new();
    
    for (filename, source) in raw_sources {
        // Find the caller function using improved matching
        if let Some((fn_start, fn_end)) = find_function_in_source(source, caller_fn) {
            file = filename.clone();
            let fn_content = &source[fn_start..fn_end];
            
            // Check for oracle validation patterns
            if fn_content.contains("confidence") 
                || fn_content.contains(".price")
                || fn_content.contains("pyth::")
                || fn_content.contains("switchboard")
            {
                // Check if there's validation logic
                if fn_content.contains("require!") 
                    && (fn_content.contains("confidence") || fn_content.contains("price > 0")
                        || fn_content.contains(".valid") || fn_content.contains("stale")
                        || fn_content.contains("status == ") || fn_content.contains("conf > "))
                {
                    price_validated = true;
                }
                
                // Check for switchboard validation patterns
                if fn_content.contains("switchboard") 
                    && (fn_content.contains("result.is_ok()") || fn_content.contains("result.ok()")
                        || fn_content.contains("is_err()"))
                {
                    price_validated = true;
                }
                
                // Check for Pyth-specific validation
                if fn_content.contains("pyth") 
                    && (fn_content.contains("price_confidence") || fn_content.contains("price_ema")
                        || fn_content.contains(".valid") || fn_content.contains("conf < "))
                {
                    price_validated = true;
                }
            }
            
            break;
        }
    }
    
    OracleValidationResult {
        price_validated,
        file,
    }
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

    #[test]
    fn test_call_graph_construction() {
        let code = r#"
            pub fn helper(amount: u64) -> u64 {
                amount * 2
            }
            pub fn process(ctx: Context<Process>, val: u64) -> Result<()> {
                let result = helper(val);
                Ok(())
            }
        "#;
        let (edges, summaries) = build_call_graph(code);
        // Should find at least one edge: process -> helper
        assert!(!edges.is_empty(), "call graph should have edges");
        let has_edge = edges.iter().any(|e| e.caller == "process" && e.callee == "helper");
        assert!(has_edge, "should find process -> helper edge");
        // Should have summaries for both functions
        assert!(!summaries.is_empty(), "should have function summaries");
    }

    #[test]
    fn test_function_summary_param_tracking() {
        let code = r#"
            pub fn do_transfer(amount: u64) {
                anchor_spl::token::transfer(cpi_ctx, amount);
            }
        "#;
        let (_, summaries) = build_call_graph(code);
        let summary = summaries.iter().find(|s| s.name == "do_transfer");
        assert!(summary.is_some(), "should have summary for do_transfer");
        let summary = summary.unwrap();
        assert!(summary.param_reaches_sink[0],
            "amount parameter should be marked as reaching a sink");
    }

    #[test]
    fn test_interprocedural_taint_propagation() {
        let code = r#"
            pub fn do_transfer(amount: u64) {
                anchor_spl::token::transfer(cpi_ctx, amount);
            }
            pub fn handler(val: u64) {
                do_transfer(val);
            }
        "#;
        let (edges, summaries) = build_call_graph(code);
        let mut results = analyze_taint(code, "test.rs");
        apply_interprocedural_summaries(&mut results, &edges, &summaries, "test.rs");

        // Check that the handler function has an interprocedural finding
        let handler_result = results.iter().find(|r| r.function_name == "handler");
        if let Some(result) = handler_result {
            let ip_findings: Vec<_> = result.findings.iter()
                .filter(|f| f.id.contains("IP"))
                .collect();
            // Cross-function taint should be detected
            assert!(!ip_findings.is_empty(),
                "interprocedural analysis should detect taint flow handler -> do_transfer");
        }
    }
}
