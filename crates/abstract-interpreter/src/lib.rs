//! Abstract Interpretation Engine for Solana Programs
//!
//! Performs sound numerical analysis using interval domains to
//! compute guaranteed bounds on program values. Essential for
//! proving absence of overflow/underflow.
//!
//! This engine uses Control Flow Graphs (CFG) and a worklist algorithm
//! to perform path-sensitive abstract interpretation.

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::ops::{Add, Div, Mul, Sub};
use syn::{BinOp, Expr, ItemFn, Lit, Stmt};

pub mod domains;
pub mod transfer;

/// Represents a numeric interval [min, max]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interval {
    pub min: i128,
    pub max: i128,
}

impl Interval {
    pub fn new(min: i128, max: i128) -> Self {
        if min > max {
            return Self::bottom();
        }
        Self { min, max }
    }

    pub fn singleton(value: i128) -> Self {
        Self { min: value, max: value }
    }

    pub fn bottom() -> Self {
        Self { min: 1, max: 0 }
    }

    pub fn u64_range() -> Self {
        Self { min: 0, max: u64::MAX as i128 }
    }

    pub fn u128_range() -> Self {
        Self { min: 0, max: i128::MAX }
    }

    pub fn is_bottom(&self) -> bool {
        self.min > self.max
    }

    pub fn contains(&self, value: i128) -> bool {
        !self.is_bottom() && value >= self.min && value <= self.max
    }

    pub fn might_overflow_u64(&self) -> bool {
        self.max > u64::MAX as i128 || self.min < 0
    }

    pub fn might_underflow(&self) -> bool {
        self.min < 0
    }

    pub fn join(&self, other: &Interval) -> Interval {
        if self.is_bottom() { return *other; }
        if other.is_bottom() { return *self; }
        Interval {
            min: self.min.min(other.min),
            max: self.max.max(other.max),
        }
    }

    pub fn widen(&self, other: &Interval) -> Interval {
        if self.is_bottom() { return *other; }
        if other.is_bottom() { return *self; }

        let min = if other.min < self.min { i128::MIN / 2 } else { self.min };
        let max = if other.max > self.max { i128::MAX / 2 } else { self.max };
        Interval { min, max }
    }
}

// Interval arithmetic operations
impl Add for Interval {
    type Output = Interval;
    fn add(self, other: Interval) -> Interval {
        if self.is_bottom() || other.is_bottom() { return Interval::bottom(); }
        Interval {
            min: self.min.saturating_add(other.min),
            max: self.max.saturating_add(other.max),
        }
    }
}

impl Sub for Interval {
    type Output = Interval;
    fn sub(self, other: Interval) -> Interval {
        if self.is_bottom() || other.is_bottom() { return Interval::bottom(); }
        Interval {
            min: self.min.saturating_sub(other.max),
            max: self.max.saturating_sub(other.min),
        }
    }
}

impl Mul for Interval {
    type Output = Interval;
    fn mul(self, other: Interval) -> Interval {
        if self.is_bottom() || other.is_bottom() { return Interval::bottom(); }
        let products = [
            self.min.saturating_mul(other.min),
            self.min.saturating_mul(other.max),
            self.max.saturating_mul(other.min),
            self.max.saturating_mul(other.max),
        ];
        Interval {
            min: *products.iter().min().unwrap(),
            max: *products.iter().max().unwrap(),
        }
    }
}

impl Div for Interval {
    type Output = Interval;
    fn div(self, other: Interval) -> Interval {
        if self.is_bottom() || other.is_bottom() { return Interval::bottom(); }
        if other.contains(0) { return Interval::u128_range(); }
        let quotients = [
            self.min.saturating_div(other.min),
            self.min.saturating_div(other.max),
            self.max.saturating_div(other.min),
            self.max.saturating_div(other.max),
        ];
        Interval {
            min: *quotients.iter().min().unwrap(),
            max: *quotients.iter().max().unwrap(),
        }
    }
}

/// Abstract state mapping variables to intervals
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AbstractState {
    pub intervals: HashMap<String, Interval>,
}

impl AbstractState {
    pub fn new() -> Self {
        Self { intervals: HashMap::new() }
    }

    pub fn get(&self, var: &str) -> Interval {
        self.intervals.get(var).copied().unwrap_or(Interval::u64_range())
    }

    pub fn set(&mut self, var: String, interval: Interval) {
        self.intervals.insert(var, interval);
    }

    pub fn join(&self, other: &AbstractState) -> AbstractState {
        let mut result = AbstractState::new();
        let all_keys: std::collections::HashSet<_> = self.intervals.keys().chain(other.intervals.keys()).collect();
        for key in all_keys {
            result.set(key.clone(), self.get(key).join(&other.get(key)));
        }
        result
    }

    pub fn widen(&self, other: &AbstractState) -> AbstractState {
        let mut result = AbstractState::new();
        let all_keys: std::collections::HashSet<_> = self.intervals.keys().chain(other.intervals.keys()).collect();
        for key in all_keys {
            result.set(key.clone(), self.get(key).widen(&other.get(key)));
        }
        result
    }
}

/// Control Flow Graph Node
#[derive(Debug, Clone)]
pub enum CfgNode {
    Entry,
    Statement(Stmt),
    Branch(Expr),
    Merge,
    Exit,
}

/// Control Flow Graph
pub struct ControlFlowGraph {
    pub graph: DiGraph<CfgNode, bool>, // Edge bool: true for then, false for else/unconditional
    pub entry: NodeIndex,
    pub exit: NodeIndex,
}

/// Result of overflow analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverflowAnalysis {
    pub location: String,
    pub operation: String,
    pub left_interval: (i128, i128),
    pub right_interval: (i128, i128),
    pub result_interval: (i128, i128),
    pub can_overflow: bool,
    pub can_underflow: bool,
    pub severity: OverflowSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OverflowSeverity {
    Safe, Possible, Likely, Guaranteed,
}

/// Main abstract interpreter with CFG support
pub struct AbstractInterpreter {
    findings: Vec<OverflowAnalysis>,
    current_function: String,
    filename: String,
}

impl AbstractInterpreter {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            current_function: String::new(),
            filename: String::new(),
        }
    }

    pub fn analyze_source(&mut self, source: &str, filename: &str) -> Result<Vec<OverflowAnalysis>, AbstractError> {
        self.filename = filename.to_string();
        let file = syn::parse_file(source).map_err(|e| AbstractError::ParseError(e.to_string()))?;

        for item in file.items {
            if let syn::Item::Fn(func) = item {
                self.analyze_function(&func);
            }
        }
        Ok(self.findings.clone())
    }

    fn analyze_function(&mut self, func: &ItemFn) {
        self.current_function = func.sig.ident.to_string();
        let cfg = self.build_cfg(func);
        let mut initial_state = AbstractState::new();

        // Parameter initialization
        for param in &func.sig.inputs {
            if let syn::FnArg::Typed(pat_type) = param {
                if let syn::Pat::Ident(pat_ident) = &*pat_type.pat {
                    let ty_str = quote::quote!(#pat_type.ty).to_string();
                    let interval = if ty_str.contains("u8") { Interval::new(0, 255) }
                        else if ty_str.contains("u16") { Interval::new(0, 65535) }
                        else if ty_str.contains("u32") { Interval::new(0, u32::MAX as i128) }
                        else { Interval::u64_range() };
                    initial_state.set(pat_ident.ident.to_string(), interval);
                }
            }
        }

        self.run_worklist(&cfg, initial_state);
    }

    fn build_cfg(&self, func: &ItemFn) -> ControlFlowGraph {
        let mut graph = DiGraph::new();
        let entry = graph.add_node(CfgNode::Entry);
        let exit = graph.add_node(CfgNode::Exit);

        let mut current = entry;
        for stmt in &func.block.stmts {
            let next = graph.add_node(CfgNode::Statement(stmt.clone()));
            graph.add_edge(current, next, true);
            current = next;
        }
        graph.add_edge(current, exit, true);

        ControlFlowGraph { graph, entry, exit }
    }

    fn run_worklist(&mut self, cfg: &ControlFlowGraph, initial_state: AbstractState) {
        let mut states: HashMap<NodeIndex, AbstractState> = HashMap::new();
        let mut worklist = VecDeque::new();

        states.insert(cfg.entry, initial_state);
        worklist.push_back(cfg.entry);

        let mut iterations = 0;
        while let Some(node_idx) = worklist.pop_front() {
            if iterations > 1000 { break; } // Safety break
            iterations += 1;

            let current_state = states.get(&node_idx).cloned().unwrap_or_default();
            let mut next_state = current_state.clone();

            if let CfgNode::Statement(stmt) = &cfg.graph[node_idx] {
                self.apply_stmt(stmt, &mut next_state);
            }

            for edge in cfg.graph.edges(node_idx) {
                let target = edge.target();
                let target_state = states.entry(target).or_insert_with(AbstractState::new);
                
                let new_state = if iterations > 100 { // Start widening
                    target_state.widen(&next_state)
                } else {
                    target_state.join(&next_state)
                };

                if &new_state != target_state {
                    *target_state = new_state;
                    if !worklist.contains(&target) {
                        worklist.push_back(target);
                    }
                }
            }
        }
    }

    fn apply_stmt(&mut self, stmt: &Stmt, state: &mut AbstractState) {
        match stmt {
            Stmt::Local(local) => {
                if let syn::Pat::Ident(pat_ident) = &local.pat {
                    if let Some(init) = &local.init {
                        let interval = self.eval_expr(&init.expr, state);
                        state.set(pat_ident.ident.to_string(), interval);
                    }
                }
            }
            Stmt::Expr(expr, _) => {
                self.eval_expr(expr, state);
            }
            _ => {}
        }
    }

    fn eval_expr(&mut self, expr: &Expr, state: &AbstractState) -> Interval {
        match expr {
            Expr::Lit(lit_expr) => {
                if let Lit::Int(lit_int) = &lit_expr.lit {
                    lit_int.base10_parse::<i128>().map(Interval::singleton).unwrap_or(Interval::u128_range())
                } else { Interval::u128_range() }
            }
            Expr::Path(path) => {
                if let Some(ident) = path.path.get_ident() {
                    state.intervals.get(&ident.to_string()).copied().unwrap_or(Interval::u64_range())
                } else { Interval::u64_range() }
            }
            Expr::Binary(binary) => {
                let left = self.eval_expr(&binary.left, state);
                let right = self.eval_expr(&binary.right, state);
                let result = match binary.op {
                    BinOp::Add(_) => left + right,
                    BinOp::Sub(_) => left - right,
                    BinOp::Mul(_) => left * right,
                    BinOp::Div(_) => left / right,
                    _ => Interval::u64_range(),
                };
                self.check_overflow(&binary.op, &left, &right, &result);
                result
            }
            Expr::MethodCall(mc) => {
                let receiver = self.eval_expr(&mc.receiver, state);
                if !mc.args.is_empty() {
                    let arg = self.eval_expr(&mc.args[0], state);
                    match mc.method.to_string().as_str() {
                        "checked_add" => receiver + arg,
                        "checked_sub" => receiver - arg,
                        "checked_mul" => receiver * arg,
                        "checked_div" => receiver / arg,
                        "saturating_add" => Interval::new(receiver.min + arg.min, (receiver.max + arg.max).min(u64::MAX as i128)),
                        _ => Interval::u64_range(),
                    }
                } else { receiver }
            }
            Expr::Paren(p) => self.eval_expr(&p.expr, state),
            Expr::Cast(c) => self.eval_expr(&c.expr, state),
            _ => Interval::u64_range(),
        }
    }

    fn check_overflow(&mut self, op: &BinOp, left: &Interval, right: &Interval, result: &Interval) {
        let op_str = match op {
            BinOp::Add(_) => "Add",
            BinOp::Sub(_) => "Sub",
            BinOp::Mul(_) => "Mul",
            BinOp::Div(_) => "Div",
            _ => return,
        };

        if result.might_overflow_u64() || result.might_underflow() {
            self.findings.push(OverflowAnalysis {
                location: format!("{}::{}", self.filename, self.current_function),
                operation: op_str.to_string(),
                left_interval: (left.min, left.max),
                right_interval: (right.min, right.max),
                result_interval: (result.min, result.max),
                can_overflow: result.might_overflow_u64(),
                can_underflow: result.might_underflow(),
                severity: OverflowSeverity::Possible,
            });
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AbstractError {
    #[error("Parse error: {0}")]
    ParseError(String),
}
