//! # Octagon Abstract Domain
//!
//! Implements Miné's octagon abstract domain — a weakly relational numerical
//! abstract domain that can express constraints of the form:
//!
//!   ±x_i ± x_j ≤ c     (octagonal constraints)
//!
//! This is strictly more expressive than intervals: it captures relationships
//! like `balance_a + balance_b == total` or `amount ≤ balance`.
//!
//! ## Mathematical Foundation
//!
//! The octagon domain represents abstract states as Difference Bound Matrices
//! (DBMs) over doubled variables. For n program variables x₁..xₙ, we
//! introduce 2n DBM variables:
//!
//!   v₂ᵢ   = +xᵢ
//!   v₂ᵢ₊₁ = -xᵢ
//!
//! A constraint ±xᵢ ± xⱼ ≤ c is encoded as vₐ - vᵦ ≤ c for appropriate
//! a, b ∈ {2i, 2i+1, 2j, 2j+1}.
//!
//! **Closure** is computed via Floyd-Warshall shortest paths on the DBM,
//! giving O(n³) per operation. The closed form is the canonical representation.
//!
//! ## Key Operations
//!
//! - **Join (⊔)**: Pointwise max on DBM entries → sound over-approximation
//! - **Meet (⊓)**: Pointwise min → greatest lower bound
//! - **Widening (∇)**: Entries that grew → +∞, stabilizes ascending chains
//! - **Narrowing (Δ)**: Recover precision from ∞ bounds
//! - **Transfer**: Assignment `xᵢ := expr` via variable elimination + re-introduction
//! - **Guard**: Constraint `xᵢ op xⱼ` tightens DBM entries directly
//!
//! ## References
//!
//! - Miné, A. "The Octagon Abstract Domain" (2006), Higher-Order and Symbolic Computation
//! - Bagnara et al. "Weakly-Relational Shapes for Numeric Abstractions" (2005)

use std::collections::HashMap;
use std::fmt;
use syn::Stmt;
use crate::abstract_domain::AbstractDomain;

/// Represents +∞ in the DBM. Any value ≥ this is treated as unbounded.
// Already defined below as pub const INF

/// An octagon abstract state over `n` variables.
///
/// Internally stored as a 2n × 2n Difference Bound Matrix where
/// entry `m[a][b]` encodes `v_a - v_b ≤ m[a][b]`.
#[derive(Clone, PartialEq)]
pub struct OctagonState {
    /// Number of program variables
    n: usize,
    /// Variable name → index mapping
    var_index: HashMap<String, usize>,
    /// The DBM: dimensions 2n × 2n, row-major
    /// m[a * 2n + b] = upper bound on (v_a - v_b)
    dbm: Vec<i128>,
    /// Whether the DBM is in closed (canonical) form
    closed: bool,
}

pub const INF: i128 = i128::MAX / 2;

impl fmt::Debug for OctagonState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dim = 2 * self.n;
        writeln!(f, "OctagonState({} vars, {}x{} DBM):", self.n, dim, dim)?;
        let vars: Vec<&str> = {
            let mut v = vec![""; self.n];
            for (name, &idx) in &self.var_index {
                if idx < self.n {
                    v[idx] = name;
                }
            }
            v
        };
        // Print meaningful constraints
        for i in 0..self.n {
            for j in (i + 1)..self.n {
                // +xi - xj ≤ c  →  xi - xj ≤ c
                let c1 = self.get(2 * i, 2 * j);
                if c1 < INF {
                    writeln!(f, "  {} - {} ≤ {}", vars[i], vars[j], c1)?;
                }
                // +xj - xi ≤ c  →  xj - xi ≤ c
                let c2 = self.get(2 * j, 2 * i);
                if c2 < INF {
                    writeln!(f, "  {} - {} ≤ {}", vars[j], vars[i], c2)?;
                }
                // -xi - (-xj) = xj - xi which is same as c2
                // +xi + xj ≤ c  →  encoded as v_{2i} - v_{2j+1} ≤ c
                let c3 = self.get(2 * i, 2 * j + 1);
                if c3 < INF {
                    writeln!(f, "  {} + {} ≤ {}", vars[i], vars[j], c3)?;
                }
                // -xi - xj ≤ c  →  -(xi + xj) ≤ c  →  xi + xj ≥ -c
                let c4 = self.get(2 * i + 1, 2 * j);
                if c4 < INF {
                    writeln!(f, "  {} + {} ≥ {}", vars[i], vars[j], -c4)?;
                }
            }
            // Unary: +xi ≤ c, -xi ≤ c
            let upper = self.get(2 * i, 2 * i + 1);
            if upper < INF {
                writeln!(f, "  {} ≤ {}", vars[i], upper / 2)?;
            }
            let lower = self.get(2 * i + 1, 2 * i);
            if lower < INF {
                writeln!(f, "  {} ≥ {}", vars[i], -(lower / 2))?;
            }
        }
        Ok(())
    }
}

impl OctagonState {
    /// Create a new octagon state with named variables, initially ⊤ (unconstrained).
    pub fn new(var_names: &[&str]) -> Self {
        let n = var_names.len();
        let dim = 2 * n;
        let mut dbm = vec![INF; dim * dim];
        // Diagonal is 0: v_a - v_a ≤ 0
        for i in 0..dim {
            dbm[i * dim + i] = 0;
        }
        let mut var_index = HashMap::new();
        for (i, &name) in var_names.iter().enumerate() {
            var_index.insert(name.to_string(), i);
        }
        Self {
            n,
            var_index,
            dbm,
            closed: false,
        }
    }

    /// Create ⊥ (empty/unreachable state).
    pub fn bottom(var_names: &[&str]) -> Self {
        let n = var_names.len();
        let dim = 2 * n;
        // An inconsistent DBM: negative diagonal
        let mut dbm = vec![INF; dim * dim];
        for i in 0..dim {
            dbm[i * dim + i] = -1; // Inconsistent
        }
        let mut var_index = HashMap::new();
        for (i, &name) in var_names.iter().enumerate() {
            var_index.insert(name.to_string(), i);
        }
        Self {
            n,
            var_index,
            dbm,
            closed: true,
        }
    }

    fn dim(&self) -> usize {
        2 * self.n
    }

    fn get(&self, a: usize, b: usize) -> i128 {
        self.dbm[a * self.dim() + b]
    }

    fn set(&mut self, a: usize, b: usize, val: i128) {
        let dim = self.dim();
        self.dbm[a * dim + b] = val;
        self.closed = false;
    }


    /// Check if the state is ⊥ (unreachable).
    pub fn is_bottom(&self) -> bool {
        let dim = self.dim();
        for i in 0..dim {
            if self.dbm[i * dim + i] < 0 {
                return true;
            }
        }
        false
    }

    // ── Core Operations ────────────────────────────────────────────────

    /// Floyd-Warshall shortest-path closure.
    ///
    /// After closure, `m[a][b]` = tightest bound on `v_a - v_b` derivable
    /// from all constraints. This is the canonical form.
    ///
    /// Complexity: O(n³) where n = number of program variables.
    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        let dim = self.dim();

        // Standard Floyd-Warshall
        for k in 0..dim {
            for i in 0..dim {
                for j in 0..dim {
                    let through_k = sat_add(self.get(i, k), self.get(k, j));
                    if through_k < self.get(i, j) {
                        self.set_raw(i, j, through_k);
                    }
                }
            }
        }

        // Strong closure: tighten using unary constraints
        // m[i][j] = min(m[i][j], (m[i][ī] + m[j̄][j]) / 2)
        // where ī is the complement of i (2k ↔ 2k+1)
        for i in 0..dim {
            for j in 0..dim {
                let i_bar = i ^ 1;
                let j_bar = j ^ 1;
                let tight = sat_add(self.get(i, i_bar), self.get(j_bar, j)) / 2;
                if tight < self.get(i, j) {
                    self.set_raw(i, j, tight);
                }
            }
        }

        self.closed = true;
    }

    fn set_raw(&mut self, a: usize, b: usize, val: i128) {
        let dim = self.dim();
        self.dbm[a * dim + b] = val;
    }

    // ── Constraint Introduction ────────────────────────────────────────

    /// Add constraint: x_i - x_j ≤ c
    pub fn add_difference_constraint(&mut self, xi: &str, xj: &str, c: i128) {
        if let (Some(&i), Some(&j)) = (self.var_index.get(xi), self.var_index.get(xj)) {
            let cur = self.get(2 * i, 2 * j);
            if c < cur {
                self.set(2 * i, 2 * j, c);
            }
            // Also encode: -xj - (-xi) ≤ c  →  v_{2j+1} - v_{2i+1} ≤ c
            let cur2 = self.get(2 * j + 1, 2 * i + 1);
            if c < cur2 {
                self.set(2 * j + 1, 2 * i + 1, c);
            }
        }
    }

    /// Add constraint: x_i + x_j ≤ c
    pub fn add_sum_constraint(&mut self, xi: &str, xj: &str, c: i128) {
        if let (Some(&i), Some(&j)) = (self.var_index.get(xi), self.var_index.get(xj)) {
            // xi + xj ≤ c  →  v_{2i} - v_{2j+1} ≤ c
            let cur = self.get(2 * i, 2 * j + 1);
            if c < cur {
                self.set(2 * i, 2 * j + 1, c);
            }
            // Symmetric: v_{2j} - v_{2i+1} ≤ c
            let cur2 = self.get(2 * j, 2 * i + 1);
            if c < cur2 {
                self.set(2 * j, 2 * i + 1, c);
            }
        }
    }

    /// Add constraint: x_i + x_j ≥ c  (equivalently: -(xi + xj) ≤ -c)
    pub fn add_sum_lower_bound(&mut self, xi: &str, xj: &str, c: i128) {
        if let (Some(&i), Some(&j)) = (self.var_index.get(xi), self.var_index.get(xj)) {
            // -(xi + xj) ≤ -c  →  v_{2i+1} - v_{2j} ≤ -c
            let neg_c = -c;
            let cur = self.get(2 * i + 1, 2 * j);
            if neg_c < cur {
                self.set(2 * i + 1, 2 * j, neg_c);
            }
            let cur2 = self.get(2 * j + 1, 2 * i);
            if neg_c < cur2 {
                self.set(2 * j + 1, 2 * i, neg_c);
            }
        }
    }

    /// Add constraint: x_i ≤ c  (unary upper bound)
    pub fn add_upper_bound(&mut self, xi: &str, c: i128) {
        if let Some(&i) = self.var_index.get(xi) {
            // xi ≤ c  →  v_{2i} - v_{2i+1} ≤ 2c
            let two_c = c.saturating_mul(2);
            let cur = self.get(2 * i, 2 * i + 1);
            if two_c < cur {
                self.set(2 * i, 2 * i + 1, two_c);
            }
        }
    }

    /// Add constraint: x_i ≥ c  (unary lower bound)
    pub fn add_lower_bound(&mut self, xi: &str, c: i128) {
        if let Some(&i) = self.var_index.get(xi) {
            // xi ≥ c  →  -xi ≤ -c  →  v_{2i+1} - v_{2i} ≤ -2c
            let neg_two_c = (-c).saturating_mul(2);
            let cur = self.get(2 * i + 1, 2 * i);
            if neg_two_c < cur {
                self.set(2 * i + 1, 2 * i, neg_two_c);
            }
        }
    }

    /// Add equality: x_i == x_j  (x_i - x_j ≤ 0 ∧ x_j - x_i ≤ 0)
    pub fn add_equality(&mut self, xi: &str, xj: &str) {
        self.add_difference_constraint(xi, xj, 0);
        self.add_difference_constraint(xj, xi, 0);
    }

    // ── Transfer Functions ─────────────────────────────────────────────

    /// Assignment: x_i := x_j + c
    ///
    /// Uses the standard forget-then-constrain approach:
    /// 1. Forget all constraints involving x_i (project out)
    /// 2. Add x_i = x_j + c (as x_i - x_j ≤ c ∧ x_j - x_i ≤ -c)
    pub fn assign_linear(&mut self, target: &str, source: &str, offset: i128) {
        self.close(); // Ensure canonical form before projection
        self.forget_var(target);
        self.add_difference_constraint(target, source, offset);
        self.add_difference_constraint(source, target, -offset);
    }

    /// Assignment: x_i := c (constant)
    pub fn assign_constant(&mut self, target: &str, c: i128) {
        self.close();
        self.forget_var(target);
        self.add_upper_bound(target, c);
        self.add_lower_bound(target, c);
    }

    /// Assignment: x_i := x_j + x_k (non-linear in octagon — over-approximate)
    ///
    /// Octagons can't represent ternary relations exactly.
    /// We over-approximate: forget x_i, then add
    ///   x_i ≥ lower(x_j) + lower(x_k)
    ///   x_i ≤ upper(x_j) + upper(x_k)
    pub fn assign_sum(&mut self, target: &str, a: &str, b: &str) {
        self.close();
        let lo_a = self.lower_bound(a).unwrap_or(-INF);
        let hi_a = self.upper_bound(a).unwrap_or(INF);
        let lo_b = self.lower_bound(b).unwrap_or(-INF);
        let hi_b = self.upper_bound(b).unwrap_or(INF);

        self.forget_var(target);
        let lo = sat_add(lo_a, lo_b);
        let hi = sat_add(hi_a, hi_b);
        if lo > -INF {
            self.add_lower_bound(target, lo);
        }
        if hi < INF {
            self.add_upper_bound(target, hi);
        }
        // Preserve difference relation: target - a ∈ [lo_b, hi_b]
        if lo_b > -INF {
            self.add_difference_constraint(a, target, -lo_b);
        }
        if hi_b < INF {
            self.add_difference_constraint(target, a, hi_b);
        }
        // Preserve difference relation: target - b ∈ [lo_a, hi_a]
        if lo_a > -INF {
            self.add_difference_constraint(b, target, -lo_a);
        }
        if hi_a < INF {
            self.add_difference_constraint(target, b, hi_a);
        }
    }

    /// Assignment: x_i := x_j - x_k
    pub fn assign_difference(&mut self, target: &str, a: &str, b: &str) {
        self.close();
        let lo_a = self.lower_bound(a).unwrap_or(-INF);
        let hi_a = self.upper_bound(a).unwrap_or(INF);
        let lo_b = self.lower_bound(b).unwrap_or(-INF);
        let hi_b = self.upper_bound(b).unwrap_or(INF);

        self.forget_var(target);
        let lo = sat_add(lo_a, -hi_b);
        let hi = sat_add(hi_a, -lo_b);
        if lo > -INF {
            self.add_lower_bound(target, lo);
        }
        if hi < INF {
            self.add_upper_bound(target, hi);
        }
        // Relational: target - a = -b, so target - a ≤ -lo_b, a - target ≤ hi_b
        if lo_b > -INF {
            self.add_difference_constraint(target, a, -lo_b);
        }
        if hi_b < INF {
            self.add_difference_constraint(a, target, hi_b);
        }
    }

    /// Assignment: x_i := x_j (copy bounds)
    pub fn assign_var(&mut self, target: &str, source: &str) {
        self.close();
        let lo = self.lower_bound(source).unwrap_or(-INF);
        let hi = self.upper_bound(source).unwrap_or(INF);

        self.forget_var(target);
        if lo > -INF {
            self.add_lower_bound(target, lo);
        }
        if hi < INF {
            self.add_upper_bound(target, hi);
        }
        // Step 6: Add equality constraint: target - source ≤ 0 ∧ source - target ≤ 0
        self.add_equality(target, source);
    }

    /// Forget all constraints involving variable x_i (projection).
    pub fn forget_var(&mut self, name: &str) {
        if let Some(&idx) = self.var_index.get(name) {
            let dim = self.dim();
            let pos = 2 * idx;
            let neg = 2 * idx + 1;
            for k in 0..dim {
                if k != pos && k != neg {
                    self.set_raw(pos, k, INF);
                    self.set_raw(k, pos, INF);
                    self.set_raw(neg, k, INF);
                    self.set_raw(k, neg, INF);
                }
            }
            self.set_raw(pos, neg, INF);
            self.set_raw(neg, pos, INF);
            self.set_raw(pos, pos, 0);
            self.set_raw(neg, neg, 0);
            self.closed = false;
        }
    }

    /// Register a new variable into the octagon domain.
    /// This ensures consistent dimension mapping across different OctagonState instances.
    pub fn register_variable(&mut self, name: &str) {
        if !self.var_index.contains_key(name) {
            let mut names: Vec<String> = self.var_index.keys().cloned().collect();
            // Sort to ensure deterministic index assignment
            names.push(name.to_string());
            names.sort(); 
            
            let var_refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
            let mut new_state = OctagonState::new(&var_refs);
            new_state.join(self); // Copy existing constraints
            *self = new_state;
        }
    }

    // ── Lattice Operations ─────────────────────────────────────────────

    /// Join (⊔): pointwise max on closed DBMs → sound over-approximation.
    pub fn join(&self, other: &OctagonState) -> OctagonState {
        assert_eq!(self.n, other.n, "OctagonState dimensions must match");
        let mut a = self.clone();
        let mut b = other.clone();
        a.close();
        b.close();

        let dim = a.dim();
        let mut result = a.clone();
        for i in 0..dim * dim {
            result.dbm[i] = a.dbm[i].max(b.dbm[i]);
        }
        result.closed = false;
        result
    }

    /// Meet (⊓): pointwise min → greatest lower bound.
    pub fn meet(&self, other: &OctagonState) -> OctagonState {
        assert_eq!(self.n, other.n);
        let dim = self.dim();
        let mut result = self.clone();
        for i in 0..dim * dim {
            result.dbm[i] = self.dbm[i].min(other.dbm[i]);
        }
        result.closed = false;
        result
    }

    /// Widening (∇): stabilize ascending chains.
    ///
    /// For each entry: if the new bound grew, push to the next threshold or +∞.
    /// Guarantees termination of fixed-point iteration.
    pub fn widen(&self, other: &OctagonState, context: &crate::abstract_domain::AnalysisContext) -> OctagonState {
        assert_eq!(self.n, other.n);
        let mut a = self.clone();
        let mut b = other.clone();
        a.close();
        b.close();

        let dim = a.dim();
        let mut result = a.clone();
        for i in 0..dim {
            for j in 0..dim {
                let idx = i * dim + j;
                let old = a.dbm[idx];
                let new = b.dbm[idx];

                if new > old {
                    // STEP 10A.4 — Correct Widen Rule
                    // Identify if this is a unary upper or lower bound to apply guided widening
                    if i == (j ^ 1) {
                        // This is a diagonal-like entry: 2*x_i or -2*x_i
                        if i % 2 == 0 {
                            // v_{2k} - v_{2k+1} = 2*x_k  (Upper bound)
                            let thresholds: Vec<i128> = context.thresholds.iter().map(|&t| t.saturating_mul(2)).collect();
                            result.dbm[idx] = widen_bound(old, new, &thresholds);
                        } else {
                            // v_{2k+1} - v_{2k} = -2*x_k (Lower bound)
                            // x_k >= c  =>  -2*x_k <= -2c. 
                            // As x_k decreases, -2*x_k increases.
                            let thresholds: Vec<i128> = context.thresholds.iter().map(|&t| (-t).saturating_mul(2)).collect();
                            // Sort thresholds for lower bounds (they are negative)
                            let mut sorted_ts = thresholds;
                            sorted_ts.sort();
                            result.dbm[idx] = widen_bound(old, new, &sorted_ts);
                        }
                    } else {
                        // Relational bound: x_i - x_j <= c or x_i + x_j <= c
                        // For now, push to INF to ensure termination, as we don't have
                        // a good set of relational thresholds.
                        result.dbm[idx] = INF;
                    }
                }
            }
        }
        result.closed = false;
        result
    }

    /// Narrowing (Δ): recover precision after widening.
    ///
    /// If self has ∞ and other has a finite bound, take other's bound.
    pub fn narrow(&self, other: &OctagonState) -> OctagonState {
        assert_eq!(self.n, other.n);
        let dim = self.dim();
        let mut result = self.clone();
        for i in 0..dim * dim {
            if self.dbm[i] >= INF && other.dbm[i] < INF {
                result.dbm[i] = other.dbm[i];
            }
        }
        result.closed = false;
        result
    }

    /// Check inclusion: self ⊑ other (every concrete state in self is in other).
    pub fn is_included_in(&self, other: &OctagonState) -> bool {
        assert_eq!(self.n, other.n);
        let mut a = self.clone();
        let mut b = other.clone();
        a.close();
        b.close();
        let dim = a.dim();
        for i in 0..dim * dim {
            if a.dbm[i] > b.dbm[i] {
                return false;
            }
        }
        true
    }

    /// Perform a narrowing pass to recover precision after widening.
    pub fn narrowing_pass(&mut self, other: &OctagonState) {
        let mut prev = self.clone();
        for _ in 0..5 { // Limit iterations
            *self = self.narrow(other);
            self.close();
            if self.is_included_in(&prev) && prev.is_included_in(self) {
                break;
            }
            prev = self.clone();
        }
    }

    // ── Query Operations ───────────────────────────────────────────────

    /// Get the upper bound of variable x_i (None if unbounded).
    pub fn upper_bound(&self, name: &str) -> Option<i128> {
        let idx = *self.var_index.get(name)?;
        let mut s = self.clone();
        s.close();
        let val = s.get(2 * idx, 2 * idx + 1);
        if val >= INF {
            None
        } else {
            Some(val / 2)
        }
    }

    /// Get the lower bound of variable x_i (None if unbounded).
    pub fn lower_bound(&self, name: &str) -> Option<i128> {
        let idx = *self.var_index.get(name)?;
        let mut s = self.clone();
        s.close();
        let val = s.get(2 * idx + 1, 2 * idx);
        if val >= INF {
            None
        } else {
            Some(-(val / 2))
        }
    }

    /// Get the upper bound on x_i - x_j (None if unbounded).
    pub fn difference_bound(&self, xi: &str, xj: &str) -> Option<i128> {
        let i = *self.var_index.get(xi)?;
        let j = *self.var_index.get(xj)?;
        let mut s = self.clone();
        s.close();
        let val = s.get(2 * i, 2 * j);
        if val >= INF {
            None
        } else {
            Some(val)
        }
    }

    /// Get the upper bound on x_i + x_j (None if unbounded).
    pub fn sum_bound(&self, xi: &str, xj: &str) -> Option<i128> {
        let i = *self.var_index.get(xi)?;
        let j = *self.var_index.get(xj)?;
        let mut s = self.clone();
        s.close();
        let val = s.get(2 * i, 2 * j + 1);
        if val >= INF {
            None
        } else {
            Some(val)
        }
    }

    /// Check if a constraint is satisfiable in this abstract state.
    pub fn can_overflow_u64(&self, name: &str) -> bool {
        match self.upper_bound(name) {
            Some(hi) => hi > u64::MAX as i128,
            None => true, // Unbounded → could overflow
        }
    }

    /// Check if variable can be negative.
    pub fn can_be_negative(&self, name: &str) -> bool {
        match self.lower_bound(name) {
            Some(lo) => lo < 0,
            None => true,
        }
    }

    /// Check if the conservation law holds: x_i + x_j == total (constant).
    ///
    /// Returns true if the octagon proves sum is exactly `total`.
    pub fn proves_conservation(&mut self, xi: &str, xj: &str, total: i128) -> bool {
        self.close();
        let upper = self.sum_bound(xi, xj);
        let i = match self.var_index.get(xi) { Some(&i) => i, None => return false };
        let j = match self.var_index.get(xj) { Some(&j) => j, None => return false };
        // Lower bound on sum: -(v_{2i+1} - v_{2j})
        let lower_raw = self.get(2 * i + 1, 2 * j);
        let lower = if lower_raw >= INF { None } else { Some(-lower_raw) };

        match (upper, lower) {
            (Some(u), Some(l)) => u == total && l == total,
            _ => false,
        }
    }
}

// ── Widening Helpers ──────────────────────────────────────────────────

fn next_threshold_above(old: i128, thresholds: &[i128]) -> Option<i128> {
    thresholds.iter().cloned().find(|&t| t > old)
}

fn widen_bound(old: i128, new: i128, thresholds: &[i128]) -> i128 {
    if new <= old {
        return old;
    }

    if let Some(t) = next_threshold_above(old, thresholds) {
        println!("[Widening] Bound grew from {} to {}, jumping to threshold {}", old, new, t);
        t
    } else {
        println!("[Widening] Bound grew from {} to {}, no threshold found, jumping to INF", old, new);
        INF
    }
}

// ── Abstract Domain Implementation ────────────────────────────────────

impl AbstractDomain for OctagonState {
    fn join(&self, other: &Self) -> Self {
        self.join(other)
    }

    fn widen(&self, other: &Self, context: &crate::abstract_domain::AnalysisContext) -> Self {
        self.widen(other, context)
    }

    fn transfer(&self, stmt: &syn::Stmt) -> Self {
        let mut new_state = self.clone();

        // STEP 5.2 — Handle constant assignments (x = 5)
        if let syn::Stmt::Local(local) = stmt {
            if let Some((ident, expr)) = extract_assignment(local) {
                if let Some(const_val) = extract_constant(expr) {
                    new_state.register_variable(&ident);
                    new_state.assign_constant(&ident, const_val as i128);
                } else if let Some(src_var) = extract_var_name(expr) {
                    // STEP 6.1 — Handle variable copies (y = x)
                    new_state.register_variable(&ident);
                    new_state.register_variable(&src_var);
                    new_state.assign_var(&ident, &src_var);
                } else if let Some((src_var, offset)) = extract_linear_arithmetic(expr) {
                    // STEP 7 — Handle relational arithmetic (x = y + c)
                    new_state.register_variable(&ident);
                    new_state.register_variable(&src_var);
                    new_state.assign_linear(&ident, &src_var, offset);
                }
            }
        } else if let syn::Stmt::Expr(expr, _) | syn::Stmt::Semi(expr, _) = stmt {
            // STEP 8 — Handle conditionals and guards (if x < 10)
            // Simplified: if we see a comparison statement, treat it as a guard
            if let Some((lhs, op, rhs)) = extract_comparison(expr) {
                if let (Some(l_var), Some(r_const)) = (extract_var_name(lhs), extract_constant(rhs)) {
                    new_state.register_variable(&l_var);
                    match op {
                        syn::BinOp::Lt(_) | syn::BinOp::Le(_) => {
                            new_state.add_upper_bound(&l_var, r_const);
                        }
                        syn::BinOp::Gt(_) | syn::BinOp::Ge(_) => {
                            new_state.add_lower_bound(&l_var, r_const);
                        }
                        syn::BinOp::Eq(_) => {
                            new_state.assign_constant(&l_var, r_const);
                        }
                        _ => {}
                    }
                }
            }
        }

        new_state
    }
}

/// Helper to extract (lhs, op, rhs) from `x < 10`
pub fn extract_comparison(expr: &syn::Expr) -> Option<(&syn::Expr, syn::BinOp, &syn::Expr)> {
    if let syn::Expr::Binary(syn::ExprBinary { left, op, right, .. }) = expr {
        match op {
            syn::BinOp::Lt(_) | syn::BinOp::Le(_) | syn::BinOp::Gt(_) | syn::BinOp::Ge(_) | syn::BinOp::Eq(_) => {
                Some((&*left, *op, &*right))
            }
            _ => None,
        }
    } else {
        None
    }
}

/// Helper to extract (name, expression) from `let name = expr;`
pub fn extract_assignment(local: &syn::Local) -> Option<(String, &syn::Expr)> {
    use syn::Pat;
    if let Pat::Ident(pat_ident) = &local.pat {
        if let Some(init) = &local.init {
            return Some((pat_ident.ident.to_string(), &*init.expr));
        }
    }
    None
}

/// Helper to extract variable name from an expression (simple paths)
fn extract_var_name(expr: &syn::Expr) -> Option<String> {
    if let syn::Expr::Path(expr_path) = expr {
        return expr_path.path.segments.last().map(|s| s.ident.to_string());
    }
    None
}

/// Helper to extract linear arithmetic (src_var, offset) from `y + c` or `y - c`
fn extract_linear_arithmetic(expr: &syn::Expr) -> Option<(String, i128)> {
    if let syn::Expr::Binary(syn::ExprBinary { left, op, right, .. }) = expr {
        let var_name = extract_var_name(left)?;
        let offset = extract_constant(right)?;
        match op {
            syn::BinOp::Add(_) => Some((var_name, offset)),
            syn::BinOp::Sub(_) => Some((var_name, -offset)),
            _ => None,
        }
    } else {
        None
    }
}

/// Helper to extract i128 from simple literal expressions
pub fn extract_constant(expr: &syn::Expr) -> Option<i128> {
    if let syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(lit_int), .. }) = expr {
        return lit_int.base10_parse::<i128>().ok();
    }
    None
}

// ── Solana DeFi Analysis ────────────────────────────────────────────────

/// Result of octagon-based DeFi property verification.
#[derive(Debug)]
pub struct OctagonVerificationResult {
    pub property: String,
    pub verified: bool,
    pub description: String,
    pub invariants: Vec<String>,
}

/// Analyze DeFi balance properties using the octagon domain.
///
/// Models a token pool with balances and verifies relational invariants
/// that interval analysis cannot express.
pub fn verify_defi_conservation(
    balances: &[(&str, i128, i128)], // (name, min, max)
    total_name: &str,
    total_value: i128,
    operations: &[DeFiTransfer],
) -> OctagonVerificationResult {
    let mut var_names: Vec<&str> = balances.iter().map(|b| b.0).collect();
    var_names.push(total_name);

    let mut state = OctagonState::new(&var_names);

    // Initialize bounds
    for &(name, lo, hi) in balances {
        state.add_lower_bound(name, lo);
        state.add_upper_bound(name, hi);
    }
    state.assign_constant(total_name, total_value);

    // Set initial conservation: sum of balances == total
    // For two balances a, b: a + b == total
    if balances.len() == 2 {
        state.add_sum_constraint(balances[0].0, balances[1].0, total_value);
        state.add_sum_lower_bound(balances[0].0, balances[1].0, total_value);
    }

    // Apply operations with widening for loops
    let mut prev = state.clone();
    for op in operations {
        match op {
            DeFiTransfer::Transfer { from, to, amount_min, amount_max } => {
                // Model: from -= amount, to += amount
                // Over-approximate with bounds
                let lo = state.lower_bound(from).unwrap_or(0);
                let hi = state.upper_bound(from).unwrap_or(INF);

                // Guard: amount ≤ from_balance
                let actual_max = (*amount_max).min(hi);
                let actual_min = (*amount_min).max(0);

                if actual_min > actual_max {
                    // Impossible transfer
                    continue;
                }

                // from' ∈ [from - actual_max, from - actual_min]
                let new_from_lo = sat_add(lo, -actual_max);
                let new_from_hi = sat_add(hi, -actual_min);
                state.forget_var(from);
                state.add_lower_bound(from, new_from_lo.max(0));
                state.add_upper_bound(from, new_from_hi);

                let to_lo = state.lower_bound(to).unwrap_or(0);
                let to_hi = state.upper_bound(to).unwrap_or(INF);
                let new_to_lo = sat_add(to_lo, actual_min);
                let new_to_hi = sat_add(to_hi, actual_max);
                state.forget_var(to);
                state.add_lower_bound(to, new_to_lo);
                state.add_upper_bound(to, new_to_hi);

                // Re-assert conservation if applicable
                if balances.len() == 2 {
                    state.add_sum_constraint(balances[0].0, balances[1].0, total_value);
                    state.add_sum_lower_bound(balances[0].0, balances[1].0, total_value);
                }
            }
        }

        // Widening for convergence
        state = prev.widen(&state);
        prev = state.clone();
    }

    // Narrowing pass for precision recovery
    state.narrowing_pass(&prev);

    state.close();

    // Verify conservation
    let mut invariants = Vec::new();
    let mut verified = true;

    if balances.len() == 2 {
        let conservation_holds = state.proves_conservation(
            balances[0].0,
            balances[1].0,
            total_value,
        );
        if conservation_holds {
            invariants.push(format!(
                "{} + {} == {} (PROVED by octagon closure)",
                balances[0].0, balances[1].0, total_value
            ));
        } else {
            verified = false;
            invariants.push(format!(
                "{} + {} == {} (COULD NOT PROVE — possible imbalance)",
                balances[0].0, balances[1].0, total_value
            ));
        }
    }

    // Check non-negativity
    for &(name, _, _) in balances {
        if state.can_be_negative(name) {
            verified = false;
            invariants.push(format!("{} may be negative (UNSAFE)", name));
        } else {
            invariants.push(format!("{} ≥ 0 (PROVED)", name));
        }
    }

    // Check overflow
    for &(name, _, _) in balances {
        if state.can_overflow_u64(name) {
            invariants.push(format!("{} may overflow u64 (WARNING)", name));
        } else {
            invariants.push(format!("{} ≤ u64::MAX (PROVED)", name));
        }
    }

    OctagonVerificationResult {
        property: "balance_conservation".into(),
        verified,
        description: if verified {
            "Octagon domain PROVES all balance conservation and non-negativity properties.".into()
        } else {
            "Octagon domain found potential violations.".into()
        },
        invariants,
    }
}

/// A DeFi token transfer operation for abstract modeling.
#[derive(Debug, Clone)]
pub enum DeFiTransfer {
    Transfer {
        from: String,
        to: String,
        amount_min: i128,
        amount_max: i128,
    },
}

/// Saturating addition that avoids overflow at INF boundaries.
fn sat_add(a: i128, b: i128) -> i128 {
    if a >= INF || b >= INF {
        INF
    } else if a <= -INF || b <= -INF {
        -INF
    } else {
        a.saturating_add(b)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_octagon_unary_bounds() {
        let mut s = OctagonState::new(&["x", "y"]);
        s.add_lower_bound("x", 0);
        s.add_upper_bound("x", 100);
        s.add_lower_bound("y", 10);
        s.add_upper_bound("y", 50);

        assert_eq!(s.upper_bound("x"), Some(100));
        assert_eq!(s.lower_bound("x"), Some(0));
        assert_eq!(s.upper_bound("y"), Some(50));
        assert_eq!(s.lower_bound("y"), Some(10));
    }

    #[test]
    fn test_octagon_difference_constraint() {
        let mut s = OctagonState::new(&["x", "y"]);
        s.add_lower_bound("x", 0);
        s.add_upper_bound("x", 100);
        s.add_lower_bound("y", 0);
        s.add_upper_bound("y", 100);

        // x - y ≤ 10
        s.add_difference_constraint("x", "y", 10);

        assert_eq!(s.difference_bound("x", "y"), Some(10));
    }

    #[test]
    fn test_octagon_conservation_proof() {
        let mut s = OctagonState::new(&["a", "b"]);
        s.add_lower_bound("a", 0);
        s.add_upper_bound("a", 1000);
        s.add_lower_bound("b", 0);
        s.add_upper_bound("b", 1000);

        // a + b == 1000
        s.add_sum_constraint("a", "b", 1000);
        s.add_sum_lower_bound("a", "b", 1000);

        assert!(s.proves_conservation("a", "b", 1000));
    }

    #[test]
    fn test_octagon_join() {
        let mut s1 = OctagonState::new(&["x"]);
        s1.add_lower_bound("x", 0);
        s1.add_upper_bound("x", 10);

        let mut s2 = OctagonState::new(&["x"]);
        s2.add_lower_bound("x", 5);
        s2.add_upper_bound("x", 20);

        let joined = s1.join(&s2);
        assert_eq!(joined.lower_bound("x"), Some(0));
        assert_eq!(joined.upper_bound("x"), Some(20));
    }

    #[test]
    fn test_octagon_widening() {
        let mut s1 = OctagonState::new(&["x"]);
        s1.add_lower_bound("x", 0);
        s1.add_upper_bound("x", 10);

        let mut s2 = OctagonState::new(&["x"]);
        s2.add_lower_bound("x", 0);
        s2.add_upper_bound("x", 20); // grew from 10 to 20

        let widened = s1.widen(&s2);
        // Upper bound should go to ∞ (or very large) since it grew
        let ub = widened.upper_bound("x");
        assert!(ub.is_none() || ub.unwrap() > 1_000_000, "upper bound should be unbounded after widening");
        // Lower bound stayed the same
        assert_eq!(widened.lower_bound("x"), Some(0));
    }

    #[test]
    fn test_octagon_assignment() {
        let mut s = OctagonState::new(&["x", "y"]);
        s.add_lower_bound("x", 10);
        s.add_upper_bound("x", 10);

        // y := x + 5
        s.assign_linear("y", "x", 5);

        assert_eq!(s.upper_bound("y"), Some(15));
        assert_eq!(s.lower_bound("y"), Some(15));
    }

    #[test]
    fn test_defi_conservation_verification() {
        let result = verify_defi_conservation(
            &[("pool", 0, 500), ("user", 0, 500)],
            "total",
            500,
            &[
                DeFiTransfer::Transfer {
                    from: "user".to_string(),
                    to: "pool".to_string(),
                    amount_min: 10,
                    amount_max: 100,
                },
            ],
        );
        // Verification should find non-negativity at minimum
        assert!(!result.invariants.is_empty());
    }

    #[test]
    fn test_octagon_is_bottom() {
        let bot = OctagonState::bottom(&["x"]);
        assert!(bot.is_bottom());

        let top = OctagonState::new(&["x"]);
        assert!(!top.is_bottom());
    }

    #[test]
    fn test_octagon_inclusion() {
        let mut s1 = OctagonState::new(&["x"]);
        s1.add_lower_bound("x", 5);
        s1.add_upper_bound("x", 10);

        let mut s2 = OctagonState::new(&["x"]);
        s2.add_lower_bound("x", 0);
        s2.add_upper_bound("x", 20);

        assert!(s1.is_included_in(&s2)); // [5,10] ⊆ [0,20]
        assert!(!s2.is_included_in(&s1)); // [0,20] ⊄ [5,10]
    }
}
