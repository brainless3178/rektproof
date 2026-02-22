//! # Temporal Logic Model Checker for Solana Transaction Sequences
//!
//! Implements CTL (Computation Tree Logic) model checking for verifying
//! safety and liveness properties over Solana transaction sequences.
//!
//! ## CTL Syntax
//!
//!   φ ::= p                      (atomic proposition)
//!       | ¬φ | φ ∧ φ | φ ∨ φ     (boolean connectives)
//!       | AX φ                    (on ALL next states, φ holds)
//!       | EX φ                    (on SOME next state, φ holds)
//!       | AG φ                    (on ALL paths, φ holds Globally)
//!       | EG φ                    (on SOME path, φ holds Globally)
//!       | AF φ                    (on ALL paths, φ holds Eventually)
//!       | EF φ                    (on SOME path, φ holds Eventually)
//!       | A[φ U ψ]               (on ALL paths, φ Until ψ)
//!       | E[φ U ψ]               (on SOME path, φ Until ψ)
//!
//! ## Solana-Specific Properties
//!
//! - **AG(balance ≥ 0)**: Balance never goes negative (safety)
//! - **AG(deposited → AF(withdrawable))**: Every deposit is eventually withdrawable (liveness)
//! - **AG(upgraded → AX(frozen))**: After upgrade, program is frozen next step (safety)
//! - **¬EF(balance > total_supply)**: No execution can exceed total supply (safety)
//! - **AG(signed → A[authorized U completed])**: Authorization persists until completion
//!
//! ## Algorithm
//!
//! Uses the standard CTL model checking algorithm based on fixed-point
//! computation over the Kripke structure (state graph):
//!
//! - `EF φ = μZ. φ ∨ EX Z` (least fixed point)
//! - `AG φ = νZ. φ ∧ AX Z` (greatest fixed point)
//! - `A[φ U ψ] = μZ. ψ ∨ (φ ∧ AX Z)` (least fixed point)
//!
//! ## References
//!
//! - Clarke, Grumberg, Peled. "Model Checking" (MIT Press, 1999)
//! - Baier, Katoen. "Principles of Model Checking" (MIT Press, 2008)

use std::collections::{HashMap, HashSet, VecDeque};

/// An atomic proposition that can be true or false in a state.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum AtomicProp {
    /// balance(account_name) ≥ value
    BalanceGeq(String, u64),
    /// balance(account_name) == 0
    BalanceZero(String),
    /// An account is signed
    IsSigned(String),
    /// A program is frozen (immutable)
    IsFrozen(String),
    /// A deposit has been made
    Deposited(String),
    /// Funds are withdrawable
    Withdrawable(String),
    /// An instruction has been executed
    InstructionExecuted(String),
    /// Custom boolean predicate
    Custom(String),
}

/// CTL formula.
#[derive(Debug, Clone)]
pub enum CTLFormula {
    Atom(AtomicProp),
    Not(Box<CTLFormula>),
    And(Box<CTLFormula>, Box<CTLFormula>),
    Or(Box<CTLFormula>, Box<CTLFormula>),
    /// AX φ: on ALL successors, φ holds
    AX(Box<CTLFormula>),
    /// EX φ: on SOME successor, φ holds
    EX(Box<CTLFormula>),
    /// AG φ: on ALL paths, φ holds globally
    AG(Box<CTLFormula>),
    /// EG φ: on SOME path, φ holds globally
    EG(Box<CTLFormula>),
    /// AF φ: on ALL paths, φ holds eventually
    AF(Box<CTLFormula>),
    /// EF φ: on SOME path, φ holds eventually
    EF(Box<CTLFormula>),
    /// A[φ U ψ]: on ALL paths, φ until ψ
    AU(Box<CTLFormula>, Box<CTLFormula>),
    /// E[φ U ψ]: on SOME path, φ until ψ
    EU(Box<CTLFormula>, Box<CTLFormula>),
}

impl CTLFormula {
    pub fn atom(p: AtomicProp) -> Self { CTLFormula::Atom(p) }
    pub fn not(f: CTLFormula) -> Self { CTLFormula::Not(Box::new(f)) }
    pub fn and(a: CTLFormula, b: CTLFormula) -> Self { CTLFormula::And(Box::new(a), Box::new(b)) }
    pub fn or(a: CTLFormula, b: CTLFormula) -> Self { CTLFormula::Or(Box::new(a), Box::new(b)) }
    pub fn ax(f: CTLFormula) -> Self { CTLFormula::AX(Box::new(f)) }
    pub fn ex(f: CTLFormula) -> Self { CTLFormula::EX(Box::new(f)) }
    pub fn ag(f: CTLFormula) -> Self { CTLFormula::AG(Box::new(f)) }
    pub fn eg(f: CTLFormula) -> Self { CTLFormula::EG(Box::new(f)) }
    pub fn af(f: CTLFormula) -> Self { CTLFormula::AF(Box::new(f)) }
    pub fn ef(f: CTLFormula) -> Self { CTLFormula::EF(Box::new(f)) }
    pub fn au(a: CTLFormula, b: CTLFormula) -> Self { CTLFormula::AU(Box::new(a), Box::new(b)) }
    pub fn eu(a: CTLFormula, b: CTLFormula) -> Self { CTLFormula::EU(Box::new(a), Box::new(b)) }
}

/// A state in the Kripke structure.
#[derive(Debug, Clone)]
pub struct KripkeState {
    pub id: usize,
    pub name: String,
    /// Atomic propositions true in this state
    pub labels: HashSet<AtomicProp>,
    /// Account balances in this state
    pub balances: HashMap<String, u64>,
}

/// A Kripke structure: states + transitions.
#[derive(Debug)]
pub struct KripkeStructure {
    pub states: Vec<KripkeState>,
    /// Transition relation: state_id → set of successor state_ids
    pub transitions: HashMap<usize, HashSet<usize>>,
    /// Initial states
    pub initial: HashSet<usize>,
}

impl KripkeStructure {
    pub fn new() -> Self {
        Self {
            states: Vec::new(),
            transitions: HashMap::new(),
            initial: HashSet::new(),
        }
    }

    pub fn add_state(&mut self, name: &str, labels: HashSet<AtomicProp>, balances: HashMap<String, u64>) -> usize {
        let id = self.states.len();
        self.states.push(KripkeState {
            id,
            name: name.to_string(),
            labels,
            balances,
        });
        id
    }

    pub fn add_transition(&mut self, from: usize, to: usize) {
        self.transitions.entry(from).or_default().insert(to);
    }

    pub fn set_initial(&mut self, state: usize) {
        self.initial.insert(state);
    }

    /// Get successors of a state.
    fn successors(&self, state: usize) -> HashSet<usize> {
        self.transitions.get(&state).cloned().unwrap_or_default()
    }

    /// Compute the set of predecessors for each state (reverse transitions).
    fn predecessors(&self) -> HashMap<usize, HashSet<usize>> {
        let mut preds: HashMap<usize, HashSet<usize>> = HashMap::new();
        for (&from, tos) in &self.transitions {
            for &to in tos {
                preds.entry(to).or_default().insert(from);
            }
        }
        preds
    }
}

/// CTL Model Checker.
pub struct CTLModelChecker<'a> {
    kripke: &'a KripkeStructure,
}

impl<'a> CTLModelChecker<'a> {
    pub fn new(kripke: &'a KripkeStructure) -> Self {
        Self { kripke }
    }

    /// Check if a CTL formula holds in the initial states.
    ///
    /// Returns the set of states where the formula is satisfied,
    /// plus whether ALL initial states satisfy it.
    pub fn check(&self, formula: &CTLFormula) -> ModelCheckResult {
        let sat_states = self.sat(formula);
        let holds_globally = self.kripke.initial.iter().all(|s| sat_states.contains(s));
        let counterexample = if !holds_globally {
            self.find_counterexample(formula)
        } else {
            None
        };

        ModelCheckResult {
            holds: holds_globally,
            satisfying_states: sat_states.into_iter().collect(),
            total_states: self.kripke.states.len(),
            counterexample,
        }
    }

    /// Compute Sat(φ): the set of states where φ holds.
    ///
    /// This is the core CTL model checking algorithm via structural recursion
    /// on the formula, with fixed-point computations for temporal operators.
    fn sat(&self, formula: &CTLFormula) -> HashSet<usize> {
        let n = self.kripke.states.len();
        let all: HashSet<usize> = (0..n).collect();

        match formula {
            CTLFormula::Atom(p) => {
                self.kripke.states.iter()
                    .filter(|s| self.eval_atom(s, p))
                    .map(|s| s.id)
                    .collect()
            }

            CTLFormula::Not(f) => {
                let inner = self.sat(f);
                all.difference(&inner).copied().collect()
            }

            CTLFormula::And(a, b) => {
                let sa = self.sat(a);
                let sb = self.sat(b);
                sa.intersection(&sb).copied().collect()
            }

            CTLFormula::Or(a, b) => {
                let sa = self.sat(a);
                let sb = self.sat(b);
                sa.union(&sb).copied().collect()
            }

            CTLFormula::EX(f) => {
                // EX φ: states with at least one successor in Sat(φ)
                let inner = self.sat(f);
                self.pre_exists(&inner)
            }

            CTLFormula::AX(f) => {
                // AX φ: states where ALL successors are in Sat(φ)
                let inner = self.sat(f);
                self.pre_forall(&inner)
            }

            CTLFormula::EF(f) => {
                // EF φ = μZ. φ ∨ EX Z  (least fixed point)
                let seed = self.sat(f);
                self.lfp_ex(seed)
            }

            CTLFormula::AG(f) => {
                // AG φ = νZ. φ ∧ AX Z  (greatest fixed point)
                let inner = self.sat(f);
                self.gfp_ax(inner)
            }

            CTLFormula::AF(f) => {
                // AF φ = μZ. φ ∨ AX Z  (least fixed point)
                let seed = self.sat(f);
                self.lfp_ax(seed)
            }

            CTLFormula::EG(f) => {
                // EG φ = νZ. φ ∧ EX Z  (greatest fixed point)
                let inner = self.sat(f);
                self.gfp_ex(inner)
            }

            CTLFormula::EU(phi, psi) => {
                // E[φ U ψ] = μZ. ψ ∨ (φ ∧ EX Z)
                let sat_phi = self.sat(phi);
                let sat_psi = self.sat(psi);
                self.lfp_eu(&sat_phi, sat_psi)
            }

            CTLFormula::AU(phi, psi) => {
                // A[φ U ψ] = μZ. ψ ∨ (φ ∧ AX Z)
                let sat_phi = self.sat(phi);
                let sat_psi = self.sat(psi);
                self.lfp_au(&sat_phi, sat_psi)
            }
        }
    }

    /// Evaluate an atomic proposition in a state.
    fn eval_atom(&self, state: &KripkeState, prop: &AtomicProp) -> bool {
        match prop {
            AtomicProp::BalanceGeq(name, val) => {
                state.balances.get(name).map_or(false, |b| b >= val)
            }
            AtomicProp::BalanceZero(name) => {
                state.balances.get(name).map_or(false, |b| *b == 0)
            }
            _ => state.labels.contains(prop),
        }
    }

    /// Pre∃(S): states with at least one successor in S.
    fn pre_exists(&self, target: &HashSet<usize>) -> HashSet<usize> {
        let mut result = HashSet::new();
        for (from, tos) in &self.kripke.transitions {
            if tos.iter().any(|t| target.contains(t)) {
                result.insert(*from);
            }
        }
        result
    }

    /// Pre∀(S): states where ALL successors are in S.
    fn pre_forall(&self, target: &HashSet<usize>) -> HashSet<usize> {
        let mut result = HashSet::new();
        for state in &self.kripke.states {
            let succs = self.kripke.successors(state.id);
            if succs.is_empty() {
                // Dead-end states: AX φ is vacuously true
                result.insert(state.id);
            } else if succs.iter().all(|s| target.contains(s)) {
                result.insert(state.id);
            }
        }
        result
    }

    /// Least fixed point: μZ. seed ∨ EX Z
    /// (backward BFS from seed through existential predecessors)
    fn lfp_ex(&self, seed: HashSet<usize>) -> HashSet<usize> {
        let preds = self.kripke.predecessors();
        let mut result = seed.clone();
        let mut worklist: VecDeque<usize> = seed.into_iter().collect();

        while let Some(s) = worklist.pop_front() {
            if let Some(pred_set) = preds.get(&s) {
                for &p in pred_set {
                    if result.insert(p) {
                        worklist.push_back(p);
                    }
                }
            }
        }
        result
    }

    /// Greatest fixed point: νZ. constraint ∧ AX Z
    fn gfp_ax(&self, constraint: HashSet<usize>) -> HashSet<usize> {
        let mut result = constraint.clone();
        let mut changed = true;

        while changed {
            changed = false;
            let mut next = HashSet::new();
            for &s in &result {
                let succs = self.kripke.successors(s);
                if succs.is_empty() || succs.iter().all(|t| result.contains(t)) {
                    next.insert(s);
                } else {
                    changed = true;
                }
            }
            result = next;
        }
        result
    }

    /// Least fixed point: μZ. seed ∨ AX Z
    fn lfp_ax(&self, seed: HashSet<usize>) -> HashSet<usize> {
        let mut result = seed.clone();
        let mut changed = true;

        while changed {
            changed = false;
            for state in &self.kripke.states {
                if result.contains(&state.id) {
                    continue;
                }
                let succs = self.kripke.successors(state.id);
                if !succs.is_empty() && succs.iter().all(|s| result.contains(s)) {
                    result.insert(state.id);
                    changed = true;
                }
            }
        }
        result
    }

    /// Greatest fixed point: νZ. constraint ∧ EX Z
    fn gfp_ex(&self, constraint: HashSet<usize>) -> HashSet<usize> {
        let mut result = constraint.clone();
        let mut changed = true;

        while changed {
            changed = false;
            let mut next = HashSet::new();
            for &s in &result {
                let succs = self.kripke.successors(s);
                if succs.is_empty() || succs.iter().any(|t| result.contains(t)) {
                    next.insert(s);
                } else {
                    changed = true;
                }
            }
            result = next;
        }
        result
    }

    /// Least fixed point for E[φ U ψ]: μZ. ψ ∨ (φ ∧ EX Z)
    fn lfp_eu(&self, sat_phi: &HashSet<usize>, sat_psi: HashSet<usize>) -> HashSet<usize> {
        let preds = self.kripke.predecessors();
        let mut result = sat_psi.clone();
        let mut worklist: VecDeque<usize> = sat_psi.into_iter().collect();

        while let Some(s) = worklist.pop_front() {
            if let Some(pred_set) = preds.get(&s) {
                for &p in pred_set {
                    if sat_phi.contains(&p) && result.insert(p) {
                        worklist.push_back(p);
                    }
                }
            }
        }
        result
    }

    /// Least fixed point for A[φ U ψ]: μZ. ψ ∨ (φ ∧ AX Z)
    fn lfp_au(&self, sat_phi: &HashSet<usize>, sat_psi: HashSet<usize>) -> HashSet<usize> {
        // Track how many successors of each state are NOT yet in the result
        let mut count: HashMap<usize, usize> = HashMap::new();
        for state in &self.kripke.states {
            let succs = self.kripke.successors(state.id);
            count.insert(state.id, succs.len());
        }

        let preds = self.kripke.predecessors();
        let mut result = sat_psi.clone();
        let mut worklist: VecDeque<usize> = sat_psi.into_iter().collect();

        while let Some(s) = worklist.pop_front() {
            if let Some(pred_set) = preds.get(&s) {
                for &p in pred_set {
                    if !result.contains(&p) {
                        if let Some(c) = count.get_mut(&p) {
                            *c = c.saturating_sub(1);
                            if *c == 0 && sat_phi.contains(&p) {
                                result.insert(p);
                                worklist.push_back(p);
                            }
                        }
                    }
                }
            }
        }
        result
    }

    /// Find a counterexample trace (for AG properties).
    fn find_counterexample(&self, formula: &CTLFormula) -> Option<Vec<String>> {
        let sat = self.sat(formula);
        for &init in &self.kripke.initial {
            if !sat.contains(&init) {
                return Some(vec![self.kripke.states[init].name.clone()]);
            }
        }
        None
    }
}

/// Result of model checking.
#[derive(Debug)]
pub struct ModelCheckResult {
    pub holds: bool,
    pub satisfying_states: Vec<usize>,
    pub total_states: usize,
    pub counterexample: Option<Vec<String>>,
}

// ── Solana-Specific Model Building ──────────────────────────────────────

/// Build a Kripke structure from a Solana DeFi protocol's state machine.
///
/// Models the protocol as states (account configurations) and transitions
/// (instructions that modify state).
pub fn build_defi_kripke(
    states: &[ProtocolState],
    transitions: &[ProtocolTransition],
) -> KripkeStructure {
    let mut kripke = KripkeStructure::new();

    for ps in states {
        let mut labels = HashSet::new();
        for (acc, bal) in &ps.balances {
            if *bal == 0 {
                labels.insert(AtomicProp::BalanceZero(acc.clone()));
            }
            labels.insert(AtomicProp::BalanceGeq(acc.clone(), *bal));
        }
        for label in &ps.custom_labels {
            labels.insert(AtomicProp::Custom(label.clone()));
        }
        let id = kripke.add_state(&ps.name, labels, ps.balances.clone());
        if ps.is_initial {
            kripke.set_initial(id);
        }
    }

    for t in transitions {
        kripke.add_transition(t.from, t.to);
    }

    kripke
}

/// A protocol state for model building.
#[derive(Debug)]
pub struct ProtocolState {
    pub name: String,
    pub balances: HashMap<String, u64>,
    pub custom_labels: Vec<String>,
    pub is_initial: bool,
}

/// A protocol transition.
#[derive(Debug)]
pub struct ProtocolTransition {
    pub from: usize,
    pub to: usize,
    pub instruction: String,
}

/// Standard Solana safety properties as CTL formulas.
pub fn standard_safety_properties() -> Vec<(String, CTLFormula)> {
    vec![
        (
            "Balance non-negativity: AG(balance ≥ 0)".into(),
            CTLFormula::ag(CTLFormula::atom(AtomicProp::BalanceGeq("vault".into(), 0))),
        ),
        (
            "No token creation: AG(balance ≤ total_supply)".into(),
            CTLFormula::not(CTLFormula::ef(
                CTLFormula::atom(AtomicProp::Custom("exceeds_supply".into()))
            )),
        ),
        (
            "Deposit eventually withdrawable: AG(deposited → AF(withdrawable))".into(),
            CTLFormula::ag(CTLFormula::or(
                CTLFormula::not(CTLFormula::atom(AtomicProp::Deposited("user".into()))),
                CTLFormula::af(CTLFormula::atom(AtomicProp::Withdrawable("user".into()))),
            )),
        ),
    ]
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_simple_kripke() -> KripkeStructure {
        // Simple vault protocol:
        // S0 (init, bal=100) → S1 (deposited, bal=200) → S2 (withdrawn, bal=50) → S0
        let mut k = KripkeStructure::new();

        let mut labels0 = HashSet::new();
        labels0.insert(AtomicProp::BalanceGeq("vault".into(), 0));
        let mut bal0 = HashMap::new();
        bal0.insert("vault".into(), 100);
        let s0 = k.add_state("initial", labels0, bal0);

        let mut labels1 = HashSet::new();
        labels1.insert(AtomicProp::BalanceGeq("vault".into(), 0));
        labels1.insert(AtomicProp::Deposited("user".into()));
        let mut bal1 = HashMap::new();
        bal1.insert("vault".into(), 200);
        let s1 = k.add_state("deposited", labels1, bal1);

        let mut labels2 = HashSet::new();
        labels2.insert(AtomicProp::BalanceGeq("vault".into(), 0));
        labels2.insert(AtomicProp::Withdrawable("user".into()));
        let mut bal2 = HashMap::new();
        bal2.insert("vault".into(), 50);
        let s2 = k.add_state("withdrawn", labels2, bal2);

        k.add_transition(s0, s1);
        k.add_transition(s1, s2);
        k.add_transition(s2, s0);
        k.set_initial(s0);

        k
    }

    #[test]
    fn test_ag_balance_non_negative() {
        let k = make_simple_kripke();
        let mc = CTLModelChecker::new(&k);

        // AG(balance ≥ 0) should hold
        let formula = CTLFormula::ag(
            CTLFormula::atom(AtomicProp::BalanceGeq("vault".into(), 0))
        );
        let result = mc.check(&formula);
        assert!(result.holds, "AG(balance ≥ 0) should hold");
    }

    #[test]
    fn test_ef_deposit() {
        let k = make_simple_kripke();
        let mc = CTLModelChecker::new(&k);

        // EF(deposited) should hold from initial
        let formula = CTLFormula::ef(
            CTLFormula::atom(AtomicProp::Deposited("user".into()))
        );
        let result = mc.check(&formula);
        assert!(result.holds, "EF(deposited) should hold");
    }

    #[test]
    fn test_ag_af_liveness() {
        let k = make_simple_kripke();
        let mc = CTLModelChecker::new(&k);

        // AF(withdrawable) — liveness: eventually funds are withdrawable
        let formula = CTLFormula::af(
            CTLFormula::atom(AtomicProp::Withdrawable("user".into()))
        );
        let result = mc.check(&formula);
        assert!(result.holds, "AF(withdrawable) should hold — cyclic path ensures it");
    }

    #[test]
    fn test_safety_violation_detected() {
        let mut k = KripkeStructure::new();

        let mut labels0 = HashSet::new();
        labels0.insert(AtomicProp::BalanceGeq("vault".into(), 0));
        let mut bal0 = HashMap::new();
        bal0.insert("vault".into(), 100);
        let s0 = k.add_state("safe", labels0, bal0);

        // Bug state: balance is still ≥ 0 but custom "exceeds_supply" is true
        let mut labels1 = HashSet::new();
        labels1.insert(AtomicProp::Custom("exceeds_supply".into()));
        let mut bal1 = HashMap::new();
        bal1.insert("vault".into(), 999999);
        let s1 = k.add_state("overflow", labels1, bal1);

        k.add_transition(s0, s1);
        k.set_initial(s0);

        let mc = CTLModelChecker::new(&k);

        // ¬EF(exceeds_supply) should FAIL
        let formula = CTLFormula::not(CTLFormula::ef(
            CTLFormula::atom(AtomicProp::Custom("exceeds_supply".into()))
        ));
        let result = mc.check(&formula);
        assert!(!result.holds, "Should detect supply overflow reachability");
    }

    #[test]
    fn test_eu_until() {
        let k = make_simple_kripke();
        let mc = CTLModelChecker::new(&k);

        // E[balance ≥ 0 U withdrawable]: there exists a path where balance stays non-negative until withdrawal
        let formula = CTLFormula::eu(
            CTLFormula::atom(AtomicProp::BalanceGeq("vault".into(), 0)),
            CTLFormula::atom(AtomicProp::Withdrawable("user".into())),
        );
        let result = mc.check(&formula);
        assert!(result.holds, "E[balance ≥ 0 U withdrawable] should hold");
    }

    #[test]
    fn test_build_defi_kripke() {
        let states = vec![
            ProtocolState {
                name: "init".into(),
                balances: [("vault".into(), 0)].into(),
                custom_labels: vec![],
                is_initial: true,
            },
            ProtocolState {
                name: "funded".into(),
                balances: [("vault".into(), 1000)].into(),
                custom_labels: vec!["active".into()],
                is_initial: false,
            },
        ];
        let transitions = vec![
            ProtocolTransition { from: 0, to: 1, instruction: "deposit".into() },
        ];

        let k = build_defi_kripke(&states, &transitions);
        assert_eq!(k.states.len(), 2);
        assert!(k.initial.contains(&0));
    }
}
