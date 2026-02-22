//! # Separation Logic for Solana Account Reasoning
//!
//! Implements a fragment of separation logic tailored for Solana's account model.
//! Solana's "accounts must not alias" is precisely a separating conjunction property:
//!
//!   acc₁ ↦ data₁ ∗ acc₂ ↦ data₂    (∗ = separating conjunction)
//!
//! This means acc₁ and acc₂ point to **disjoint** memory regions — exactly what
//! Solana enforces at the runtime level.
//!
//! ## Heap Model
//!
//! The symbolic heap is modeled as:
//!   Σ ::= emp                       (empty heap)
//!       | x ↦ (owner, data, lamports)  (single account points-to)
//!       | Σ₁ ∗ Σ₂                    (separating conjunction: disjoint union)
//!
//! Pure formulas:
//!   Π ::= true | x = y | x ≠ y | Π₁ ∧ Π₂ | x.owner = P
//!
//! ## Entailment Checking
//!
//! Given a precondition and postcondition as symbolic heaps, we check:
//!   Π₁ ; Σ₁ ⊢ Π₂ ; Σ₂
//!
//! Using the frame rule:
//!   If {P} C {Q}, then {P ∗ R} C {Q ∗ R} for any R
//!
//! This enables **compositional reasoning** about Solana instructions:
//! each instruction's effect is specified as a pre/post symbolic heap,
//! and the frame rule lets us verify without knowing the full state.
//!
//! ## References
//!
//! - Reynolds, J.C. "Separation Logic: A Logic for Shared Mutable Data Structures" (2002)
//! - O'Hearn, P. "A Primer on Separation Logic" (2012)

use std::collections::{HashMap, HashSet};
use std::fmt;

/// A Solana public key (symbolic or concrete).
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum SolanaKey {
    /// A concrete base58 pubkey
    Concrete(String),
    /// A symbolic variable representing an unknown key
    Symbolic(String),
    /// A PDA derived from seeds
    PDA { program: Box<SolanaKey>, seeds: Vec<String> },
}

impl fmt::Display for SolanaKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SolanaKey::Concrete(s) => write!(f, "{}", s),
            SolanaKey::Symbolic(s) => write!(f, "?{}", s),
            SolanaKey::PDA { program, seeds } => {
                write!(f, "PDA({}, [{}])", program, seeds.join(", "))
            }
        }
    }
}

/// Describes one account's heap cell in separation logic.
#[derive(Debug, Clone)]
pub struct AccountCell {
    /// The key this cell is addressed by
    pub key: SolanaKey,
    /// The owning program
    pub owner: SolanaKey,
    /// Whether the account is a signer
    pub is_signer: bool,
    /// Whether the account is writable
    pub is_writable: bool,
    /// Symbolic token balance (if applicable)
    pub lamports: SymbolicValue,
    /// Abstract data type
    pub data_type: Option<String>,
    /// Whether this cell has been consumed (for linear resource tracking)
    consumed: bool,
}

/// A symbolic integer value.
#[derive(Debug, Clone)]
pub enum SymbolicValue {
    Concrete(u64),
    Symbolic(String),
    Add(Box<SymbolicValue>, Box<SymbolicValue>),
    Sub(Box<SymbolicValue>, Box<SymbolicValue>),
}

impl fmt::Display for SymbolicValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SymbolicValue::Concrete(n) => write!(f, "{}", n),
            SymbolicValue::Symbolic(s) => write!(f, "?{}", s),
            SymbolicValue::Add(a, b) => write!(f, "({} + {})", a, b),
            SymbolicValue::Sub(a, b) => write!(f, "({} - {})", a, b),
        }
    }
}

/// A pure formula (non-heap constraint).
#[derive(Debug, Clone)]
pub enum PureFormula {
    True,
    False,
    KeyEq(SolanaKey, SolanaKey),
    KeyNeq(SolanaKey, SolanaKey),
    OwnerIs(SolanaKey, SolanaKey),
    IsSigner(SolanaKey),
    IsWritable(SolanaKey),
    And(Vec<PureFormula>),
    ValueLeq(SymbolicValue, SymbolicValue),
    ValueGeq(SymbolicValue, SymbolicValue),
}

/// A symbolic heap: a collection of account cells under separating conjunction.
///
/// The key invariant: all cells in the heap are for **distinct** keys.
/// This is the separation logic property — the heap IS a separating conjunction.
#[derive(Debug, Clone)]
pub struct SymbolicHeap {
    /// Account cells: key_name → cell
    cells: HashMap<String, AccountCell>,
    /// Pure constraints
    pure: Vec<PureFormula>,
}

impl SymbolicHeap {
    /// Empty heap (emp).
    pub fn emp() -> Self {
        Self {
            cells: HashMap::new(),
            pure: vec![],
        }
    }

    /// Add an account cell (extends the separating conjunction).
    ///
    /// Returns Err if the key already exists (violates separation!).
    pub fn add_cell(&mut self, name: &str, cell: AccountCell) -> Result<(), SepLogicError> {
        if self.cells.contains_key(name) {
            return Err(SepLogicError::AliasingViolation {
                key: name.to_string(),
                detail: "Account already exists in heap — would violate separating conjunction"
                    .to_string(),
            });
        }
        self.cells.insert(name.to_string(), cell);
        Ok(())
    }

    /// Remove and return an account cell (consuming the resource).
    pub fn consume_cell(&mut self, name: &str) -> Option<AccountCell> {
        self.cells.get_mut(name).map(|cell| {
            cell.consumed = true;
            cell.clone()
        })
    }

    /// Add a pure constraint.
    pub fn add_pure(&mut self, formula: PureFormula) {
        self.pure.push(formula);
    }

    /// Separating conjunction: self ∗ other.
    ///
    /// Requires disjoint domains (no key appears in both heaps).
    pub fn star(&self, other: &SymbolicHeap) -> Result<SymbolicHeap, SepLogicError> {
        let mut result = self.clone();

        for (name, cell) in &other.cells {
            if result.cells.contains_key(name) {
                return Err(SepLogicError::AliasingViolation {
                    key: name.clone(),
                    detail: format!(
                        "Separating conjunction violated: '{}' appears in both heaps",
                        name
                    ),
                });
            }
            result.cells.insert(name.clone(), cell.clone());
        }

        result.pure.extend(other.pure.iter().cloned());
        Ok(result)
    }

    /// Check if this heap entails another: self ⊢ other.
    ///
    /// For each cell in `other`, there must be a matching cell in `self`
    /// with compatible constraints. The remaining cells form the frame.
    pub fn entails(&self, other: &SymbolicHeap) -> EntailmentResult {
        let mut frame_cells = self.cells.clone();
        let mut missing = Vec::new();
        let mut mismatched = Vec::new();

        for (name, required_cell) in &other.cells {
            match frame_cells.remove(name) {
                Some(actual_cell) => {
                    // Check owner match
                    if !keys_may_equal(&actual_cell.owner, &required_cell.owner) {
                        mismatched.push(format!(
                            "{}: owner mismatch (have {}, need {})",
                            name, actual_cell.owner, required_cell.owner
                        ));
                    }
                    // Check signer requirement
                    if required_cell.is_signer && !actual_cell.is_signer {
                        mismatched.push(format!("{}: required to be signer", name));
                    }
                    // Check writable requirement
                    if required_cell.is_writable && !actual_cell.is_writable {
                        mismatched.push(format!("{}: required to be writable", name));
                    }
                }
                None => {
                    missing.push(name.clone());
                }
            }
        }

        if missing.is_empty() && mismatched.is_empty() {
            EntailmentResult::Valid {
                frame: SymbolicHeap {
                    cells: frame_cells,
                    pure: vec![],
                },
            }
        } else {
            EntailmentResult::Invalid {
                missing_accounts: missing,
                constraint_violations: mismatched,
            }
        }
    }

    /// Get all account names in this heap.
    pub fn account_names(&self) -> Vec<&str> {
        self.cells.keys().map(|s| s.as_str()).collect()
    }

    /// Check the fundamental no-aliasing property for all pairs.
    pub fn check_no_aliasing(&self) -> Vec<AliasingViolation> {
        let mut violations = Vec::new();
        let names: Vec<&String> = self.cells.keys().collect();

        for i in 0..names.len() {
            for j in (i + 1)..names.len() {
                let cell_i = &self.cells[names[i]];
                let cell_j = &self.cells[names[j]];

                if keys_must_equal(&cell_i.key, &cell_j.key) {
                    violations.push(AliasingViolation {
                        account_a: names[i].clone(),
                        account_b: names[j].clone(),
                        reason: format!(
                            "Keys {} and {} are provably equal — \
                             violates separating conjunction (∗). \
                             An attacker could pass the same account for both.",
                            cell_i.key, cell_j.key
                        ),
                    });
                } else if keys_may_equal(&cell_i.key, &cell_j.key)
                    && !keys_provably_distinct(&cell_i, &cell_j, &self.pure)
                {
                    violations.push(AliasingViolation {
                        account_a: names[i].clone(),
                        account_b: names[j].clone(),
                        reason: format!(
                            "Keys {} and {} MIGHT alias — \
                             no constraint (has_one, #[account] seed, owner check) \
                             enforces distinctness. Consider adding a ≠ check.",
                            cell_i.key, cell_j.key
                        ),
                    });
                }
            }
        }

        violations
    }
}

/// Result of entailment checking.
#[derive(Debug)]
pub enum EntailmentResult {
    /// Entailment holds, with the remaining frame.
    Valid { frame: SymbolicHeap },
    /// Entailment fails.
    Invalid {
        missing_accounts: Vec<String>,
        constraint_violations: Vec<String>,
    },
}

/// A detected aliasing violation.
#[derive(Debug, Clone)]
pub struct AliasingViolation {
    pub account_a: String,
    pub account_b: String,
    pub reason: String,
}

/// Errors in separation logic operations.
#[derive(Debug, Clone)]
pub enum SepLogicError {
    AliasingViolation { key: String, detail: String },
    FrameRuleViolation { detail: String },
}

impl fmt::Display for SepLogicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SepLogicError::AliasingViolation { key, detail } => {
                write!(f, "Aliasing violation on '{}': {}", key, detail)
            }
            SepLogicError::FrameRuleViolation { detail } => {
                write!(f, "Frame rule violation: {}", detail)
            }
        }
    }
}

// ── Specification Language ──────────────────────────────────────────────

/// A Solana instruction specification in separation logic.
///
/// {Pre} instruction {Post}
///
/// The frame rule allows composing specs:
/// If {P} C {Q}, then {P ∗ R} C {Q ∗ R}
#[derive(Debug, Clone)]
pub struct InstructionSpec {
    pub name: String,
    pub precondition: SymbolicHeap,
    pub postcondition: SymbolicHeap,
    pub modifies: Vec<String>, // Account names modified
}

impl InstructionSpec {
    /// Verify that a concrete set of accounts satisfies the precondition.
    pub fn check_precondition(&self, accounts: &SymbolicHeap) -> EntailmentResult {
        accounts.entails(&self.precondition)
    }

    /// Apply the frame rule: {Pre ∗ Frame} C {Post ∗ Frame}.
    pub fn apply_with_frame(&self, frame: &SymbolicHeap) -> Result<SymbolicHeap, SepLogicError> {
        self.postcondition.star(frame)
    }
}

/// Verify a sequence of instructions using separation logic.
///
/// Threads the symbolic heap through each instruction, checking
/// preconditions and computing postconditions via the frame rule.
pub fn verify_instruction_sequence(
    initial_state: SymbolicHeap,
    instructions: &[InstructionSpec],
) -> SequenceVerificationResult {
    let mut current = initial_state;
    let mut steps = Vec::new();

    for (i, spec) in instructions.iter().enumerate() {
        // Check precondition
        let entailment = spec.check_precondition(&current);
        match entailment {
            EntailmentResult::Valid { frame } => {
                // Apply postcondition ∗ frame
                match spec.apply_with_frame(&frame) {
                    Ok(new_state) => {
                        steps.push(VerificationStep {
                            instruction: spec.name.clone(),
                            step_index: i,
                            precondition_met: true,
                            frame_accounts: frame.account_names().iter().map(|s| s.to_string()).collect(),
                            aliasing_violations: vec![],
                        });
                        current = new_state;
                    }
                    Err(e) => {
                        return SequenceVerificationResult {
                            verified: false,
                            steps,
                            error: Some(format!("Frame rule failed at step {}: {}", i, e)),
                            final_state: current,
                            aliasing_violations: vec![],
                        };
                    }
                }
            }
            EntailmentResult::Invalid {
                missing_accounts,
                constraint_violations,
            } => {
                return SequenceVerificationResult {
                    verified: false,
                    steps,
                    error: Some(format!(
                        "Precondition failed at step {} ({}): missing={:?}, violations={:?}",
                        i, spec.name, missing_accounts, constraint_violations
                    )),
                    final_state: current,
                    aliasing_violations: vec![],
                };
            }
        }
    }

    // Final no-aliasing check
    let aliasing_violations = current.check_no_aliasing();

    SequenceVerificationResult {
        verified: aliasing_violations.is_empty(),
        steps,
        error: if aliasing_violations.is_empty() {
            None
        } else {
            Some(format!(
                "{} aliasing violations found in final state",
                aliasing_violations.len()
            ))
        },
        final_state: current,
        aliasing_violations,
    }
}

/// Result of verifying an instruction sequence.
#[derive(Debug)]
pub struct SequenceVerificationResult {
    pub verified: bool,
    pub steps: Vec<VerificationStep>,
    pub error: Option<String>,
    pub final_state: SymbolicHeap,
    pub aliasing_violations: Vec<AliasingViolation>,
}

/// One step in the sequence verification.
#[derive(Debug)]
pub struct VerificationStep {
    pub instruction: String,
    pub step_index: usize,
    pub precondition_met: bool,
    pub frame_accounts: Vec<String>,
    pub aliasing_violations: Vec<AliasingViolation>,
}

// ── Helper Functions ────────────────────────────────────────────────────

fn keys_may_equal(a: &SolanaKey, b: &SolanaKey) -> bool {
    match (a, b) {
        (SolanaKey::Concrete(x), SolanaKey::Concrete(y)) => x == y,
        (SolanaKey::Symbolic(_), _) | (_, SolanaKey::Symbolic(_)) => true,
        (SolanaKey::PDA { program: p1, seeds: s1 }, SolanaKey::PDA { program: p2, seeds: s2 }) => {
            keys_may_equal(p1, p2) && s1 == s2
        }
        _ => false,
    }
}

fn keys_must_equal(a: &SolanaKey, b: &SolanaKey) -> bool {
    match (a, b) {
        (SolanaKey::Concrete(x), SolanaKey::Concrete(y)) => x == y,
        (SolanaKey::PDA { program: p1, seeds: s1 }, SolanaKey::PDA { program: p2, seeds: s2 }) => {
            keys_must_equal(p1, p2) && s1 == s2
        }
        _ => false,
    }
}

fn keys_provably_distinct(a: &AccountCell, b: &AccountCell, pure: &[PureFormula]) -> bool {
    // Different concrete keys
    if let (SolanaKey::Concrete(x), SolanaKey::Concrete(y)) = (&a.key, &b.key) {
        if x != y {
            return true;
        }
    }

    // Different owners → might still alias the same account
    // Different PDAs with different seeds → provably distinct
    if let (
        SolanaKey::PDA { program: p1, seeds: s1 },
        SolanaKey::PDA { program: p2, seeds: s2 },
    ) = (&a.key, &b.key) {
        if keys_must_equal(p1, p2) && s1 != s2 {
            return true; // Same program, different seeds → different PDAs
        }
    }

    // Check pure constraints for explicit disequality
    for formula in pure {
        if let PureFormula::KeyNeq(k1, k2) = formula {
            if (keys_must_equal(k1, &a.key) && keys_must_equal(k2, &b.key))
                || (keys_must_equal(k1, &b.key) && keys_must_equal(k2, &a.key))
            {
                return true;
            }
        }
    }

    false
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_account(name: &str, owner: &str, signer: bool, writable: bool) -> AccountCell {
        AccountCell {
            key: SolanaKey::Symbolic(name.to_string()),
            owner: SolanaKey::Concrete(owner.to_string()),
            is_signer: signer,
            is_writable: writable,
            lamports: SymbolicValue::Symbolic(format!("{}_lamports", name)),
            data_type: None,
            consumed: false,
        }
    }

    #[test]
    fn test_separating_conjunction_disjoint() {
        let mut h1 = SymbolicHeap::emp();
        h1.add_cell("vault", make_account("vault", "program_id", false, true)).unwrap();

        let mut h2 = SymbolicHeap::emp();
        h2.add_cell("user", make_account("user", "system", true, false)).unwrap();

        let combined = h1.star(&h2);
        assert!(combined.is_ok());
        assert_eq!(combined.unwrap().cells.len(), 2);
    }

    #[test]
    fn test_separating_conjunction_aliasing_rejected() {
        let mut h1 = SymbolicHeap::emp();
        h1.add_cell("vault", make_account("vault", "program_id", false, true)).unwrap();

        let mut h2 = SymbolicHeap::emp();
        h2.add_cell("vault", make_account("vault", "program_id", false, true)).unwrap();

        let combined = h1.star(&h2);
        assert!(combined.is_err());
    }

    #[test]
    fn test_entailment_valid() {
        let mut actual = SymbolicHeap::emp();
        actual.add_cell("vault", make_account("vault", "prog", false, true)).unwrap();
        actual.add_cell("user", make_account("user", "system", true, false)).unwrap();
        actual.add_cell("extra", make_account("extra", "prog", false, false)).unwrap();

        let mut required = SymbolicHeap::emp();
        required.add_cell("vault", make_account("vault", "prog", false, true)).unwrap();
        required.add_cell("user", make_account("user", "system", true, false)).unwrap();

        let result = actual.entails(&required);
        match result {
            EntailmentResult::Valid { frame } => {
                assert_eq!(frame.cells.len(), 1); // "extra" is the frame
                assert!(frame.cells.contains_key("extra"));
            }
            _ => panic!("Entailment should be valid"),
        }
    }

    #[test]
    fn test_entailment_missing_account() {
        let mut actual = SymbolicHeap::emp();
        actual.add_cell("vault", make_account("vault", "prog", false, true)).unwrap();

        let mut required = SymbolicHeap::emp();
        required.add_cell("vault", make_account("vault", "prog", false, true)).unwrap();
        required.add_cell("user", make_account("user", "system", true, false)).unwrap();

        let result = actual.entails(&required);
        match result {
            EntailmentResult::Invalid { missing_accounts, .. } => {
                assert!(missing_accounts.contains(&"user".to_string()));
            }
            _ => panic!("Should be invalid — missing 'user' account"),
        }
    }

    #[test]
    fn test_aliasing_detection() {
        let mut heap = SymbolicHeap::emp();

        // Two accounts with symbolic keys that COULD alias
        let cell1 = AccountCell {
            key: SolanaKey::Symbolic("key_a".into()),
            owner: SolanaKey::Concrete("prog".into()),
            is_signer: false,
            is_writable: true,
            lamports: SymbolicValue::Symbolic("lam_a".into()),
            data_type: None,
            consumed: false,
        };
        let cell2 = AccountCell {
            key: SolanaKey::Symbolic("key_b".into()),
            owner: SolanaKey::Concrete("prog".into()),
            is_signer: false,
            is_writable: true,
            lamports: SymbolicValue::Symbolic("lam_b".into()),
            data_type: None,
            consumed: false,
        };

        heap.add_cell("authority", cell1).unwrap();
        heap.add_cell("target", cell2).unwrap();

        let violations = heap.check_no_aliasing();
        // Symbolic keys might alias — should be flagged
        assert!(!violations.is_empty());
    }

    #[test]
    fn test_pda_distinctness() {
        let mut heap = SymbolicHeap::emp();

        let prog = SolanaKey::Concrete("my_program".into());
        let cell1 = AccountCell {
            key: SolanaKey::PDA { program: Box::new(prog.clone()), seeds: vec!["pool".into(), "a".into()] },
            owner: SolanaKey::Concrete("prog".into()),
            is_signer: false,
            is_writable: true,
            lamports: SymbolicValue::Concrete(1000),
            data_type: None,
            consumed: false,
        };
        let cell2 = AccountCell {
            key: SolanaKey::PDA { program: Box::new(prog.clone()), seeds: vec!["pool".into(), "b".into()] },
            owner: SolanaKey::Concrete("prog".into()),
            is_signer: false,
            is_writable: true,
            lamports: SymbolicValue::Concrete(2000),
            data_type: None,
            consumed: false,
        };

        heap.add_cell("pool_a", cell1).unwrap();
        heap.add_cell("pool_b", cell2).unwrap();

        let violations = heap.check_no_aliasing();
        // PDAs with same program but different seeds → provably distinct
        assert!(violations.is_empty());
    }

    #[test]
    fn test_instruction_spec_verification() {
        // Spec: transfer requires a signer and writable vault
        let mut pre = SymbolicHeap::emp();
        pre.add_cell("vault", make_account("vault", "prog", false, true)).unwrap();
        pre.add_cell("authority", make_account("authority", "system", true, false)).unwrap();

        let mut post = SymbolicHeap::emp();
        post.add_cell("vault", make_account("vault", "prog", false, true)).unwrap();
        post.add_cell("authority", make_account("authority", "system", true, false)).unwrap();

        let spec = InstructionSpec {
            name: "transfer".into(),
            precondition: pre,
            postcondition: post,
            modifies: vec!["vault".into()],
        };

        // Actual state has all required + extra accounts
        let mut state = SymbolicHeap::emp();
        state.add_cell("vault", make_account("vault", "prog", false, true)).unwrap();
        state.add_cell("authority", make_account("authority", "system", true, false)).unwrap();
        state.add_cell("token_program", make_account("token_prog", "bpf_loader", false, false)).unwrap();

        let result = verify_instruction_sequence(state, &[spec]);
        // Sequence should complete all steps
        assert_eq!(result.steps.len(), 1);
        assert!(result.steps[0].precondition_met);
    }
}
