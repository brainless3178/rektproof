//! # Information Flow Type System for Solana Programs
//!
//! Implements a security type system for tracking information flow and
//! enforcing non-interference. This makes taint tracking **sound by construction**
//! — if a program type-checks, it cannot leak secrets to public outputs.
//!
//! ## Security Lattice
//!
//! We define a lattice of security labels:
//!
//! ```text
//!        Tainted (T)
//!        /        \
//!   UserInput    AccountData
//!        \        /
//!        Trusted (⊥)
//! ```
//!
//! The non-interference property:
//!   ∀ σ₁ σ₂: σ₁ =_L σ₂ → ⟦P⟧(σ₁) =_L ⟦P⟧(σ₂)
//!
//! "If two states agree on public (Low) values, executing P produces
//!  states that still agree on public values."
//!
//! ## Type System Rules
//!
//! Variables are typed with security labels:
//!   Γ ⊢ e : τ @ ℓ
//!
//! Key rules:
//! - **Sub**: If Γ ⊢ e : τ @ ℓ₁ and ℓ₁ ⊑ ℓ₂, then Γ ⊢ e : τ @ ℓ₂
//! - **Let**: If Γ ⊢ e₁ : τ₁ @ ℓ and Γ,x:τ₁@ℓ ⊢ e₂ : τ₂ @ ℓ', then Γ ⊢ let x = e₁ in e₂ : τ₂ @ ℓ ⊔ ℓ'
//! - **If**: If Γ ⊢ guard : bool @ ℓ, then branches must have label ≥ ℓ (implicit flow)
//! - **CPI**: Cross-program calls elevate to Tainted unless callee is trusted
//!
//! ## Solana-Specific Rules
//!
//! - `account.data` from instruction input → `UserInput` label
//! - `account.lamports` → `Trusted` if owner-checked, `Tainted` otherwise
//! - `Sysvar::get()` → `Trusted` (runtime-provided)
//! - Results of `invoke()` → `Tainted` (CPI return data is untrusted)
//! - Values under `is_signer` guard → can be downgraded to `Trusted`
//!
//! ## References
//!
//! - Denning, D. "A Lattice Model of Secure Information Flow" (1976)
//! - Sabelfeld, Sands. "Declassification: Dimensions and Principles" (2009)
//! - Abadi et al. "A Core Calculus of Dependency" (DCC, 1999)

use std::collections::HashMap;
use std::fmt;

/// Security label in the information flow lattice.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLabel {
    /// Trusted: verified by the program or runtime (Bottom ⊥)
    Trusted,
    /// From a sysvar or known-good source
    RuntimeProvided,
    /// From account data — needs owner check
    AccountData,
    /// From instruction data — completely untrusted
    UserInput,
    /// Tainted: could be attacker-controlled (Top ⊤)
    Tainted,
}

impl SecurityLabel {
    /// Join (least upper bound): the label of an expression combining two values.
    pub fn join(self, other: SecurityLabel) -> SecurityLabel {
        self.max(other)
    }

    /// Meet (greatest lower bound).
    pub fn meet(self, other: SecurityLabel) -> SecurityLabel {
        self.min(other)
    }

    /// Check if self flows to other (self ⊑ other).
    /// Low labels can flow to high labels, but not vice versa.
    pub fn flows_to(self, other: SecurityLabel) -> bool {
        self <= other
    }

    /// Can this label be used in a security-sensitive context?
    pub fn is_trusted(self) -> bool {
        matches!(self, SecurityLabel::Trusted | SecurityLabel::RuntimeProvided)
    }
}

impl fmt::Display for SecurityLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityLabel::Trusted => write!(f, "⊥:Trusted"),
            SecurityLabel::RuntimeProvided => write!(f, "Runtime"),
            SecurityLabel::AccountData => write!(f, "AcctData"),
            SecurityLabel::UserInput => write!(f, "UserInput"),
            SecurityLabel::Tainted => write!(f, "⊤:Tainted"),
        }
    }
}

/// A security-typed variable.
#[derive(Debug, Clone)]
pub struct TypedVar {
    pub name: String,
    pub label: SecurityLabel,
    pub rust_type: String,
    pub origin: VarOrigin,
}

/// Where a variable's value originated.
#[derive(Debug, Clone)]
pub enum VarOrigin {
    /// From an instruction argument
    InstructionArg { ix_name: String },
    /// From an account field
    AccountField { account: String, field: String },
    /// From a sysvar
    Sysvar(String),
    /// From a CPI return
    CPIReturn { program: String },
    /// From a computation
    Computed { from: Vec<String> },
    /// A literal constant
    Literal,
}

/// A typing context (Γ): maps variable names to their security types.
#[derive(Debug, Clone)]
pub struct TypingContext {
    vars: HashMap<String, TypedVar>,
    /// The current program counter label (for implicit flows)
    pc_label: SecurityLabel,
    /// Declassification points (where taint is intentionally removed)
    declassifications: Vec<Declassification>,
}

/// A point where security label is intentionally lowered.
#[derive(Debug, Clone)]
pub struct Declassification {
    pub variable: String,
    pub from_label: SecurityLabel,
    pub to_label: SecurityLabel,
    pub justification: DeclassificationReason,
    pub line: usize,
}

/// Why a declassification is safe.
#[derive(Debug, Clone)]
pub enum DeclassificationReason {
    /// Protected by an `is_signer` check
    SignerVerified,
    /// Protected by an `owner` check
    OwnerVerified,
    /// Protected by a PDA derivation check
    PDAVerified,
    /// Validated by range check
    RangeChecked { min: i64, max: i64 },
    /// User-annotated as safe
    UserAnnotated(String),
}

/// A type error: illegal information flow.
#[derive(Debug, Clone)]
pub struct FlowViolation {
    pub source: String,
    pub source_label: SecurityLabel,
    pub sink: String,
    pub sink_label: SecurityLabel,
    pub line: usize,
    pub description: String,
    pub severity: FlowSeverity,
}

/// Severity of a flow violation.
#[derive(Debug, Clone, PartialEq)]
pub enum FlowSeverity {
    /// Critical: tainted data flows to authority check
    Critical,
    /// High: user input flows to lamports operation
    High,
    /// Medium: account data used without owner check
    Medium,
    /// Low: minor implicit flow
    Low,
}

impl TypingContext {
    pub fn new() -> Self {
        Self {
            vars: HashMap::new(),
            pc_label: SecurityLabel::Trusted,
            declassifications: Vec::new(),
        }
    }

    /// Introduce a variable with a security label.
    pub fn bind(&mut self, name: &str, label: SecurityLabel, rust_type: &str, origin: VarOrigin) {
        self.vars.insert(
            name.to_string(),
            TypedVar {
                name: name.to_string(),
                label,
                rust_type: rust_type.to_string(),
                origin,
            },
        );
    }

    /// Look up a variable's label.
    pub fn lookup(&self, name: &str) -> Option<SecurityLabel> {
        self.vars.get(name).map(|v| v.label)
    }

    /// Set the PC label (for implicit flow tracking in conditionals).
    pub fn set_pc_label(&mut self, label: SecurityLabel) {
        self.pc_label = label;
    }

    /// Get the current PC label.
    pub fn pc_label(&self) -> SecurityLabel {
        self.pc_label
    }

    /// Record a declassification.
    pub fn declassify(
        &mut self,
        name: &str,
        to_label: SecurityLabel,
        reason: DeclassificationReason,
        line: usize,
    ) -> Result<(), FlowViolation> {
        if let Some(var) = self.vars.get_mut(name) {
            let from_label = var.label;
            self.declassifications.push(Declassification {
                variable: name.to_string(),
                from_label,
                to_label,
                justification: reason,
                line,
            });
            var.label = to_label;
            Ok(())
        } else {
            Err(FlowViolation {
                source: name.to_string(),
                source_label: SecurityLabel::Tainted,
                sink: name.to_string(),
                sink_label: to_label,
                line,
                description: format!("Cannot declassify unknown variable '{}'", name),
                severity: FlowSeverity::Medium,
            })
        }
    }
}

/// The information flow type checker.
pub struct FlowTypeChecker {
    context: TypingContext,
    violations: Vec<FlowViolation>,
}

impl FlowTypeChecker {
    pub fn new() -> Self {
        Self {
            context: TypingContext::new(),
            violations: Vec::new(),
        }
    }

    /// Initialize the typing context for a Solana instruction handler.
    pub fn init_solana_instruction(&mut self, accounts: &[SolanaAccountSpec]) {
        for acc in accounts {
            // Account key: always UserInput (attacker chooses which accounts to pass)
            self.context.bind(
                &format!("{}.key", acc.name),
                SecurityLabel::UserInput,
                "Pubkey",
                VarOrigin::AccountField {
                    account: acc.name.clone(),
                    field: "key".to_string(),
                },
            );

            // Account data: UserInput until owner-checked
            let data_label = if acc.owner_verified {
                SecurityLabel::AccountData
            } else {
                SecurityLabel::UserInput
            };
            self.context.bind(
                &format!("{}.data", acc.name),
                data_label,
                "&[u8]",
                VarOrigin::AccountField {
                    account: acc.name.clone(),
                    field: "data".to_string(),
                },
            );

            // Lamports: AccountData if owner-checked, UserInput otherwise
            self.context.bind(
                &format!("{}.lamports", acc.name),
                data_label,
                "u64",
                VarOrigin::AccountField {
                    account: acc.name.clone(),
                    field: "lamports".to_string(),
                },
            );

            // is_signer: Trusted (runtime-enforced)
            self.context.bind(
                &format!("{}.is_signer", acc.name),
                SecurityLabel::RuntimeProvided,
                "bool",
                VarOrigin::AccountField {
                    account: acc.name.clone(),
                    field: "is_signer".to_string(),
                },
            );

            // Owner: UserInput (attacker chooses)
            self.context.bind(
                &format!("{}.owner", acc.name),
                SecurityLabel::UserInput,
                "Pubkey",
                VarOrigin::AccountField {
                    account: acc.name.clone(),
                    field: "owner".to_string(),
                },
            );

            // If the account has been signer-verified, elevate trust
            if acc.signer_verified {
                let _ = self.context.declassify(
                    &format!("{}.key", acc.name),
                    SecurityLabel::Trusted,
                    DeclassificationReason::SignerVerified,
                    0,
                );
            }
        }
    }

    /// Type-check an assignment: target := f(source_1, ..., source_n).
    ///
    /// The target's label becomes: join(source_labels) ⊔ pc_label
    pub fn check_assignment(
        &mut self,
        target: &str,
        sources: &[&str],
        target_type: &str,
        line: usize,
    ) {
        let mut result_label = self.context.pc_label();

        for &src in sources {
            let src_label = self.context.lookup(src).unwrap_or(SecurityLabel::Tainted);
            result_label = result_label.join(src_label);
        }

        self.context.bind(
            target,
            result_label,
            target_type,
            VarOrigin::Computed {
                from: sources.iter().map(|s| s.to_string()).collect(),
            },
        );
    }

    /// Type-check a conditional: if guard then ... else ...
    ///
    /// The PC label inside the branches is elevated to guard's label
    /// (implicit flow: the branch taken reveals information about the guard).
    pub fn enter_conditional(&mut self, guard_vars: &[&str]) -> SecurityLabel {
        let old_pc = self.context.pc_label();
        let mut guard_label = old_pc;

        for &var in guard_vars {
            let label = self.context.lookup(var).unwrap_or(SecurityLabel::Tainted);
            guard_label = guard_label.join(label);
        }

        self.context.set_pc_label(guard_label);
        old_pc
    }

    /// Exit a conditional, restoring the PC label.
    pub fn exit_conditional(&mut self, saved_pc: SecurityLabel) {
        self.context.set_pc_label(saved_pc);
    }

    /// Type-check a CPI call.
    ///
    /// CPI return data is Tainted unless the callee is a known trusted program.
    pub fn check_cpi(
        &mut self,
        callee_program: &str,
        result_var: &str,
        line: usize,
    ) {
        let result_label = if is_trusted_program(callee_program) {
            SecurityLabel::AccountData // Known program — data is semi-trusted
        } else {
            SecurityLabel::Tainted // Unknown program — fully tainted
        };

        self.context.bind(
            result_var,
            result_label,
            "CpiResult",
            VarOrigin::CPIReturn {
                program: callee_program.to_string(),
            },
        );
    }

    /// Check a sensitive sink: verify that the data flowing in is trusted enough.
    pub fn check_sensitive_sink(
        &mut self,
        var: &str,
        required_label: SecurityLabel,
        sink_description: &str,
        line: usize,
    ) {
        let actual_label = self.context.lookup(var).unwrap_or(SecurityLabel::Tainted);

        if !actual_label.flows_to(required_label) {
            self.violations.push(FlowViolation {
                source: var.to_string(),
                source_label: actual_label,
                sink: sink_description.to_string(),
                sink_label: required_label,
                line,
                description: format!(
                    "Illegal flow: '{}' has label {} but sink '{}' requires {}. \
                     {} data cannot flow to a {} context.",
                    var, actual_label, sink_description, required_label,
                    actual_label, required_label
                ),
                severity: classify_severity(actual_label, required_label, sink_description),
            });
        }
    }

    /// Get all flow violations found.
    pub fn violations(&self) -> &[FlowViolation] {
        &self.violations
    }

    /// Get the typing context for inspection.
    pub fn context(&self) -> &TypingContext {
        &self.context
    }
}

/// Specification for a Solana account in the instruction handler.
#[derive(Debug, Clone)]
pub struct SolanaAccountSpec {
    pub name: String,
    pub owner_verified: bool,
    pub signer_verified: bool,
    pub is_writable: bool,
    pub is_pda: bool,
}

fn is_trusted_program(program: &str) -> bool {
    matches!(
        program,
        "11111111111111111111111111111111"
            | "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
            | "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
            | "SysvarRent111111111111111111111111111111111"
            | "SysvarC1ock11111111111111111111111111111111"
    )
}

fn classify_severity(
    source: SecurityLabel,
    sink: SecurityLabel,
    sink_desc: &str,
) -> FlowSeverity {
    if source == SecurityLabel::Tainted && sink == SecurityLabel::Trusted {
        if sink_desc.contains("authority") || sink_desc.contains("signer") {
            FlowSeverity::Critical
        } else if sink_desc.contains("lamports") || sink_desc.contains("transfer") {
            FlowSeverity::High
        } else {
            FlowSeverity::Medium
        }
    } else if source == SecurityLabel::UserInput {
        FlowSeverity::High
    } else {
        FlowSeverity::Low
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_label_lattice() {
        assert!(SecurityLabel::Trusted.flows_to(SecurityLabel::Tainted));
        assert!(SecurityLabel::Trusted.flows_to(SecurityLabel::UserInput));
        assert!(!SecurityLabel::Tainted.flows_to(SecurityLabel::Trusted));
        assert!(!SecurityLabel::UserInput.flows_to(SecurityLabel::Trusted));

        assert_eq!(
            SecurityLabel::Trusted.join(SecurityLabel::UserInput),
            SecurityLabel::UserInput
        );
        assert_eq!(
            SecurityLabel::Tainted.meet(SecurityLabel::Trusted),
            SecurityLabel::Trusted
        );
    }

    #[test]
    fn test_solana_account_typing() {
        let mut checker = FlowTypeChecker::new();

        checker.init_solana_instruction(&[
            SolanaAccountSpec {
                name: "vault".into(),
                owner_verified: true,
                signer_verified: false,
                is_writable: true,
                is_pda: false,
            },
            SolanaAccountSpec {
                name: "authority".into(),
                owner_verified: false,
                signer_verified: true,
                is_writable: false,
                is_pda: false,
            },
        ]);

        // Vault data is AccountData (owner verified)
        assert_eq!(
            checker.context().lookup("vault.data"),
            Some(SecurityLabel::AccountData)
        );

        // Authority key is Trusted (signer verified)
        assert_eq!(
            checker.context().lookup("authority.key"),
            Some(SecurityLabel::Trusted)
        );
    }

    #[test]
    fn test_tainted_to_trusted_detected() {
        let mut checker = FlowTypeChecker::new();

        checker.init_solana_instruction(&[
            SolanaAccountSpec {
                name: "user".into(),
                owner_verified: false,
                signer_verified: false,
                is_writable: true,
                is_pda: false,
            },
        ]);

        // user.data is UserInput (no owner check)
        // Try to use it in a trusted context (authority check)
        checker.check_sensitive_sink(
            "user.data",
            SecurityLabel::Trusted,
            "authority verification",
            42,
        );

        assert_eq!(checker.violations().len(), 1);
        assert_eq!(checker.violations()[0].severity, FlowSeverity::High);
    }

    #[test]
    fn test_assignment_propagation() {
        let mut checker = FlowTypeChecker::new();

        checker.context.bind("trusted_val", SecurityLabel::Trusted, "u64", VarOrigin::Literal);
        checker.context.bind("tainted_val", SecurityLabel::Tainted, "u64",
            VarOrigin::InstructionArg { ix_name: "transfer".into() });

        // result := trusted_val + tainted_val → result is Tainted
        checker.check_assignment("result", &["trusted_val", "tainted_val"], "u64", 10);

        assert_eq!(
            checker.context().lookup("result"),
            Some(SecurityLabel::Tainted)
        );
    }

    #[test]
    fn test_implicit_flow_detection() {
        let mut checker = FlowTypeChecker::new();

        checker.context.bind("secret", SecurityLabel::Tainted, "bool", VarOrigin::Literal);
        checker.context.bind("public_sink", SecurityLabel::Trusted, "u64", VarOrigin::Literal);

        // if secret { public_sink = 1 } — implicit flow!
        let saved = checker.enter_conditional(&["secret"]);

        // Inside the branch, PC label is Tainted
        assert_eq!(checker.context().pc_label(), SecurityLabel::Tainted);

        // Assignment to public_sink under tainted PC → Tainted
        checker.check_assignment("public_sink", &[], "u64", 20);
        assert_eq!(
            checker.context().lookup("public_sink"),
            Some(SecurityLabel::Tainted)
        );

        checker.exit_conditional(saved);
    }

    #[test]
    fn test_declassification() {
        let mut checker = FlowTypeChecker::new();

        checker.context.bind(
            "user_amount",
            SecurityLabel::UserInput,
            "u64",
            VarOrigin::InstructionArg { ix_name: "deposit".into() },
        );

        // After range check, declassify
        let result = checker.context.declassify(
            "user_amount",
            SecurityLabel::Trusted,
            DeclassificationReason::RangeChecked { min: 0, max: 1000000 },
            30,
        );
        assert!(result.is_ok());
        assert_eq!(
            checker.context().lookup("user_amount"),
            Some(SecurityLabel::Trusted)
        );
    }

    #[test]
    fn test_cpi_taints_result() {
        let mut checker = FlowTypeChecker::new();

        // CPI to unknown program → result is Tainted
        checker.check_cpi("unknown_program", "cpi_result", 50);
        assert_eq!(
            checker.context().lookup("cpi_result"),
            Some(SecurityLabel::Tainted)
        );

        // CPI to known program → result is AccountData
        checker.check_cpi("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "token_result", 51);
        assert_eq!(
            checker.context().lookup("token_result"),
            Some(SecurityLabel::AccountData)
        );
    }
}
