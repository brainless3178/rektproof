//! Account Security Expert — Comprehensive Account Vulnerability Knowledge Base
//!
//! Covers all Solana account validation attack vectors including signer checks,
//! PDA validation, ownership verification, reinitialization, and type confusion.

use serde::{Deserialize, Serialize};

pub struct AccountSecurityExpert;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInsight {
    pub id: String,
    pub name: String,
    pub severity: AccountSeverity,
    pub architecture_verdict: String,
    pub attack_vector: String,
    pub secure_pattern: String,
    pub design_checklist: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl AccountSeverity {
    pub fn score(&self) -> u8 {
        match self {
            AccountSeverity::Critical => 10,
            AccountSeverity::High => 8,
            AccountSeverity::Medium => 5,
            AccountSeverity::Low => 3,
        }
    }
}

impl AccountSecurityExpert {
    /// All known account vulnerability IDs.
    pub fn all_ids() -> &'static [&'static str] {
        &[
            "SOL-001", "SOL-002", "SOL-003", "SOL-004",
            "SOL-005", "SOL-006", "SOL-007", "SOL-008", "SOL-009",
        ]
    }

    /// Enumerate every insight in the database.
    pub fn all_insights() -> Vec<AccountInsight> {
        Self::all_ids()
            .iter()
            .filter_map(|id| Self::get_insight_for_id(id))
            .collect()
    }

    pub fn get_insight_for_id(id: &str) -> Option<AccountInsight> {
        match id {
            // ── Missing Signer Check ─────────────────────────────────
            "3.1" | "SOL-001" => Some(AccountInsight {
                id: "SOL-001".into(),
                name: "Missing Signer Check".into(),
                severity: AccountSeverity::Critical,
                architecture_verdict: "Vulnerable to unauthorized takeovers. Any user can \
                    invoke privileged operations by passing the target account without \
                    signing the transaction."
                    .into(),
                attack_vector: "Attacker passes a target account without signing, bypassing \
                    authority checks. This allows unauthorized state modifications, fund \
                    transfers, and ownership changes."
                    .into(),
                secure_pattern: r#"#[derive(Accounts)]
pub struct SecureTransfer<'info> {
    #[account(mut, constraint = vault.owner == authority.key())]
    pub vault: Account<'info, VaultState>,
    #[account(signer)]
    pub authority: Signer<'info>,  // MUST be Signer<'info>
}"#
                    .into(),
                design_checklist: vec![
                    "Use Signer<'info> for all authority accounts".into(),
                    "Add owner constraint on mutable accounts".into(),
                    "Verify signer matches stored authority pubkey".into(),
                    "Test with unsigned authority transactions".into(),
                ],
            }),

            // ── Integer Overflow/Underflow ───────────────────────────
            "2.1" | "SOL-002" => Some(AccountInsight {
                id: "SOL-002".into(),
                name: "Integer Overflow/Underflow in Account State".into(),
                severity: AccountSeverity::Critical,
                architecture_verdict: "Arithmetic overflow/underflow in account state \
                    calculations allows manipulation of balances, shares, and indices."
                    .into(),
                attack_vector: "Attacker triggers arithmetic overflow to wrap a large \
                    subtraction around to a huge positive value, granting themselves \
                    an inflated balance."
                    .into(),
                secure_pattern: r#"// Use checked arithmetic for ALL user-influenced calculations
vault.total_deposits = vault.total_deposits
    .checked_add(deposit_amount)
    .ok_or(ErrorCode::ArithmeticOverflow)?;
vault.user_balance = vault.user_balance
    .checked_sub(withdraw_amount)
    .ok_or(ErrorCode::InsufficientFunds)?;
// For share calculations: multiply before dividing
let shares = deposit_amount
    .checked_mul(total_shares)
    .ok_or(ErrorCode::ArithmeticOverflow)?
    .checked_div(total_assets)
    .ok_or(ErrorCode::DivisionByZero)?;"#
                    .into(),
                design_checklist: vec![
                    "Use checked_add/checked_sub/checked_mul/checked_div everywhere".into(),
                    "Never use wrapping arithmetic for financial calculations".into(),
                    "Multiply before dividing to preserve precision".into(),
                    "Enable overflow-checks = true in Cargo.toml release profile".into(),
                    "Test with MAX and 0 boundary values".into(),
                ],
            }),

            // ── PDA Validation Failure ───────────────────────────────
            "4.1" | "SOL-003" => Some(AccountInsight {
                id: "SOL-003".into(),
                name: "PDA Validation Failure".into(),
                severity: AccountSeverity::Critical,
                architecture_verdict: "Protocol-wide security bypass. Unverified PDAs allow \
                    fake state injection, enabling complete protocol takeover."
                    .into(),
                attack_vector: "Using unverified PDAs allows fake state injection. Attacker \
                    creates a counterfeit account with the same structure, bypassing all \
                    protocol invariants."
                    .into(),
                secure_pattern: r#"#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault", user.key().as_ref()],
        bump = vault.bump,  // Store and verify canonical bump
    )]
    pub vault: Account<'info, VaultState>,
    pub user: Signer<'info>,
}"#
                    .into(),
                design_checklist: vec![
                    "Always store and verify the canonical bump seed".into(),
                    "Use Anchor seeds/bump constraints on all PDAs".into(),
                    "Include unique discriminators in PDA seeds".into(),
                    "Test with manually crafted non-canonical PDAs".into(),
                ],
            }),

            // ── Account Data Re-initialization ──────────────────────
            "3.2" | "SOL-004" => Some(AccountInsight {
                id: "SOL-004".into(),
                name: "Account Reinitialization Attack".into(),
                severity: AccountSeverity::Critical,
                architecture_verdict: "Allows resetting account state to attacker-controlled \
                    values. Can overwrite ownership, balances, and all protocol invariants."
                    .into(),
                attack_vector: "Calling the initialize instruction on an already-initialized \
                    account resets its state. Attacker reinitializes a vault to set \
                    themselves as owner, then withdraws all funds."
                    .into(),
                secure_pattern: r#"#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,          // Anchor's init constraint checks is_initialized
        payer = user,
        space = 8 + VaultState::INIT_SPACE,
        seeds = [b"vault", user.key().as_ref()],
        bump,
    )]
    pub vault: Account<'info, VaultState>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}"#
                    .into(),
                design_checklist: vec![
                    "Use Anchor's init constraint (prevents double-init)".into(),
                    "If manual: check is_initialized flag before writing".into(),
                    "Store an is_initialized discriminator in account data".into(),
                    "Test that calling init twice returns an error".into(),
                ],
            }),

            // ── Account Type / Discriminator Confusion ──────────────
            "3.3" | "SOL-005" => Some(AccountInsight {
                id: "SOL-005".into(),
                name: "Account Type Confusion".into(),
                severity: AccountSeverity::High,
                architecture_verdict: "Missing discriminator checks allow one account type \
                    to be substituted for another, causing misinterpretation of data."
                    .into(),
                attack_vector: "Attacker passes an account of type A where type B is expected. \
                    Without a discriminator check, the raw bytes are misinterpreted, \
                    potentially reading an authority field from a balance offset."
                    .into(),
                secure_pattern: r#"// Anchor automatically handles discriminators via Account<'info, T>
// For manual deserialization:
let disc = &account_data[..8];
require!(
    disc == VaultState::DISCRIMINATOR,
    Error::InvalidAccountDiscriminator
);
let state = VaultState::try_deserialize(&mut &account_data[..])?;"#
                    .into(),
                design_checklist: vec![
                    "Always verify 8-byte Anchor discriminator".into(),
                    "Use Account<'info, T> instead of raw AccountInfo".into(),
                    "Never deserialize without checking discriminator first".into(),
                    "Use unique seeds per account type to prevent substitution".into(),
                ],
            }),

            // ── Missing Owner Check ─────────────────────────────────
            "3.4" | "SOL-006" => Some(AccountInsight {
                id: "SOL-006".into(),
                name: "Missing Owner Check (Program Ownership)".into(),
                severity: AccountSeverity::Critical,
                architecture_verdict: "Accounts not verified to be owned by the correct program \
                    can be forged by the attacker using a different program."
                    .into(),
                attack_vector: "Attacker creates an account with identical data layout using \
                    a different program. Without an owner check, the protocol accepts \
                    the attacker-controlled account as legitimate."
                    .into(),
                secure_pattern: r#"// Anchor does this automatically with Account<'info, T>
// For manual verification:
require!(
    account.owner == &crate::ID,
    Error::InvalidProgramOwner
);
// Or with Anchor constraint:
#[account(owner = crate::ID)]
pub vault: AccountInfo<'info>,"#
                    .into(),
                design_checklist: vec![
                    "Verify account.owner == expected_program_id".into(),
                    "Use Account<'info, T> which auto-checks ownership".into(),
                    "Check program ownership for ALL deserialized accounts".into(),
                    "Test with accounts owned by a different program".into(),
                ],
            }),

            // ── Closing Account Without Zeroing Data ────────────────
            "3.5" | "SOL-007" => Some(AccountInsight {
                id: "SOL-007".into(),
                name: "Account Closing Without Data Zeroing".into(),
                severity: AccountSeverity::High,
                architecture_verdict: "Accounts closed without zeroing data can be re-opened \
                    in the same transaction (revival attack) with stale data intact."
                    .into(),
                attack_vector: "Attacker closes an account (draining lamports), then re-opens \
                    it within the same transaction. The stale data remains, allowing them \
                    to bypass initialization checks and reuse old state."
                    .into(),
                secure_pattern: r#"// Anchor's close constraint handles this correctly:
#[account(
    mut,
    close = recipient,  // Zeros data + transfers lamports
    constraint = vault.owner == authority.key(),
)]
pub vault: Account<'info, VaultState>,
// Manual close must zero ALL data:
let account_data = vault.to_account_info();
let mut data = account_data.try_borrow_mut_data()?;
data.fill(0);  // Zero ALL bytes
**account_data.try_borrow_mut_lamports()? = 0;"#
                    .into(),
                design_checklist: vec![
                    "Use Anchor's close = recipient constraint".into(),
                    "If manual: zero ALL account data before draining lamports".into(),
                    "Set discriminator to a CLOSED sentinel value".into(),
                    "Test revival attack: close + re-open in same tx".into(),
                ],
            }),

            // ── Duplicate Mutable Account ───────────────────────────
            "3.6" | "SOL-008" => Some(AccountInsight {
                id: "SOL-008".into(),
                name: "Duplicate Mutable Account (Aliasing)".into(),
                severity: AccountSeverity::High,
                architecture_verdict: "Passing the same account for two different parameters \
                    can cause double-counting or self-transfer exploits."
                    .into(),
                attack_vector: "Attacker passes the same account as both 'source' and \
                    'destination'. A transfer from source to destination becomes a no-op \
                    that still increments a counter, leading to free funds."
                    .into(),
                secure_pattern: r#"// Ensure source and destination are different accounts
require!(
    source.key() != destination.key(),
    Error::DuplicateAccount
);
// Anchor can prevent aliasing with constraint:
#[account(
    mut,
    constraint = source.key() != destination.key() @ Error::DuplicateAccount
)]
pub source: Account<'info, TokenAccount>,"#
                    .into(),
                design_checklist: vec![
                    "Check that mutable account pairs are distinct".into(),
                    "Add key() != key() constraints for all account pairs".into(),
                    "Test with same account passed for source and dest".into(),
                    "Audit all instruction handlers for aliasing potential".into(),
                ],
            }),

            // ── Remaining Accounts Not Validated ────────────────────
            "3.7" | "SOL-009" => Some(AccountInsight {
                id: "SOL-009".into(),
                name: "Remaining Accounts Not Validated".into(),
                severity: AccountSeverity::Medium,
                architecture_verdict: "Accounts passed via remaining_accounts bypass Anchor's \
                    automatic validation. Manual checks are required."
                    .into(),
                attack_vector: "Any account can be passed via remaining_accounts. If the \
                    program iterates over these without validation, an attacker can \
                    inject malicious accounts."
                    .into(),
                secure_pattern: r#"// Validate each remaining account explicitly
for account_info in ctx.remaining_accounts.iter() {
    require!(
        account_info.owner == &crate::ID,
        Error::InvalidAccountOwner
    );
    let data = account_info.try_borrow_data()?;
    require!(
        data.len() >= 8 && data[..8] == WhitelistedAccount::DISCRIMINATOR,
        Error::InvalidAccountType
    );
}"#
                    .into(),
                design_checklist: vec![
                    "Validate owner of every remaining_account".into(),
                    "Check discriminator/type of remaining accounts".into(),
                    "Limit the number of remaining accounts accepted".into(),
                    "Prefer typed Anchor accounts over remaining_accounts".into(),
                ],
            }),

            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_ids_are_resolvable() {
        for id in AccountSecurityExpert::all_ids() {
            assert!(
                AccountSecurityExpert::get_insight_for_id(id).is_some(),
                "ID {} should resolve to an insight",
                id
            );
        }
    }

    #[test]
    fn test_all_insights_returns_full_set() {
        let insights = AccountSecurityExpert::all_insights();
        assert_eq!(insights.len(), AccountSecurityExpert::all_ids().len());
    }

    #[test]
    fn test_numeric_aliases() {
        let pairs = [
            ("3.1", "SOL-001"),
            ("2.1", "SOL-002"),
            ("4.1", "SOL-003"),
            ("3.2", "SOL-004"),
            ("3.3", "SOL-005"),
            ("3.4", "SOL-006"),
            ("3.5", "SOL-007"),
            ("3.6", "SOL-008"),
            ("3.7", "SOL-009"),
        ];
        for (numeric, sol_id) in pairs {
            let a = AccountSecurityExpert::get_insight_for_id(numeric);
            let b = AccountSecurityExpert::get_insight_for_id(sol_id);
            assert!(a.is_some(), "{} should resolve", numeric);
            assert_eq!(a.unwrap().name, b.unwrap().name);
        }
    }

    #[test]
    fn test_severity_scoring() {
        assert_eq!(AccountSeverity::Critical.score(), 10);
        assert!(AccountSeverity::Critical.score() > AccountSeverity::Medium.score());
    }

    #[test]
    fn test_every_insight_has_content() {
        for insight in AccountSecurityExpert::all_insights() {
            assert!(!insight.design_checklist.is_empty(), "{} has empty checklist", insight.name);
            assert!(!insight.secure_pattern.is_empty(), "{} has empty pattern", insight.name);
            assert!(!insight.attack_vector.is_empty(), "{} has empty attack vector", insight.name);
        }
    }

    #[test]
    fn test_get_insight_for_unknown_id() {
        assert!(AccountSecurityExpert::get_insight_for_id("99.99").is_none());
        assert!(AccountSecurityExpert::get_insight_for_id("").is_none());
    }

    #[test]
    fn test_insight_serialization() {
        let insight = AccountSecurityExpert::get_insight_for_id("3.1").unwrap();
        let json = serde_json::to_string(&insight).unwrap();
        let deserialized: AccountInsight = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, insight.name);
        assert_eq!(deserialized.id, "SOL-001");
        assert_eq!(deserialized.design_checklist.len(), insight.design_checklist.len());
    }
}
