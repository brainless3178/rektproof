//! Token Security Expert — Comprehensive Token Vulnerability Knowledge Base
//!
//! Covers SPL Token, Token-2022 extensions, mint/freeze authority abuse,
//! and token-specific attack vectors on Solana.
//!
//! Includes an active [`scanner`] module for on-chain + source-code token
//! risk analysis (rug-pull probability, risk flags, composite scoring).

pub mod scanner;

use serde::{Deserialize, Serialize};

pub struct TokenSecurityExpert;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInsight {
    pub id: String,
    pub name: String,
    pub severity: TokenSeverity,
    pub extension_risk_matrix: Vec<ExtensionRisk>,
    pub rust_secure_pattern: String,
    pub security_checklist: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionRisk {
    pub extension: String,
    pub risk_level: String,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl TokenSeverity {
    pub fn score(&self) -> u8 {
        match self {
            TokenSeverity::Critical => 10,
            TokenSeverity::High => 8,
            TokenSeverity::Medium => 5,
            TokenSeverity::Low => 3,
        }
    }
}

impl TokenSecurityExpert {
    /// All known token vulnerability IDs.
    pub fn all_ids() -> &'static [&'static str] {
        &[
            "SOL-010", "SOL-011", "SOL-012", "SOL-013", "SOL-014",
            "SOL-015", "SOL-016", "SOL-017", "SOL-018", "SOL-019",
            "SOL-020", "SOL-021", "SOL-022", "SOL-023", "SOL-024",
            "SOL-025", "SOL-026", "SOL-027",
        ]
    }

    /// Enumerate every insight in the database.
    pub fn all_insights() -> Vec<TokenInsight> {
        Self::all_ids()
            .iter()
            .filter_map(|id| Self::get_insight_for_id(id))
            .collect()
    }

    pub fn get_insight_for_id(id: &str) -> Option<TokenInsight> {
        match id {
            // ── Token Program Confusion ──────────────────────────────
            "6.1" | "SOL-010" => Some(TokenInsight {
                id: "SOL-010".into(),
                name: "Token Program Confusion".into(),
                severity: TokenSeverity::High,
                extension_risk_matrix: vec![
                    ExtensionRisk {
                        extension: "Transfer Fee".into(),
                        risk_level: "High".into(),
                        description: "Bypasses protocol fee logic; actual received amount \
                            differs from transfer amount."
                            .into(),
                    },
                    ExtensionRisk {
                        extension: "Closing Account".into(),
                        risk_level: "Medium".into(),
                        description: "Potential lamport drainage when closing token accounts \
                            with remaining balance."
                            .into(),
                    },
                    ExtensionRisk {
                        extension: "Permanent Delegate".into(),
                        risk_level: "Critical".into(),
                        description: "Delegate can transfer tokens from ANY holder at any time."
                            .into(),
                    },
                ],
                rust_secure_pattern:
                    "pub token_program: Interface<'info, TokenInterface>,".into(),
                security_checklist: vec![
                    "Use TokenInterface instead of raw Program<Token>".into(),
                    "Verify mint address and decimals on every instruction".into(),
                    "Check for transfer fee extension and adjust amounts".into(),
                    "Verify permanent delegate status before accepting tokens".into(),
                ],
            }),

            // ── Mint Authority Not Revoked ───────────────────────────
            "6.2" | "SOL-011" => Some(TokenInsight {
                id: "SOL-011".into(),
                name: "Mint Authority Not Revoked".into(),
                severity: TokenSeverity::Critical,
                extension_risk_matrix: vec![ExtensionRisk {
                    extension: "MintCloseAuthority".into(),
                    risk_level: "Critical".into(),
                    description: "Mint authority can create unlimited tokens, diluting \
                        all holders. If never revoked, this is a rug-pull vector."
                        .into(),
                }],
                rust_secure_pattern: r#"// Verify mint authority is None (revoked)
let mint_info = Mint::unpack(&mint_account.data.borrow())?;
require!(
    mint_info.mint_authority.is_none(),
    Error::MintAuthorityNotRevoked
);"#
                    .into(),
                security_checklist: vec![
                    "Check that mint_authority == COption::None".into(),
                    "Verify freeze_authority status for DeFi tokens".into(),
                    "Reject interaction with mints that have active authority".into(),
                    "Log warning if mint authority is a non-multisig account".into(),
                ],
            }),

            // ── Freeze Authority Abuse ───────────────────────────────
            "6.3" | "SOL-012" => Some(TokenInsight {
                id: "SOL-012".into(),
                name: "Freeze Authority Abuse".into(),
                severity: TokenSeverity::High,
                extension_risk_matrix: vec![ExtensionRisk {
                    extension: "FreezeAccount".into(),
                    risk_level: "High".into(),
                    description: "Freeze authority can lock user funds indefinitely, \
                        preventing withdrawals or transfers."
                        .into(),
                }],
                rust_secure_pattern: r#"// Check freeze authority status before accepting deposit
let mint_info = Mint::unpack(&mint_account.data.borrow())?;
require!(
    mint_info.freeze_authority.is_none()
    || mint_info.freeze_authority == COption::Some(TRUSTED_MULTISIG),
    Error::UntrustedFreezeAuthority
);"#
                    .into(),
                security_checklist: vec![
                    "Verify freeze_authority is None or a trusted multisig".into(),
                    "Warn users about tokens with active freeze authority".into(),
                    "Check token account frozen status before operations".into(),
                ],
            }),

            // ── Token Account Ownership ──────────────────────────────
            "6.4" | "SOL-013" => Some(TokenInsight {
                id: "SOL-013".into(),
                name: "Token Account Ownership Mismatch".into(),
                severity: TokenSeverity::High,
                extension_risk_matrix: vec![],
                rust_secure_pattern: r#"// Validate token account ownership
let token_account = TokenAccount::unpack(&account.data.borrow())?;
require!(
    token_account.owner == expected_owner.key(),
    Error::InvalidTokenAccountOwner
);
require!(
    token_account.mint == expected_mint.key(),
    Error::InvalidMint
);"#
                    .into(),
                security_checklist: vec![
                    "Verify token account owner matches expected user".into(),
                    "Verify token account mint matches expected mint".into(),
                    "Check that token account is initialized".into(),
                    "Validate associated token account derivation".into(),
                ],
            }),

            // ── Decimal Precision Mismatch ───────────────────────────
            "6.5" | "SOL-014" => Some(TokenInsight {
                id: "SOL-014".into(),
                name: "Decimal Precision Mismatch".into(),
                severity: TokenSeverity::Medium,
                extension_risk_matrix: vec![],
                rust_secure_pattern: r#"// Normalize amounts to a common precision
let mint = Mint::unpack(&mint_account.data.borrow())?;
let decimals = mint.decimals;
let normalized_amount = if decimals < STANDARD_DECIMALS {
    amount.checked_mul(10u64.pow((STANDARD_DECIMALS - decimals) as u32))
        .ok_or(Error::Overflow)?
} else {
    amount.checked_div(10u64.pow((decimals - STANDARD_DECIMALS) as u32))
        .ok_or(Error::DivisionByZero)?
};"#
                    .into(),
                security_checklist: vec![
                    "Always read decimals from mint account, never hardcode".into(),
                    "Normalize amounts to common precision before math".into(),
                    "Handle edge cases: 0 decimals, max decimals".into(),
                    "Test with various decimal token mints (0, 6, 9, 18)".into(),
                ],
            }),

            // ── Close Authority Token Drain ──────────────────────────
            "6.6" | "SOL-015" => Some(TokenInsight {
                id: "SOL-015".into(),
                name: "Token Account Close Authority Drain".into(),
                severity: TokenSeverity::High,
                extension_risk_matrix: vec![ExtensionRisk {
                    extension: "CloseAuthority".into(),
                    risk_level: "High".into(),
                    description: "Close authority can close token accounts, causing remaining \
                        lamports to be drained to the closer."
                        .into(),
                }],
                rust_secure_pattern: r#"// Ensure close authority is the account owner or PDA
let token_account = TokenAccount::unpack(&account.data.borrow())?;
if let COption::Some(close_auth) = token_account.close_authority {
    require!(
        close_auth == token_account.owner || close_auth == program_pda,
        Error::UntrustedCloseAuthority
    );
}"#
                    .into(),
                security_checklist: vec![
                    "Verify close authority is owner or trusted PDA".into(),
                    "Check for remaining balance before allowing close".into(),
                    "Require explicit zero-balance check before closing".into(),
                ],
            }),

            // ── Transfer Hook Injection ──────────────────────────────
            "6.7" | "SOL-016" => Some(TokenInsight {
                id: "SOL-016".into(),
                name: "Transfer Hook Injection (Token-2022)".into(),
                severity: TokenSeverity::Critical,
                extension_risk_matrix: vec![ExtensionRisk {
                    extension: "TransferHook".into(),
                    risk_level: "Critical".into(),
                    description: "Malicious transfer hook program can block transfers, \
                        steal data, or execute arbitrary logic on every transfer."
                        .into(),
                }],
                rust_secure_pattern: r#"// Validate transfer hook program before accepting mint
let mint_data = mint_account.data.borrow();
if let Ok(hook) = TransferHook::unpack(&mint_data) {
    require!(
        hook.program_id == TRUSTED_HOOK_PROGRAM
        || hook.program_id == Pubkey::default(),
        Error::UntrustedTransferHook
    );
}"#
                    .into(),
                security_checklist: vec![
                    "Whitelist acceptable transfer hook programs".into(),
                    "Reject mints with untrusted transfer hooks".into(),
                    "Audit transfer hook program for malicious logic".into(),
                    "Test with and without transfer hooks enabled".into(),
                ],
            }),

            // ── Confidential Transfer Abuse ──────────────────────────
            "6.8" | "SOL-017" => Some(TokenInsight {
                id: "SOL-017".into(),
                name: "Confidential Transfer Supply Obfuscation".into(),
                severity: TokenSeverity::Medium,
                extension_risk_matrix: vec![ExtensionRisk {
                    extension: "ConfidentialTransfer".into(),
                    risk_level: "Medium".into(),
                    description: "Encrypted balances make it impossible to verify total \
                        supply or detect inflation on-chain."
                        .into(),
                }],
                rust_secure_pattern: r#"// DeFi protocols should reject confidential-transfer mints
// unless they can handle encrypted balance proofs
let mint_data = account.data.borrow();
if ConfidentialTransferMint::unpack(&mint_data).is_ok() {
    return Err(Error::ConfidentialTransferNotSupported);
}"#
                    .into(),
                security_checklist: vec![
                    "Decide if protocol supports confidential transfers".into(),
                    "Reject confidential-transfer mints if not supported".into(),
                    "If supported, verify zero-knowledge proofs".into(),
                    "Monitor for supply inflation via auditor key".into(),
                ],
            }),

            // ── AMM Admin Centralization Risk ─────────────────────
            "6.9" | "SOL-018" => Some(TokenInsight {
                id: "SOL-018".into(),
                name: "AMM Admin Centralization Risk".into(),
                severity: TokenSeverity::Critical,
                extension_risk_matrix: vec![ExtensionRisk {
                    extension: "AdminKey".into(),
                    risk_level: "Critical".into(),
                    description: "Single hardcoded admin key controls all protocol \
                        parameters: fee rates, pool freezing, owner changes. \
                        No multisig, timelock, or governance."
                        .into(),
                }],
                rust_secure_pattern: r#"// Require multisig or timelock for admin ops
require!(
    admin_config.governance == governance_program::ID,
    Error::UnauthorizedAdmin
);
// Enforce timelock on parameter changes
require!(
    Clock::get()?.unix_timestamp >= pending_change.execute_after,
    Error::TimelockNotExpired
);"#
                    .into(),
                security_checklist: vec![
                    "Verify admin is multisig, not a single EOA".into(),
                    "Check for timelock on fee/parameter changes".into(),
                    "Verify max fee rate caps exist on-chain".into(),
                    "Confirm admin cannot freeze withdrawals unilaterally".into(),
                    "Check if governance or DAO controls admin key".into(),
                ],
            }),

            // ── Pool Status Freeze Authority ─────────────────────────
            "6.10" | "SOL-019" => Some(TokenInsight {
                id: "SOL-019".into(),
                name: "Pool Status Freeze Authority".into(),
                severity: TokenSeverity::Critical,
                extension_risk_matrix: vec![ExtensionRisk {
                    extension: "PoolStatus".into(),
                    risk_level: "Critical".into(),
                    description: "Admin can set pool status bits to disable deposits, \
                        withdrawals, and swaps simultaneously. Users have zero recourse \
                        to recover frozen funds."
                        .into(),
                }],
                rust_secure_pattern: r#"// Never allow disabling withdrawals
pub fn update_pool_status(ctx: Context<UpdatePoolStatus>, status: u8) -> Result<()> {
    // Bit 1 (withdraw) must always be enabled
    require!(
        status & 0b010 == 0,
        Error::CannotDisableWithdrawals
    );
    pool_state.set_status(status);
    Ok(())
}"#
                    .into(),
                security_checklist: vec![
                    "Verify withdrawals can NEVER be disabled".into(),
                    "Check if pool freeze requires timelock".into(),
                    "Verify admin cannot set status = 7 (freeze all)".into(),
                    "Ensure emergency withdraw exists even when pool is frozen".into(),
                ],
            }),

            // ── First Depositor / Inflation Attack ───────────────────
            "6.11" | "SOL-020" => Some(TokenInsight {
                id: "SOL-020".into(),
                name: "First Depositor Inflation Attack".into(),
                severity: TokenSeverity::High,
                extension_risk_matrix: vec![],
                rust_secure_pattern: r#"// Lock meaningful LP amount on initialization
let lock_lp_amount = std::cmp::max(
    liquidity / 1000,   // Lock at least 0.1% of initial LP
    MINIMUM_LIQUIDITY,   // Or an absolute minimum (e.g., 10_000)
);
require_gte!(init_amount_0, MINIMUM_INIT_AMOUNT, Error::InsufficientInitialLiquidity);
require_gte!(init_amount_1, MINIMUM_INIT_AMOUNT, Error::InsufficientInitialLiquidity);"#
                    .into(),
                security_checklist: vec![
                    "Check minimum locked LP amount is meaningful (not just 100)".into(),
                    "Verify minimum initial liquidity requirements exist".into(),
                    "Test first-deposit with tiny amounts for rounding attacks".into(),
                    "Ensure LP lock prevents initial price manipulation".into(),
                ],
            }),

            // ── Fee Accumulator Overflow ─────────────────────────────
            "6.12" | "SOL-021" => Some(TokenInsight {
                id: "SOL-021".into(),
                name: "Fee Accumulator Overflow".into(),
                severity: TokenSeverity::High,
                extension_risk_matrix: vec![],
                rust_secure_pattern: r#"// Use saturating_add or checked_add with proper error
self.protocol_fees_token_0 = self
    .protocol_fees_token_0
    .checked_add(protocol_fee)
    .ok_or(ErrorCode::MathOverflow)?;
// OR use saturating_add to cap at u64::MAX
self.protocol_fees_token_0 = self
    .protocol_fees_token_0
    .saturating_add(protocol_fee);"#
                    .into(),
                security_checklist: vec![
                    "Verify fee accumulators use checked_add with error handling".into(),
                    "Check if uncollected fees can overflow u64::MAX".into(),
                    "Verify fee collection is performed regularly".into(),
                    "Test high-volume scenarios for accumulator overflow".into(),
                ],
            }),

            // ── Oracle Price Manipulation (Single-Block) ─────────────
            "6.13" | "SOL-022" => Some(TokenInsight {
                id: "SOL-022".into(),
                name: "Oracle Price Manipulation".into(),
                severity: TokenSeverity::Medium,
                extension_risk_matrix: vec![],
                rust_secure_pattern: r#"// Implement TWAP instead of spot price oracle
pub fn update_oracle(
    &mut self,
    block_timestamp: u64,
    token_0_price: u128,
    token_1_price: u128,
) -> Result<()> {
    let time_elapsed = block_timestamp.saturating_sub(self.last_update_timestamp);
    if time_elapsed > 0 {
        self.cumulative_price_0 = self.cumulative_price_0
            .wrapping_add(token_0_price.wrapping_mul(time_elapsed as u128));
        self.last_update_timestamp = block_timestamp;
    }
    Ok(())
}"#
                    .into(),
                security_checklist: vec![
                    "Check if oracle uses TWAP or spot price".into(),
                    "Verify oracle cannot be manipulated in a single block".into(),
                    "Check if external protocols depend on this oracle".into(),
                    "Test flash-loan-style price manipulation scenarios".into(),
                ],
            }),

            // ── Interest-Bearing Token AMM Incompatibility ───────────
            "6.14" | "SOL-023" => Some(TokenInsight {
                id: "SOL-023".into(),
                name: "Interest-Bearing Token AMM Incompatibility".into(),
                severity: TokenSeverity::Medium,
                extension_risk_matrix: vec![
                    ExtensionRisk {
                        extension: "InterestBearingConfig".into(),
                        risk_level: "Medium".into(),
                        description: "Interest-bearing tokens accrue value over time, but \
                            AMM vault balances don't reflect accrued interest. This causes \
                            the constant product formula to underprice these tokens."
                            .into(),
                    },
                    ExtensionRisk {
                        extension: "ScaledUiAmount".into(),
                        risk_level: "Medium".into(),
                        description: "Scaled UI amounts differ from actual on-chain amounts, \
                            potentially confusing AMM pricing calculations."
                            .into(),
                    },
                ],
                rust_secure_pattern: r#"// Reject interest-bearing tokens in AMM pools
for e in extensions {
    if e == ExtensionType::InterestBearingConfig
        || e == ExtensionType::ScaledUiAmount
    {
        return err!(ErrorCode::UnsupportedExtension);
    }
}"#
                    .into(),
                security_checklist: vec![
                    "Check if AMM supports interest-bearing tokens correctly".into(),
                    "Verify vault balances account for accrued interest".into(),
                    "Test pricing with interest-bearing tokens over time".into(),
                    "Check ScaledUiAmount handling in swap calculations".into(),
                ],
            }),

            // ── Unchecked Arithmetic Panics in DeFi ──────────────────
            "6.15" | "SOL-024" => Some(TokenInsight {
                id: "SOL-024".into(),
                name: "Unchecked Arithmetic Panics in DeFi".into(),
                severity: TokenSeverity::Critical,
                extension_risk_matrix: vec![],
                rust_secure_pattern: r#"// Replace all .unwrap() with proper error propagation
let numerator = input_amount
    .checked_mul(output_vault_amount)
    .ok_or(ErrorCode::MathOverflow)?;
let denominator = input_vault_amount
    .checked_add(input_amount)
    .ok_or(ErrorCode::MathOverflow)?;
let result = numerator
    .checked_div(denominator)
    .ok_or(ErrorCode::DivisionByZero)?;"#
                    .into(),
                security_checklist: vec![
                    "Search for all .unwrap() on checked arithmetic operations".into(),
                    "Verify no unchecked mul/div/add/sub in swap calculations".into(),
                    "Check for raw * / + - operators on u64/u128 values".into(),
                    "Ensure assert!() is replaced with require!() or err!()".into(),
                    "Test with extreme values (u64::MAX, 0, 1)".into(),
                ],
            }),

            // ── Reentrancy via Token-2022 Transfer Hooks ─────────────
            "6.16" | "SOL-025" => Some(TokenInsight {
                id: "SOL-025".into(),
                name: "Reentrancy via Token-2022 Transfer Hooks".into(),
                severity: TokenSeverity::Critical,
                extension_risk_matrix: vec![ExtensionRisk {
                    extension: "TransferHook".into(),
                    risk_level: "Critical".into(),
                    description: "Token-2022 transfer hooks invoke arbitrary programs during \
                        transfers. If pool state is modified before CPI transfer calls, a \
                        malicious hook could re-enter the program and manipulate state."
                        .into(),
                }],
                rust_secure_pattern: r#"// Implement reentrancy guard
let pool_state = &mut ctx.accounts.pool_state.load_mut()?;
require!(!pool_state.reentrancy_locked, Error::ReentrancyDetected);
pool_state.reentrancy_locked = true;

// ... perform swaps, transfers ...

pool_state.reentrancy_locked = false;"#
                    .into(),
                security_checklist: vec![
                    "Check if program supports Token-2022 with transfer hooks".into(),
                    "Verify state writes happen AFTER all CPI calls".into(),
                    "Check for reentrancy guard flag in pool/program state".into(),
                    "Audit all CPI call ordering (checks-effects-interactions)".into(),
                    "Test with malicious transfer hook programs".into(),
                ],
            }),

            // ── Missing Admin Action Events ──────────────────────────
            "6.17" | "SOL-026" => Some(TokenInsight {
                id: "SOL-026".into(),
                name: "Missing Admin Action Events".into(),
                severity: TokenSeverity::Medium,
                extension_risk_matrix: vec![],
                rust_secure_pattern: r#"// Emit events for ALL admin actions
emit!(AdminConfigUpdate {
    admin: ctx.accounts.owner.key(),
    param_changed: param,
    old_value: old_value,
    new_value: value,
    timestamp: Clock::get()?.unix_timestamp,
});

emit!(PoolStatusUpdate {
    pool_id: pool_state.key(),
    old_status: old_status,
    new_status: status,
    admin: ctx.accounts.authority.key(),
});"#
                    .into(),
                security_checklist: vec![
                    "Verify admin fee changes emit events".into(),
                    "Check if pool freeze/unfreeze emits events".into(),
                    "Verify owner/authority changes emit events".into(),
                    "Ensure off-chain monitoring can detect all admin actions".into(),
                ],
            }),

            // ── Hardcoded Mint Whitelist Bypass ──────────────────────
            "6.18" | "SOL-027" => Some(TokenInsight {
                id: "SOL-027".into(),
                name: "Hardcoded Mint Whitelist Bypass".into(),
                severity: TokenSeverity::Medium,
                extension_risk_matrix: vec![ExtensionRisk {
                    extension: "MintWhitelist".into(),
                    risk_level: "Medium".into(),
                    description: "Hardcoded mint addresses bypass ALL extension safety \
                        checks. If a whitelisted mint is upgraded with dangerous extensions \
                        (PermanentDelegate, TransferHook), the whitelist overrides the check."
                        .into(),
                }],
                rust_secure_pattern: r#"// Always check extensions, even for whitelisted mints
pub fn is_supported_mint(mint_account: &InterfaceAccount<Mint>) -> Result<bool> {
    let mint_data = mint_info.try_borrow_data()?;
    let mint = StateWithExtensions::<spl_token_2022::state::Mint>::unpack(&mint_data)?;
    let extensions = mint.get_extension_types()?;
    // Check ALL mints, no whitelist bypass
    for e in extensions {
        if DANGEROUS_EXTENSIONS.contains(&e) {
            return Ok(false);
        }
    }
    Ok(true)
}"#
                    .into(),
                security_checklist: vec![
                    "Check for hardcoded mint address whitelists".into(),
                    "Verify whitelisted mints still have safe extensions".into(),
                    "Ensure whitelist doesn't bypass critical safety checks".into(),
                    "Audit each whitelisted mint address and its current state".into(),
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
        for id in TokenSecurityExpert::all_ids() {
            assert!(
                TokenSecurityExpert::get_insight_for_id(id).is_some(),
                "ID {} should resolve to an insight",
                id
            );
        }
    }

    #[test]
    fn test_all_insights_returns_full_set() {
        let insights = TokenSecurityExpert::all_insights();
        assert_eq!(insights.len(), TokenSecurityExpert::all_ids().len());
    }

    #[test]
    fn test_numeric_aliases() {
        let pairs = [
            ("6.1", "SOL-010"),
            ("6.2", "SOL-011"),
            ("6.3", "SOL-012"),
            ("6.4", "SOL-013"),
            ("6.5", "SOL-014"),
            ("6.6", "SOL-015"),
            ("6.7", "SOL-016"),
            ("6.8", "SOL-017"),
            ("6.9", "SOL-018"),
            ("6.10", "SOL-019"),
            ("6.11", "SOL-020"),
            ("6.12", "SOL-021"),
            ("6.13", "SOL-022"),
            ("6.14", "SOL-023"),
            ("6.15", "SOL-024"),
            ("6.16", "SOL-025"),
            ("6.17", "SOL-026"),
            ("6.18", "SOL-027"),
        ];
        for (numeric, sol_id) in pairs {
            let a = TokenSecurityExpert::get_insight_for_id(numeric);
            let b = TokenSecurityExpert::get_insight_for_id(sol_id);
            assert!(a.is_some(), "{} should resolve", numeric);
            assert_eq!(a.unwrap().name, b.unwrap().name);
        }
    }

    #[test]
    fn test_severity_scoring() {
        assert_eq!(TokenSeverity::Critical.score(), 10);
        assert!(TokenSeverity::Critical.score() > TokenSeverity::Low.score());
    }

    #[test]
    fn test_every_insight_has_content() {
        for insight in TokenSecurityExpert::all_insights() {
            assert!(!insight.security_checklist.is_empty(), "{} has empty checklist", insight.name);
            assert!(!insight.rust_secure_pattern.is_empty(), "{} has empty pattern", insight.name);
        }
    }

    #[test]
    fn test_get_insight_for_unknown_id() {
        assert!(TokenSecurityExpert::get_insight_for_id("99.99").is_none());
        assert!(TokenSecurityExpert::get_insight_for_id("").is_none());
    }

    #[test]
    fn test_risk_matrix_content() {
        let insight = TokenSecurityExpert::get_insight_for_id("6.1").unwrap();
        assert!(insight.extension_risk_matrix.len() >= 2);
        assert_eq!(insight.extension_risk_matrix[0].extension, "Transfer Fee");
    }

    #[test]
    fn test_insight_serialization() {
        let insight = TokenSecurityExpert::get_insight_for_id("6.1").unwrap();
        let json = serde_json::to_string(&insight).unwrap();
        assert!(json.contains("Token Program Confusion"));
        let deserialized: TokenInsight = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, insight.name);
        assert_eq!(deserialized.id, "SOL-010");
    }
}
