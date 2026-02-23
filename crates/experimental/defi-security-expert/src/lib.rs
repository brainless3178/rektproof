#![allow(dead_code)]
//! DeFi Security Expert — Comprehensive DeFi Vulnerability Knowledge Base
//!
//! Provides defense strategies, secure Rust patterns, and checklists for
//! all known DeFi-specific attack vectors on Solana.

use serde::{Deserialize, Serialize};

pub struct DeFiSecurityExpert;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeFiInsight {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    pub defense_strategy: String,
    pub rust_implementation: String,
    pub security_checklist: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl Severity {
    pub fn score(&self) -> u8 {
        match self {
            Severity::Critical => 10,
            Severity::High => 8,
            Severity::Medium => 5,
            Severity::Low => 3,
            Severity::Informational => 1,
        }
    }
}

impl DeFiSecurityExpert {
    /// Return all known DeFi vulnerability IDs.
    pub fn all_ids() -> &'static [&'static str] {
        &[
            "SOL-020", "SOL-021", "SOL-022", "SOL-023", "SOL-024",
            "SOL-025", "SOL-026", "SOL-027", "SOL-028", "SOL-029",
            "SOL-030",
        ]
    }

    /// Enumerate every insight in the database.
    pub fn all_insights() -> Vec<DeFiInsight> {
        Self::all_ids()
            .iter()
            .filter_map(|id| Self::get_defense_for_id(id))
            .collect()
    }

    pub fn get_defense_for_id(id: &str) -> Option<DeFiInsight> {
        match id {
            // ── Oracle Price Manipulation ────────────────────────────
            "7.1" | "SOL-020" => Some(DeFiInsight {
                id: "SOL-020".into(),
                name: "Oracle Price Manipulation".into(),
                severity: Severity::Critical,
                defense_strategy: "Use multiple oracles (Pyth + Switchboard) with staleness \
                    and confidence-interval checks. Implement a circuit breaker that pauses \
                    the protocol when the price deviates >5% between sources."
                    .into(),
                rust_implementation: r#"let pyth_price = pyth_feed.get_price_no_older_than(clock.slot, 60)?;
let sb_price = switchboard_feed.get_result()?;
require!(pyth_price.conf < pyth_price.price / 20, Error::LowConfidence);
let diff = (pyth_price.price - sb_price).abs();
require!(diff * 100 < pyth_price.price * 5, Error::OracleDivergence);"#
                    .into(),
                security_checklist: vec![
                    "Verify oracle staleness (max 60s)".into(),
                    "Check oracle confidence interval (<5% of price)".into(),
                    "Implement circuit breaker for large price swings".into(),
                    "Use TWAP instead of spot price for large operations".into(),
                    "Validate oracle account ownership (Pyth/Switchboard program)".into(),
                ],
            }),

            // ── Flash Loan Attacks ───────────────────────────────────
            "7.2" | "SOL-021" => Some(DeFiInsight {
                id: "SOL-021".into(),
                name: "Flash Loan Price Manipulation".into(),
                severity: Severity::Critical,
                defense_strategy: "Enforce a minimum holding period between deposit and \
                    withdrawal. Use TWAP oracles instead of spot AMM prices. Check that \
                    the transaction doesn't contain flash-borrow instructions."
                    .into(),
                rust_implementation: r#"// Enforce cooldown: deposits cannot be withdrawn in the same slot
require!(
    clock.slot > vault.last_deposit_slot + MIN_HOLDING_SLOTS,
    Error::CooldownNotMet
);
// Use TWAP instead of instantaneous price
let twap = oracle.get_twap(TWAP_WINDOW_SECONDS)?;
let shares = deposit_amount.checked_mul(total_shares)
    .ok_or(Error::Overflow)?
    .checked_div(twap.checked_mul(total_supply).ok_or(Error::Overflow)?)
    .ok_or(Error::DivisionByZero)?;"#
                    .into(),
                security_checklist: vec![
                    "Enforce minimum holding period between deposit/withdraw".into(),
                    "Use TWAP oracle pricing for share calculations".into(),
                    "Detect flash-loan instructions in transaction".into(),
                    "Add reentrancy guard on all state-modifying functions".into(),
                ],
            }),

            // ── Sandwich / MEV Attacks ───────────────────────────────
            "7.3" | "SOL-022" => Some(DeFiInsight {
                id: "SOL-022".into(),
                name: "Sandwich / MEV Attack".into(),
                severity: Severity::High,
                defense_strategy: "Enforce user-specified slippage tolerance. Use commit-reveal \
                    schemes for large trades. Consider integration with Jito or other MEV \
                    protection services."
                    .into(),
                rust_implementation: r#"// User specifies minimum output amount
require!(
    output_amount >= params.minimum_amount_out,
    Error::SlippageExceeded
);
// Enforce maximum price impact
let price_impact = (price_before - price_after).abs() * 10000 / price_before;
require!(price_impact <= MAX_PRICE_IMPACT_BPS, Error::ExcessivePriceImpact);"#
                    .into(),
                security_checklist: vec![
                    "Require user-specified minimum output (slippage protection)".into(),
                    "Enforce maximum price impact per trade".into(),
                    "Consider commit-reveal for large orders".into(),
                    "Integrate Jito bundles or MEV protection relayer".into(),
                ],
            }),

            // ── Reentrancy via CPI ───────────────────────────────────
            "7.4" | "SOL-023" => Some(DeFiInsight {
                id: "SOL-023".into(),
                name: "Reentrancy via CPI Callback".into(),
                severity: Severity::Critical,
                defense_strategy: "Follow the checks-effects-interactions pattern. Use a \
                    reentrancy guard (boolean flag) that is set before any CPI and cleared \
                    after. Update all state BEFORE making external calls."
                    .into(),
                rust_implementation: r#"// Checks-Effects-Interactions pattern
require!(!vault.is_locked, Error::ReentrancyDetected);
vault.is_locked = true; // EFFECT: set guard BEFORE CPI

// EFFECT: update state BEFORE external call
vault.total_assets = vault.total_assets.checked_sub(amount)
    .ok_or(Error::Underflow)?;
user.balance = user.balance.checked_add(amount)
    .ok_or(Error::Overflow)?;

// INTERACTION: external CPI call LAST
let cpi_ctx = CpiContext::new(token_program.to_account_info(), transfer_accounts);
token::transfer(cpi_ctx, amount)?;

vault.is_locked = false; // Clear guard"#
                    .into(),
                security_checklist: vec![
                    "Apply checks-effects-interactions pattern".into(),
                    "Set reentrancy guard before any CPI".into(),
                    "Update all balances/state before external calls".into(),
                    "Audit all CPI targets for callback potential".into(),
                ],
            }),

            // ── AMM Slippage Exploit ─────────────────────────────────
            "7.5" | "SOL-024" => Some(DeFiInsight {
                id: "SOL-024".into(),
                name: "AMM Slippage / Constant-Product Violation".into(),
                severity: Severity::High,
                defense_strategy: "Validate the constant-product invariant (x·y ≥ k) after \
                    every swap. Enforce minimum output amounts and maximum trade sizes \
                    relative to pool liquidity."
                    .into(),
                rust_implementation: r#"// Constant-product AMM with invariant check
let k_before = reserve_a.checked_mul(reserve_b).ok_or(Error::Overflow)?;
let dy = (reserve_b.checked_mul(dx).ok_or(Error::Overflow)?)
    .checked_div(reserve_a.checked_add(dx).ok_or(Error::Overflow)?)
    .ok_or(Error::DivisionByZero)?;
require!(dy >= min_amount_out, Error::SlippageExceeded);
reserve_a = reserve_a.checked_add(dx).ok_or(Error::Overflow)?;
reserve_b = reserve_b.checked_sub(dy).ok_or(Error::Underflow)?;
let k_after = reserve_a.checked_mul(reserve_b).ok_or(Error::Overflow)?;
require!(k_after >= k_before, Error::InvariantViolation);"#
                    .into(),
                security_checklist: vec![
                    "Verify k_after >= k_before after every swap".into(),
                    "Enforce user-specified minimum output".into(),
                    "Cap max trade size relative to pool depth".into(),
                    "Use checked arithmetic for all reserve calculations".into(),
                ],
            }),

            // ── Vault Inflation / Share Dilution ─────────────────────
            "7.6" | "SOL-025" => Some(DeFiInsight {
                id: "SOL-025".into(),
                name: "Vault Share Dilution (ERC-4626 Inflation Attack)".into(),
                severity: Severity::Critical,
                defense_strategy: "Use virtual offsets for shares and assets (OpenZeppelin \
                    pattern). The offset must exceed the maximum possible donation. Add \
                    minimum deposit requirements and dead-share initialization."
                    .into(),
                rust_implementation: r#"const VIRTUAL_OFFSET: u64 = 1_000_000_000; // Must exceed max donation
// Defended share calculation
let effective_assets = total_assets
    .checked_add(VIRTUAL_OFFSET).ok_or(Error::Overflow)?;
let effective_shares = total_shares
    .checked_add(VIRTUAL_OFFSET).ok_or(Error::Overflow)?;
let shares_minted = deposit_amount
    .checked_mul(effective_shares).ok_or(Error::Overflow)?
    .checked_div(effective_assets).ok_or(Error::DivisionByZero)?;
require!(shares_minted > 0, Error::ZeroSharesMinted);"#
                    .into(),
                security_checklist: vec![
                    "Use virtual offset >= max expected donation".into(),
                    "Enforce minimum deposit amount".into(),
                    "Initialize vault with dead shares on creation".into(),
                    "Verify shares_minted > 0 after calculation".into(),
                    "Use checked arithmetic for all share math".into(),
                ],
            }),

            // ── Interest Rate Manipulation ───────────────────────────
            "7.7" | "SOL-026" => Some(DeFiInsight {
                id: "SOL-026".into(),
                name: "Interest Rate Manipulation".into(),
                severity: Severity::High,
                defense_strategy: "Use time-weighted averaging for utilization rates. Cap \
                    maximum rate changes per epoch. Implement rate smoothing with exponential \
                    moving averages."
                    .into(),
                rust_implementation: r#"// Smoothed utilization rate with capped change
let current_util = total_borrows * PRECISION / total_deposits;
let delta = if current_util > pool.smoothed_utilization {
    current_util - pool.smoothed_utilization
} else {
    pool.smoothed_utilization - current_util
};
let capped_delta = delta.min(MAX_RATE_CHANGE_PER_SLOT);
pool.smoothed_utilization = if current_util > pool.smoothed_utilization {
    pool.smoothed_utilization.checked_add(capped_delta).ok_or(Error::Overflow)?
} else {
    pool.smoothed_utilization.checked_sub(capped_delta).ok_or(Error::Underflow)?
};
let interest_rate = calculate_rate(pool.smoothed_utilization)?;"#
                    .into(),
                security_checklist: vec![
                    "Use time-weighted utilization averaging".into(),
                    "Cap maximum rate change per slot/epoch".into(),
                    "Prevent single-block utilization spikes from setting rates".into(),
                    "Use WAD/RAY precision for rate calculations".into(),
                ],
            }),

            // ── Liquidation Cascade ──────────────────────────────────
            "7.8" | "SOL-027" => Some(DeFiInsight {
                id: "SOL-027".into(),
                name: "Liquidation Cascade / Bad Debt Accumulation".into(),
                severity: Severity::Critical,
                defense_strategy: "Implement gradual liquidation (partial close). Set \
                    conservative LTV ratios with safety buffer. Use a liquidation \
                    incentive that decreases as bad debt increases."
                    .into(),
                rust_implementation: r#"// Partial liquidation with incentive decay
let health_factor = collateral_value * LTV_RATIO / borrow_value;
require!(health_factor < LIQUIDATION_THRESHOLD, Error::Healthy);
// Cap liquidation to 50% of position (prevent cascade)
let max_liquidatable = borrow_value / 2;
let liquidation_amount = requested_amount.min(max_liquidatable);
// Liquidation incentive decays as protocol bad debt grows
let base_incentive: u64 = 500; // 5% in bps
let bad_debt_factor = protocol.bad_debt * 10000 / protocol.total_deposits;
let incentive = base_incentive.saturating_sub(bad_debt_factor);
let bonus = liquidation_amount * incentive / 10000;"#
                    .into(),
                security_checklist: vec![
                    "Implement partial liquidation (max 50% per tx)".into(),
                    "Set conservative LTV with safety buffer".into(),
                    "Track and cap protocol bad debt exposure".into(),
                    "Decay liquidation incentive as bad debt grows".into(),
                    "Add emergency pause for cascade scenarios".into(),
                ],
            }),

            // ── Governance Attack ────────────────────────────────────
            "7.9" | "SOL-028" => Some(DeFiInsight {
                id: "SOL-028".into(),
                name: "Governance Takeover / Flash-Loan Voting".into(),
                severity: Severity::High,
                defense_strategy: "Require token lock-up period before voting power is \
                    active. Use vote-escrowed (ve) token model. Implement time-delayed \
                    execution after proposal passes."
                    .into(),
                rust_implementation: r#"// Vote-escrowed governance with timelock
require!(
    clock.unix_timestamp >= voter.lock_start + MIN_LOCK_PERIOD,
    Error::TokensNotVested
);
let voting_power = voter.locked_amount
    .checked_mul(voter.lock_remaining() as u64).ok_or(Error::Overflow)?
    .checked_div(MAX_LOCK_PERIOD as u64).ok_or(Error::DivisionByZero)?;
// Timelock execution: proposal must wait TIMELOCK_DELAY after passing
require!(
    clock.unix_timestamp >= proposal.passed_at + TIMELOCK_DELAY,
    Error::TimelockNotExpired
);"#
                    .into(),
                security_checklist: vec![
                    "Require minimum lock period before voting".into(),
                    "Use vote-escrowed (ve) token weighting".into(),
                    "Implement timelock delay on proposal execution".into(),
                    "Set minimum quorum requirements".into(),
                    "Prevent flash-loan acquired tokens from voting".into(),
                ],
            }),

            // ── Cross-Program Reentrancy ─────────────────────────────
            "7.10" | "SOL-029" => Some(DeFiInsight {
                id: "SOL-029".into(),
                name: "Cross-Program Reentrancy (CPI Re-entry)".into(),
                severity: Severity::Critical,
                defense_strategy: "Use a global reentrancy guard stored in a PDA. Set the \
                    guard before any CPI. The CPI target program cannot re-enter because \
                    the guard PDA is already marked as locked."
                    .into(),
                rust_implementation: r#"// PDA-based cross-program reentrancy guard
let guard = &mut ctx.accounts.reentrancy_guard;
require!(!guard.locked, Error::ReentrancyDetected);
guard.locked = true;  // Lock BEFORE any CPI

// Perform all state updates...
pool.reserves = pool.reserves.checked_add(amount).ok_or(Error::Overflow)?;

// CPI call (if target tries to re-enter, guard.locked == true)
let cpi_ctx = CpiContext::new_with_signer(
    ctx.accounts.target_program.to_account_info(),
    accounts,
    signer_seeds,
);
external_program::execute(cpi_ctx, params)?;

guard.locked = false; // Unlock after CPI returns"#
                    .into(),
                security_checklist: vec![
                    "Store reentrancy guard in a PDA account".into(),
                    "Set guard before any CPI or state modification".into(),
                    "Verify guard is checked in all entry points".into(),
                    "Audit all programs in the CPI chain".into(),
                ],
            }),

            // ── Price Curve Manipulation ─────────────────────────────
            "7.11" | "SOL-030" => Some(DeFiInsight {
                id: "SOL-030".into(),
                name: "Bonding Curve / Price Curve Manipulation".into(),
                severity: Severity::High,
                defense_strategy: "Enforce monotonic price progression. Cap maximum buy/sell \
                    size per transaction. Use fixed-point math with sufficient precision \
                    (WAD/RAY) to prevent rounding exploits."
                    .into(),
                rust_implementation: r#"// Bonding curve with monotonic price enforcement
let price_before = calculate_spot_price(supply, reserve)?;
let cost = integrate_curve(supply, supply + buy_amount)?;
require!(cost <= max_cost, Error::SlippageExceeded);
// Update state
pool.supply = pool.supply.checked_add(buy_amount).ok_or(Error::Overflow)?;
pool.reserve = pool.reserve.checked_add(cost).ok_or(Error::Overflow)?;
let price_after = calculate_spot_price(pool.supply, pool.reserve)?;
// Monotonicity: price must not decrease after a buy
require!(price_after >= price_before, Error::NonMonotonicPrice);"#
                    .into(),
                security_checklist: vec![
                    "Enforce monotonic price progression".into(),
                    "Cap max transaction size relative to supply".into(),
                    "Use WAD (1e18) precision for curve math".into(),
                    "Verify curve formula against edge cases (supply=0, supply=MAX)".into(),
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
        for id in DeFiSecurityExpert::all_ids() {
            assert!(
                DeFiSecurityExpert::get_defense_for_id(id).is_some(),
                "ID {} should resolve to an insight",
                id
            );
        }
    }

    #[test]
    fn test_all_insights_returns_full_set() {
        let insights = DeFiSecurityExpert::all_insights();
        assert_eq!(
            insights.len(),
            DeFiSecurityExpert::all_ids().len(),
            "all_insights should return one insight per ID"
        );
    }

    #[test]
    fn test_numeric_aliases() {
        // Every SOL-0XX ID should match its numeric alias
        let pairs = [
            ("7.1", "SOL-020"),
            ("7.2", "SOL-021"),
            ("7.3", "SOL-022"),
            ("7.4", "SOL-023"),
            ("7.5", "SOL-024"),
            ("7.6", "SOL-025"),
            ("7.7", "SOL-026"),
            ("7.8", "SOL-027"),
            ("7.9", "SOL-028"),
            ("7.10", "SOL-029"),
            ("7.11", "SOL-030"),
        ];
        for (numeric, sol_id) in pairs {
            let a = DeFiSecurityExpert::get_defense_for_id(numeric);
            let b = DeFiSecurityExpert::get_defense_for_id(sol_id);
            assert!(a.is_some(), "{} should resolve", numeric);
            assert_eq!(a.unwrap().name, b.unwrap().name);
        }
    }

    #[test]
    fn test_severity_scoring() {
        assert_eq!(Severity::Critical.score(), 10);
        assert_eq!(Severity::High.score(), 8);
        assert_eq!(Severity::Medium.score(), 5);
        assert!(Severity::Critical.score() > Severity::Low.score());
    }

    #[test]
    fn test_every_insight_has_checklist() {
        for insight in DeFiSecurityExpert::all_insights() {
            assert!(
                !insight.security_checklist.is_empty(),
                "{} has empty checklist",
                insight.name
            );
            assert!(
                !insight.rust_implementation.is_empty(),
                "{} has empty implementation",
                insight.name
            );
            assert!(
                !insight.defense_strategy.is_empty(),
                "{} has empty strategy",
                insight.name
            );
        }
    }

    #[test]
    fn test_unknown_id_returns_none() {
        assert!(DeFiSecurityExpert::get_defense_for_id("99.99").is_none());
        assert!(DeFiSecurityExpert::get_defense_for_id("").is_none());
        assert!(DeFiSecurityExpert::get_defense_for_id("unknown").is_none());
    }

    #[test]
    fn test_insight_serialization() {
        let insight = DeFiSecurityExpert::get_defense_for_id("7.1").unwrap();
        let json = serde_json::to_string(&insight).unwrap();
        assert!(json.contains("Oracle Price Manipulation"));
        let deserialized: DeFiInsight = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, insight.name);
        assert_eq!(deserialized.id, "SOL-020");
    }
}
