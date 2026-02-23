# [shield] Shanon Security Audit Report

**Target:** `/tmp/marinade-liquid-staking/programs/marinade-finance`  
**Duration:** 82.2s  
**Score:** 20 / 100 (Grade: **F**)  

---

## 📊 Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 2 |
| 🟠 High | 2 |
| 🟡 Medium | 0 |
| 🔵 Low | 0 |
| **Total** | **4** |

---

## 🔍 Detailed Findings

### 1. 🔴 SOL-001 - Missing Signer Validation

**Severity:** 🔴 CRITICAL | **Confidence:** 80% | **Category:** Access Control

**CWE:** [CWE-862](https://cwe.mitre.org/data/definitions/862.html)  
**Location:** `/tmp/marinade-liquid-staking/programs/marinade-finance/src/instructions/user/withdraw_stake_account.rs` -> `WithdrawStakeAccount::stake_withdraw_authority()` (line 71)  

**Description:**  
Field `stake_withdraw_authority` in `WithdrawStakeAccount` is a privileged role (UncheckedAccount) using `UncheckedAccount` without signer enforcement. The Solana runtime does not check `is_signer` unless the program explicitly validates it. An attacker can pass any pubkey as `stake_withdraw_authority` and execute privileged operations. Use `Signer<'info>` instead of `AccountInfo<'info>`, or add `#[account(signer)]`. Without signer validation, the Solana runtime allows any account to be passed in the authority position. An attacker constructs a transaction with their own pubkey as the authority field and the runtime will not reject it. This is the most common Solana vulnerability pattern -- the Wormhole bridge exploit ($320M) was caused by a missing signer check on the guardian set update. [found in 12 locations; also in: deposit_stake_account.rs:DepositStakeAccount::msol_mint_authority, deposit.rs:Deposit::liq_pool_msol_leg_authority, partial_unstake.rs:PartialUnstake::stake_deposit_authority, emergency_unstake.rs:EmergencyUnstake::stake_deposit_authority, remove_liquidity.rs:RemoveLiquidity::liq_pool_msol_leg_authority, add_liquidity.rs:AddLiquidity::lp_mint_authority, update.rs:UpdateCommon::stake_withdraw_authority, stake_reserve.rs:StakeReserve::stake_deposit_authority, redelegate.rs:ReDelegate::stake_deposit_authority, merge_stakes.rs:MergeStakes::stake_deposit_authority, deactivate_stake.rs:DeactivateStake::stake_deposit_authority]

**Vulnerable Code:**
```rust
69:         bump = state.stake_system.stake_withdraw_bump_seed
70:     )]
71:     pub stake_withdraw_authority: UncheckedAccount<'info>,
72:     /// CHECK: PDA
73:     #[account(
```

**Attack Scenario:**  
Attacker passes a target account without signing, bypassing authority checks. This allows unauthorized state modifications, fund transfers, and ownership changes.

**Recommended Fix:**
```rust
Replace `AccountInfo<'info>` with `Signer<'info>`:
```rust
pub stake_withdraw_authority: Signer<'info>,
```
Or add the signer constraint:
```rust
#[account(signer)]
pub stake_withdraw_authority: AccountInfo<'info>,
```
```

---

### 2. 🔴 SOL-017 - Missing CPI Guard

**Severity:** 🔴 CRITICAL | **Confidence:** 75% | **Category:** Access Control

**CWE:** [CWE-346](https://cwe.mitre.org/data/definitions/346.html)  
**Location:** `/tmp/marinade-liquid-staking/programs/marinade-finance/src/instructions/user/withdraw_stake_account.rs` -> `unknown()` (line 264)  

**Description:**  
Line 264: Raw `invoke_signed()` call without prior program ID validation. The CPI target program is passed by the caller as an `AccountInfo`. Without checking `program.key() == expected_program::ID`, an attacker substitutes a malicious program that mimics the expected instruction interface. Use Anchor's `CpiContext` with `Program<'info, T>` instead, or add `require!(program.key() == expected::ID)` before the invoke call. Raw CPI via invoke/invoke_signed passes whatever program Account the caller provides. The Solana runtime does not validate that the target program is the one the developer intended. This is the primary CPI attack vector on Solana. [found in 7 locations; also in: deposit_stake_account.rs:unknown, partial_unstake.rs:unknown, stake_reserve.rs:unknown, redelegate.rs:unknown, merge_stakes.rs:unknown, deactivate_stake.rs:unknown]

**Vulnerable Code:**
```rust
261:         .last()
262:         .unwrap()
263:         .clone();
264:         invoke_signed(
265:             &split_instruction,
266:             &[
267:                 self.stake_program.to_account_info(),
```

**Attack Scenario:**  


**Recommended Fix:**
```rust
Replace raw invoke with Anchor's typed CPI:
```rust
// In Accounts struct:
pub token_program: Program<'info, Token>,

// In handler:
token::transfer(
CpiContext::new(ctx.accounts.token_program.to_account_info(), ...),
amount,
)?;
```
```

---

### 3. 🟠 SOL-082 - Missing has_one Constraint

**Severity:** 🟠 HIGH | **Confidence:** 65% | **Category:** Anchor Safety

**CWE:** [CWE-862](https://cwe.mitre.org/data/definitions/862.html)  
**Location:** `/tmp/marinade-liquid-staking/programs/marinade-finance/src/instructions/user/withdraw_stake_account.rs` -> `WithdrawStakeAccount::burn_msol_authority()` (line 46)  

**Description:**  
Field `burn_msol_authority` in `WithdrawStakeAccount` is a `Signer` but no state account in this struct uses `#[account(has_one = burn_msol_authority)]` to verify ownership. This means ANY valid wallet can call this instruction as the `burn_msol_authority`. Add `has_one = burn_msol_authority` to the relevant state/vault/pool account to bind the signer to stored authority. A Signer constraint only proves that the wallet signed the transaction. It does NOT prove the signer is the authorized authority for a specific account. Without `has_one`, any wallet that signs can act as the authority. The `has_one` constraint makes Anchor compare `state_account.authority == signer.key()` during deserialization. [found in 13 locations; also in: deposit_stake_account.rs:DepositStakeAccount::stake_authority, set_validator_score.rs:SetValidatorScore::manager_authority, remove_validator.rs:RemoveValidator::manager_authority, partial_unstake.rs:PartialUnstake::validator_manager_authority, emergency_unstake.rs:EmergencyUnstake::validator_manager_authority, add_validator.rs:AddValidator::manager_authority, remove_liquidity.rs:RemoveLiquidity::burn_from_authority, liquid_unstake.rs:LiquidUnstake::get_msol_from_authority, order_unstake.rs:OrderUnstake::burn_msol_authority, stake_reserve.rs:StakeReserve::rent_payer, redelegate.rs:ReDelegate::split_stake_rent_payer, deactivate_stake.rs:DeactivateStake::split_stake_rent_payer]

**Vulnerable Code:**
```rust
44:     pub burn_msol_from: Box<Account<'info, TokenAccount>>,
45:     #[account(mut)]
46:     pub burn_msol_authority: Signer<'info>,
47: 
48:     /// CHECK: deserialized in code, must be the one in State (State has_one treasury_msol_account)
```

**Attack Scenario:**  


**Recommended Fix:**
```rust
Add `has_one = burn_msol_authority` to the state account that stores this authority:
```rust
#[account(mut, has_one = burn_msol_authority @ ErrorCode::Unauthorized)]
pub vault: Account<'info, VaultState>,
```
```

---

### 4. 🟠 SOL-073 - Missing PDA Validation

**Severity:** 🟠 HIGH | **Confidence:** 65% | **Category:** Cryptographic

**CWE:** [CWE-20](https://cwe.mitre.org/data/definitions/20.html)  
**Location:** `/tmp/marinade-liquid-staking/programs/marinade-finance/src/instructions/user/withdraw_stake_account.rs` -> `WithdrawStakeAccount::split_stake_account()` (line 90)  

**Description:**  
Field `split_stake_account` in `WithdrawStakeAccount` uses `#[account(init)]` on a custom Account type without `seeds` derivation. If this account should be unique per user/mint/pool, it MUST be a PDA with appropriate seeds. Without seeds, the account address is determined by the caller's keypair, meaning:
- No uniqueness enforcement (two callers can create separate accounts)
- No deterministic address derivation (other instructions can't find it)
Add `seeds = [b"prefix", user.key().as_ref()], bump` for per-user PDAs. Without PDA seed derivation, account addresses are not deterministic. Other instructions cannot reliably locate the account, and there is no on-chain enforcement that the account belongs to a specific user, mint, or pool. This breaks composability and opens the door for account substitution attacks. [found in 5 locations; also in: partial_unstake.rs:PartialUnstake::split_stake_account, stake_reserve.rs:StakeReserve::stake_account, redelegate.rs:ReDelegate::split_stake_account, deactivate_stake.rs:DeactivateStake::split_stake_account]

**Vulnerable Code:**
```rust
88:         owner = stake::program::ID,
89:     )]
90:     pub split_stake_account: Account<'info, StakeAccount>,
91:     #[account(
92:         mut,
```

**Attack Scenario:**  


**Recommended Fix:**
```rust
Add seed derivation to create a deterministic, per-user PDA:
```rust
#[account(
init,
seeds = [b"state", user.key().as_ref()],
bump,
payer = user,
space = 8 + std::mem::size_of::<StateAccount>(),
)]
pub split_stake_account: Account<'info, StateAccount>,
```
```

---

## 🛠️ Remediation Priority

| # | ID | Type | Severity | Location | Line |
|---|----|----|----------|----------|------|
| 1 | SOL-001 | Missing Signer Validation | 🔴 CRITICAL | `/tmp/marinade-liquid-staking/programs/marinade-finance/src/instructions/user/withdraw_stake_account.rs` | 71 |
| 2 | SOL-017 | Missing CPI Guard | 🔴 CRITICAL | `/tmp/marinade-liquid-staking/programs/marinade-finance/src/instructions/user/withdraw_stake_account.rs` | 264 |
| 3 | SOL-082 | Missing has_one Constraint | 🟠 HIGH | `/tmp/marinade-liquid-staking/programs/marinade-finance/src/instructions/user/withdraw_stake_account.rs` | 46 |
| 4 | SOL-073 | Missing PDA Validation | 🟠 HIGH | `/tmp/marinade-liquid-staking/programs/marinade-finance/src/instructions/user/withdraw_stake_account.rs` | 90 |

---

*Generated by [Shanon](https://shanon.security) - Enterprise-Grade Solana Security Platform*

