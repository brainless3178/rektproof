# Marinade Finance Liquid Staking Program — Complete Repository Scan

> **Repository**: https://github.com/marinade-finance/liquid-staking-program  
> **Program ID**: `MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD`  
> **Framework**: Anchor 0.27.0 / Solana 1.14.29  
> **Language**: Rust (Edition 2021)  
> **Total Lines of Rust**: 7,610 across 51 source files  
> **Total Commits**: 213 (main branch)  
> **Latest Release**: `release-20231114` (Anchor v0.27 upgrade)  
> **Audits**: Neodyme (2023), Sec3 (2023), Kudelski Security (2021), Ackee Blockchain (2021), Neodyme (2021)  

---

## 1. Repository Structure

```
marinade-liquid-staking/
├── Anchor.toml                      # Anchor config (v0.27.0, Solana 1.14.29)
├── Cargo.toml                       # Workspace: overflow-checks=true, lto="fat"
├── Cargo.lock
├── README.md
├── LICENSE.md                       # License
├── Docs/
│   ├── Backend-Design.md            # 392 lines - comprehensive design doc
│   └── img/                         # Diagrams
├── scripts/
│   ├── verify.sh                    # Anchor verify on mainnet
│   ├── verify-buffer.sh             # Buffer verification
│   └── prepare-upgrade.sh           # Multisig upgrade flow
└── programs/marinade-finance/
    ├── Cargo.toml                   # anchor-lang 0.27, anchor-spl 0.27
    ├── Xargo.toml
    └── src/
        ├── lib.rs                   # 273 lines — Entry point, 22 instructions
        ├── calc.rs                  #  31 lines — proportional math
        ├── checks.rs               # 159 lines — Validation helpers
        ├── error.rs                # 273 lines — 87 error codes (6000-6086)
        ├── state/                  # Core data structures
        ├── instructions/           # All instruction handlers
        └── events/                 # Anchor event definitions
```

---

## 2. Architecture Overview

### 2.1 Core State (`state/mod.rs` — 284 lines)

The central `State` account (Anchor `#[account]`) stores all protocol configuration:

| Field | Type | Description |
|-------|------|-------------|
| `msol_mint` | `Pubkey` | mSOL SPL Token mint |
| `admin_authority` | `Pubkey` | Admin (DAO) authority |
| `operational_sol_account` | `Pubkey` | Bot wallet for rent returns |
| `treasury_msol_account` | `Pubkey` | Treasury for protocol fees |
| `reserve_bump_seed` | `u8` | PDA bump for reserve |
| `reward_fee` | `Fee` | % fee on staking rewards |
| `stake_system` | `StakeSystem` | Stake account management |
| `validator_system` | `ValidatorSystem` | Validator list management |
| `liq_pool` | `LiqPool` | Liquidity pool state |
| `available_reserve_balance` | `u64` | Virtual reserve balance |
| `msol_supply` | `u64` | Virtual mSOL supply |
| `msol_price` | `u64` | Cached mSOL price (binary-denominated) |
| `circulating_ticket_count` | `u64` | Outstanding delayed-unstake tickets |
| `circulating_ticket_balance` | `u64` | Total lamports in tickets |
| `paused` | `bool` | Emergency pause flag |
| `pause_authority` | `Pubkey` | Who can pause |
| `delayed_unstake_fee` | `FeeCents` | Fee on delayed unstake |
| `withdraw_stake_account_fee` | `FeeCents` | Fee on direct stake withdrawal |
| `max_stake_moved_per_epoch` | `Fee` | Stake movement cap |

**Key Constants**:
- `PRICE_DENOMINATOR`: `0x1_0000_0000` (2^32)
- `MAX_REWARD_FEE`: 10% (1000 basis points)
- `MAX_DELAYED_UNSTAKE_FEE`: 0.2% (2000 bp_cents)
- `MAX_WITHDRAW_STAKE_ACCOUNT_FEE`: 0.2% (2000 bp_cents)
- `MIN_STAKE_LOWER_LIMIT`: 0.01 SOL

**Critical Functions**:
- `total_lamports_under_control()` = active_balance + cooling_down + reserve_balance
- `total_virtual_staked_lamports()` = total_under_control - circulating_ticket_balance
- `calc_msol_from_lamports()` — shares_from_value (SOL → mSOL conversion)
- `msol_to_sol()` — value_from_shares (mSOL → SOL conversion)
- `stake_delta()` — determines how much to stake/unstake (i128 calculation)
- `on_stake_moved()` — enforces per-epoch stake movement cap

### 2.2 Sub-State Components

#### Fee (`state/fee.rs` — 136 lines)
- **`Fee`**: basis points (u32), max 10,000 (100%). `apply()` does `amount * bp / 10000` in u128.
- **`FeeCents`**: higher-precision fee (u32 bp_cents), max 1,000,000 (100%). `apply()` does `amount * bp_cents / 1_000_000` in u128.

#### LiqPool (`state/liq_pool.rs` — 136 lines)
- SOL-mSOL liquidity pool with **linear fee curve** from `lp_max_fee` (at 0 liquidity) → `lp_min_fee` (at target liquidity)
- PDA seeds: `liq_mint`, `liq_sol`, `liq_st_sol_authority`
- Treasury cut: up to 75% of swap fees
- Min liquidity target: 50 SOL
- Max fee: 10%
- Virtual `lp_supply` tracking

#### StakeSystem (`state/stake_system.rs` — 210 lines)
- Maintains on-chain list of all Marinade-controlled stake accounts
- **`StakeRecord`**: `{stake_account, last_update_delegated_lamports, last_update_epoch, is_emergency_unstaking}`
- PDA authorities: `deposit` (staker) and `withdraw` (withdrawer)
- `delayed_unstake_cooling_down` tracks SOL being deactivated
- `slots_for_stake_delta` (min 3000 slots = ~21 min) — window at end of epoch
- `extra_stake_delta_runs` allows re-staking late deposits
- `min_stake` minimum delegation

#### ValidatorSystem (`state/validator_system.rs` — 277 lines)
- **`ValidatorRecord`**: `{validator_account, active_balance, score, last_stake_delta_epoch, duplication_flag_bump_seed}`
- Score-proportional stake targeting: `stake_target = total_target × score / total_score`
- Duplication prevention via PDA flag accounts (seed: `unique_validator`)
- `auto_add_validator_enabled` — DEPRECATED

#### List (`state/list.rs` — 173 lines)
- Generic on-chain list with fixed-size serialized items
- 8-byte discriminator prefix
- O(1) index access, O(1) remove (swap with last)
- Capacity bounded by account size

#### TicketAccountData (`state/delayed_unstake_ticket.rs` — 11 lines)
- Anchor account: `{state_address, beneficiary, lamports_amount, created_epoch}`

---

## 3. Instruction Catalog (22 Instructions)

### 3.1 Admin Instructions (8)

| Instruction | Auth | Description |
|-------------|------|-------------|
| `initialize` | First-time | Create State, stake_list, validator_list, reserve PDA, liq pool |
| `change_authority` | `admin_authority` | Change admin, validator manager, operational SOL, treasury, pause authority |
| `config_lp` | `admin_authority` | Set LP min/max fee, liquidity target, treasury cut |
| `config_marinade` | `admin_authority` | Set rewards fee, slots_for_delta, min_stake, caps, withdrawal fees |
| `config_validator_system` | `manager_authority` | Set extra_stake_delta_runs |
| `pause` | `pause_authority` | Emergency pause all operations |
| `resume` | `pause_authority` | Resume from pause |
| `realloc_validator_list` | `admin_authority` | Resize validator list account |
| `realloc_stake_list` | `admin_authority` | Resize stake list account |

### 3.2 User Instructions (4)

| Instruction | Description |
|-------------|-------------|
| `deposit` | Stake SOL → receive mSOL. First tries to swap from LiqPool mSOL leg, remainder goes to reserve + mint |
| `deposit_stake_account` | Deposit active stake account → receive mSOL. Transfers staker/withdrawer auth to PDAs |
| `liquid_unstake` | Swap mSOL → SOL through LiqPool. Fee based on linear curve, treasury cut applied |
| `withdraw_stake_account` | Burn mSOL → receive split stake account. Fee applied, min_stake remainder enforced |

### 3.3 Liquidity Pool Instructions (3)

| Instruction | Description |
|-------------|-------------|
| `add_liquidity` | Deposit SOL into LiqPool → receive LP tokens |
| `remove_liquidity` | Burn LP tokens → receive proportional SOL + mSOL |
| `liquid_unstake` | (listed under user, operates on LiqPool) |

### 3.4 Delayed Unstake Instructions (2)

| Instruction | Description |
|-------------|-------------|
| `order_unstake` | Burn mSOL → create TicketAccountData. Waits ≥ 1 epoch + 30 min |
| `claim` | Present valid ticket → receive SOL from reserve |

### 3.5 Management Instructions (4)

| Instruction | Auth | Description |
|-------------|------|-------------|
| `add_validator` | `manager_authority` | Add validator to list with score, create duplication flag PDA |
| `remove_validator` | `manager_authority` | Remove validator (balance must be 0), delete flag |
| `set_validator_score` | `manager_authority` | Update validator score for stake allocation |
| `emergency_unstake` | `manager_authority` | Deactivate entire stake for zero-scored validator (with stake_moved cap) |
| `partial_unstake` | `manager_authority` | Partially unstake from over-target validator (with stake_moved cap) |

### 3.6 Crank (Bot) Instructions (5)

| Instruction | Description |
|-------------|-------------|
| `stake_reserve` | Create + delegate new stake account from reserve (end-of-epoch window) |
| `update_active` | Check active stake: compute rewards, mint protocol fee, update mSOL price |
| `update_deactivated` | Withdraw deactivated stake to reserve, update cooling_down, remove from list |
| `deactivate_stake` | Split + deactivate stake when delta is negative (end-of-epoch window) |
| `merge_stakes` | Merge two same-validator stake accounts, return extra rent |
| `redelegate` | Move stake between validators using Solana redelegate instruction |

---

## 4. Token Flow Architecture

### mSOL Price Formula
```
mSOL_price = total_virtual_staked_lamports / msol_supply
           = (total_active_balance + total_cooling_down + available_reserve_balance 
              - circulating_ticket_balance) / msol_supply
```

### Deposit SOL Flow
```
User SOL → [Try swap mSOL from LiqPool mSOL leg] → [Remainder to Reserve PDA]
         → [Mint mSOL for remainder] → User mSOL
```

### Liquid Unstake Flow
```
User mSOL → [Compute fee based on remaining liquidity curve]
          → [mSOL to LiqPool mSOL leg (minus treasury cut)]
          → [Treasury cut to treasury_msol_account]
          → [SOL from LiqPool SOL leg to User]
```

### Delayed Unstake Flow
```
User mSOL → [Burn mSOL] → [Create Ticket with lamports_amount]
         → [Wait 1+ epoch] → [Bot runs deactivate_stake / update_deactivated]
         → [SOL arrives in reserve] → [User claims ticket → receives SOL]
```

---

## 5. PDA Seeds & Accounts

| PDA | Seeds | Purpose |
|-----|-------|---------|
| Reserve | `[state, "reserve"]` | Holds SOL between staking operations |
| mSOL Mint Authority | `[state, "st_mint"]` | Authority to mint mSOL |
| Stake Deposit Auth | `[state, "deposit"]` | Staker authority for all stake accounts |
| Stake Withdraw Auth | `[state, "withdraw"]` | Withdrawer authority for all stake accounts |
| LP Mint Authority | `[state, "liq_mint"]` | Authority to mint LP tokens |
| LP SOL Leg | `[state, "liq_sol"]` | SOL side of liquidity pool |
| LP mSOL Leg Auth | `[state, "liq_st_sol_authority"]` | Authority for mSOL side of LP |
| Validator Dup Flag | `[state, "unique_validator", validator]` | Prevents duplicate validator entries |

---

## 6. Security Analysis

### 6.1 Access Control
- **Admin**: `admin_authority` (DAO controlled) — can configure fees, caps, authorities
- **Validator Manager**: `manager_authority` — manages validator list, emergency unstake
- **Pause Authority**: `pause_authority` — can emergency pause/resume
- **All user-facing instructions** check `!self.state.paused`
- **`check_context()`** verifies program ID and rejects extra accounts (anti-CPI-hijack)

### 6.2 Arithmetic Safety
- All arithmetic uses `u128` intermediates for multiply-then-divide operations
- `overflow-checks = true` in both workspace and program Cargo.toml
- `saturating_sub` used in slashing scenarios to prevent underflow
- `proportional()` in `calc.rs` uses `u128` cast: `(amount as u128) * (numerator as u128) / (denominator as u128)`

### 6.3 Re-entrancy & CPI Guards
- `check_context()` blocks extra accounts (no unexpected re-entrancy vectors)
- All CPI calls use `invoke_signed` with proper PDA seeds
- Anchor's account ownership checks enforced

### 6.4 Stake Account Management
- On-chain list of all controlled stake accounts (prevents fake reward injection)
- `get_checked()` validates index matches account pubkey (prevents index manipulation)
- Duplication flags prevent adding same validator twice
- `is_emergency_unstaking` flag prevents double-deactivation
- `last_stake_delta_epoch` prevents double-staking per validator per epoch

### 6.5 Economic Protections
- **Staking cap**: `staking_sol_cap` limits total deposits
- **Liquidity cap**: `liquidity_sol_cap` limits LP deposits
- **Min stake**: prevents dust stake accounts
- **Min deposit/withdraw**: prevents tiny uneconomical operations
- **Delayed unstake fee**: prevents epoch-boundary gaming
- **Withdraw stake account fee**: prevents instant-withdrawal economic attacks
- **Stake movement cap**: `max_stake_moved_per_epoch` limits validator-to-validator moves
- **Ticket timing**: 1 epoch wait + 30 min buffer for bot processing
- **Treasury cut validation**: gracefully handles invalid treasury accounts (returns `None`)

### 6.6 mSOL Supply Integrity
- Virtual `msol_supply` field tracked, synced with real mint supply on `update_*`
- If `mint.supply > state.msol_supply` → warning, `staking_sol_cap = 0` (halt deposits)
- Checks `msol_mint.supply <= state.msol_supply` before deposits

### 6.7 LP Supply Integrity
- Virtual `lp_supply` tracked, synced with real supply
- `UnregisteredLPMinted` error if real supply exceeds virtual

---

## 7. Fee Structure

| Fee | Range | Applied On |
|-----|-------|------------|
| Reward Fee | 0–10% | Staking rewards (minted as mSOL to treasury) |
| LP Swap Fee | lp_min_fee – lp_max_fee (max 10%) | Liquid unstake operations |
| Treasury Cut | 0–75% of LP swap fee | Portion of swap fee to treasury |
| Delayed Unstake Fee | 0–0.2% | Delayed unstake orders |
| Withdraw Stake Fee | 0–0.2% | Direct stake account withdrawals |

---

## 8. Bot/Crank Operations

The system requires an external bot to perform epoch-maintenance:

1. **End of epoch** (within `slots_for_stake_delta` of epoch end):
   - `stake_reserve` — stake positive delta to under-target validators
   - `deactivate_stake` — unstake negative delta from over-target validators
   - `redelegate` — move stake between validators

2. **Start of epoch**:
   - `update_active` — for each active stake account: compute rewards, mint protocol fees, update mSOL price
   - `update_deactivated` — withdraw fully deactivated accounts to reserve

3. **Mid-epoch**:
   - `merge_stakes` — consolidate stake accounts per validator

All crank operations are **permissionless** — anyone can call them.

---

## 9. Key Algorithms

### 9.1 Stake Delta Calculation (`State::stake_delta()`)
```rust
// i128 arithmetic — can be positive (need to stake) or negative (need to unstake)
raw = reserve_balance - rent_exempt + delayed_unstake_cooling_down - circulating_ticket_balance
if raw >= 0 { return raw }
// When negative, include emergency_cooling_down but cap at 0
with_emergency = raw + emergency_cooling_down
return min(with_emergency, 0)
```

### 9.2 Linear Fee Curve (`LiqPool::linear_fee()`)
```
fee(lamports) = lp_max_fee - delta * lamports / lp_liquidity_target
where delta = lp_max_fee - lp_min_fee
if lamports >= lp_liquidity_target → fee = lp_min_fee
```

### 9.3 mSOL Price Update (`UpdateCommon::update_msol_price()`)
```rust
msol_price = msol_to_sol(PRICE_DENOMINATOR)
           = PRICE_DENOMINATOR * total_virtual_staked_lamports / msol_supply
```

---

## 10. Event System

Every instruction emits a detailed Anchor event capturing:
- State key and epoch
- Pre-operation balances (for auditability)
- Computed values (fees, amounts, prices)
- mSOL price components (`total_virtual_staked_lamports`, `msol_supply`)

Events defined in 6 modules: `admin`, `crank`, `delayed_unstake`, `liq_pool`, `management`, `user`.

---

## 11. Deployment & Verification

- **Mainnet program**: `MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD`
- **Verification**: `anchor verify` against mainnet deployment  
- **Upgrade**: Via multisig (`551FBXSXdhcRDDkdcb3ThDRg84Mwe5Zs6YjJ1EEoyzBp`)
- **Security TXT**: Embedded via `solana-security-txt` crate (v1.1.1)
- **Build profile**: `lto = "fat"`, `codegen-units = 1`, `overflow-checks = true`

---

## 12. File-by-File Line Count (Sorted)

| Lines | File |
|------:|------|
| 548 | `instructions/crank/update.rs` |
| 454 | `instructions/crank/redelegate.rs` |
| 368 | `instructions/user/withdraw_stake_account.rs` |
| 356 | `instructions/crank/deactivate_stake.rs` |
| 339 | `instructions/crank/stake_reserve.rs` |
| 295 | `instructions/management/partial_unstake.rs` |
| 294 | `instructions/user/deposit_stake_account.rs` |
| 284 | `state/mod.rs` |
| 284 | `instructions/admin/initialize.rs` |
| 277 | `state/validator_system.rs` |
| 274 | `error.rs` |
| 273 | `lib.rs` |
| 249 | `instructions/crank/merge_stakes.rs` |
| 242 | `instructions/user/deposit.rs` |
| 235 | `instructions/admin/config_marinade.rs` |
| 210 | `state/stake_system.rs` |
| 187 | `instructions/liq_pool/liquid_unstake.rs` |
| 182 | `instructions/liq_pool/remove_liquidity.rs` |
| 173 | `state/list.rs` |
| 168 | `instructions/liq_pool/add_liquidity.rs` |
| 160 | `checks.rs` |
| 154 | `instructions/delayed_unstake/claim.rs` |
| 136 | `state/liq_pool.rs` |
| 136 | `state/fee.rs` |
| 132 | `instructions/management/emergency_unstake.rs` |
| 128 | `events/crank.rs` |
| 126 | `instructions/delayed_unstake/order_unstake.rs` |
| 96 | `instructions/admin/change_authority.rs` |
| 91 | `instructions/management/remove_validator.rs` |
| 87 | `instructions/admin/config_lp.rs` |
| 82 | `events/admin.rs` |
| 74 | `instructions/management/add_validator.rs` |
| 60 | `events/user.rs` |
| 59 | `instructions/management/set_validator_score.rs` |
| 53 | `events/liq_pool.rs` |
| 51 | `instructions/admin/realloc_validator_list.rs` |
| 51 | `instructions/admin/realloc_stake_list.rs` |
| 47 | `events/mod.rs` |
| 40 | `instructions/admin/emergency_pause.rs` |
| 32 | `calc.rs` |
| 32 | `events/delayed_unstake.rs` |
| 31 | `events/management.rs` |
| 22 | `instructions/admin/config_validator_system.rs` |
| 11 | `state/delayed_unstake_ticket.rs` |

---

## 13. Dependencies

| Crate | Version |
|-------|---------|
| `anchor-lang` | 0.27.0 |
| `anchor-spl` | 0.27.0 (features: stake, mint, spl-token, token) |
| `solana-security-txt` | 1.1.1 |

---

## 14. Branches & Tags

| Branch/Tag | Description |
|------------|-------------|
| `main` | Current HEAD |
| `mainnet` / `anchor-0.27` | Production release |
| `release-20231114` | Tagged release |
| `main-before-anchor-0.27` | Pre-upgrade snapshot |
| `anchor-0.29` | WIP upgrade |
| `fix-delinquent*` | Delinquent validator fixes |

---

*Scan completed: All 51 Rust source files, 3 scripts, 2 config files, 2 documentation files read in their entirety.*
