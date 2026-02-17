# Shanon Oracle — External Audit Scope

> **Prepared:** 2026-02-17  
> **Program:** `shanon-oracle`  
> **Program ID:** `Ea1qKkVjEEGa5mLAWdDryPB1nsGHyuxwB7oQFz8obbw4`  
> **Framework:** Anchor 0.30.x  
> **Language:** Rust  
> **Chain:** Solana

---

## 1. Executive Summary

Shanon Oracle is an on-chain security intelligence layer for Solana. Security
analysts submit vulnerability assessments with granular flag-level data, and
any Solana program can query risk scores via CPI to make security-aware decisions.

The system is **not a financial protocol** — it stores reputation scores and
security assessments, not user funds. However, the integrity of its data is
critical for downstream consumers who may use these scores to gate financial
operations (e.g., "only interact with programs scoring ≥ 80").

---

## 2. Scope

### In-Scope Files

| File | LOC | Description |
|------|-----|-------------|
| `programs/shanon-oracle/src/lib.rs` | 160 | Program entry point, instruction routing |
| `programs/shanon-oracle/src/state/config.rs` | 65 | `OracleConfig` — global settings, authority, guardians |
| `programs/shanon-oracle/src/state/analyst.rs` | ~80 | `AnalystAccount` — registered analyst profiles |
| `programs/shanon-oracle/src/state/risk_score.rs` | 248 | `ProgramRiskScore` — on-chain assessment data |
| `programs/shanon-oracle/src/instructions/admin.rs` | 143 | Admin ops: guardian mgmt, pause, authority transfer |
| `programs/shanon-oracle/src/instructions/initialize.rs` | 60 | One-time config initialization |
| `programs/shanon-oracle/src/instructions/register_analyst.rs` | ~60 | Analyst registration |
| `programs/shanon-oracle/src/instructions/submit_assessment.rs` | ~100 | Submit security assessment |
| `programs/shanon-oracle/src/instructions/update_assessment.rs` | ~80 | Update existing assessment |
| `programs/shanon-oracle/src/instructions/confirm_assessment.rs` | 165 | Confirm assessment + receipt PDA |
| `programs/shanon-oracle/src/instructions/query_risk.rs` | ~40 | CPI-callable risk query |
| `programs/shanon-oracle/src/errors/mod.rs` | 90 | Custom error codes |
| **TOTAL** | **~1,291** | |

### Out-of-Scope
- Off-chain orchestrator (`crates/orchestrator/`) — not deployed on-chain
- Vulnerability detectors (`crates/program-analyzer/`) — not part of the oracle
- Test programs (`programs/vulnerable-vault/`, etc.) — intentionally buggy
- Frontend / CLI tools

---

## 3. Architecture

```
                    ┌─────────────────────────┐
                    │      OracleConfig       │
                    │  (authority, guardians,  │
                    │   paused, version)       │
                    └───────────┬─────────────┘
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                 │
     ┌────────▼─────────┐ ┌────▼────────┐ ┌──────▼──────────┐
     │  AnalystAccount  │ │ RiskScore   │ │ Confirmation    │
     │  (per analyst)   │ │ (per target │ │   Receipt       │
     │                  │ │  program)   │ │ (per analyst ×  │
     │  wallet          │ │             │ │  program)       │
     │  reputation_bps  │ │  flags[]    │ │                 │
     │  assessments     │ │  confidence │ │  analyst        │
     │  active          │ │  analyst    │ │  target_program │
     └──────────────────┘ │  status     │ │  confirmed_at   │
                          └─────────────┘ └─────────────────┘
```

### PDA Seeds

| Account | Seeds | Derivation |
|---------|-------|-----------|
| `OracleConfig` | `["shanon_config"]` | Singleton |
| `AnalystAccount` | `["shanon_analyst", wallet]` | Per analyst wallet |
| `ProgramRiskScore` | `["risk_score", target_program]` | Per assessed program |
| `ConfirmationReceipt` | `["confirmation", target_program, analyst_wallet]` | Per analyst × program |

---

## 4. Focus Areas

### 4.1 Access Control (Critical)
- Authority validation on all admin instructions
- Two-step authority transfer correctness (propose → accept → cancel)
- Guardian quorum enforcement (currently `min_guardian_signatures` is set but
  analyst registration gate is commented out — verify if this is intentional)
- Analyst activation/deactivation cannot be bypassed

### 4.2 Economic / Reputation Attacks (Critical)
- **Reputation inflation:** Can an analyst artificially boost their reputation?
  - Duplicate confirmations are prevented by `ConfirmationReceipt` PDA
  - Self-confirmation is blocked by `SelfConfirmation` error
  - Verify: Can an analyst register multiple wallets and cross-confirm?
- **Score manipulation:** Can a single analyst dominate a program's score?
  - Only one assessment per program (tied to `risk_score` PDA)
  - Updates require same analyst
  - Verify: What happens if analyst is deactivated after submitting?
- **Denial of Service:** Can an attacker make assessments unusable?
  - Assessments can be superseded (verify status transitions)
  - Verify: Can a malicious analyst submit garbage assessments?

### 4.3 PDA Security (High)
- All PDAs use canonical bumps (Anchor handles this, but verify)
- Seed collision resistance (no two accounts share seeds)
- Account reinitialization attacks (Anchor discriminator mitigates, verify)

### 4.4 Arithmetic Safety (Medium)
- `compute_confidence` uses basis points math — verify no overflow
- `reputation_bps` capped at 10000 — verify cap is enforced everywhere
- `confirmations` (u8) — verify saturation at 255 is acceptable

### 4.5 CPI Safety (Medium)
- `query_risk` uses `set_return_data` — verify data encoding is correct
- Verify CPI callers cannot pass spoofed accounts

### 4.6 State Transitions (Medium)
- `AssessmentStatus` transitions: `Pending → Confirmed → Disputed/Superseded/Withdrawn`
- Verify finalized assessments cannot be re-opened
- Verify only valid transitions are allowed

---

## 5. Known Issues (Already Fixed)

These issues were identified and fixed internally. The auditor should **verify
the fixes are correct** rather than re-discovering them:

| Issue | Severity | Fix Applied |
|-------|----------|-------------|
| Immediate authority transfer (no 2-step) | High | Added propose/accept/cancel flow |
| PDA validation missing in `deactivate_analyst` | Medium | Added `seeds` constraint with `analyst_wallet` arg |
| No duplicate confirmation prevention | Medium | Added `ConfirmationReceipt` PDA with `init` constraint |
| `_reserved` space not accounted for `pending_authority` | Low | Carved 33 bytes from 128 → 95 |

---

## 6. Testing Environment

```bash
# Build
anchor build

# Run unit tests
cargo test --workspace

# Run accuracy benchmarks
cargo test -p program-analyzer --test accuracy_benchmarks -- --nocapture

# Local validator testing (if integration tests are added)
solana-test-validator --reset &
anchor test
```

---

## 7. Deliverables Expected

1. **Audit Report** (PDF) with:
   - All findings categorized by severity (Critical / High / Medium / Low / Informational)
   - Reproduction steps for each finding
   - Recommended fixes
2. **Fix Review** — After fixes are applied, re-review the specific findings
3. **Executive Summary** — Suitable for public disclosure

---

## 8. Timeline & Budget

| Phase | Duration | Deliverable |
|-------|----------|-------------|
| Initial Review | 1 week | Draft findings |
| Deep Dive | 1-2 weeks | Final report |
| Fix Review | 3-5 days | Updated report |
| **Total** | **2-4 weeks** | **Full audit report** |

**Estimated Budget:** $15,000 – $40,000  
(Varies by firm. Program is ~1,300 LOC of Anchor, which is on the smaller side.)
