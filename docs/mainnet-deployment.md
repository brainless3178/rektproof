# Shanon Oracle — Mainnet Deployment Checklist

> **Status:** ⚠️ NOT READY FOR MAINNET — External audit required  
> **Last Updated:** 2026-02-17  
> **Program ID:** `Ea1qKkVjEEGa5mLAWdDryPB1nsGHyuxwB7oQFz8obbw4`

---

## Table of Contents

1. [Pre-Deployment Requirements](#1-pre-deployment-requirements)
2. [Multi-Sig Authority Setup](#2-multi-sig-authority-setup)
3. [Economic Model](#3-economic-model)
4. [Deployment Procedure](#4-deployment-procedure)
5. [Post-Deployment Monitoring](#5-post-deployment-monitoring)
6. [Emergency Procedures](#6-emergency-procedures)
7. [State Migration (Devnet → Mainnet)](#7-state-migration-devnet--mainnet)
8. [Governance & Upgrades](#8-governance--upgrades)

---

## 1. Pre-Deployment Requirements

### Security Audit
- [ ] **External audit complete** — Contact one of:
  - OtterSec (`security@osec.io`) — Solana specialist, audited Marinade/Solend
  - Neodyme (`audit@neodyme.io`) — Niche Solana, found multiple Anchor CVEs
  - Sec3/Soteria — If still active, original Solana static analysis firm
- [ ] **Audit scope documented:**
  - 11 instructions across `programs/shanon-oracle/` (~800 LOC)
  - Focus areas: economic attacks (reputation inflation), PDA security, access control
  - Two-step authority transfer correctness
  - Confirmation receipt PDA rent economics
- [ ] **All audit findings resolved** (Critical/High: mandatory, Medium: recommended)
- [ ] **Audit report published** (transparency for analyst community)

### Accuracy Validation
- [ ] **Accuracy benchmark recall ≥ 80%** across 10+ vulnerable programs
  - Current: 72.2% across 3 programs (13/18 bugs)
  - Target: Add 7+ historical exploit reproductions
- [ ] **Per-detector precision measured** (false positive rate per SOL-XXX detector)
- [ ] **Confidence calibration validated** (predicted confidence correlates with actual accuracy)

### Code Quality
- [x] **All 467 tests passing, 0 failures**
- [x] **Oracle security fixes applied:**
  - [x] Two-step authority transfer (propose → accept → cancel)
  - [x] PDA validation on `deactivate_analyst`
  - [x] Duplicate confirmation prevention (ConfirmationReceipt PDA)
  - [x] Reserved space for future upgrades (95 bytes)
- [x] **Registry client synced** with actual oracle instruction set
- [ ] **Integration tests with `solana-test-validator`** — Currently missing
- [ ] **Anchor IDL generated and verified** (`anchor build && anchor idl parse`)

---

## 2. Multi-Sig Authority Setup

### Recommended Configuration
```
Multi-sig Provider: Squads Protocol v4 (squads.so)
Threshold:          3-of-5 signers
Timelock:           24 hours for program upgrades
                    0 hours for emergency pause

Signer Roles:
┌──────────────────┬────────────────────────────────────────┐
│ Signer           │ Responsibility                         │
├──────────────────┼────────────────────────────────────────┤
│ Core Developer 1 │ Day-to-day operations, analyst mgmt    │
│ Core Developer 2 │ Emergency response, monitoring         │
│ Security Lead    │ Audit oversight, vulnerability triage   │
│ Community Rep    │ Governance decisions, dispute resolution│
│ Cold Storage     │ Backup key, stored offline              │
└──────────────────┴────────────────────────────────────────┘
```

### Setup Steps
- [ ] **Create Squads multisig** at [app.squads.so](https://app.squads.so)
- [ ] **Add 5 guardian public keys** to the multisig
- [ ] **Set threshold to 3-of-5**
- [ ] **Transfer program upgrade authority** to the Squads vault:
  ```bash
  solana program set-upgrade-authority <PROGRAM_ID> \
    --new-upgrade-authority <SQUADS_VAULT_PUBKEY> \
    --upgrade-authority <CURRENT_AUTHORITY>
  ```
- [ ] **Initialize OracleConfig** with Squads vault as authority:
  ```bash
  # min_guardian_signatures should match Squads threshold
  shanon-cli initialize --authority <SQUADS_VAULT> --min-guardian-sigs 3
  ```
- [ ] **Add all 5 Squads signers as guardians** in OracleConfig
- [ ] **Test multi-sig flows:**
  - [ ] Propose authority transfer → requires 3/5 approval
  - [ ] Pause oracle → requires 3/5 approval
  - [ ] Add guardian → requires 3/5 approval

---

## 3. Economic Model

### Rent Costs

| Account Type | Size (bytes) | Rent (SOL) | Who Pays |
|---|---|---|---|
| `OracleConfig` | 381 | ~0.0034 | Program deployer (once) |
| `AnalystAccount` | 194 | ~0.0019 | Authority (per analyst) |
| `ProgramRiskScore` | ~780 | ~0.0064 | Analyst submitting assessment |
| `ConfirmationReceipt` | 81 | ~0.0011 | Confirming analyst |

### Scale Projections

| Scale | Analysts | Assessments | Confirmations | Total Rent |
|---|---|---|---|---|
| **Beta** (Month 1) | 10 | 50 | 100 | ~0.45 SOL |
| **Growth** (Month 6) | 50 | 500 | 2,500 | ~5.9 SOL |
| **Mature** (Year 1) | 200 | 5,000 | 25,000 | ~60.5 SOL |

### Key Economic Considerations
- **Analyst Registration:** Authority-gated — no permissionless spam risk
- **Assessment Cost:** ~0.0064 SOL per assessment — negligible at $150/SOL
- **Confirmation Cost:** ~0.0011 SOL per receipt — negligible
- **Reputation Gaming:** Confirmation receipts prevent inflation (Phase 1 fix)
- **Rent Recovery:** `ProgramRiskScore` accounts can be closed to reclaim rent
  when assessments are superseded (not yet implemented — future upgrade)

---

## 4. Deployment Procedure

### Pre-Flight (Day -1)
```bash
# 1. Build the program
anchor build

# 2. Verify the program hash
solana-verify build --program-id Ea1qKkVjEEGa5mLAWdDryPB1nsGHyuxwB7oQFz8obbw4

# 3. Run full test suite
cargo test --workspace

# 4. Run accuracy benchmarks
cargo test -p program-analyzer --test accuracy_benchmarks -- --nocapture

# 5. Generate IDL
anchor idl parse -f programs/shanon-oracle/src/lib.rs -o target/idl/shanon_oracle.json
```

### Deploy (Day 0)
```bash
# 1. Deploy program to mainnet
solana program deploy \
  target/deploy/shanon_oracle.so \
  --program-id Ea1qKkVjEEGa5mLAWdDryPB1nsGHyuxwB7oQFz8obbw4 \
  --url mainnet-beta \
  --keypair <DEPLOYER_KEYPAIR>

# 2. Transfer upgrade authority to Squads multisig
solana program set-upgrade-authority \
  Ea1qKkVjEEGa5mLAWdDryPB1nsGHyuxwB7oQFz8obbw4 \
  --new-upgrade-authority <SQUADS_VAULT> \
  --keypair <DEPLOYER_KEYPAIR>

# 3. Initialize oracle config
shanon-cli initialize \
  --authority <SQUADS_VAULT> \
  --min-guardian-sigs 3 \
  --url mainnet-beta

# 4. Add guardians (requires Squads approval for each)
for GUARDIAN in $GUARDIAN_KEYS; do
  shanon-cli add-guardian --guardian $GUARDIAN --url mainnet-beta
done

# 5. Register initial analysts (whitelisted)
for ANALYST in $ANALYST_KEYS; do
  shanon-cli register-analyst --wallet $ANALYST --url mainnet-beta
done
```

### Post-Deploy Verification
```bash
# Verify config account
shanon-cli show-config --url mainnet-beta

# Verify program is live
solana program show Ea1qKkVjEEGa5mLAWdDryPB1nsGHyuxwB7oQFz8obbw4

# Verify upgrade authority is Squads vault
solana program show Ea1qKkVjEEGa5mLAWdDryPB1nsGHyuxwB7oQFz8obbw4 | grep Authority
```

---

## 5. Post-Deployment Monitoring

### Week 1-2: Observation Period
- [ ] **Monitor assessment submissions** (expect 5-10 per day from whitelisted analysts)
- [ ] **Monitor confirmation activity** (verify no duplicate attempts)
- [ ] **Monitor authority transfer proposals** (should be zero in normal operation)
- [ ] **Set up alerts:**
  - Any `set_paused` instruction → immediate team notification
  - Any `propose_authority_transfer` → immediate team notification
  - Assessment rate > 50/day → investigate (potential spam)
  - Analyst registration without team knowledge → investigate

### Dashboard Metrics
```
Key Metrics to Track:
├─ Total assessments submitted
├─ Total confirmations
├─ Average confidence score
├─ Analyst reputation distribution
├─ Programs assessed (unique count)
├─ Dispute rate (if disputes are implemented)
└─ Rent costs (cumulative SOL spent on PDAs)
```

### Gradual Rollout
| Phase | Week | Analysts | Programs | Guardrails |
|---|---|---|---|---|
| **Alpha** | 1-2 | 5 (hand-picked) | 10 | Pause-ready, daily review |
| **Beta** | 3-4 | 20 | 50 | Weekly review, community feedback |
| **GA** | 5+ | Open registration | Unlimited | Automated monitoring |

---

## 6. Emergency Procedures

### Immediate Pause
```bash
# If any vulnerability is discovered in production:
shanon-cli set-paused --paused true --url mainnet-beta
# Requires 3-of-5 Squads approval
```

### Authority Transfer (Compromised Key)
```bash
# If a guardian key is compromised:
# 1. Propose transfer to new authority
shanon-cli propose-authority-transfer --new-authority <NEW_SQUADS_VAULT>
# 2. New authority accepts
shanon-cli accept-authority-transfer --url mainnet-beta
# 3. Remove compromised guardian
shanon-cli remove-guardian --guardian <COMPROMISED_KEY>
```

### Program Upgrade
```bash
# If a critical bug requires a code fix:
# 1. Apply fix, rebuild
anchor build
# 2. Deploy via Squads (requires 3/5 + 24hr timelock)
squads-cli program-upgrade \
  --program Ea1qKkVjEEGa5mLAWdDryPB1nsGHyuxwB7oQFz8obbw4 \
  --buffer <BUFFER_ACCOUNT> \
  --multisig <SQUADS_MULTISIG>
```

---

## 7. State Migration (Devnet → Mainnet)

**There is no state migration.** Mainnet starts fresh with:
- New `OracleConfig` account (initialized via `initialize` instruction)
- No analysts (registered individually after deploy)
- No assessments (submitted after analysts are registered)

Devnet data is preserved for testing but is **not** migrated to mainnet.

### Future Upgrades (Using Reserved Space)
The `OracleConfig` has **95 bytes of reserved space**. Future fields can be
added without reallocation:

```
Available Budget: 95 bytes
Possible Additions:
├─ max_analysts: u32        (4 bytes)  → cap analyst registration
├─ max_flags_per_score: u8  (1 byte)   → limit flag spam
├─ fee_lamports: u64        (8 bytes)  → assessment submission fee
├─ treasury: Pubkey         (32 bytes) → fee recipient
└─ Remaining: 50 bytes for future use
```

---

## 8. Governance & Upgrades

### Upgrade Process
1. **Proposal** — Any guardian proposes upgrade via Squads
2. **Review Period** — 24-hour timelock for non-emergency upgrades
3. **Approval** — 3-of-5 guardians must approve
4. **Execution** — Squads vault executes the upgrade
5. **Verification** — `solana-verify build` to confirm on-chain matches source

### Governance Decisions Requiring Multi-Sig
| Action | Threshold | Timelock |
|---|---|---|
| Program upgrade | 3-of-5 | 24 hours |
| Add/remove guardian | 3-of-5 | 0 hours |
| Pause/unpause oracle | 3-of-5 | 0 hours |
| Authority transfer | 3-of-5 | 0 hours |
| Register analyst | 1-of-5 (authority) | 0 hours |
| Deactivate analyst | 1-of-5 (authority) | 0 hours |

### Program Immutability Timeline
```
Month 1-3:  Upgradeable (bug fixes expected)
Month 4-6:  Upgradeable (feature additions)
Month 7-12: Consider freezing upgrade authority
Year 2+:    Immutable (renounce upgrade authority)
```

---

## Appendix: Contact & Resources

| Resource | Link |
|---|---|
| Squads Protocol | [squads.so](https://squads.so) |
| OtterSec Audits | [osec.io](https://osec.io) |
| Neodyme Audits | [neodyme.io](https://neodyme.io) |
| Solana Verify | [github.com/Ellipsis-Labs/solana-verifiable-build](https://github.com/Ellipsis-Labs/solana-verifiable-build) |
| Anchor Book | [anchor-lang.com](https://www.anchor-lang.com) |
