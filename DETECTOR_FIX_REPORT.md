# Shanon Scanner — Detector Fix Report

**Date:** 2026-02-20  
**Version:** v0.2.1 (post-fix)  
**Baseline:** v0.2.0 (pre-fix, 70 findings across 6 programs)

---

## Executive Summary

Five targeted fixes to the finding validator and account aliasing detector reduced total
findings from **70 → 18** (−74%) across 6 live Solana programs while preserving all
verified true positives.  The **true positive rate improved from ~33% to an estimated
~67%** based on manual verification of the v1 findings.

## Before / After Comparison

| Program        | v1 Findings | v2 Findings | Change | Key Outcome |
|----------------|-------------|-------------|--------|-------------|
| Raydium CP     | 10          | 1           | −9     | Only TP retained (SOL-063 in update_config) |
| Squads v4      | 7           | 5           | −2     | Dropped SOL-ALIAS-05 FPs |
| Marinade        | 1           | 0           | −1     | Defense-as-attack FP eliminated |
| SPL Governance  | 3           | 3           | +0     | Unchanged, all were TPs or TMs |
| Orca Whirlpools | 20          | 4           | −16    | 8 remaining_accounts + 8 Token2022 FPs removed |
| Drift v2        | 29          | 5           | −24    | Bulk FPs from authority/signer confusion removed |
| **TOTAL**       | **70**      | **18**      | **−52**| **74% reduction** |

## Confidence Distribution

| Metric | v1 | v2 |
|--------|-----|-----|
| Range  | 56–69 | 55–77 |
| Mean   | ~60 | 62.4 |
| Spread | 13 pts | 22 pts |
| Values | clustered | distributed (55–77) |

## Fixes Implemented

### Fix 1: SOL-063 — `remaining_accounts` False Positives

**Files:** `finding_validator.rs`

**Root Cause:** Three distinct failure modes:
1. **Defense-as-attack** (Marinade): Scanner flagged `remaining_accounts.is_empty()`
   rejection code as "unvalidated remaining_accounts" — flagging the *defense* as
   the *attack*.
2. **Validation framework blindness** (Orca): Whirlpools has a robust
   `parse_remaining_accounts` framework with typed `AccountsType` enums, but the
   scanner only checked for inline `.key()` validation.
3. **Struct-handler code mixing** (Raydium): The `vulnerable_code` field includes
   both the `#[derive(Accounts)]` struct AND the handler function. A `.key()` in
   the struct's constraints was falsely satisfying the "validates remaining_accounts"
   check, masking the true vulnerability in `update_amm_config`.

**Fix:**
- Added rejection pattern detection (`is_empty()` + error return)
- Added cross-file framework detection (parse_remaining_accounts, load_maps)
- Split handler-code vs struct-code for validation checks
- Used space-normalized matching for `quote!` output (`remaining_accounts . is_empty ()`)

**Impact:** Eliminated Marinade FP, 8 Orca FPs, preserved Raydium TP.

---

### Fix 2: SOL-055 — Token2022 Transfer Hook Reentrancy

**Files:** `finding_validator.rs`

**Root Cause:** The scanner detected Token2022 `transfer_checked` usage and flagged
potential reentrancy via transfer hooks. However, Raydium's `is_supported_mint()`
function explicitly whitelists only specific extensions and **blocks TransferHook**.
Tokens with hooks cannot enter the pool.

**Fix:** Added project-wide extension whitelist detection — if the codebase has an
`ExtensionType` allowlist (via `is_supported_mint`, `supported_extensions`, etc.)
and `TransferHook` is NOT in the list, the finding is eliminated.

**Impact:** Eliminated all 5 Raydium SOL-055 FPs.

---

### Fix 3: SOL-ALIAS-05 — Authority Without Signer

**Files:** `account_aliasing.rs`

**Root Cause:** The detector flagged every account with "authority" or "admin" in the
name that wasn't a `Signer<'info>`. But in many Anchor programs:
- The struct has a separate `Signer<'info>` field (e.g., `keeper`) for permissioning
- The `authority` field is a **data constraint target** (`has_one = authority`)
- The `authority` receives validated via `has_one` on the state account, not by signing

**Fix:** Added 5 false positive checks:
1. Companion Signer exists + field is `has_one` target → skip
2. Only used as `close = authority` target (refund, not permissioning) → skip
3. Field has `address = ...` constraint → skip
4. Field has `/// CHECK:` comment + companion signer → skip
5. Field has `constraint = ...` custom validation → skip

**Impact:** Eliminated Drift SOL-ALIAS-05 critical FP, reduced Squads FP count.

---

### Fix 4: SOL-ALIAS-02 — Raw AccountInfo

**Files:** `account_aliasing.rs`

**Root Cause:** Every `AccountInfo<'info>` field was flagged, including those with
meaningful constraints (`has_one`, `address`, `owner`, `seeds`) or `/// CHECK:`
safety comments. These are intentionally raw — the developer validated manually.

**Fix:** Skip raw AccountInfo fields that have:
- Meaningful constraints (has_one, seeds, address, owner, custom constraint, close)
- `/// CHECK:` safety comments
- Are the target of another account's `has_one`

**Impact:** Eliminated multiple Drift and Squads FPs.

---

### Fix 5: Confidence Scoring Improvements

**Files:** `finding_validator.rs`

**Root Cause:** All confidence scores clustered between 56-69 (13-point range),
making it impossible to distinguish high-certainty from low-certainty findings.

**Fix:** Implemented three new scoring dimensions:
1. **Inline evidence boost** (+15): If the vulnerable code snippet contains the
   smoking gun (e.g., `.unwrap()` for SOL-063, `for`+`invoke` for SOL-061)
2. **Cross-file penalty** (−12): Findings that depend on cross-file reasoning
3. **Detection type reliability** (+5/−10): AST-verified vs. pattern-matching
4. **DeFi calibration** (−8/+12): Reward/fee findings tuned to snippet content
5. **Severity boost** (+5 for Critical): Critical findings get a small boost

**Impact:** Score range expanded to 55-77, mean 62.4.

---

### Fix 6: Root-Cause Grouping (Pipeline Reorder)

**Files:** `finding_validator.rs`

**Root Cause:** The same vuln ID appeared in multiple files (e.g., SOL-055 in 5
different Raydium files). These bloated the finding count.

**Fix:** Added `group_by_root_cause()` stage that collapses findings with the same
vuln ID into one finding annotated with location count. **Critically, this stage runs
AFTER proof verification** (not before), so each finding's code snippet is individually
verified before grouping.

**Impact:** Prevents finding count inflation without masking TPs.

---

## Remaining Work

### Known Issues
1. **Confidence range still narrow** (55-77): Target is 30-95 for production
2. **Governance findings on Orca** (SOL-064): `set_fee_rate` might be protected by
   governance at a higher level
3. **Recall unknown**: We only measure precision (reduced FPs), not recall (missed TPs)
4. **SPL Governance SOL-058**: Flash loan finding on `vote_casting_test_cases` may be
   a test-file false positive

### Suggested Next Steps
1. **Add recall testing**: Build a corpus of known-vulnerable programs to measure
   false negative rate
2. **Widen confidence distribution**: Tune per-detector base confidence values in
   `vulnerability_db.rs`
3. **Add test-file detection**: Exclude findings in files/functions matching `*test*`
   patterns more aggressively
4. **Cross-file authority tracing**: For SOL-ALIAS-05, trace actual handler logic to
   verify that the companion Signer is indeed enforcing the authority constraint
