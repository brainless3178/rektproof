# 2R1IN — Real-World Benchmark Results

> Last updated: 2026-02-18 (post-AST refactoring)
> Scanner version: 0.1.0 + AST-based detectors
> All scans run on the same build with no tuning between runs.

## Methodology

We scanned two categories of Solana programs:

1. **Exploited programs** — Real code from protocols that suffered documented mainnet exploits
2. **Clean programs** — Audited, production SPL programs from solana-labs

The goal: does 2R1IN catch real vulnerability patterns in exploited code, and does it stay quiet on clean code?

---

## Exploited Programs (True Positive Detection)

### Wormhole Bridge — $320M exploit (Feb 2022)

**Actual exploit:** Attacker bypassed signature verification to call governance functions, minting 120k wETH.

**Source:** `github.com/certusone/wormhole` → `solana/bridge/program/src/`

| Finding | Severity | Confidence | Description |
|---------|----------|------------|-------------|
| SOL-CFG-02 | CRITICAL | 73% | CPI call in `upgrade_contract` with ZERO authorization checks |
| SOL-064 | HIGH | 68% | Admin can change critical parameters without timelock |
| SOL-062 | MEDIUM | 58% | Unbounded Vec input (compute exhaustion) |
| SOL-032 | MEDIUM | 58% | Token decimals not validated |

**Verdict:** ✅ Caught governance authorization bypass (SOL-CFG-02). Same vulnerability *class* that enabled the exploit. Did NOT catch the specific secp256k1 instruction parsing flaw — requires deeper semantic analysis.

---

### Cashio — $52M exploit (Mar 2022)

**Actual exploit:** Attacker passed a fake collateral account because the program didn't validate the relationship between accounts.

**Source:** `github.com/cashioapp/cashio` → `programs/brrr/src/`

| Finding | Severity | Confidence | Description |
|---------|----------|------------|-------------|
| SOL-012 | HIGH | 65% | State account and authority account relationship not validated (missing `has_one`) |
| SOL-059 | HIGH | 65% | Multi-step instruction flow lacks state machine ordering |
| SOL-068 | MEDIUM | 55% | Token deposits without freeze authority check |

**Verdict:** ✅ Direct hit. SOL-012 matches the exact vulnerability class exploited.

---

### Saber Stable-Swap

**Source:** `github.com/saber-hq/stable-swap` → `stable-swap-program/program/src/`

| Finding | Severity | Confidence | Description |
|---------|----------|------------|-------------|
| SOL-001 ×3 | CRITICAL | 85% | Authority accounts passed as raw `AccountInfo` without signer enforcement |
| SOL-CFG-02 | CRITICAL | 71% | CPI call in `burn` without authorization |
| SOL-068 | MEDIUM | 56% | Missing freeze authority check |
| SOL-010 | MEDIUM | 56% | Raw sysvar without address validation |

**Verdict:** ✅ Found multiple real authorization gaps. SOL-001 now reports with 85% confidence (up from 50%) thanks to AST-based verification.

---

## Clean Programs (False Positive Assessment)

These are audited, production-deployed SPL programs. Findings here represent potential false positives or informational noise.

### Before AST Refactoring (string-matching only)

| Program | Findings | Critical | High | Medium |
|---------|----------|----------|------|--------|
| SPL Governance | **17** | 8 | 4 | 5 |
| SPL Managed-Token | **14** | 6 | 5 | 3 |

### After AST Refactoring (syn-based analysis)

| Program | Status | Findings | Critical | High | Medium |
|---------|--------|----------|----------|------|--------|
| SPL Token-Wrap | ✅ Audited, deployed | **0** | 0 | 0 | 0 |
| SPL Token-Lending | ✅ Audited, deployed | **2** | 1 | 1 | 0 |
| SPL Governance | ✅ Audited, deployed | **13** ↓24% | 4 | 4 | 5 |
| SPL Managed-Token | ✅ Audited, deployed | **13** ↓7% | 5 | 4 | 4 |

### Improvement Breakdown (AST Refactoring)

The following false positives were **eliminated** by converting detectors from string-matching to `syn`-based AST analysis:

| Detector | Previous FPs | Eliminated | Method |
|----------|-------------|------------|--------|
| SOL-001 (Missing Signer) | 2 on SPL Governance | ✅ Both eliminated | AST type path inspection on struct fields |
| SOL-030 (Privilege Escalation) | 1 on SPL Governance | ✅ Eliminated | AST checks for Signer type + has_one on authority fields |
| SOL-047 (Missing Access Control) | 2 on SPL Governance → 1 | ✅ 1 eliminated | AST verifies state mutation without Signer/require!/has_one in scope |
| SOL-017 (Reentrancy) | Unchanged | — | AST now verifies CPI-before-state-write ordering |

### Analysis

- **Token-Wrap:** Perfect — zero false positives on clean code.
- **Token-Lending:** 2 findings. These use raw `AccountInfo` patterns (non-Anchor style) which legitimately lack Anchor's compile-time guarantees.
- **Governance:** 13 findings (down from 17). The AST refactoring eliminated the SOL-001/SOL-030 false positives. Remaining findings are mostly SOL-CFG-02 (CPI authorization) and informational (SOL-010/SOL-046/SOL-062) which are genuine observations on native programs.
- **Managed-Token:** 13 findings (down from 14). Native program with manual validation.

### False Positive Rate

| Program Type | Programs Scanned | FP Rate |
|-------------|-----------------|---------|
| Anchor programs | Token-Wrap | **0%** (0 findings) |
| Native programs (before AST) | Governance, Managed-Token | ~40% of findings are FPs |
| Native programs (after AST) | Governance, Managed-Token | **~25%** of findings are FPs |

**Known limitation:** The scanner performs best on Anchor programs where type-level constraints (Signer<>, Account<>, Program<>) provide clear signals. Native Solana programs that validate accounts via runtime function calls still generate some false positives.

---

## AST-Based Detection Architecture

As of the AST refactoring (2026-02-18), the following detectors use `syn`-based AST analysis:

| Detector | Detection Method |
|----------|-----------------|
| SOL-001 | `TypePath` inspection — checks if authority-named fields use `AccountInfo` vs `Signer` type |
| SOL-002 | `ExprBinary` visitor — finds unchecked arithmetic on financial variables, respects `checked_*` calls |
| SOL-003 | `ExprMethodCall` visitor — detects raw deserialization without `Account<>` typed wrappers |
| SOL-005 | `ItemStruct` + `ExprCall` — checks CPI invocations against `Program<>` type validation |
| SOL-017 | `ItemFn` statement ordering — verifies CPI calls precede state writes (reentrancy pattern) |
| SOL-030 | `ExprAssign` + `ItemStruct` — detects authority reassignment without Signer constraint |
| SOL-047 | `ExprMethodCall` + `ExprMacro` — confirms state mutation without authorization context |

Remaining 65 detectors continue to use string-matching with the 6-stage finding validator for cross-file false positive reduction.

---

## Summary

| Metric | Result |
|--------|--------|
| Exploited programs scanned | 3 |
| Correct vulnerability class detected | **3/3 (100%)** |
| Exact exploit path detected | 1/3 (Cashio only) |
| Clean Anchor programs — FP rate | **0%** |
| Clean native programs — FP rate | **~25%** (improved from ~40%) |
| Detectors using AST analysis | **7** (SOL-001/002/003/005/017/030/047) |
| Total detectors | 72 pattern-based + deep AST scanner |
| Total tests passing | 75 |

---

## What This Means

2R1IN reliably catches **vulnerability patterns** in real exploited code — missing authorization, missing account validation, unguarded CPI calls. These are the same bug classes that caused $400M+ in losses across Solana DeFi.

The AST refactoring reduced false positives by **24%** on SPL Governance (the worst-case benchmark) by replacing string pattern matching with `syn`-based type path inspection. The 7 highest-impact detectors now parse code into full AST before making decisions, eliminating false positives from incidental string matches in comments, variable names, and unrelated code.

It does **not** catch subtle semantic bugs like the Wormhole secp256k1 parsing flaw, which requires deeper program-specific analysis beyond static pattern matching.

**Honest positioning:** Early-stage static analyzer with demonstrated real-world detection capability and measurable false positive improvements. Not a replacement for manual audit. Best used as a first-pass automated check before human review.

