# 🔬 rektproof — Brutally Honest Deep Audit

**Audit Date:** 2026-02-21  
**Auditor:** Independent code review (zero prior involvement)  
**Scope:** Full codebase — 76,761 lines of Rust across 183 source files, 13 crates + 33 experimental crates  
**Methodology:** Source code review, build verification, test execution, architectural analysis

---

## Executive Summary

**rektproof is a real, working Solana security scanner.** It compiles, passes all tests (200+ across workspace), and can genuinely scan Solana/Anchor programs for vulnerabilities. The core engine (`program-analyzer`) is legitimate and well-built. The validation pipeline is thoughtfully designed.

**However**, the project over-claims its capabilities in the README and architecture docs. Many of the "15 analysis engines" are not what they claim to be. Some are genuine static analysis; others are pattern-matching heuristics dressed up in academic language. The "formal verification" features are largely mocked. The claimed "live results" are not reproducible independently.

**Overall Verdict: A strong hackathon project that has been aggressively marketed beyond its actual capabilities.**

---

## 🟢 What ACTUALLY Works (and Works Well)

### 1. Build & Test Infrastructure — **A Grade**

- `cargo check` passes cleanly (only 1 minor warning: dead `usage` field in `ai-enhancer`)
- `cargo test --workspace` — **ALL tests pass. Zero failures.** Including Z3 solver tests that take 242 seconds.
- Clean workspace setup with proper `default-members` separation
- No `todo!()` or `unimplemented!()` macros anywhere in the codebase (impressive)
- Only 2 lines with TODO/FIXME comments across 76k LoC (both in test files — acceptable)
- Release profile has `overflow-checks = true` and `lto = "fat"` — correct for a security tool

### 2. Pattern Matching Engine (Phase 1) — **A- Grade**

`crates/program-analyzer/src/vulnerability_db.rs` — **3,231 lines, 72+ vulnerability patterns**

This is the real workhorse. Each SOL-XXX detector is a function that takes source code and returns a finding:
- **SOL-001 to SOL-012**: Core Solana vulns (missing signer, overflow, owner, type cosplay, CPI, duplicates, bump seeds, PDA sharing, closing, sysvar, init, data matching)
- **SOL-013 to SOL-052**: Extended patterns (rent, deser, reentrancy, flash loans, oracle manipulation, Token-2022, governance, etc.)
- **SOL-053 to SOL-072**: Advanced Solana-specific (close resurrection, program impersonation, Token-2022 hooks/fees, permanent delegate, state machines, CU exhaustion)

**The Good:** These are all real pattern matchers. They look for actual code patterns using string analysis. Each has severity, CWE mapping, attack scenarios, and fix suggestions. The coverage is genuinely comprehensive for Solana.

**The Bad:** They're all string-matching heuristics, not true semantic analysis. `check_missing_signer(code: &str)` searches for string patterns like `AccountInfo` without `Signer`. This means they can't reason about control flow, data flow, or cross-function interactions. But this is honest — most commercial SAST tools work exactly this way.

### 3. Deep AST Scanner (Phase 2) — **A Grade**

`crates/program-analyzer/src/deep_ast_scanner.rs` — **954 lines**

This is legitimately excellent. It uses `syn::visit` to walk the actual Rust AST:
- **SOL-001**: Finds `AccountInfo` fields named authority/admin/owner that should be `Signer`
- **SOL-002**: Walks AST for `BinOp::Add/Sub/Mul` not inside `checked_*` calls
- **SOL-003**: Missing owner checks with actual Anchor constraint parsing
- **SOL-007**: PDA seed canonicalization via struct attribute analysis
- **SOL-009**: Unsafe account close detection
- **SOL-011**: Unprotected initialization
- **SOL-017**: Reentrancy (CPI followed by state write analysis)
- **Privilege escalation**: `set_authority` without multi-sig patterns

This provides **real line numbers** from the AST, not just "found somewhere in the file." The `ArithmeticChecker` is a proper `syn::visit::Visit` implementation. This is good work.

### 4. Finding Validator — **A+ Grade (Best Part of the Codebase)**

`crates/program-analyzer/src/finding_validator.rs` — **1,638 lines**

This is the crown jewel. It implements a 6-stage false-positive elimination pipeline:

1. **Deduplication** — Same (vuln_id, file) = one finding
2. **Proof Verification** — 723-line `is_proven_safe()` function that recognizes:
   - `checked_add`/`saturating_sub` → eliminates arithmetic overflow FPs
   - `has_one = authority` → eliminates missing signer FPs on data fields
   - Extension whitelist patterns → eliminates Token-2022 hook FPs
   - `remaining_accounts.is_empty() → return Err()` → eliminates defensive patterns
   - Anchor `seeds = [...]` → eliminates PDA signing FPs
   - `constant_product` invariant → eliminates oracle manipulation FPs in AMMs
3. **Root-Cause Grouping** — Same vuln across files → one annotated finding
4. **Confidence Scoring** — Per-finding verifiability with inline-evidence boost
5. **Non-Program Filtering** — Excludes tests, scripts, migrations
6. **Severity Capping** — Prevents finding count inflation

The `ProjectContext` struct aggregates 50+ codebase signals (checked math usage, PDA signers, extension whitelists, slippage checks, Anchor constraint density, etc.) and uses them to contextualize every finding. The maturity scoring is based on real security indicators. **This is auditor-level reasoning implemented in code.**

### 5. Taint Lattice (Phase 3) — **B+ Grade**

`crates/program-analyzer/src/taint_lattice.rs` — **801 lines**

A real lattice-based taint analysis with formal mathematical foundation:
- Proper `TaintLevel` enum: `Untainted ⊑ SignerControlled ⊑ AccountInput ⊑ ArithmeticDerived ⊑ ExternalData ⊑ Tainted`
- Join, meet, subsumption operations properly implemented
- Transfer functions for assignments, method calls, etc.
- Worklist algorithm with fixed-point iteration

**Honest assessment:** The lattice algebra is correct, but the analysis operates on `syn` AST nodes, not on a proper intermediate representation. It's doing intraprocedural taint analysis — it can track taint within a single function but cannot track across function calls or modules. Still, for source-level analysis, this is legitimate.

### 6. CFG Analyzer (Phase 4) — **B+ Grade**

`crates/program-analyzer/src/cfg_analyzer.rs` — **1,012 lines**

Real CFG construction with proper algorithms:
- Basic block construction from `syn::Stmt`
- Dominator computation via iterative data-flow
- `reachable_without_guard()` — checks if dangerous ops can be reached without auth checks
- Back-edge detection for loop identification
- Natural loop computation

**Honest assessment:** Each statement becomes a basic block (overly fine-grained, but safe). The dominator algorithm is textbook correct. The security checks (auth bypass, unbounded loops) are real. However, it can't handle Anchor's macro-generated control flow — it only sees what `syn` can parse.

### 7. Abstract Interpretation (Phase 5) — **A Grade**

`crates/program-analyzer/src/abstract_interp.rs` — **925 lines**

This is genuinely impressive for a hackathon project:
- Proper `Interval` domain: `[lo, hi]` over extended integers (ℤ ∪ {-∞, +∞})
- Correct abstract arithmetic (add, sub, mul, div with interval propagation)
- **Widening** (`∇`) and **narrowing** (`Δ`) operators for loop convergence
- Overflow detection: `Definite` (always overflows), `Possible` (may overflow), `Safe`
- Division-by-zero detection
- Type-aware initialization (`u64` → `[0, 2^64-1]`, `i64` → `[i64::MIN, i64::MAX]`)

**Honest assessment:** The interval arithmetic is correct. However, the abstract interpretation operates on a string-level expression parser, not on a proper abstract syntax. `evaluate_abstract_expr` splits expressions by `+`, `-`, `*`, `/` at the text level, which can misparse complex Rust expressions. The widening is implemented but there's no actual loop-head detection wiring the widening to real loops — it's not used in practice. The fixed-point iteration is not actually run. Still, the interval domain math itself is textbook correct.

### 8. Account Aliasing (Phase 6) — **A- Grade**

`crates/program-analyzer/src/account_aliasing.rs` — **981 lines**

This is a real must-not-alias analysis with proper false-positive suppression:
- Parses Anchor account structs with field-level type classification
- Constraint parsing: `has_one`, `seeds`, `constraint`, `address`, `owner`, `token::mint`, `token::authority`, `init`, `close`
- Must-not-alias check: finds account pairs that could be the same key without any distinguishing constraint
- Smart false-positive handling: skips pairs where one has PDA seeds, or they're linked by `has_one`, or there's an explicit inequality constraint
- References real incidents (Wormhole $320M, Cashio $52M, Crema Finance $8.8M)

### 9. Interactive Dashboard — **A Grade**

`crates/shanon-cli/src/dashboard.rs` — **1,154 lines**

Ratatui-powered interactive TUI with:
- Overview tab with score gauge
- Findings tab with severity filtering
- Engines tab with phase timing visualization
- Fix queue with prioritization
- Keyboard navigation (Tab, arrows, 1-4 severity toggles)
- Color-coded severity badges

**This is production-quality TUI work.** The non-interactive `tui.rs` (445 lines) also provides beautiful box-drawing output with gradient text.

### 10. CLI — **B+ Grade**

`crates/shanon-cli/src/main.rs` — **1,740 lines, 13 commands**

Working commands: `scan`, `score`, `guard`, `firedancer`, `cpi`, `token`, `watch`, `verify`, `benchmark`, `verify-formal`, `fuzz`, `economic-verify`, `orchestrate`, `scan-repo`

Multi-format output: `dashboard` (interactive), `human` (terminal), `json`, `sarif` (v2.1.0), `markdown`

The `cmd_scan` function is 477 lines and handles the entire pipeline: parse → scan → validate → display. The SARIF output generator is 121 lines and produces spec-compliant output. The markdown report generator produces professional-looking audit reports.

### 11. API Server — **B Grade**

`crates/shanon-api/` — Full REST API with:
- On-chain account deserialization (reads from Solana directly)
- Background scan worker with async job queue (max 4 concurrent, max 100 total)
- GitHub repo cloning and scanning
- On-chain program analysis with verified source lookup
- OpenAPI specification
- Rate limiting
- Badge generation

This is a working web service, though it's coupled to the `shanon-oracle` Solana program which needs to be deployed.

---

## 🟡 Grey Area — Works But Overstated

### 12. Experimental "Analysis Engines" — **The Marketing Problem**

The README claims **"15 analysis engines"**. Let me break down what's real vs. what's inflated:

| Phase | Claimed Name | Reality | Honest Grade |
|-------|-------------|---------|--------------|
| 1 | Pattern Scanner | ✅ Real. 72 pattern matchers. | A- |
| 2 | Deep AST Scanner | ✅ Real. Proper `syn::visit`. | A |
| 3 | Taint Lattice | ✅ Real. Proper lattice algebra. Intraprocedural only. | B+ |
| 4 | CFG Analyzer | ✅ Real. Dominator-based analysis. | B+ |
| 5 | Abstract Interp | ✅ Real interval domain. Expression parser is string-based. | B+ |
| 6 | Account Aliasing | ✅ Real. Must-not-alias analysis. | A- |
| 7 | Sec3 (Soteria) | 🟡 Not the actual Soteria tool. It's a pattern-matching reimplementation. 624 LoC. | B |
| 8 | Anchor Security | 🟡 Constraint validation. Works, but it's pattern matching on attribute strings. 388 LoC. | B |
| 9 | Dataflow | 🟡 Reaching definitions analysis. 816 LoC. Operates on `syn` AST, not SSA/IR. | B |
| 10 | Taint Analyzer | ⚠️ 14-line `lib.rs` that re-exports submodules. The actual work is in the submodules. Works but thin. | B- |
| 11 | Geiger | 🟡 `unsafe` code analysis. 337 LoC. Pattern matching for `unsafe` blocks. | B |
| 12 | Arithmetic Expert | ✅ Real. 429 LoC. Focused numeric analysis. | B+ |
| 13 | L3X Heuristic | ⚠️ Described as "ML-inspired" but it's bag-of-words scoring with hand-tuned weights. No ML. | C+ |
| 14 | Invariant Miner | 🟡 Discovers invariants from patterns (balance, access control, arithmetic). Z3 verification of mined invariants. 729 LoC. | B+ |
| 15 | Concolic Executor | 🟡 Has Z3 integration for constraint solving. 558 LoC. Generates random/boundary inputs. The actual concolic analysis is more of a guided fuzzing harness than true concolic execution. | B |

**The honest count: ~6 genuinely distinct analysis techniques, dressed up as 15.** Phases 1, 7, 8, 11, 13 are all pattern matching with different dictionaries. Phases 3, 9, 10 are all data-flow analysis at different granularities. This isn't fraud — many commercial tools do the same — but the README should be more honest.

### 13. Formal Verification Pipeline — **Mostly Mocked**

The FV layer stack (`fv-layer1` through `fv-layer4`, `fv-scanner-core`):
- **Layer 1** (304 LoC): Generates properties from AST. No actual verification.
- **Layer 2** (466 LoC): "SMT model generation." Uses Z3 for some overflow checks.
- **Layer 3** (203 LoC): Z3 invariant checking on `#[account]` structs. Real but simple.
- **Layer 4** (474 LoC): State machine proofs and DOT graph generation. Real but limited.

The `verify-formal` CLI command runs all 4 layers and produces output that *looks* like:
```
Layer 1: Property Extraction .... 12 properties
Layer 2: Model Generation ...... SMT model built
Layer 3: Z3 Verification ...... 11/12 proved safe
Layer 4: Counterexamples ...... 1 potential violation
```

**Honest assessment:** The Z3 integration is real (tests take 242 seconds proving it). But calling this "formal verification" is a stretch. It does not generate Z3 assertions from actual program semantics. It generates Z3 constraints from pattern-matched properties. This is "property-guided testing with Z3" not formal verification in the academic sense.

### 14. Z3 / Symbolic Engine — **Real But Disconnected**

`symbolic-engine` (332 LoC) has genuine Z3 operations:
- Arithmetic overflow checking on bitvectors
- Authority bypass checking
- Custom logic invariant verification
- `prove_exploitability` entry point

BUT it requires manually constructed `SymbolicAccount` and `BV<'ctx>` values. There's no automated pipeline from Rust source → Z3 constraints. The user (or the CLI) would need to manually specify what to verify. The `concolic-executor` does use Z3 for constraint solving, but the constraint generation comes from the pattern matchers, not from the actual program semantics.

### 15. "Live Results" Claims — **Unverifiable**

The README claims:
```
| Raydium CP Swap | 1 | 100% | 0.3s |
| Squads v4 Multisig | 5 | ~80% | 0.4s |
| Marinade Finance | 0 | N/A (clean) | 0.2s |
```

There is a `RAYDIUM_CP_SWAP_AUDIT.json` (7.8 MB!) and a `live-audit-results/` directory, but no automated regression tests that reproduce these exact results. The `benchmark_precision_recall.py` script exists but requires manual setup.

---

## 🔴 What's Broken / Misleading

### 1. "ML-Inspired" L3X Analyzer — **No ML**

The L3X analyzer is described as "ML-inspired pattern detection" and originally called "ML Detection." It was renamed to "Heuristic Detection" (good), but the README still says "ML-inspired." In reality, it's:
- A bag-of-words tokenizer with hand-tuned weights
- 22 Solana-specific token weights (e.g., `lamports` → 5.0, `checked_div` → -3.0)
- Cosine similarity between code embeddings

This is a TF-IDF variant, not machine learning. No training, no model, no inference. Calling it "ML-inspired" is misleading.

### 2. 33 Experimental Crates — **Feature Count Inflation**

The workspace has **33 experimental crates**. Total LoC: ~16,076 across those crates. Average: 487 lines per crate. Many of them are:
- Thin wrappers around the core engine
- Separate crates for what should be modules
- "Analyzer" crates that do the same pattern matching as the core
- "Expert" crates that are re-exports with extra context

Example: `account-security-expert` (423 LoC), `arithmetic-security-expert` (429 LoC), `defi-security-expert` (486 LoC) — these add value but could be modules, not crates. They exist as separate crates to make the project look like it has more components.

### 3. The Orchestrator Doesn't Orchestrate (Well)

The `integration-orchestrator` is 137 LoC with 4 tests. The `SHANON_COMPLETION_PLAN.md` admits it has "24 modules" but many are stubs. The real orchestration happens in `shanon-cli/src/main.rs` in the `cmd_orchestrate` function.

### 4. Kani / Certora — Fallback Only

`kani-verifier` (1,096 LoC, 30 tests) and `certora-prover` (801 LoC, 9 tests) both work in "offline mode" which means they do NOT actually call Kani or Certora. They run Z3-based fallback analysis. The names imply integration with these real tools that doesn't actually happen without manual setup.

### 5. main.rs Is a God File

At 1,740 lines, `main.rs` handles:
- CLI parsing (200 lines)
- Scan command (477 lines)
- Score, Guard, Firedancer, CPI, Token, Watch, Verify commands
- SARIF output generation (121 lines)
- Markdown report generation (82 lines)
- Orchestrate, Scan-repo, Benchmark, Verify-formal, Fuzz, Economic-verify commands

This is a maintenance nightmare. Each command handler should be a separate module.

### 6. Solana SDK Pinned to 1.18 (Outdated)

The workspace pins `solana-sdk = "1.18"` and `solana-client = "1.18"`. The current Solana version is 2.x. The Cargo.toml even acknowledges:

> NOTE: solana-client v1.18.x triggers a future-incompatibility warning about never type fallback. Newer versions (2.x/3.x) exist but require a full Solana SDK migration.

This means `cargo build` will eventually break when Rust enforces the never-type fallback change.

### 7. No CI/CD Running

There's a `.github/` directory but I can see no evidence of actual CI runs. The GitHub Action (`shanon-action/`) is defined but the workflow file at `.github/` isn't populated with real CI.

### 8. Docker Config — Incomplete

The `Dockerfile` (1,195 bytes) and `docker-compose.yml` (1,318 bytes) exist but are minimal. The compose file likely doesn't handle the Z3 dependency properly for all the crates that need it.

---

## 📊 By-the-Numbers

| Metric | Value | Assessment |
|--------|-------|-----------|
| Total Rust LoC | 76,761 | Large for a hackathon |
| Source files | 183 | Well-structured |
| Workspace crates | 46 (13 prod + 33 experimental) | Inflated |
| `cargo check` | ✅ Clean (1 warning) | Excellent |
| `cargo test --workspace` | ✅ ALL PASS (0 failures) | Excellent |
| Approximate test count | 200+ | Good for the scope |
| Files with tests | 91 / 183 (50%) | Decent coverage |
| `todo!()` / `unimplemented!()` | 0 | Excellent |
| TODO/FIXME comments | 2 | Excellent |
| Vulnerability patterns | 72 (SOL-001 to SOL-072) | Best-in-class for Solana |
| CLI commands | 13 | Comprehensive |
| Output formats | 5 (dashboard, human, json, sarif, markdown) | Professional |
| External tool dependencies | Z3 only (statically linked) | Practical |

---

## 🏗️ Architecture Assessment

### What's Good About the Architecture

1. **Workspace structure is clean**: Production crates separated from experimental, programs, tests, exploits
2. **Core engine is well-factored**: `ProgramAnalyzer` orchestrates phases cleanly
3. **Finding model is robust**: `VulnerabilityFinding` has all the right fields (CWE, confidence, attack scenario, fix, prevention, real-world incident)
4. **Validation pipeline is the right idea**: The "prosecutor test" approach (can an attacker actually exploit this?) is exactly how experienced auditors think
5. **Multi-format output**: JSON, SARIF, Markdown, interactive TUI — covers all use cases

### What's Wrong with the Architecture

1. **No proper intermediate representation**: Everything operates on `syn` AST or raw strings. A real multi-engine scanner would compile to an IR (like LLVM IR or a custom Solana IR) and run analyses on that
2. **String-based heuristics dominate**: Most "engines" are `fn check_foo(code: &str) -> Option<Finding>`. This is grep-with-context, not program analysis
3. **No interprocedural analysis**: Every analysis engine works within a single function or struct. Cross-function data flow? Cross-module taint tracking? Not happening.
4. **Z3 is disconnected from source**: Z3 constraints are manually constructed, not derived from program semantics. There's no `Rust source → Z3 formula` pipeline.
5. **The AST scanner and pattern scanner overlap significantly**: Phases 1 and 2 detect many of the same things with different methods. The dedup works, but it's engineering waste.

---

## 🎯 Verdict: What Judges / Reviewers Should Know

### If This Is a Hackathon Project
**Grade: A-**. This is exceptional hackathon work. The core engine is real, the validation pipeline is thoughtful, the TUI is polished, and everything actually compiles and passes tests. The over-marketing is par for the course at hackathons.

### If This Claims to Be an "Enterprise-Grade" Security Scanner
**Grade: C+**. The fundamental analysis techniques (string matching, AST walking) are sufficient for catching common patterns but insufficient for the deep semantic analysis that "enterprise-grade" implies. No interprocedural analysis, no IR-based reasoning, no actual formal verification pipeline. Commercial tools like Semgrep or Aderyn do similar string/AST matching but are honest about their limitations.

### If You're Evaluating the Detection Quality
**The finding validator is genuinely good.** The approach of "generate many findings, then aggressively filter false positives" is the right architecture. The 723-line `is_proven_safe()` function shows deep understanding of Solana/Anchor patterns. The confidence scoring with project maturity modulation is sophisticated.

The pattern coverage (72 patterns) is genuinely comprehensive for Solana. The README's claim of going from 70 raw detections to 18 validated findings across 6 programs is plausible given the validation pipeline.

### What's Missing for Real Production Use

1. **Independent validation**: No third-party has verified the precision/recall claims
2. **Benchmark suite against known CVEs**: Should test against every known Solana exploit and verify detection
3. **False negative analysis**: The project focuses on false positives but never addresses false negatives — what does it MISS?
4. **Incremental scanning**: No support for scanning diffs or changed files only
5. **IDE integration**: The LSP crate (`shanon-lsp`, 194 lines) is a stub
6. **Config file support**: No `.rektproof.toml` for project-specific configuration
7. **Rule suppression**: No inline `// rektproof-ignore` comments or per-project rule configuration

---

## 🔧 Top 10 Fixes (If You Have Time)

1. **Honest README**: Remove "ML-inspired", clarify "15 engines" as "6 analysis techniques applied through 15 phases", remove unverifiable precision claims
2. **Split main.rs**: Each command handler into its own module under `src/commands/`
3. **Add regression test against real CVEs**: Take 10 known Solana exploits, write the vulnerable code, assert detection
4. **Wire widening to real loops**: The abstract interpreter has widening but never applies it at loop heads
5. **Interprocedural taint**: Even simple call-chain tracking would improve detection
6. **Automate CI**: Add GitHub Actions workflow that runs `cargo test --workspace` on every push
7. **Upgrade Solana SDK**: Migrate from 1.18 to 2.x before the future-incompatibility break
8. **Add false-negative tests**: For every SOL-XXX pattern, write a test case that exercises both detection AND evasion
9. **Extract CLI commands**: The 1,740-line `main.rs` is unmaintainable
10. **Document what it can't detect**: Every security tool should be honest about blind spots

---

## Bottom Line

**The code is real. The engineering is solid. The marketing is aggressive.** 

The core of this project — pattern matching + AST analysis + a smart validation pipeline — is genuinely useful and well-implemented. Approximately 50% of the codebase (the core engine, deep AST scanner, finding validator, account aliasing, abstract interpreter) is high-quality work that does what it claims. The other 50% (experimental crates, "formal verification," "ML," "15 engines") is packaging-inflation that makes the project look bigger and more sophisticated than it is.

For a hackathon: **this is outstanding work and should place highly.**  
For production: **strip the marketing, focus the core, and be honest about capabilities.**
