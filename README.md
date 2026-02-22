<p align="center">
  <h1 align="center">⚡ rektproof</h1>
  <p align="center">
    <strong>Enterprise-grade Solana security scanner — proof against getting rekt.</strong>
  </p>
  <p align="center">
    <a href="#features">Features</a> •
    <a href="#quick-start">Quick Start</a> •
    <a href="#architecture">Architecture</a> •
    <a href="#honest-capabilities">Honest Capabilities</a> •
    <a href="#contributing">Contributing</a>
  </p>
</p>

[![CI](https://github.com/brainless3178/rektproof/actions/workflows/ci.yml/badge.svg)](https://github.com/brainless3178/rektproof/actions/workflows/ci.yml)

---

## What is rektproof?

**rektproof** is a multi-technique security scanner for Solana programs. It applies
6 distinct analysis techniques through 20 scanning phases — from pattern matching
to abstract interpretation — via a single CLI tool.

```
$ rektproof scan ./programs/my-protocol --format json

  ╭ ◉ SECURITY SCORE ╮
  │       87/100      │
  ╰───────────────────╯

  ✓ 20 scanning phases completed in 0.8s
  ✓ 3 findings survived validation (from 47 raw detections)
```

### Why rektproof?

| Problem | rektproof's Answer |
|---|---|
| Scanners produce 50+ findings, mostly noise | **Multi-stage validation pipeline** eliminates provably-safe findings |
| "Missing signer" on a `has_one` target | **AST-aware context** understands Anchor struct semantics |
| Token2022 reentrancy on programs that block hooks | **Extension whitelist detection** across the entire codebase |
| `remaining_accounts` defense flagged as attack | **Pattern-aware elimination** recognizes rejection checks |
| All findings get confidence 60% | **Per-finding verifiability scoring** with 30-95% range |

---

## Features

### 🔬 6 Analysis Techniques, 20 Scanning Phases

| Technique | Phases | What it finds |
|-----------|--------|---------------|
| **Pattern Matching** | 1, 7-8, 11-13 | 72 vulnerability patterns (SOL-001 to SOL-073), Anchor constraints, Sec3, unsafe code, arithmetic issues |
| **Deep AST Analysis** | 2, 9 | Line-level detection via `syn::visit`, reaching definitions, uninitialized uses |
| **Taint Analysis** | 3 (intra + interprocedural), 10 | Information flow from untrusted sources to sinks, cross-function taint propagation |
| **CFG Analysis** | 4 | Dominator-based property verification, reachability without guards |
| **Abstract Interpretation** | 5 | Interval arithmetic with widening/narrowing at loop heads, overflow proofs, division-by-zero detection |
| **Account Security** | 6, 14 | Must-not-alias analysis, authority spoofing, invariant mining |

> **Transparency Note:** Phases 15-20 use experimental formal verification crates
> (Z3, Kani, Certora, Crux-MIR wrappers). These provide heuristic property checking,
> not fully automated end-to-end formal verification. See [Honest Capabilities](#honest-capabilities).

### 🛡️ Enterprise Validation Pipeline

Raw findings pass through a 6-stage gauntlet:

1. **Deduplication** — Same (vuln_id, file) = one finding
2. **Proof Verification** — Code-level mitigation detection (PDA signing, Anchor constraints, extension whitelists, rejection patterns)
3. **Root-Cause Grouping** — Same vuln across files = one annotated finding
4. **Confidence Scoring** — Per-finding verifiability with inline-evidence boost
5. **Non-Program Filtering** — Exclude tests, scripts, migrations
6. **Severity Capping** — Prevent finding count inflation

### 🎯 Token-2022 Awareness

- Detects transfer hook reentrancy risks
- Recognizes extension whitelists that block hooks
- Identifies fee mismatch vulnerabilities
- Checks permanent delegate exposure

### 🔬 Abstract Interpretation (Real)

The abstract interpreter operates directly on the `syn::Expr` AST — no string splitting.
It implements proper widening at loop heads with narrowing for precision recovery:

```
For a loop body B with entry state S₀:
  1. Forward pass: S' = S₀ ⊔ ⟦B⟧(S₀)
  2. Widening: S = S ∇ S'  (forces convergence)
  3. Repeat until stable
  4. Narrowing: S = S Δ ⟦B⟧(S)  (recovers precision)
```

**Soundness guarantee:** The widened state is a post-fixpoint — every concrete
loop execution stays within the computed intervals.

### 🔗 Interprocedural Taint Analysis

Builds a call graph from the AST and computes per-function taint summaries.
At call sites, summaries are applied to propagate taint across function boundaries:

- **Param → Return tracking**: Knows which parameters influence return values
- **Param → Sink tracking**: Knows which parameters reach security sinks in callees
- **Cross-function findings**: Flags when tainted data flows through helper functions to privileged operations

### 🔗 Formal Verification (Experimental)

```
$ rektproof verify-formal ./programs/my-protocol

  Layer 1: Property Extraction .... 12 properties
  Layer 2: Model Generation ...... SMT model built
  Layer 3: Z3 Verification ...... 11/12 proved safe
  Layer 4: Counterexamples ...... 1 potential violation
```

---

## Honest Capabilities

### What Works Well ✅

- **Pattern matching**: 72 detectors with field-tested heuristics
- **Deep AST scanning**: Precise line-level detection using `syn::visit`
- **Taint analysis**: Lattice-based with worklist fixed-point iteration (intra + interprocedural)
- **CFG dominators**: Sound property verification on the control flow graph
- **Abstract interpretation**: AST-based with real widening/narrowing at loop heads
- **Account aliasing**: Must-not-alias analysis for authority spoofing
- **Validation pipeline**: 6-stage filtering that significantly reduces false positives

### What's Experimental ⚠️

- **Formal verification (Phases 16-20)**: Z3 constraints are pattern-matched, not generated from program semantics. The "formal" in "formal verification" is aspirational — it provides heuristic property checking, not mathematical proofs.
- **Concolic execution (Phase 15)**: Pattern-based constraint generation, not actual symbolic execution with concrete seed values.
- **Kani/Certora/Crux-MIR**: These are thin wrappers that fall back to offline Z3 when the actual tools aren't installed.

### What's Not There Yet ❌

- **LSP integration**: Not implemented
- **Incremental scanning**: Not implemented
- **Configuration file**: Not implemented (all config via CLI flags)
- **Cross-module interprocedural analysis**: Call graph is per-file, not cross-crate

---

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/brainless3178/rektproof.git
cd rektproof

# Build (requires Rust 1.75+ and Z3)
cargo build --release

# The binary is at ./target/release/shanon
```

### Usage

```bash
# Scan a Solana program (interactive dashboard)
./target/release/shanon scan ./path/to/program

# JSON output for CI/CD
./target/release/shanon scan ./path/to/program --format json

# SARIF output for GitHub Security tab
./target/release/shanon scan ./path/to/program --format sarif

# Markdown audit report
./target/release/shanon scan ./path/to/program --format markdown

# Formal verification (experimental)
./target/release/shanon verify-formal ./path/to/program
```

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  rektproof CLI                   │
├─────────┬───────────┬───────────┬───────────────┤
│  scan   │ verify-fm │  deploy   │   ...         │
├─────────┴───────────┴───────────┴───────────────┤
│              program-analyzer                    │
│  ┌─────────┐ ┌──────────┐ ┌──────────────────┐  │
│  │ Engines │ │Validator │ │  Vuln Database   │  │
│  │ (1-20)  │ │Pipeline  │ │  (72 patterns)   │  │
│  └────┬────┘ └────┬─────┘ └────────┬─────────┘  │
│       └───────────┴────────────────┘             │
├──────────────────────────────────────────────────┤
│  Analysis Sub-engines                            │
│  taint-lattice · cfg-analyzer · abstract-interp  │
│  account-aliasing · deep-ast · anchor-security   │
│  sec3 · geiger · arithmetic · dataflow           │
│  defi-security · invariant-miner                 │
├──────────────────────────────────────────────────┤
│  FV Scanner (experimental, Z3-backed)            │
│  property-extraction → model-gen → z3 → report  │
└──────────────────────────────────────────────────┘
```

---

## Project Structure

```
rektproof/
├── crates/
│   ├── shanon-cli/          # CLI binary
│   ├── program-analyzer/    # Core analysis engine + validation pipeline
│   └── experimental/        # Analysis sub-engines
│       ├── sec3-analyzer/
│       ├── anchor-security-analyzer/
│       ├── taint-analyzer/
│       ├── geiger-analyzer/
│       ├── arithmetic-security-expert/
│       ├── dataflow-analyzer/
│       ├── account-security-expert/
│       ├── defi-security-expert/
│       ├── fv-scanner-core/
│       └── ...
├── test-live-programs/      # Live program sources for testing
├── .github/workflows/       # CI/CD pipeline
├── BRUTALLY_HONEST_AUDIT.md # Internal audit findings
└── PRODUCTION_UPGRADE_PLAN.md
```

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/new-detector`)
3. Run tests (`cargo test -p program-analyzer`)
4. Submit a PR

### Adding a New Detector

1. Add pattern to `crates/program-analyzer/src/vulnerability_db.rs`
2. Add false-positive elimination to `crates/program-analyzer/src/finding_validator.rs`
3. Add tests covering both true positives and known false positives

---

## License

MIT

---

<p align="center">
  <strong>Built for auditors who refuse to get rekt.</strong>
</p>
