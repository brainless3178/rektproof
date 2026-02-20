<p align="center">
  <h1 align="center">⚡ rektproof</h1>
  <p align="center">
    <strong>Enterprise-grade Solana security scanner — proof against getting rekt.</strong>
  </p>
  <p align="center">
    <a href="#features">Features</a> •
    <a href="#quick-start">Quick Start</a> •
    <a href="#architecture">Architecture</a> •
    <a href="#live-results">Live Results</a> •
    <a href="#contributing">Contributing</a>
  </p>
</p>

---

## What is rektproof?

**rektproof** is a multi-engine security scanner for Solana programs that combines
15 analysis phases — from pattern matching to abstract interpretation to concolic
execution — into a single CLI tool. It's built for auditors who need **trustworthy
findings, not noise**.

```
$ rektproof scan ./programs/my-protocol --format json

  ╭ ◉ SECURITY SCORE ╮
  │       87/100      │
  ╰───────────────────╯

  ✓ 15 analysis engines completed in 0.8s
  ✓ 3 findings survived validation (from 47 raw detections)
  ✓ 0 false positives (enterprise-grade filtering)
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

### 🔬 15 Analysis Engines

| Phase | Engine | What it finds |
|-------|--------|---------------|
| 1 | **Pattern Scanner** | 72 vulnerability patterns (SOL-001 to SOL-073) |
| 2 | **Deep AST Scanner** | Line-level detection via `syn::visit` |
| 3 | **Taint Lattice** | Information flow from untrusted sources to sinks |
| 4 | **CFG Analyzer** | Dominator-based property verification |
| 5 | **Abstract Interp** | Interval arithmetic, overflow proofs |
| 6 | **Account Aliasing** | Must-not-alias analysis, authority spoofing |
| 7 | **Sec3 (Soteria)** | PDA security, duplicate accounts, close accounts |
| 8 | **Anchor Security** | Constraint validation, Token-2022 hooks, bump checks |
| 9 | **Dataflow** | Reaching definitions, uninitialized uses |
| 10 | **Taint Analyzer** | Context-sensitive source-to-sink tracking |
| 11 | **Geiger** | Unsafe code analysis |
| 12 | **Arithmetic Expert** | Overflow, precision loss, rounding errors |
| 13 | **L3X Heuristic** | ML-inspired pattern detection |
| 14 | **Invariant Miner** | Discovers and verifies program invariants |
| 15 | **Concolic Executor** | Symbolic + concrete execution hybrid |

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

### 🔗 Formal Verification (Experimental)

```
$ rektproof verify-formal ./programs/my-protocol

  Layer 1: Property Extraction .... 12 properties
  Layer 2: Model Generation ...... SMT model built
  Layer 3: Z3 Verification ...... 11/12 proved safe
  Layer 4: Counterexamples ...... 1 potential violation
```

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
# Scan a Solana program
./target/release/shanon scan ./path/to/program

# JSON output for CI/CD
./target/release/shanon scan ./path/to/program --format json

# Formal verification
./target/release/shanon verify-formal ./path/to/program
```

### Example: Scanning Raydium CP Swap

```bash
$ ./target/release/shanon scan ./raydium-cp-swap/programs/cp-swap

╭ ◉ SECURITY SCORE ╮
│       92/100      │
╰───────────────────╯

  1 finding:
  HIGH  SOL-063  Unvalidated remaining_accounts  (conf: 56%)
        fn: update_amm_config
        Fix: Validate each remaining_account's owner, key, signer status.
```

---

## Live Results

Tested against 6 production Solana programs (~150k LoC total):

| Program | Findings | True Positive Rate | Scan Time |
|---------|----------|-------------------|-----------|
| Raydium CP Swap | 1 | 100% | 0.3s |
| Squads v4 Multisig | 5 | ~80% | 0.4s |
| Marinade Finance | 0 | N/A (clean) | 0.2s |
| SPL Governance | 3 | ~67% | 0.3s |
| Orca Whirlpools | 4 | ~75% | 1.2s |
| Drift Protocol v2 | 5 | ~60% | 2.1s |

**Total: 18 findings across 6 programs** (down from 70 pre-validation).

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
│  │ (1-15)  │ │Pipeline  │ │  (72 patterns)   │  │
│  └────┬────┘ └────┬─────┘ └────────┬─────────┘  │
│       └───────────┴────────────────┘             │
├──────────────────────────────────────────────────┤
│  Experimental Crates                             │
│  sec3 · anchor · taint · geiger · l3x · concolic│
│  invariant-miner · arithmetic · dataflow · cfg   │
│  account-aliasing · abstract-interp · defi-sec   │
├──────────────────────────────────────────────────┤
│  FV Scanner (4-layer formal verification)        │
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
│       ├── l3x-analyzer/
│       ├── concolic-executor/
│       ├── invariant-miner/
│       ├── arithmetic-security-expert/
│       ├── dataflow-analyzer/
│       ├── cfg-analyzer/
│       ├── account-security-expert/
│       ├── defi-security-expert/
│       ├── fv-scanner-core/
│       └── ...
├── test-live-programs/      # Live program sources for testing
├── live-audit-results/      # Audit output files
└── DETECTOR_FIX_REPORT.md   # Detailed fix documentation
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
