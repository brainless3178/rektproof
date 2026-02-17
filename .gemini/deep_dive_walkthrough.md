# Shanon Web3 — Deep-Dive Architecture & Codebase Walkthrough

> **Date:** 2026-02-16  
> **Status:** Build ✅ | Tests ✅ (260+ unit tests, 0 failures)  
> **Binary:** `solana-security-swarm`  
> **Stack:** Rust · Z3 · Solana · Anchor · Actix-web · Ratatui TUI

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Repository Layout](#2-repository-layout)
3. [Architecture Overview](#3-architecture-overview)
4. [The Audit Pipeline (Core)](#4-the-audit-pipeline-core)
5. [Crate-by-Crate Deep Dive](#5-crate-by-crate-deep-dive)
6. [On-Chain Oracle Program](#6-on-chain-oracle-program)
7. [Vulnerable Test Programs](#7-vulnerable-test-programs)
8. [Frontend / API Layer](#8-frontend--api-layer)
9. [TUI Dashboard](#9-tui-dashboard)
10. [Data Flow & How It All Connects](#10-data-flow--how-it-all-connects)
11. [Build & CI/CD](#11-build--cicd)
12. [Security Model & Threat Surface](#12-security-model--threat-surface)
13. [Known Limitations & Future Work](#13-known-limitations--future-work)

---

## 1. Executive Summary

**Shanon Web3** (a.k.a. *Solana Security Swarm*) is an enterprise-grade, multi-engine security audit platform for Solana smart contracts. It combines:

- **Static analysis** (52 vulnerability detectors via `program-analyzer`)
- **Formal verification** (Z3-backed proofs via `symbolic-engine`, Kani model checking, Crux-MIR)
- **Fuzzing** (FuzzDelSol eBPF fuzzer, Trident, security-fuzzer)
- **Abstract interpretation** (interval domains, CFG-based overflow analysis)
- **Concolic execution** (Z3-backed path exploration)
- **Multi-LLM consensus** (OpenRouter/OpenAI/Anthropic/NVIDIA for false-positive reduction)
- **Exploit generation** (TypeScript & Rust PoCs, Transaction Forge for on-chain simulation)
- **DeFi-specific proofs** (AMM invariants, vault share dilution, oracle staleness, conservation of value)
- **Auto-remediation** (secure code pattern generation via `secure-code-gen`)

The entire pipeline runs from a single Rust binary (`solana-security-swarm`) with a rich Ratatui TUI dashboard and an Actix-web API server (`shanon-api`).

---

## 2. Repository Layout

```
hackathon/
├── Cargo.toml                     # Workspace root (52 members)
├── Anchor.toml                    # Anchor project config
│
├── programs/
│   ├── shanon-oracle/             # On-chain Solana program (Anchor)
│   ├── vulnerable-vault/          # Intentionally vulnerable test program
│   ├── vulnerable-token/          # Intentionally vulnerable test program
│   └── vulnerable-staking/        # Intentionally vulnerable test program
│
├── crates/
│   ├── orchestrator/              # ★ MAIN BINARY — audit pipeline orchestrator
│   ├── shanon-api/                # Actix-web REST API server
│   ├── program-analyzer/          # 52-detector static analyzer (syn-based AST)
│   ├── symbolic-engine/           # Z3 symbolic execution + DeFi proof engine
│   ├── transaction-forge/         # Exploit TX builder & on-chain simulation
│   ├── consensus-engine/          # Multi-LLM consensus voting
│   ├── llm-strategist/            # LLM-powered exploit strategy generation
│   ├── secure-code-gen/           # Automated fix generation
│   ├── attack-simulator/          # Executable PoC generation (TS + Rust)
│   ├── kani-verifier/             # Kani/CBMC formal verification
│   ├── certora-prover/            # Certora-style property checking
│   ├── fuzzdelsol/                # FuzzDelSol eBPF fuzzer integration
│   ├── trident-fuzzer/            # Trident fuzz test orchestration
│   ├── abstract-interpreter/      # Interval domain abstract interpretation
│   ├── concolic-executor/         # Concolic execution (Z3-backed)
│   ├── invariant-miner/           # Automatic program invariant discovery
│   ├── economic-verifier/         # Economic attack verification
│   ├── fv-scanner-core/           # Multi-layer FV scanner orchestrator
│   ├── fv-layer1-verifier/        # Layer 1: Kani + ArithmeticSecurityExpert
│   ├── fv-layer2-verifier/        # Layer 2: Crux-MIR analysis
│   ├── fv-layer3-verifier/        # Layer 3: Z3 symbolic invariant checking
│   ├── fv-layer4-verifier/        # Layer 4: Protocol state graph
│   ├── crux-mir-analyzer/         # Crux-MIR integration (syn-based)
│   ├── taint-analyzer/            # Taint analysis for data flow tracking
│   ├── dataflow-analyzer/         # Dataflow analysis
│   ├── cpi-analyzer/              # Cross-Program Invocation analysis
│   ├── security-fuzzer/           # Property-based fuzzing
│   ├── ai-enhancer/               # AI-powered finding enhancement
│   ├── defi-security-expert/      # DeFi vulnerability knowledge base
│   ├── token-security-expert/     # Token security patterns
│   ├── account-security-expert/   # Account security patterns
│   ├── arithmetic-security-expert/# Arithmetic vulnerability expert
│   ├── benchmark-suite/           # Performance benchmarking
│   ├── integration-orchestrator/  # Deployment package generation
│   ├── git-scanner/               # GitHub repo cloning & scanning
│   ├── hackathon-client/          # Demo client
│   ├── wacana-analyzer/           # Wacana static analyzer
│   ├── sec3-analyzer/             # Sec3 (x-ray) integration
│   ├── l3x-analyzer/              # L3X analyzer integration
│   ├── geiger-analyzer/           # Unsafe code detection
│   ├── anchor-security-analyzer/  # Anchor-specific analysis
│   ├── firedancer-monitor/        # Firedancer validator monitoring
│   └── fv-web-server/             # FV results web server
│
├── exploits/                      # Generated exploit PoCs
├── integration-tests/             # Integration test suite
└── .github/workflows/ci.yml       # CI pipeline
```

---

## 3. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    SHANON SECURITY SWARM                         │
│                                                                  │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │ CLI/TUI  │  │  Actix API   │  │  On-Chain     │              │
│  │ (main.rs)│  │ (shanon-api) │  │ (shanon-oracle)│             │
│  └────┬─────┘  └──────┬───────┘  └──────┬────────┘             │
│       │               │                  │                       │
│       ▼               ▼                  ▼                       │
│  ┌────────────────────────────────────────────────────┐          │
│  │          AUDIT PIPELINE (orchestrator)              │          │
│  │                                                     │          │
│  │  1. Static Analysis (program-analyzer, 52 detectors)│         │
│  │  2. FV Scanner (Kani, Crux-MIR, Z3, Protocol Graph) │         │
│  │  3. DeFi Proof Engine (7 Z3-backed theorems)        │         │
│  │  4. Symbolic Execution (exploit proving)             │         │
│  │  5. Transaction Forge (on-chain simulation)          │         │
│  │  6. Consensus Engine (multi-LLM verification)        │         │
│  │  7. Secure Code Gen (auto-remediation)               │         │
│  └─────────────────────┬──────────────────────────────┘          │
│                        │                                          │
│                        ▼                                          │
│  ┌──────────────────────────────────────┐                        │
│  │           OUTPUTS                     │                        │
│  │  • AuditReport (JSON/PDF/Markdown)   │                        │
│  │  • Exploit PoCs (Rust + TypeScript)   │                        │
│  │  • TUI Dashboard (Ratatui)            │                        │
│  │  • Bounty Report                      │                        │
│  │  • On-chain Risk Score                │                        │
│  └──────────────────────────────────────┘                        │
└──────────────────────────────────────────────────────────────────┘
```

---

## 4. The Audit Pipeline (Core)

**File:** `crates/orchestrator/src/audit_pipeline/mod.rs`

The `EnterpriseAuditor` struct is the heart of the system. Its `audit_program()` method orchestrates the full pipeline:

### Pipeline Stages

| # | Stage | Engine | Output |
|---|-------|--------|--------|
| 1 | **Static Analysis** | `program-analyzer` | `Vec<VulnerabilityFinding>` (52 detectors) |
| 2 | **FV Scanner** | `fv-scanner-core` (4 layers) | Layer reports (Kani, Crux-MIR, Z3, Protocol Graph) |
| 3 | **DeFi Proof Engine** | `symbolic-engine::ProofEngine` | `Vec<ProofResult>` (7 Z3 theorems) |
| 4 | **Symbolic Execution** | `symbolic-engine::SymbolicEngine` | `ExploitProof` (counterexamples) |
| 5 | **Transaction Forge** | `transaction-forge` | On-chain simulation results |
| 6 | **Consensus Engine** | `consensus-engine` | Multi-LLM verified findings |
| 7 | **Secure Code Gen** | `secure-code-gen` | Remediation patterns |
| 8 | **Attack Simulation** | `attack-simulator` | Executable PoCs (TS + Rust) |
| 9 | **Report Generation** | `bounty_report.rs`, `pdf_report.rs` | Final reports |

### Key Types

```rust
// Engine status tracking
pub struct EngineStatus {
    pub static_analyzer_ran: bool,
    pub static_analyzer_ok: bool,
    pub fv_scanner_ran: bool,
    pub fv_scanner_ok: bool,
    pub symbolic_ran: bool,
    pub symbolic_ok: bool,
    pub forge_ran: bool,
    pub forge_ok: bool,
    pub consensus_ran: bool,
    pub consensus_ok: bool,
    pub certora_ran: bool,
    pub certora_ok: bool,
    pub fuzzdelsol_ran: bool,
    pub fuzzdelsol_real_fuzz: bool,
    pub taint_ran: bool,
    pub taint_ok: bool,
    pub defi_proof_ran: bool,
    pub defi_proof_ok: bool,
}

// Final audit output
pub struct AuditReport {
    pub program_id: String,
    pub risk_score: u8,             // 0-100
    pub exploits: Vec<ConfirmedExploit>,
    pub scan_scope: Vec<String>,
    pub engine_status: EngineStatus,
    pub proof_engine_results: Vec<ProofResult>,
    // ... more fields
}
```

---

## 5. Crate-by-Crate Deep Dive

### 5.1 `program-analyzer` — Static Analysis Core

**Purpose:** Parse Solana/Anchor `.rs` files with `syn` and run 52 vulnerability detectors.

**Key Components:**
- `ProgramAnalyzer::new(program_dir)` — walks directory, parses all `.rs` files
- `scan_for_vulnerabilities()` — runs all 52 patterns via `VulnerabilityDatabase`
- `vulnerability_db/` — contains all detection patterns (SOL-001 through SOL-052)
- `normalize_quote_output()` — critical helper that normalizes `quote!()` token spacing

**Vulnerability IDs:** SOL-001 (Missing Signer) through SOL-052, covering:
- Authorization (signer, owner, PDA checks)
- Arithmetic (overflow, underflow, precision)
- Account validation (type cosplay, reinitialization)
- DeFi (oracle manipulation, MEV, slippage)
- CPI (arbitrary invocations)
- Reentrancy
- Token security

**Architecture:** Each vulnerability is a `VulnerabilityPattern` with a closure detector that receives the normalized source code and returns `Vec<VulnerabilityFinding>`.

### 5.2 `symbolic-engine` — Z3-Backed Symbolic Execution

**Purpose:** Formal verification using Z3 SMT solver.

**Two major components:**

#### 5.2.1 `SymbolicEngine`
- Creates Z3 variables for account fields
- Checks arithmetic overflows, logic invariants
- `prove_exploitability()` — generates exploit proofs (currently handles SOL-019 oracle manipulation)

#### 5.2.2 `ProofEngine` (DeFi-specific)
**File:** `proof_engine.rs` (1149 lines)

Seven Z3-backed mathematical proofs:

| # | Proof | What it proves | Result |
|---|-------|---------------|--------|
| 1 | **AMM Constant-Product** | x·y ≥ k after swap | UNSAT = safe |
| 2 | **Vault Share Dilution** (no offset) | Victim gets 0 shares via donation | SAT = vulnerable |
| 3 | **Vault Share Dilution** (with offset) | Same, but with virtual offset defense | UNSAT = safe |
| 4 | **Fixed-Point Precision** | >1% error after N operations | SAT/UNSAT |
| 5 | **Conservation of Value** | deposits = withdrawals + balance | UNSAT = safe |
| 6 | **Oracle Staleness** | Stale data exploitable? | SAT/UNSAT |
| 7 | **Arithmetic Boundedness** | u64 overflow possible? | SAT/UNSAT |

Each proof uses Z3's `Solver` to search for counterexamples. If `UNSAT` → property holds. If `SAT` → a concrete counterexample (exploit) is extracted from the Z3 model.

### 5.3 `transaction-forge` — Exploit Transaction Builder

**Purpose:** Convert symbolic exploit proofs into executable Solana transactions.

**Key Features:**
- `TransactionBuilder` — constructs Solana transactions from exploit proofs
- `ExploitExecutor` — submits to Solana RPC for simulation
- `verify_vulnerability_with_proof()` — real RPC simulation of exploits
- `generate_exploit_poc()` — generates full Rust test code (SOL-019 first-depositor PoC)
- Anchor discriminator generation via SHA-256

**Enterprise Logic:**
```rust
// Generates Anchor instruction discriminator
let mut hasher = Sha256::new();
hasher.update(format!("global:{}", proof.instruction_name));
let result = hasher.finalize();
data.extend_from_slice(&result[..8]);
```

### 5.4 `consensus-engine` — Multi-LLM Verification

**Purpose:** Reduce false positives by having multiple LLMs vote on findings.

**Supported Providers:**
- OpenRouter
- OpenAI
- Anthropic
- NVIDIA

**Flow:**
```
Finding → Build Prompt → Query N LLMs → Parse Votes → Compute Consensus
```

Each LLM returns a `LlmVote` (verdict + confidence + reasoning). The consensus engine computes weighted agreement across all models.

### 5.5 `kani-verifier` — Formal Verification via CBMC

**Purpose:** Kani Rust Model Checker integration for bounded verification.

**Full Pipeline:**
1. **Invariant Extraction** (`InvariantExtractor`) — parse source, find account structs, constraints
2. **Solana Invariant Generation** (`SolanaInvariantGenerator`) — domain-specific invariants
3. **Harness Generation** (`HarnessGenerator`) — create `#[kani::proof]` harnesses
4. **Kani Runner** (`KaniRunner`) — invoke `cargo kani` or fall back to offline analysis
5. **Result Parser** (`KaniResultParser`) — parse CBMC output

**Invariant Kinds:** ArithmeticBounds, BalanceConservation, AccessControl, AccountOwnership, StateTransition, BoundsCheck, PdaValidation

**Offline Fallback:** When Kani/CBMC isn't installed, performs static invariant analysis based on code patterns (checked math, signer checks, owner checks, etc.).

### 5.6 `fv-scanner-core` — Multi-Layer Formal Verification

Orchestrates 4 verification layers:

| Layer | Engine | Focus |
|-------|--------|-------|
| **Layer 1** | Kani + ArithmeticSecurityExpert | Model checking + arithmetic analysis |
| **Layer 2** | Crux-MIR | MIR-level symbolic analysis |
| **Layer 3** | Z3 SymbolicEngine | Account invariant checking |
| **Layer 4** | Protocol Graph | State machine analysis + DOT graph |

### 5.7 `abstract-interpreter` — Sound Numerical Analysis

**Purpose:** Interval domain abstract interpretation for overflow/underflow detection.

**Key Components:**
- `Interval` — [min, max] with arithmetic operations (Add, Sub, Mul, Div)
- `AbstractState` — maps variables to intervals
- `ControlFlowGraph` — built from `syn` AST using `petgraph`
- `AbstractInterpreter::analyze_source()` — CFG-based worklist algorithm with widening

**Soundness:** Uses widening after 100 iterations to ensure termination. All interval arithmetic uses `saturating_*` operations.

### 5.8 `concolic-executor` — Hybrid Concrete/Symbolic Execution

**Purpose:** Systematically explore program paths by combining concrete execution with symbolic constraint collection.

**Algorithm:**
1. Start with concrete inputs
2. Execute path, collect branch conditions
3. Negate last condition, solve with Z3
4. If SAT → new test input, explore alternative path
5. Track coverage (locations, branches taken/not-taken)

**Integration:** Supports boundary value testing (0, 1, MAX-1, MAX) and random input generation.

### 5.9 `attack-simulator` — PoC Generation

**Purpose:** Generate executable Proof-of-Concept exploits for discovered vulnerabilities.

**Supports:**
- SOL-001 (Missing Signer) — TypeScript + Rust PoCs
- SOL-002 (Integer Overflow) — TypeScript PoC
- SOL-003 (Missing Owner) — TypeScript PoC
- SOL-005 (Arbitrary CPI)
- SOL-017 (Reentrancy)
- SOL-019 (Oracle Manipulation)
- SOL-021 (Unprotected Mint) — TypeScript PoC
- SOL-033 (Missing Slippage)
- Generic fallback for all others

Each `ExecutablePoC` includes attack steps, prerequisites, mitigations, and difficulty rating.

### 5.10 `secure-code-gen` — Auto-Remediation

**Purpose:** Generate secure code fixes for discovered vulnerabilities.

**Pattern Mapping:**
```
SOL-001/047 → signer-check
SOL-002/037/038/045 → checked-arithmetic
SOL-003/015 → owner-check
SOL-007/008/027 → pda-validation
SOL-017/018 → reentrancy-guard
SOL-021/023/024 → token-validation
SOL-033/034/051 → slippage-protection
SOL-009/028/029 → account-close
```

### 5.11 `llm-strategist` — AI-Powered Analysis

**Purpose:** Use LLMs to generate exploit strategies and enhance findings.

**Capabilities:**
- `generate_strategy()` — creates exploit strategies from vulnerability + code
- `infer_invariants()` — discovers program invariants via LLM
- `enhance_finding()` — adds context, severity refinement, and exploitation details
- Supports multiple providers (same as consensus-engine)

### 5.12 Domain Expert Crates

| Crate | Focus | Content |
|-------|-------|---------|
| `defi-security-expert` | DeFi vulnerabilities | Flash loans, oracle manipulation, MEV, AMM exploits, vault attacks |
| `token-security-expert` | Token security | Mint authority, burn mechanics, freeze, approval patterns |
| `account-security-expert` | Account security | PDA validation, account closing, type cosplay |
| `arithmetic-security-expert` | Arithmetic | Division-before-multiplication, unchecked ops, precision loss, casting |

### 5.13 Analyzer Integration Crates

| Crate | Purpose | Status |
|-------|---------|--------|
| `certora-prover` | Certora-style property verification | Real `build_sbf` + workspace root detection |
| `fuzzdelsol` | FuzzDelSol eBPF binary fuzzing | Real binary search + coverage tracking |
| `trident-fuzzer` | Trident fuzz testing | Integration layer |
| `wacana-analyzer` | Wacana static analysis | Integration |
| `sec3-analyzer` | Sec3 (x-ray) | Integration |
| `l3x-analyzer` | L3X static analysis | Integration |
| `geiger-analyzer` | Unsafe Rust detection | `cargo geiger`-style |
| `anchor-security-analyzer` | Anchor-specific checks | Anchor patterns |
| `firedancer-monitor` | Firedancer validator monitoring | Runtime monitoring |
| `git-scanner` | GitHub repo cloning & scanning | Full pipeline |

### 5.14 Supporting Crates

| Crate | Purpose |
|-------|---------|
| `invariant-miner` | Automatic invariant discovery (balance conservation, access control, arithmetic, state) |
| `economic-verifier` | Economic attack verification |
| `benchmark-suite` | Performance benchmarking with warmup, comparison |
| `integration-orchestrator` | Deployment package generation |
| `taint-analyzer` | Taint analysis for data flow tracking |
| `dataflow-analyzer` | Dataflow analysis |
| `cpi-analyzer` | Cross-Program Invocation analysis |
| `security-fuzzer` | Property-based fuzzing |
| `ai-enhancer` | AI-powered enhancement |

---

## 6. On-Chain Oracle Program

**File:** `programs/shanon-oracle/`

An Anchor program deployed on Solana that stores security risk scores on-chain.

**Instructions:**
- `initialize` — set up oracle config
- `register_analyst` — register security analyst
- `submit_assessment` — submit risk assessment
- `raise_flag` — raise security flag on a program

**State Accounts:**
- `OracleConfig` — global config (admin, fee, min stake)
- `RiskScore` — per-program risk score
- `AnalystProfile` — per-analyst reputation
- `SecurityFlag` — individual security flags

**PDA Seeds:**
- Risk Score: `["risk_score", target_program_id]`
- Analyst: `["analyst", wallet]`
- Config: `["config"]`

---

## 7. Vulnerable Test Programs

Three intentionally vulnerable programs for integration testing:

### `vulnerable-vault`
- Missing signer check on `withdraw`
- Unchecked arithmetic in `deposit`
- No owner validation

### `vulnerable-token`
- Unprotected mint authority
- Missing freeze check
- Unchecked transfer amounts

### `vulnerable-staking`
- Missing signer check on `unstake`
- Unchecked reward calculation
- No minimum stake validation

---

## 8. Frontend / API Layer

### `shanon-api` — Actix-web REST API

**Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/health` | Health check |
| GET | `/api/v1/risk/{program_id}` | Get risk score |
| GET | `/api/v1/risk/{program_id}/flags` | Get security flags |
| GET | `/api/v1/analyst/{wallet}` | Get analyst profile |
| GET | `/api/v1/analysts` | List all analysts |
| GET | `/api/v1/stats` | Oracle statistics |
| GET | `/api/v1/programs` | List scored programs |
| POST | `/api/v1/scan` | Trigger security scan |
| GET | `/api/v1/engines` | List analysis engines |
| GET | `/api/v1/detectors` | List vulnerability detectors |

**GitHub Scanning:** The `POST /api/v1/scan` endpoint accepts a `source_url` field. When provided, it:
1. Clones the repository via `git clone`
2. Walks for `.rs` files
3. Runs the full `ProgramAnalyzer` (52 detectors)
4. Returns findings with severity breakdown and risk score

---

## 9. TUI Dashboard

**File:** `crates/orchestrator/src/dashboard.rs` (1445 lines)

A full Ratatui terminal dashboard with:

**Tabs:** Overview | Findings | Threats | Explorer | AI Analysis

**Widgets:**
- Security Score Gauge (0-100 with color coding)
- Severity Bar Chart (Critical/High/Medium/Low)
- Findings Browser (scrollable list with detail panel)
- Threat Detection Feed (live updates)
- On-chain Explorer (account/transaction search via RPC)
- Scan History Sparkline

**Controls:** Arrow keys, Tab/Shift-Tab, q to quit, Enter to search

**Live Mode:** `run_live_dashboard()` accepts a channel receiver for real-time threat updates.

---

## 10. Data Flow & How It All Connects

### Full Audit Flow

```
User provides: program path / GitHub URL / program ID
                          │
                          ▼
              ┌─────────────────────┐
              │  EnterpriseAuditor  │  (orchestrator/audit_pipeline)
              │  ::audit_program()  │
              └─────────┬───────────┘
                        │
    ┌───────────────────┼───────────────────┐
    ▼                   ▼                   ▼
┌──────────┐     ┌──────────┐      ┌──────────┐
│ program- │     │fv-scanner│      │ symbolic │
│ analyzer │     │  -core   │      │ -engine  │
│(52 vulns)│     │(4 layers)│      │(Z3 proofs│
└────┬─────┘     └────┬─────┘      └────┬─────┘
     │                │                  │
     │     ┌──────────┼──────────┐       │
     │     ▼          ▼          ▼       ▼
     │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────────┐
     │  │Kani  │ │Crux  │ │Z3 L3│ │ProofEngine│
     │  │Layer1│ │Layer2│ │Layer3│ │(7 proofs) │
     │  └──────┘ └──────┘ └──────┘ └──────────┘
     │                                   │
     ▼                                   ▼
┌────────────────┐            ┌─────────────────┐
│ Findings merge │◄───────────│  ProofResults    │
│ + dedup        │            │  → Exploits      │
└───────┬────────┘            └─────────────────┘
        │
        ▼
┌───────────────────┐      ┌─────────────────────┐
│ Transaction Forge │      │  Consensus Engine    │
│ (on-chain sim)    │      │  (multi-LLM verify)  │
└───────┬───────────┘      └──────────┬──────────┘
        │                             │
        ▼                             ▼
┌───────────────────┐      ┌─────────────────────┐
│ Confirmed Exploits│◄─────│  Verified Findings  │
└───────┬───────────┘      └─────────────────────┘
        │
        ├──────────────────────────────┐
        ▼                              ▼
┌──────────────────┐         ┌──────────────────┐
│ Attack Simulator │         │ Secure Code Gen  │
│ (PoC generation) │         │ (auto-remediation│
└──────────────────┘         └──────────────────┘
        │
        ▼
┌──────────────────────────────────────────────┐
│  AuditReport (JSON → PDF / Markdown / TUI)   │
└──────────────────────────────────────────────┘
```

### Engine Status Badge System

The final summary prints color-coded badges for each engine:

```
[✅] Static analysis via program-analyzer (52 detectors)
[✅] Formal verification via FV Scanner (Kani + Crux-MIR + Z3)
[✅] Symbolic execution via Z3-backed engine
[✅] DeFi invariants formally proven via Z3 Mathematical Engine
[✅] On-chain simulation via Transaction Forge
[⚠️] Consensus Engine — no API keys configured
[✅] Secure Code Gen — auto-remediation patterns applied
```

---

## 11. Build & CI/CD

### Building

```bash
# Default build (excludes Z3-dependent crates)
cargo build

# Full build including Z3 crates
cargo build --workspace

# Release build (LTO + overflow checks)
cargo build --release
```

### Testing

```bash
# Run all workspace tests (260+ tests, 0 failures)
cargo test

# Run specific crate tests
cargo test -p program-analyzer
cargo test -p kani-verifier
cargo test -p symbolic-engine
```

### CI (`ci.yml`)

- Runs on push/PR to main
- `cargo build`, `cargo test`, `cargo clippy`
- Anchor build for on-chain programs

### Workspace Configuration

- **Resolver:** 2 (modern Cargo resolver)
- **Release profile:** `overflow-checks = true`, `lto = "fat"`, `codegen-units = 1`
- **Dev profile:** `overflow-checks = true`

### Z3 Dependency Note

The `symbolic-engine`, `concolic-executor`, `economic-verifier`, and `invariant-miner` crates depend on Z3. They use `z3 = "0.12"` with `static-link-z3` feature. The Z3 C++ library is statically compiled during build.

---

## 12. Security Model & Threat Surface

### What the Tool Detects (52+ Categories)

1. **Authorization failures** — missing signer, owner, PDA validation
2. **Arithmetic vulnerabilities** — overflow, underflow, precision loss, division-before-multiplication
3. **Account validation** — type cosplay, reinitialization, account closing
4. **DeFi-specific** — oracle manipulation, flash loan attacks, MEV/sandwich, vault inflation
5. **CPI attacks** — arbitrary invocations, instruction data injection
6. **Reentrancy** — cross-program re-entry
7. **Token issues** — unprotected mint, missing freeze, delegation bugs

### Proof Soundness

- **Z3 proofs are sound** — when UNSAT, the property provably holds
- **Abstract interpretation is sound** — interval analysis with widening guarantees termination
- **Kani/CBMC** — bounded model checking within unwind depth
- **Static analysis** — pattern-based, may have false positives/negatives

### Defense in Depth

Multiple engines cross-validate findings:
1. Static analyzer finds candidates
2. Z3 engine proves/disproves
3. Transaction Forge simulates on-chain
4. Multi-LLM consensus filters false positives
5. Secure Code Gen provides remediation

---

## 13. Known Limitations & Future Work

### Current Limitations

1. **Kani/CBMC offline fallback:** When Kani isn't installed, Layer 1 falls back to static pattern analysis
2. **Crux-MIR offline:** Similarly uses syn-based analysis when crux-mir binary isn't available
3. **LLM consensus requires API keys:** Without OpenRouter/OpenAI keys, consensus is skipped
4. **Transaction Forge RPC:** On-chain simulation requires a Solana RPC endpoint
5. **Some analyzer crates are stubs:** ~15 crates identified as having minimal real implementation (wacana, sec3, l3x, etc.)
6. **`solana-client` deprecation warning:** v1.18.x triggers future-incompatibility warning; migration to 2.x requires breaking API changes

### Future Work

- **IDE integration** — LSP server for real-time vulnerability highlighting
- **Mainnet monitoring** — continuous on-chain program monitoring
- **Multi-chain support** — extend to EVM, Move, CosmWasm
- **Custom rule engine** — user-defined vulnerability patterns
- **Historical analysis** — track vulnerability trends across program versions
- **Formal specification language** — domain-specific language for writing Solana invariants

---

## Appendix: Key File Locations

| Component | Path |
|-----------|------|
| Main binary entry | `crates/orchestrator/src/main.rs` |
| Audit pipeline | `crates/orchestrator/src/audit_pipeline/mod.rs` |
| Pipeline types | `crates/orchestrator/src/audit_pipeline/types.rs` |
| TUI Dashboard | `crates/orchestrator/src/dashboard.rs` |
| PDF Report | `crates/orchestrator/src/pdf_report.rs` |
| Bounty Report | `crates/orchestrator/src/bounty_report.rs` |
| Static analyzer | `crates/program-analyzer/src/lib.rs` |
| Vulnerability DB | `crates/program-analyzer/src/vulnerability_db.rs` |
| Z3 Proof Engine | `crates/symbolic-engine/src/proof_engine.rs` |
| Symbolic Engine | `crates/symbolic-engine/src/lib.rs` |
| Transaction Forge | `crates/transaction-forge/src/executor.rs` |
| Consensus Engine | `crates/consensus-engine/src/lib.rs` |
| API Server | `crates/shanon-api/src/main.rs` |
| API Routes | `crates/shanon-api/src/routes.rs` |
| On-chain program | `programs/shanon-oracle/src/lib.rs` |
| Workspace config | `Cargo.toml` |
