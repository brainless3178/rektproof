# 2R1IN

**Static security analyzer for Solana programs.**

2R1IN scans Solana/Anchor source code for vulnerability patterns — missing signer checks, unsafe CPI calls, integer overflow, account validation gaps, and 70+ other detectors. It runs locally, outputs structured findings, and integrates with CI/CD.

## Real-World Validation

We tested against **real exploited Solana programs** (not just self-written test cases):

| Program | Exploit | Loss | Detected? |
|---------|---------|------|-----------|
| [Wormhole Bridge](https://github.com/certusone/wormhole) | Governance auth bypass | $320M | ✅ SOL-CFG-02 (unguarded governance CPI) |
| [Cashio](https://github.com/cashioapp/cashio) | Missing account validation | $52M | ✅ SOL-012 (missing `has_one` relationship) |
| [Saber Stable-Swap](https://github.com/saber-hq/stable-swap) | Authority check gaps | — | ✅ SOL-001 ×3 (raw AccountInfo authority) |

**False positive rate on clean code:**
- SPL Token-Wrap (Anchor): **0 findings** ✅
- SPL Token-Lending (native): 2 findings (debatable)
- SPL Governance (native): 17 findings (known FP limitation on native programs)

Full results: [BENCHMARKS.md](BENCHMARKS.md)

## Quick Start

```bash
# Build
cargo build --release

# Scan a local program
./target/release/shanon scan ./path/to/program --format human

# Scan with AI enhancement (Kimi K2.5)
./target/release/shanon scan ./path/to/program --ai --api-key <NVIDIA_NIM_KEY>

# JSON output for CI/CD
./target/release/shanon scan ./path/to/program --format json

# Filter by severity
./target/release/shanon scan ./path/to/program --min-severity high
```

## What It Does

**6 analysis engines** run in pipeline:

| Engine | Technique | What it catches |
|--------|-----------|----------------|
| Pattern Matcher | AST pattern matching | Missing signer, owner, type cosplay, unsafe close |
| Deep AST | Anchor-aware structural analysis | Account validation gaps, PDA issues, CPI misuse |
| Taint Analyzer | Lattice-based data flow | Untrusted input reaching sensitive operations |
| CFG Analyzer | Control flow graph | Unguarded CPI calls, CEI violations |
| Abstract Interpreter | Interval arithmetic | Integer overflow, division by zero |
| Account Aliasing | Must-not-alias analysis | Same account passed to conflicting parameters |

**73 detectors** with hardcoded confidence scores (55-95%). Confidence values are heuristic estimates based on pattern strength, not empirically calibrated against a benchmark dataset. See [BENCHMARKS.md](BENCHMARKS.md) for real-world validation.

## Detection Coverage

| Category | IDs | Examples |
|----------|-----|---------|
| Auth & Authorization | SOL-001 — SOL-005 | Missing signer, owner verification, arbitrary CPI |
| Arithmetic Safety | SOL-002, SOL-007, SOL-038 | Integer overflow, precision loss |
| Account Validation | SOL-004, SOL-008, SOL-011 | Type cosplay, uninitialized accounts |
| PDA Safety | SOL-009, SOL-012, SOL-016 | Seed collision, bump verification |
| CPI Security | SOL-015, SOL-050, SOL-054 | Cross-program invocation attacks |
| Oracle Security | SOL-019, SOL-020, SOL-058 | Price manipulation, stale data |
| DeFi Vectors | SOL-033, SOL-034, SOL-049 | Sandwich attacks, LP manipulation |
| Token-2022 | SOL-055 — SOL-057 | Transfer hooks, fee mismatch |
| Governance | SOL-059, SOL-064, SOL-067 | State machine, upgrade authority |

## Architecture

```
crates/
├── shanon-cli/          # CLI with TUI dashboard
├── program-analyzer/    # Core scanner (6 engines, 73 detectors)
├── ai-enhancer/         # Kimi K2.5 AI analysis (optional)
├── attack-simulator/    # PoC exploit generation
├── shanon-api/          # REST API server (Actix-web)
├── shanon-guard/        # Dependency supply chain scanner
├── cpi-analyzer/        # Cross-program invocation graph
├── firedancer-monitor/  # Firedancer compatibility checks
├── kani-verifier/       # Formal verification harness generation
└── ... (48 crates total — ~20 substantive analysis, rest infrastructure)
```

## AI Enhancement (Optional)

With `--ai` flag, findings are enriched by Kimi K2.5 (via NVIDIA NIM) with:
- Technical deep-dive explanation
- Attack scenario with concrete steps
- Proof-of-concept exploit code
- Recommended fix with code samples
- Economic impact estimate

Requires an NVIDIA NIM API key (`--api-key` or `OPENROUTER_API_KEY` env var).

## Testing

```bash
# Run all 120+ unit tests
cargo test --workspace

# Run specific engine tests
cargo test --package program-analyzer
```

Tests include detection-specific tests (`test_detects_missing_signer`, `test_detects_unchecked_arithmetic`, `test_detects_reentrancy`, etc.) plus infrastructure tests for serialization, config, and utilities.

## Known Limitations

1. **Optimized for Anchor programs.** Native Solana programs with manual `is_signer` checks in function bodies generate false positives — the pattern matcher looks for type-level constraints, not runtime checks.
2. **Pattern matching, not symbolic execution.** Catches vulnerability *patterns* (missing signer, unguarded CPI), not exploit *paths* (like the Wormhole secp256k1 parsing flaw). Subtle semantic bugs require manual review.
3. **Confidence scores are heuristic.** Not calibrated against a labeled dataset. No published precision/recall metrics yet.
4. **No external audit.** This tool itself has not been audited by a third-party security firm.
5. **48 crates ≠ 48 engines.** ~20 are substantive analysis modules. The rest are CLI, API, infrastructure, and utilities.

## What This Is Not

- Not a replacement for manual security audit
- Not validated against OtterSec, Neodyme, or Trail of Bits findings
- Not production-hardened for use as sole security gate on mainnet deployments

**Use as:** First-pass automated check to catch common vulnerability patterns before human review.

## License

[MIT](LICENSE)
