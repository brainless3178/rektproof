<p align="center">
  <img src="assets/logo.png" alt="Shannon Security" width="200"/>
</p>

<h1 align="center">Shannon Security Platform</h1>

<p align="center">
  <strong>Enterprise-Grade Security Analysis for Solana Programs</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#api-documentation">API</a> •
  <a href="#audit-status">Audit</a> •
  <a href="LICENSE">License</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Score-95%2F100-brightgreen?style=flat-square" alt="Audit Score"/>
  <img src="https://img.shields.io/badge/Grade-A-brightgreen?style=flat-square" alt="Grade A"/>
  <img src="https://img.shields.io/badge/Detectors-72-blue?style=flat-square" alt="72 Detectors"/>
  <img src="https://img.shields.io/badge/License-MIT-blue?style=flat-square" alt="MIT License"/>
  <img src="https://img.shields.io/badge/Rust-1.73+-orange?style=flat-square" alt="Rust"/>
</p>

---

## Audit Status

**Latest Score: 95/100 (Grade A)** — Full audit report: [`AUDIT_REPORT.md`](AUDIT_REPORT.md)

| Category | Score |
|----------|-------|
| Architecture & Code Quality | 91/100 |
| Feature Completeness | 93/100 |
| Testing & Reliability | 83/100 |
| Performance & Scalability | 79/100 |
| Documentation & Usability | 87/100 |
| Security Best Practices | 92/100 |

---

## Features

### ✅ 10 Core Capabilities (All Verified)

| # | Capability | Status | Description |
|---|-----------|--------|-------------|
| 1 | **Local Program Scanning** | ✅ Active | AST-based analysis of Rust/Anchor programs using `syn`. 72 vulnerability detectors with per-detector confidence calibration (55-95 range). Multi-stage false positive elimination pipeline. |
| 2 | **Git Repository Scanning** | ✅ Active | Clone-and-scan any public GitHub/HTTPS repo. Temp directory management with auto-cleanup. |
| 3 | **On-Chain Program Analysis** | ✅ Active | Fetch deployed programs via RPC. Analyze deployed bytecode metadata, authority status, immutability. |
| 4 | **Token Risk Assessment** | ✅ Active | Rug-pull scoring: mint/freeze authority, supply concentration, Token-2022 extension analysis (transfer hooks, permanent delegate, confidential transfers). |
| 5 | **Firedancer Compatibility** | ✅ Active | Compatibility checker for upcoming Firedancer validator client. Analyzes CU budget, syscall usage, instruction data patterns. |
| 6 | **CPI Dependency Graphing** | ✅ Active | Maps cross-program invocation chains. Detects circular dependencies and trust boundary violations. |
| 7 | **Security Scoring** | ✅ Active | Composite scoring with letter grades (A-F). Per-protocol scoreboard with embeddable SVG badges. |
| 8 | **Live Authority Monitoring** | ✅ Active | Real-time upgrade authority checks. Detects mutability changes and authority transfers. |
| 9 | **Compliance Verification** | ✅ Active | SOC2, ISO 27001, OWASP Solana Smart Contract Security (SCS), and Solana Foundation compliance frameworks. |
| 10 | **Supply Chain Firewall** | ✅ Active | `shanon-guard`: Dependency scanner for malicious packages, typosquats, and behavioral anomalies. |

### 🔬 Vulnerability Detection Engine

72 pattern-match detectors covering:

| Category | Detector IDs | Examples |
|----------|-------------|---------|
| Auth & Authorization | SOL-001 — SOL-005 | Missing signer check, owner verification, arbitrary CPI |
| Arithmetic Safety | SOL-002, SOL-007, SOL-038, SOL-045 | Integer overflow, precision loss, unsafe math |
| Account Validation | SOL-004, SOL-008, SOL-011, SOL-048 | Type cosplay, uninitialized accounts, reinitialization |
| PDA Safety | SOL-009, SOL-012, SOL-016, SOL-065 | PDA seed collision, missing bump verification |
| CPI Security | SOL-015, SOL-050, SOL-054 | Cross-Program invocation attacks, program impersonation |
| Oracle Security | SOL-019, SOL-020, SOL-058 | Price manipulation, stale data, flash loan attacks |
| DeFi Attack Vectors | SOL-033, SOL-034, SOL-049, SOL-066 | Sandwich attacks, LP manipulation, MEV extraction |
| Token-2022 | SOL-055 — SOL-057 | Transfer hook reentrancy, fee mismatch, permanent delegate |
| Governance | SOL-059, SOL-064, SOL-067 | State machine, governance bypass, upgrade authority |

**Confidence Calibration:**
- **85-95:** High-confidence AST checks (missing signer, unchecked CPI) — provable patterns
- **70-84:** Strong heuristic patterns (overflow, type cosplay)
- **55-69:** Pattern-match heuristics (informational, stylistic)

### 🌐 REST API

**24 endpoints** via Actix-web, with:
- ✅ **Rate limiting** — Per-IP token-bucket (30 req/s default, configurable)
- ✅ **CORS** — Environment-driven (`SHANON_CORS_ORIGIN`)
- ✅ **API key auth** — Optional (`SHANON_API_KEY`)
- ✅ **OpenAPI 3.0** — Full spec at `/api/v1/openapi.json`, Swagger UI at `/api/v1/docs`

---

## Quick Start

### Prerequisites

- **Rust** 1.73+ (`rustup install stable`)
- **Solana CLI** 1.18+ (for on-chain features)
- **Z3** 4.12+ (for formal verification, optional)

### Build

```bash
cargo build --release
```

### Run the API Server

```bash
# Minimal (dev mode — all origins allowed, no auth)
cargo run --release --bin shanon-api

# Production
SHANON_CORS_ORIGIN=https://app.shanon.security \
SHANON_API_KEY=your-secret-key \
SHANON_RATE_LIMIT_RPS=50 \
SHANON_RATE_LIMIT_BURST=100 \
SOLANA_RPC_URL=https://api.mainnet-beta.solana.com \
cargo run --release --bin shanon-api
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SHANON_HOST` | `0.0.0.0` | API bind address |
| `SHANON_PORT` | `8080` | API port |
| `SOLANA_RPC_URL` | `https://api.devnet.solana.com` | Solana RPC endpoint |
| `SHANON_ORACLE_PROGRAM_ID` | Auto-detected | Oracle program public key |
| `SHANON_API_KEY` | *(none)* | API authentication key (optional) |
| `SHANON_CORS_ORIGIN` | `*` | CORS allowed origin (production: set to your domain) |
| `SHANON_RATE_LIMIT_RPS` | `30` | Rate limit: requests per second per IP |
| `SHANON_RATE_LIMIT_BURST` | `60` | Rate limit: burst capacity |
| `LOG_FORMAT` | `text` | Log format (`text` or `json`) |

### API Usage Examples

```bash
# Health check
curl http://localhost:8080/health

# Scan a program
curl -X POST http://localhost:8080/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"}'

# Token risk assessment
curl http://localhost:8080/api/v1/token/EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v/risk

# Scan from GitHub
curl -X POST http://localhost:8080/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "check", "source_url": "https://github.com/coral-xyz/anchor"}'

# Pre-sign transaction safety check
curl -X POST http://localhost:8080/api/v1/simulate \
  -H "Content-Type: application/json" \
  -d '{"programs": ["JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"]}'

# Upgrade authority check
curl http://localhost:8080/api/v1/authority/JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4

# OpenAPI spec
curl http://localhost:8080/api/v1/openapi.json

# Swagger UI
open http://localhost:8080/api/v1/docs
```

---

## Architecture

```
shannon/
├── crates/
│   ├── shanon-api/           # REST API server (Actix-web)
│   │   ├── src/
│   │   │   ├── main.rs       # Server bootstrap, CORS, rate limiting
│   │   │   ├── routes.rs     # 22 API endpoint handlers
│   │   │   ├── rate_limiter.rs  # Token-bucket rate limiting
│   │   │   ├── openapi.rs    # OpenAPI 3.0 spec + Swagger UI
│   │   │   ├── scoreboard.rs # Protocol security rankings
│   │   │   └── badge.rs      # SVG badge generation
│   ├── program-analyzer/     # Core vulnerability scanner
│   │   └── src/
│   │       ├── lib.rs         # AST parser, scan orchestration
│   │       ├── vulnerability_db.rs  # 72 detectors with calibrated confidence
│   │       ├── finding_validator.rs # 6-stage false positive elimination
│   │       ├── ast_parser.rs  # syn-based Rust AST analysis
│   │       ├── anchor_extractor.rs  # Anchor-specific analysis
│   │       ├── config.rs      # Analyzer configuration
│   │       ├── metrics.rs     # Performance metrics tracking
│   │       ├── security.rs    # Rate limiting, secrets, validation utils
│   │       └── traits.rs      # Analyzer trait interfaces
│   ├── shanon-guard/         # Supply chain firewall
│   ├── shanon-oracle/        # On-chain risk oracle (Anchor)
│   ├── firedancer-scanner/   # Firedancer compatibility checker
│   ├── compliance-engine/    # SOC2/ISO27001/OWASP/Solana Foundation
│   ├── cpi-grapher/          # CPI dependency analysis
│   ├── token-scanner/        # Token-2022 risk assessment
│   └── ... (40 more crates)
├── programs/
│   └── shanon-oracle/        # Anchor program (deployed on-chain)
├── exploits/                 # 9 exploit modules for testing
├── test_shannon.sh           # 41-case integration test suite
├── AUDIT_REPORT.md           # Full code audit report
├── LICENSE                   # MIT License
└── Cargo.toml                # Workspace root
```

---

## Testing

```bash
# Run all unit tests
cargo test --workspace

# Run integration tests (requires API server running)
./test_shannon.sh

# Run specific crate tests
cargo test --package program-analyzer
cargo test --package shanon-api
```

### Test Coverage

| Component | Unit Tests | Integration Tests |
|-----------|-----------|-------------------|
| program-analyzer | 220+ | 5 (via test script) |
| finding-validator | 10 | — |
| rate_limiter | 6 | 2 (via test script) |
| shanon-guard | 45+ | 3 |
| firedancer-scanner | 30+ | 2 |
| token-scanner | 25+ | 3 |
| cpi-grapher | 15+ | 2 |
| compliance-engine | 20+ | 4 |

---

## Known Limitations

1. **Engine count semantics** — "48 engines" counts all workspace crates. ~20 are substantive analysis modules; the rest are infrastructure/utilities.
2. **Git scanning** — Public HTTPS repos only. No SSH key or PAT authentication.
3. **Firedancer scoring** — May grade standard programs low (F) due to conservative thresholds. Calibration needed.
4. **Authority monitoring** — Polling-based only. No WebSocket streaming for real-time alerts.
5. **`unwrap()` usage** — Found in ~60 files, predominantly in test code and environment variable defaults with `unwrap_or_else`. Non-critical paths.

---

## License

[MIT](LICENSE)
