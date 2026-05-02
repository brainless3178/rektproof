# Proktor Security Swarm CI/CD Pipeline

**Complete automated security audit pipeline for Solana smart contracts**

---

## 🎯 Overview

This CI/CD pipeline provides **11-phase comprehensive security auditing** for Solana programs, integrating all cutting-edge security tools in the ecosystem.

## 📋 Pipeline Phases

### Phase 1: Environment Setup
- ✅ Rust toolchain (1.75.0)
- ✅ Solana CLI (1.18.26)
- ✅ Anchor Framework (0.29.0)
- ✅ Dependency caching
- ✅ Program structure validation

### Phase 2: Cargo-Geiger (Unsafe Code Detection)
**Tool**: `cargo-geiger` unsafe Rust code analyzer  
**Purpose**: Detect unsafe blocks, FFI calls, raw pointers, transmute, inline assembly  
**Threshold**: Safety score ≥70/100  
**Execution Time**: ~2-3 minutes  

**Checks**:
- Unsafe blocks (`unsafe { ... }`)
- Unsafe functions (`unsafe fn`)
- FFI calls (`extern "C"`)
- Raw pointers (`*const`, `*mut`)
- Transmute operations
- Inline assembly
- Union types

**Failure Criteria**: Safety score <70

### Phase 3: Anchor Framework Security
**Tool**: `anchor-security-analyzer`  
**Purpose**: Validate Anchor-specific security patterns  
**Threshold**: Anchor security score ≥90/100  
**Execution Time**: ~1-2 minutes  

**Checks**:
- Missing `#[account(signer)]` on authority fields
- Missing `#[account(owner = ...)]` validation
- Weak constraint expressions
- `init_if_needed` reinitialization vulnerabilities
- Missing PDA bump validation
- Missing space calculation in `init`
- CPI guard implementation
- Token-2022 transfer hooks

**Failure Criteria**: Anchor score <90 (if Anchor program)

### Phase 4: Static Analysis (Sec3 + L3X)
**Tools**: `sec3-analyzer` (Soteria) + `l3x-analyzer` (AI-driven)  
**Purpose**: AST-level vulnerability detection + ML-powered analysis  
**Execution Time**: ~5-8 minutes  

**Sec3 Checks**:
- Missing owner checks
- Integer overflows
- Account confusion
- CPI guards
- PDA validation
- Uninitialized data access

**L3X Checks** (AI/ML):
- Code embeddings analysis
- Control flow GNN
- Anomaly detection
- Pattern learning from historical exploits
- Ensemble scoring

**Failure Criteria**: Any critical vulnerabilities

### Phase 5: Formal Verification (Kani + Certora)
**Tools**: `kani-verifier` + `certora-prover`  
**Purpose**: Mathematical proof of correctness  
**Execution Time**: ~10-15 minutes  

**Kani Checks**:
- Arithmetic overflow/underflow
- Array bounds violations
- Null pointer dereferences
- Assertion failures
- Panic conditions

**Certora Checks**:
- SBF bytecode verification
- CVLR rule generation
- Compiler-induced bugs
- Bytecode-level invariants

**Failure Criteria**: Verification failures

### Phase 6: Symbolic Execution (WACANA)
**Tool**: `wacana-analyzer` (Z3-powered)  
**Purpose**: Path exploration and constraint solving  
**Execution Time**: ~8-12 minutes  

**Checks**:
- All execution paths
- Constraint violations
- Unreachable code
- Dead branches
- Path explosion detection

**Failure Criteria**: Constraint violations

### Phase 7: Fuzzing (Trident + FuzzDelSol)
**Tools**: `trident` (property-based) + `fuzzdelsol` (eBPF bytecode)  
**Purpose**: Discover crashes and edge cases  
**Execution Time**: ~15-30 minutes  

**Trident Checks**:
- Property-based invariants
- Instruction fuzzing
- Account state fuzzing
- CPI fuzzing

**FuzzDelSol Checks**:
- eBPF bytecode fuzzing
- Instruction oracle violations
- Missing signer checks
- Unauthorized state changes
- Integer overflow/underflow
- Account confusion

**Failure Criteria**: Any crashes or oracle violations

### Phase 8: Firedancer Monitoring
**Tool**: `firedancer-monitor`  
**Purpose**: Real-time validator performance monitoring  
**Execution Time**: ~1-5 minutes  

**Checks**:
- Verification lag (threshold: 500ms)
- Skip-vote risk (threshold: 3%)
- Transaction latency (threshold: 1000ms)
- Validator stress (threshold: 70%)

**Failure Criteria**: Health score <80 (warning only)

### Phase 9: Complete Audit
**All Tools**: Integrated execution  
**Purpose**: Comprehensive security assessment  
**Execution Time**: ~30-60 minutes  

**Generates**:
- Unified security report
- Risk score (0-10)
- Vulnerability summary
- Remediation recommendations
- PDF report

**Failure Criteria**:
- Critical vulnerabilities >0
- High vulnerabilities >5
- Risk score >7

### Phase 10: Security Dashboard
**Purpose**: Unified visualization and reporting  
**Execution Time**: ~2-3 minutes  

**Generates**:
- HTML dashboard
- GitHub Pages deployment
- PR comments with summary
- Trend analysis

### Phase 11: Deployment Gate
**Purpose**: Final security validation before deployment  
**Execution Time**: ~1 minute  

**Deployment Criteria**:
- ✅ Critical vulnerabilities = 0
- ✅ High vulnerabilities ≤3
- ✅ Risk score ≤6
- ✅ Safety score ≥70
- ✅ Anchor score ≥90 (if applicable)

---

## 🚀 Workflows

### 1. `security-audit.yml` — Complete Audit Pipeline
**Triggers**:
- Push to `main` or `develop`
- Pull requests to `main`
- Daily at 2 AM UTC (scheduled)

**Duration**: ~60-90 minutes  
**Phases**: All 11 phases  
**Use Case**: Comprehensive security validation before deployment

### 2. `quick-scan.yml` — Quick Security Scan
**Triggers**:
- Pull request opened/updated

**Duration**: ~10-15 minutes  
**Phases**: Geiger + Anchor + Sec3  
**Use Case**: Fast feedback on PRs

### 3. `validator-monitoring.yml` — Continuous Monitoring
**Triggers**:
- Hourly (scheduled)
- Manual dispatch

**Duration**: ~5 minutes  
**Phases**: Firedancer monitoring only  
**Use Case**: Production validator health tracking

---

## 📊 Metrics & Thresholds

| Metric | Threshold | Severity |
|--------|-----------|----------|
| Critical Vulnerabilities | 0 | BLOCKER |
| High Vulnerabilities | ≤3 | BLOCKER |
| Medium Vulnerabilities | ≤10 | WARNING |
| Risk Score | ≤6/10 | BLOCKER |
| Safety Score (Geiger) | ≥70/100 | BLOCKER |
| Anchor Security Score | ≥90/100 | BLOCKER |
| Validator Health Score | ≥80/100 | WARNING |

---

## 🔧 Configuration

### Required Secrets

```yaml
# GitHub Repository Settings → Secrets
CERTORA_API_KEY: "your-certora-api-key"
SOLANA_RPC_URL: "https://api.mainnet-beta.solana.com"  # Optional
SLACK_WEBHOOK: "your-slack-webhook-url"  # Optional for alerts
```

### Environment Variables

```yaml
RUST_VERSION: "1.75.0"
SOLANA_VERSION: "1.18.26"
ANCHOR_VERSION: "0.29.0"
```

---

## 📦 Artifacts

Each workflow generates artifacts:

| Artifact | Content | Retention |
|----------|---------|-----------|
| `geiger-report` | Unsafe code analysis | 30 days |
| `anchor-report` | Anchor security analysis | 30 days |
| `static-analysis-reports` | Sec3 + L3X reports | 30 days |
| `formal-verification-reports` | Kani + Certora reports | 30 days |
| `wacana-report` | Symbolic execution report | 30 days |
| `fuzzing-reports` | Trident + FuzzDelSol reports | 30 days |
| `firedancer-report` | Validator monitoring report | 7 days |
| `complete-audit-report` | Unified security report | 90 days |

---

## 🎯 Usage Examples

### Run Complete Audit Locally

```bash
# All tools
cargo run -p orchestrator -- audit \
  --repo . \
  --geiger=true \
  --anchor=true \
  --sec3=true \
  --l3x=true \
  --wacana=true \
  --trident=true \
  --fuzzdelsol=true \
  --prove=true \
  --output-dir ./audit-reports \
  --dashboard=true
```

### Run Quick Scan

```bash
# Geiger + Anchor + Sec3 only
cargo run -p orchestrator -- audit \
  --repo . \
  --geiger=true \
  --anchor=true \
  --sec3=true \
  --output-dir ./quick-scan
```

### Run Firedancer Monitoring

```bash
cargo run -p firedancer-monitor -- monitor \
  --rpc-url https://api.mainnet-beta.solana.com \
  --duration 60 \
  --output ./monitoring-report.json
```

---

## 🔍 Interpreting Results

### Safety Score (Geiger)
- **90-100**: Production-ready (minimal unsafe code)
- **70-89**: Acceptable (moderate unsafe usage)
- **50-69**: High risk (extensive unsafe code)
- **<50**: Critical risk (unsafe code dominates)

### Anchor Security Score
- **90-100**: Production-ready (proper Anchor usage)
- **70-89**: Acceptable (minor issues)
- **50-69**: High risk (missing critical constraints)
- **<50**: Critical risk (fundamental Anchor misuse)

### Risk Score (Overall)
- **0-3**: Low risk (safe to deploy)
- **4-6**: Medium risk (review recommended)
- **7-8**: High risk (deployment not recommended)
- **9-10**: Critical risk (deployment blocked)

### Validator Health Score
- **90-100**: Healthy (optimal performance)
- **70-89**: Degraded (monitor closely)
- **50-69**: Stressed (intervention needed)
- **<50**: Critical (immediate action required)

---

## 🚨 Failure Scenarios

### Deployment Blocked
Pipeline fails and deployment is blocked if:
1. **Critical vulnerabilities found** (any tool)
2. **High vulnerabilities >5** (combined)
3. **Risk score >7**
4. **Safety score <70**
5. **Anchor score <90** (if Anchor program)
6. **Formal verification failures**
7. **Fuzzing crashes detected**

### Warning Only
Pipeline succeeds with warnings if:
1. **Medium vulnerabilities >10**
2. **Validator health <80**
3. **Path explosion in WACANA**

---

## 📈 Dashboard

The security dashboard is automatically deployed to GitHub Pages:

```
https://your-org.github.io/your-repo/security-dashboard/
```

**Features**:
- Vulnerability trends over time
- Tool-by-tool breakdown
- Risk score history
- Deployment status
- Interactive charts

---

## 🔄 Continuous Improvement

### Weekly Security Review
- Review all medium/low findings
- Update security policies
- Refine thresholds

### Monthly Audits
- Full manual code review
- Third-party audit (if applicable)
- Update tool versions

### Quarterly Updates
- Benchmark against industry standards
- Update threat models
- Enhance detection rules

---

## 🛠️ Troubleshooting

### Pipeline Timeout
- Reduce fuzzing duration
- Disable WACANA for large programs
- Split into multiple jobs

### False Positives
- Adjust tool thresholds in workflow
- Add suppression comments in code
- Update detection rules

### Performance Issues
- Enable caching
- Use self-hosted runners
- Parallelize independent jobs

---

## 📚 References

- **Solana Security Best Practices**: https://docs.solana.com/developing/programming-model/security
- **Anchor Security**: https://book.anchor-lang.com/anchor_in_depth/security.html
- **Cargo-geiger**: https://github.com/rust-secure-code/cargo-geiger
- **Firedancer**: https://jumpcrypto.com/firedancer/

---

## 🤝 Contributing

To add new security tools:

1. Create analyzer crate in `crates/`
2. Integrate into `orchestrator/audit_pipeline.rs`
3. Add workflow phase in `.github/workflows/security-audit.yml`
4. Update documentation

---

## 📄 License

MIT License - See LICENSE file for details

---

**Proktor Security Swarm** — Comprehensive automated security for Solana smart contracts 🛡️
