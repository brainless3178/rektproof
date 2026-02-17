# SHANON-WEB3 — Phase-Wise Implementation Plan

> Maps every feature from shanon.txt to the **exact existing codebase**.
> Each phase specifies: crates to modify, new crates to create, files to edit,
> functions to add, dependencies needed, and integration points.
>
> **Current Codebase:** 44 crates, 52 vulnerability detectors, Z3 engine,
> on-chain oracle, Actix-web API, CLI tools.

---

## TABLE OF CONTENTS

- [Phase 0: Foundation & Prerequisites](#phase-0)
- [Phase 1: `shanon guard` — Dependency Firewall (Week 1)](#phase-1)
- [Phase 2: `shanon-ci` — GitHub Action (Week 2)](#phase-2)
- [Phase 3: Security Scoreboard (Week 3)](#phase-3)
- [Phase 4: New Vulnerability Detectors (SOL-053 to SOL-072)](#phase-4)
- [Phase 5: Token Risk Scanner](#phase-5)
- [Phase 6: Firedancer Compatibility Checker](#phase-6)
- [Phase 7: CPI Blast Radius Graph](#phase-7)
- [Phase 8: API Expansion — Wallet Risk & Monitoring](#phase-8)
- [Phase 9: VS Code Extension](#phase-9)
- [Phase 10: Enterprise — Compliance & Verification](#phase-10)

---

<a id="phase-0"></a>
## PHASE 0: Foundation & Prerequisites

**Goal:** Prepare the codebase for new feature development.

### 0.1 Create CLI Binary Crate

Currently, Shanon's entry point is `crates/hackathon-client/`. We need a proper
multi-command CLI.

```
ACTION: Create new crate
PATH:   crates/shanon-cli/
```

**Files to create:**
```
crates/shanon-cli/
├── Cargo.toml
└── src/
    └── main.rs          # clap-based CLI with subcommands
```

**`Cargo.toml` dependencies:**
```toml
[dependencies]
clap = { version = "4.4", features = ["derive", "env"] }
colored = "2.1"
tokio = { version = "1.35", features = ["full"] }
serde_json = "1.0"
program-analyzer = { path = "../program-analyzer" }
shanon-guard = { path = "../shanon-guard" }       # Phase 1
firedancer-monitor = { path = "../firedancer-monitor" }
cpi-analyzer = { path = "../cpi-analyzer" }
```

**`main.rs` structure:**
```rust
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "shanon", about = "Solana Security Platform")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a Solana program for vulnerabilities
    Scan { path: String, #[arg(long)] prove: bool },
    /// Check dependencies for supply chain attacks
    Guard { #[arg(long)] path: Option<String> },
    /// Check Firedancer compatibility
    FiredancerCheck { path: String },
    /// Analyze CPI dependency graph
    CpiGraph { program_id: String },
    /// Scan a token for rug pull risk
    TokenScan { mint: String },
    /// Monitor upgrade authority changes
    Watch { program_id: String },
    /// Verify source + security + authority
    Verify { program_id: String },
}
```

**Integration with `Cargo.toml` (workspace root):**
```
Add to members: "crates/shanon-cli"
Add to default-members: "crates/shanon-cli"
```

### 0.2 Add Pre-built Binary Release Support

**Files to create:**
```
.github/workflows/release.yml    # Build binaries for linux/mac/windows
scripts/install.sh               # curl-pipe installer
```

### 0.3 Create Docker Image

**Files to create:**
```
Dockerfile                       # Multi-stage build
docker-compose.yml               # API + scanner services
```

---

<a id="phase-1"></a>
## PHASE 1: `shanon guard` — Dependency Firewall (Week 1)

**Goal:** Scan Cargo.toml + package.json for malicious/vulnerable Solana dependencies.

### 1.1 Create New Crate: `shanon-guard`

```
ACTION: Create new crate
PATH:   crates/shanon-guard/
```

**File structure:**
```
crates/shanon-guard/
├── Cargo.toml
├── src/
│   ├── lib.rs                   # Public API: GuardScanner
│   ├── cargo_scanner.rs         # Parse Cargo.toml + Cargo.lock
│   ├── npm_scanner.rs           # Parse package.json + package-lock.json
│   ├── advisory_db.rs           # Curated Solana-specific advisory database
│   ├── typosquat.rs             # Levenshtein distance typosquat detection
│   ├── behavioral.rs            # postinstall script analysis, key exfil patterns
│   └── report.rs                # GuardReport output formatting
└── advisories/
    └── solana_advisories.json   # Known malicious packages database
```

**`Cargo.toml`:**
```toml
[package]
name = "shanon-guard"
version.workspace = true
edition.workspace = true

[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
toml = "0.8"                      # Parse Cargo.toml
semver = "1.0"                    # Version comparison
strsim = "0.11"                   # Levenshtein distance for typosquat
walkdir = { workspace = true }
colored = { workspace = true }
thiserror = { workspace = true }
reqwest = { workspace = true }    # Fetch latest advisories
```

**Core API (`lib.rs`):**
```rust
pub struct GuardScanner {
    advisory_db: AdvisoryDatabase,
    config: GuardConfig,
}

pub struct GuardReport {
    pub cargo_findings: Vec<GuardFinding>,
    pub npm_findings: Vec<GuardFinding>,
    pub behavioral_findings: Vec<GuardFinding>,
    pub risk_score: u8,           // 0-100
}

pub enum GuardSeverity { Critical, High, Medium, Low, Info }

pub struct GuardFinding {
    pub package_name: String,
    pub version: String,
    pub severity: GuardSeverity,
    pub category: FindingCategory,  // Malicious, Typosquat, Advisory, Behavioral
    pub description: String,
    pub remediation: String,
}

impl GuardScanner {
    pub fn new() -> Self;
    pub fn scan_directory(path: &Path) -> Result<GuardReport>;
    pub fn scan_cargo_toml(path: &Path) -> Result<Vec<GuardFinding>>;
    pub fn scan_package_json(path: &Path) -> Result<Vec<GuardFinding>>;
    pub fn scan_postinstall_scripts(path: &Path) -> Result<Vec<GuardFinding>>;
}
```

**`advisory_db.rs` — Pre-seeded with known attacks:**
```rust
// Known malicious Solana packages (from real attacks):
const KNOWN_MALICIOUS: &[(&str, &str)] = &[
    ("@solana/web3.js", "1.95.6"),      // Dec 2024 backdoor
    ("@solana/web3.js", "1.95.7"),      // Dec 2024 backdoor
    ("solana-transaction-toolkit", "*"), // Wallet drainer
    ("solana-stable-web-huks", "*"),     // Typosquat drainer
    ("@kodane/patch-manager", "*"),      // AI-generated malware
];

// Legitimate package names for typosquat detection:
const LEGITIMATE_PACKAGES: &[&str] = &[
    "@solana/web3.js",
    "@coral-xyz/anchor",
    "@solana/spl-token",
    "solana-sdk",
    "anchor-lang",
    "spl-token",
    // ... 50+ legitimate Solana ecosystem packages
];
```

**`typosquat.rs` — Levenshtein distance detection:**
```rust
use strsim::levenshtein;

pub fn check_typosquat(package_name: &str) -> Option<TyposquatWarning> {
    for legit in LEGITIMATE_PACKAGES {
        let distance = levenshtein(package_name, legit);
        if distance > 0 && distance <= 2 {
            return Some(TyposquatWarning {
                suspicious: package_name.to_string(),
                likely_target: legit.to_string(),
                distance,
            });
        }
    }
    None
}
```

**`behavioral.rs` — Detect key exfiltration patterns:**
```rust
// Patterns that indicate private key exfiltration
const KEY_EXFIL_PATTERNS: &[&str] = &[
    "secretKey",
    "Keypair.fromSecretKey",
    "process.env.PRIVATE",
    "fs.readFileSync",       // combined with key access
    "fetch(", "axios.",      // combined with key access = exfiltration
    "XMLHttpRequest",
];
```

### 1.2 Integrate with Existing Codebase

**Modify: `crates/orchestrator/src/audit_pipeline/mod.rs`**
```
LOCATION: After static analysis (line ~300), before symbolic engine
ADD:      GuardScanner integration as pipeline step
```

```rust
// In EnterpriseAuditor::audit_program(), after static analysis:
info!("━━━ Stage 1.5: Dependency Security (shanon guard) ━━━");
let guard_scanner = shanon_guard::GuardScanner::new();
let guard_report = guard_scanner.scan_directory(program_path)
    .unwrap_or_default();
if !guard_report.cargo_findings.is_empty() || !guard_report.npm_findings.is_empty() {
    for finding in &guard_report.cargo_findings {
        exploits.push(ConfirmedExploit {
            description: format!("[SUPPLY CHAIN] {}: {}", finding.package_name, finding.description),
            severity: match finding.severity {
                GuardSeverity::Critical => "critical",
                GuardSeverity::High => "high",
                _ => "medium",
            }.to_string(),
            // ...
        });
    }
}
```

**Modify: `crates/shanon-api/src/routes.rs`**
```
LOCATION: After existing scan_github_repo() function (line ~669)
ADD:      New endpoint: POST /api/v1/guard
```

```rust
/// POST /api/v1/guard
/// Scan dependencies for supply chain attacks
async fn guard_scan(body: web::Json<GuardRequest>) -> HttpResponse {
    let scanner = shanon_guard::GuardScanner::new();
    let report = scanner.scan_directory(Path::new(&body.path));
    HttpResponse::Ok().json(report)
}
```

**Modify: `crates/shanon-api/src/main.rs`**
```
LOCATION: Line ~148, in the App::new() builder
ADD:      .route("/api/v1/guard", web::post().to(routes::guard_scan))
```

### 1.3 CLI Integration

**Modify: `crates/shanon-cli/src/main.rs` (created in Phase 0)**
```rust
Commands::Guard { path } => {
    let target = path.unwrap_or_else(|| ".".to_string());
    let scanner = shanon_guard::GuardScanner::new();
    let report = scanner.scan_directory(Path::new(&target))?;
    report.print_colored();  // Pretty CLI output
    std::process::exit(if report.has_critical() { 1 } else { 0 });
}
```

### 1.4 Workspace Integration

**Modify: `Cargo.toml` (workspace root)**
```toml
# Add to members array:
"crates/shanon-guard",
"crates/shanon-cli",

# Add to default-members array:
"crates/shanon-guard",
"crates/shanon-cli",

# Add to workspace.dependencies:
toml_edit = "0.22"
strsim = "0.11"
semver = "1.0"
```

---

<a id="phase-2"></a>
## PHASE 2: `shanon-ci` — GitHub Action (Week 2)

**Goal:** One-line YAML integration for CI/CD security scanning.

### 2.1 Create GitHub Action Files

```
ACTION: Create new directory at repo root
PATH:   shanon-action/
```

**File structure:**
```
shanon-action/
├── action.yml                   # GitHub Action metadata
├── Dockerfile                   # Container with Shanon pre-installed
├── entrypoint.sh               # Main script
├── annotate.js                  # PR comment/annotation logic
├── package.json                # For @actions/core, @actions/github
└── README.md                    # Marketplace listing
```

**`action.yml`:**
```yaml
name: 'Shanon Security Scan'
description: 'Enterprise-grade Solana security: 52 detectors + Z3 proofs + dependency firewall'
branding:
  icon: 'shield'
  color: 'blue'
inputs:
  program-path:
    description: 'Path to Solana program source'
    required: true
    default: './programs/'
  fail-on:
    description: 'Comma-separated severities to fail on'
    required: false
    default: 'critical,high'
  prove:
    description: 'Run Z3 formal proofs'
    required: false
    default: 'false'
  guard:
    description: 'Run dependency firewall'
    required: false
    default: 'true'
  annotate:
    description: 'Add inline PR comments'
    required: false
    default: 'true'
outputs:
  risk-score:
    description: 'Overall risk score (0-100)'
  findings-count:
    description: 'Total findings count'
  critical-count:
    description: 'Critical findings count'
runs:
  using: 'docker'
  image: 'Dockerfile'
  args:
    - ${{ inputs.program-path }}
    - ${{ inputs.fail-on }}
    - ${{ inputs.prove }}
    - ${{ inputs.guard }}
    - ${{ inputs.annotate }}
```

**`Dockerfile` — Builds Shanon from source:**
```dockerfile
FROM rust:1.75-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p shanon-cli -p shanon-guard -p program-analyzer

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y git nodejs npm ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/shanon-cli /usr/local/bin/shanon
COPY shanon-action/entrypoint.sh /entrypoint.sh
COPY shanon-action/annotate.js /annotate.js
COPY shanon-action/package.json /package.json
RUN cd / && npm install
ENTRYPOINT ["/entrypoint.sh"]
```

**`entrypoint.sh` — Core logic:**
```bash
#!/bin/bash
set -e
PROGRAM_PATH="$1"
FAIL_ON="$2"
PROVE="$3"
GUARD="$4"
ANNOTATE="$5"

# Run shanon scan
RESULT=$(shanon scan "$PROGRAM_PATH" --json ${PROVE:+--prove})

# Run shanon guard
if [ "$GUARD" = "true" ]; then
    GUARD_RESULT=$(shanon guard --path "$PROGRAM_PATH" --json)
fi

# Parse results
RISK_SCORE=$(echo "$RESULT" | jq '.risk_score')
CRITICAL=$(echo "$RESULT" | jq '.critical_count')
HIGH=$(echo "$RESULT" | jq '.high_count')

# Set outputs
echo "risk-score=$RISK_SCORE" >> $GITHUB_OUTPUT
echo "critical-count=$CRITICAL" >> $GITHUB_OUTPUT

# Annotate PR
if [ "$ANNOTATE" = "true" ] && [ -n "$GITHUB_EVENT_PATH" ]; then
    node /annotate.js "$RESULT" "$GUARD_RESULT"
fi

# Fail check
if echo "$FAIL_ON" | grep -q "critical" && [ "$CRITICAL" -gt 0 ]; then
    echo "::error::Shanon found $CRITICAL critical vulnerabilities"
    exit 1
fi
```

### 2.2 Integration with Existing Analysis Engine

The GitHub Action calls `shanon scan` (the CLI from Phase 0) which internally uses:

```
shanon scan → ProgramAnalyzer (52 detectors)
            → shanon-guard (dependency check)
            → JSON output → entrypoint.sh → PR annotations
```

**Key existing crates used:**
- `program-analyzer` — 52 vulnerability detectors via `scan_for_vulnerabilities()`
- `shanon-guard` — dependency firewall (Phase 1)
- `report_generator` — already exists at `crates/program-analyzer/src/report_generator.rs`

**Modify: `crates/program-analyzer/src/report_generator.rs`**
```
ADD: fn to_github_annotations(&self) -> Vec<GitHubAnnotation>
     Converts findings to GitHub Check Run annotation format
```

### 2.3 PR Comment Branding

**`annotate.js` — Posts branded PR comments:**
```javascript
const core = require('@actions/core');
const github = require('@actions/github');

async function run() {
    const result = JSON.parse(process.argv[2]);
    const octokit = github.getOctokit(process.env.GITHUB_TOKEN);
    
    // Post summary comment
    const body = `## 🛡️ Shanon Security Scan Results\n\n` +
        `| Severity | Count |\n|----------|-------|\n` +
        `| 🔴 Critical | ${result.critical_count} |\n` +
        `| 🟠 High | ${result.high_count} |\n` +
        `| 🟡 Medium | ${result.medium_count} |\n\n` +
        `**Risk Score: ${result.risk_score}/100**\n\n` +
        `---\n*Powered by [Shanon Security Oracle](https://shanon.security)*`;
    
    await octokit.rest.issues.createComment({
        ...github.context.repo,
        issue_number: github.context.payload.pull_request.number,
        body
    });
    
    // Post inline annotations on vulnerable lines
    for (const finding of result.findings) {
        await octokit.rest.pulls.createReviewComment({
            ...github.context.repo,
            pull_number: github.context.payload.pull_request.number,
            body: `🛡️ **[Shanon Security]** ${finding.severity}: ${finding.title}\n\n${finding.description}\n\n**Fix:** ${finding.remediation}`,
            path: finding.file,
            line: finding.line,
        });
    }
}
run();
```

---

<a id="phase-3"></a>
## PHASE 3: Security Scoreboard (Week 3)

**Goal:** CLI-based scoring pipeline ranking Solana protocols by security score, with API endpoints and SVG badges.

### 3.1 Backend — Scoring Pipeline

**Modify: `crates/shanon-api/src/routes.rs`**
```
LOCATION: After existing routes (~line 789)
ADD:      Scoreboard endpoints
```

```rust
// New endpoints to add:
// GET /api/v1/scoreboard              — List all scored protocols
// GET /api/v1/scoreboard/{program_id} — Individual score details
// GET /api/v1/badge/{program_id}      — SVG badge image
// POST /api/v1/scoreboard/scan        — Trigger scoring for a protocol
```

**Create new file: `crates/shanon-api/src/scoreboard.rs`**
```rust
pub struct ProtocolScore {
    pub program_id: String,
    pub name: String,
    pub score: u8,                    // 0-100
    pub source_verified: bool,        // solana-verify check
    pub upgrade_authority: AuthorityStatus, // Multisig/Single/Immutable
    pub findings: FindingSummary,
    pub last_scanned: chrono::DateTime<chrono::Utc>,
    pub badge_url: String,
}

pub enum AuthorityStatus {
    Immutable,             // Best — program can't be changed
    Multisig(u8, u8),      // (threshold, total) e.g., 3-of-5
    SingleWallet,          // Risky
    Unknown,
}

/// Scoring algorithm
pub fn calculate_protocol_score(
    findings: &[VulnerabilityFinding],
    authority: &AuthorityStatus,
    source_verified: bool,
) -> u8 {
    let mut score: i32 = 100;
    // Deductions
    for f in findings {
        match f.severity.as_str() {
            "critical" => score -= 25,
            "high" => score -= 15,
            "medium" => score -= 5,
            "low" => score -= 2,
            _ => {}
        }
    }
    if !source_verified { score -= 15; }
    match authority {
        AuthorityStatus::SingleWallet => score -= 20,
        AuthorityStatus::Unknown => score -= 25,
        _ => {}
    }
    score.max(0).min(100) as u8
}
```

### 3.2 CLI Scoreboard Command

**Modify: `crates/shanon-cli/src/main.rs`**

Add a `scoreboard` subcommand to the CLI that calls the scoring API endpoints
or performs local scoring directly via `program-analyzer` and `shanon-guard`.

### 3.3 Badge SVG Generator

**Create: `crates/shanon-api/src/badge.rs`**
```rust
/// Generate an SVG badge for a protocol's security score
pub fn generate_badge_svg(score: u8, name: &str) -> String {
    let color = match score {
        90..=100 => "#4c1",    // Green
        70..=89 => "#dfb317",  // Yellow
        50..=69 => "#fe7d37",  // Orange
        _ => "#e05d44",        // Red
    };
    format!(r#"<svg xmlns="http://www.w3.org/2000/svg" width="200" height="20">
        <rect width="120" height="20" fill="#555"/>
        <rect x="120" width="80" height="20" fill="{color}"/>
        <text x="60" y="14" fill="#fff" text-anchor="middle" font-size="11">Shanon Verified</text>
        <text x="160" y="14" fill="#fff" text-anchor="middle" font-size="11">{score}/100</text>
    </svg>"#)
}
```

### 3.4 Integration Points

**Existing crates used:**
- `program-analyzer` → `scan_for_vulnerabilities()` for scoring
- `git-scanner` → `clone_repo()` to fetch protocol source
- `shanon-api` → new routes added to existing Actix-web server
- `shanon-guard` → dependency check as part of score

---

<a id="phase-4"></a>
## PHASE 4: New Vulnerability Detectors (SOL-053 to SOL-072)

**Goal:** Add the 20 missing security checks from shanon.txt to the existing detector engine.

### 4.1 Where to Add

All detectors go into the existing file:
```
FILE: crates/program-analyzer/src/vulnerability_db.rs
```

**Current state:** 52 detectors (SOL-001 to SOL-052), each a `fn check_*(code: &str) -> Option<VulnerabilityFinding>`.

**NOTE:** Some of these already partially exist:
- `check_duplicate_accounts` (SOL-006) — exists but needs enhancement
- `check_cpi_depth` (SOL-027) — exists but needs Firedancer-awareness
- `check_lamport_drain` (SOL-026) — exists but needs close+resurrect logic
- `check_reentrancy` (SOL-018) — exists but misses Token2022 transfer hooks

### 4.2 New Detectors to Add

**Modify: `crates/program-analyzer/src/vulnerability_db.rs`**

Add to `get_default_patterns()` function (starts line 49):

```rust
// === NEW DETECTORS FROM SHANON.TXT SECURITY ANALYSIS ===

// SOL-053: Close Account + Resurrection Attack
VulnerabilityPattern::new("SOL-053", "Close Account Resurrection", 9, check_close_resurrection),

// SOL-054: System/Token Program Impersonation  
VulnerabilityPattern::new("SOL-054", "Program Impersonation", 10, check_program_impersonation),

// SOL-055: Token2022 Transfer Hook Reentrancy
VulnerabilityPattern::new("SOL-055", "Token2022 Transfer Hook Risk", 8, check_token2022_hook),

// SOL-056: Token2022 Transfer Fee Accounting
VulnerabilityPattern::new("SOL-056", "Token2022 Fee Mismatch", 7, check_token2022_fees),

// SOL-057: Token2022 Permanent Delegate Risk
VulnerabilityPattern::new("SOL-057", "Permanent Delegate Exposure", 8, check_permanent_delegate),

// SOL-058: Flash Loan Price Manipulation
VulnerabilityPattern::new("SOL-058", "Flash Loan Manipulation", 9, check_flash_loan_v2),

// SOL-059: Instruction Ordering / Missing State Machine
VulnerabilityPattern::new("SOL-059", "Missing State Machine", 7, check_state_machine),

// SOL-060: Event Log Spoofing
VulnerabilityPattern::new("SOL-060", "Event Log Spoofing", 5, check_event_spoofing),

// SOL-061: Compute Unit Exhaustion with Partial State
VulnerabilityPattern::new("SOL-061", "CU Exhaustion Partial State", 7, check_cu_exhaustion),

// SOL-062: Unbounded Route/Vec Length
VulnerabilityPattern::new("SOL-062", "Unbounded Input Length", 6, check_unbounded_input),

// SOL-063: Missing remaining_accounts Validation  
VulnerabilityPattern::new("SOL-063", "Unvalidated remaining_accounts", 8, check_remaining_accounts),

// SOL-064: Governance/Timelock Bypass
VulnerabilityPattern::new("SOL-064", "Governance Bypass Risk", 7, check_governance_bypass),

// SOL-065: PDA Seed Collision
VulnerabilityPattern::new("SOL-065", "PDA Seed Collision Risk", 6, check_seed_collision),

// SOL-066: Jito MEV Slippage Weakness
VulnerabilityPattern::new("SOL-066", "Insufficient MEV Protection", 6, check_mev_protection),

// SOL-067: Upgrade Authority Single Wallet
VulnerabilityPattern::new("SOL-067", "Single Wallet Upgrade Authority", 8, check_upgrade_authority_risk),

// SOL-068: Missing Freeze Authority Check
VulnerabilityPattern::new("SOL-068", "Unvalidated Freeze Authority", 6, check_freeze_auth_risk),

// SOL-069: Duplicate Account Enhancement (cross-instruction)
VulnerabilityPattern::new("SOL-069", "Cross-IX Duplicate Accounts", 9, check_cross_ix_duplicates),

// SOL-070: Versioned Transaction Handling
VulnerabilityPattern::new("SOL-070", "Legacy vs V0 Transaction Risk", 5, check_versioned_tx),

// SOL-071: ALT Address Validation
VulnerabilityPattern::new("SOL-071", "Lookup Table Trust Risk", 6, check_alt_validation),

// SOL-072: Slippage Cap Enforcement
VulnerabilityPattern::new("SOL-072", "Missing Slippage Cap", 7, check_slippage_cap),
```

### 4.3 Implement Each Detector Function

Each detector follows the existing pattern. Example for SOL-053:

```rust
fn check_close_resurrection(code: &str) -> Option<VulnerabilityFinding> {
    // Detect: close_account pattern without re-validation after CPI
    let has_close = code.contains("close = ")
        || code.contains("close_account")
        || code.contains("AccountInfo") && code.contains("lamports");
    let has_cpi_after_close = /* check for CPI calls after close patterns */;
    let missing_revalidation = /* check no re-check of account data after CPI */;
    
    if has_close && (has_cpi_after_close || missing_revalidation) {
        Some(VulnerabilityFinding {
            id: "SOL-053".into(),
            title: "Close Account Resurrection Attack".into(),
            severity: "critical".into(),
            description: "Account can be closed and recreated within same transaction...".into(),
            // ...
        })
    } else { None }
}
```

### 4.4 Update Finding Validator

**Modify: `crates/program-analyzer/src/finding_validator.rs`**
```
ADD: Context-aware validation rules for each new detector
     to reduce false positives (same pattern as existing validators)
```

### 4.5 Update Test Suite

**Modify: `integration-tests/src/lib.rs`**
```
ADD: Test cases for each new detector (SOL-053 to SOL-072)
     using the vulnerable test programs
```

**Modify: `programs/vulnerable-vault/src/lib.rs`**
```
ADD: Intentionally vulnerable patterns for new detectors
     (close+recreate, missing program ID check, etc.)
```

---

<a id="phase-5"></a>
## PHASE 5: Token Risk Scanner

**Goal:** Analyze tokens for rug pull risk using on-chain data + source code analysis.

### 5.1 Extend Existing Crate: `token-security-expert`

```
FILE: crates/token-security-expert/src/lib.rs
```

**Current state:** Knowledge base with `TokenInsight` entries. Needs active scanning capability.

**Add new file: `crates/token-security-expert/src/scanner.rs`**
```rust
pub struct TokenRiskScanner {
    rpc_client: Arc<RpcClient>,
    program_analyzer: ProgramAnalyzer,
}

pub struct TokenRiskReport {
    pub mint_address: String,
    pub risk_score: u8,
    pub on_chain_checks: OnChainTokenChecks,
    pub source_code_checks: Option<Vec<VulnerabilityFinding>>,
    pub z3_proofs: Vec<ProofResult>,
    pub rug_probability: f64,
}

pub struct OnChainTokenChecks {
    pub supply: u64,
    pub mint_authority: Option<String>,      // Active = can mint unlimited
    pub freeze_authority: Option<String>,     // Active = can freeze your tokens
    pub is_upgradeable: bool,
    pub upgrade_authority: Option<String>,
    pub top_holder_concentration: f64,       // % held by top 10
    pub liquidity_locked: bool,
    pub liquidity_lock_duration: Option<u64>,
}

impl TokenRiskScanner {
    pub async fn scan_token(&self, mint: &Pubkey) -> Result<TokenRiskReport>;
    async fn check_on_chain(&self, mint: &Pubkey) -> Result<OnChainTokenChecks>;
    async fn fetch_program_source(&self, program_id: &Pubkey) -> Option<PathBuf>;
    fn analyze_source_for_rug(&self, source: &Path) -> Vec<VulnerabilityFinding>;
}
```

### 5.2 Integration Points

- Uses `solana-client` (already in workspace) for on-chain queries
- Uses `program-analyzer` for source code analysis
- Uses `symbolic-engine` (Z3) for proving exploitability
- New API endpoint in `shanon-api`: `GET /api/v1/token/{mint}/risk`
- New CLI command: `shanon token-scan <mint>`

---

<a id="phase-6"></a>
## PHASE 6: Firedancer Compatibility Checker

**Goal:** Extend existing `firedancer-monitor` crate for program compatibility analysis.

### 6.1 Extend Existing Crate

```
FILE: crates/firedancer-monitor/src/lib.rs (249 lines)
```

**Current state:** Monitors validator performance (verification lag, slot timing, fork rate).
Needs: Static analysis of program source for runtime compatibility issues.

**Add new files:**
```
crates/firedancer-monitor/src/
├── lib.rs                       # Existing (keep)
├── compatibility.rs             # NEW: static analysis for program compat
├── compute_budget.rs            # NEW: CU metering difference detection
├── syscall_analyzer.rs          # NEW: syscall usage analysis
└── runtime_diff_db.rs           # NEW: known differences database
```

**`compatibility.rs`:**
```rust
pub struct FiredancerCompatChecker {
    diff_db: RuntimeDiffDatabase,
}

pub struct CompatReport {
    pub score: u8,
    pub warnings: Vec<CompatWarning>,
    pub safe_patterns: Vec<String>,
}

pub enum CompatWarning {
    ComputeBudgetRisk { syscall: String, detail: String },
    TransactionOrderingDependency { detail: String },
    ClockResolutionAssumption { detail: String },
    ConcurrentAccountAccess { accounts: Vec<String> },
}

impl FiredancerCompatChecker {
    pub fn analyze_source(path: &Path) -> Result<CompatReport>;
    fn check_compute_assumptions(code: &str) -> Vec<CompatWarning>;
    fn check_ordering_dependencies(code: &str) -> Vec<CompatWarning>;
    fn check_clock_usage(code: &str) -> Vec<CompatWarning>;
}
```

### 6.2 Integration

- CLI: `shanon firedancer-check ./programs/my-protocol/`
- Pipeline: Add as optional stage in `EnterpriseAuditor::audit_program()`
- API: `POST /api/v1/firedancer-check`

---

<a id="phase-7"></a>
## PHASE 7: CPI Blast Radius Graph

**Goal:** Extend existing `cpi-analyzer` to map cross-program dependency risk.

### 7.1 Extend Existing Crate

```
FILE: crates/cpi-analyzer/src/lib.rs (254 lines)
```

**Current state:** Detects unsafe CPI patterns within a single program's source code.
Needs: Cross-program dependency mapping using on-chain data.

**Add new file: `crates/cpi-analyzer/src/graph.rs`**
```rust
pub struct CPIDependencyGraph {
    nodes: HashMap<Pubkey, ProgramNode>,
    edges: Vec<CPIEdge>,
}

pub struct ProgramNode {
    pub program_id: Pubkey,
    pub name: Option<String>,
    pub security_score: Option<u8>,
    pub verified: bool,
}

pub struct CPIEdge {
    pub caller: Pubkey,
    pub callee: Pubkey,
    pub call_type: CPICallType,   // invoke, invoke_signed, anchor CPI
}

impl CPIDependencyGraph {
    /// Build graph from on-chain transaction history
    pub async fn build_from_transactions(
        rpc: &RpcClient,
        program_id: &Pubkey,
        depth: u8,
    ) -> Result<Self>;
    
    /// Calculate risk propagation through the graph
    pub fn propagate_risk(&mut self) -> Vec<RiskPropagation>;
    
    /// Export as JSON for D3.js visualization
    pub fn to_d3_json(&self) -> String;
}
```

### 7.2 Integration

- Uses existing `CPIAnalyzer` for source-level CPI detection
- Uses `solana-client` for on-chain transaction analysis
- New API: `GET /api/v1/cpi-graph/{program_id}`
- CLI: `shanon cpi-graph <program_id>`

---

<a id="phase-8"></a>
## PHASE 8: API Expansion — Wallet Risk & Monitoring

**Goal:** Add Transaction Risk API and Upgrade Authority Monitoring.

### 8.1 Transaction Risk API

**Modify: `crates/shanon-api/src/routes.rs`**

```rust
// NEW: POST /api/v1/simulate
// Wallet integration endpoint — check program safety before signing
async fn simulate_transaction(
    body: web::Json<SimulateRequest>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let tx_bytes = bs58::decode(&body.transaction).into_vec().unwrap();
    // 1. Extract program IDs from transaction
    // 2. Check each against scoreboard/on-chain data
    // 3. Check upgrade authority status
    // 4. Return risk assessment
    HttpResponse::Ok().json(SimulateResponse { risk_score, warnings })
}
```

### 8.2 Upgrade Authority Monitor

**Create: `crates/shanon-monitor/`**

```
crates/shanon-monitor/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── authority_watcher.rs     # Poll program accounts for authority changes
    ├── alerts.rs                # Discord/Telegram/Slack webhook alerts
    └── indexer.rs               # Track historical authority changes
```

**Uses:** `solana-client` for RPC polling, `reqwest` for webhook delivery.

**CLI:** `shanon watch <program_id> --discord <webhook_url>`

---

<a id="phase-9"></a>
## PHASE 9: VS Code Extension

**Goal:** Real-time vulnerability highlighting as developers code.

### 9.1 Architecture

```
VS Code Extension (TypeScript)
    ↕ JSON-RPC over stdio
Shanon LSP Server (Rust, new binary crate)
    ↕ calls
program-analyzer (existing crate)
```

### 9.2 Create LSP Server Crate

**Create: `crates/shanon-lsp/`**
```
crates/shanon-lsp/
├── Cargo.toml
└── src/
    └── main.rs
```

**Dependencies:**
```toml
[dependencies]
tower-lsp = "0.20"           # LSP protocol
program-analyzer = { path = "../program-analyzer" }
serde_json = { workspace = true }
tokio = { workspace = true }
```

**Core logic:** On `textDocument/didSave`, run `ProgramAnalyzer::from_source()` on the
file content, convert findings to LSP `Diagnostic` objects, publish to VS Code.

### 9.3 VS Code Extension

**Create: `shanon-vscode/`** (separate repo or directory)
```
shanon-vscode/
├── package.json
├── src/
│   └── extension.ts       # Activates LSP client
├── syntaxes/
│   └── shanon.tmLanguage.json
└── README.md
```

---

<a id="phase-10"></a>
## PHASE 10: Enterprise — Compliance & Verification

### 10.1 Compliance Report Generator

**Create: `crates/compliance-reporter/`**
```rust
pub struct ComplianceReport {
    pub framework: ComplianceFramework,   // SOC2, ISO27001, OWASP
    pub controls: Vec<ControlMapping>,
    pub findings: Vec<MappedFinding>,
    pub generated_at: DateTime<Utc>,
}

pub enum ComplianceFramework { SOC2, ISO27001, OWASPSCS, SolanaFoundation }
```

Maps existing 52+ detectors to compliance control IDs.

### 10.2 Full Program Verification

**Create: `crates/shanon-verify/`**

Combines:
1. `solana-verify` (bytecode ↔ source match) — shell out to CLI
2. `program-analyzer` (52+ detectors)
3. On-chain authority check (via `solana-client`)
4. Badge generation (from Phase 3)

---

## IMPLEMENTATION PRIORITY MATRIX

```
╔═══════════╦════════════════════════════╦══════════╦════════════╦═════════════╗
║ Priority  ║ Feature                    ║ Effort   ║ Impact     ║ Depends On  ║
╠═══════════╬════════════════════════════╬══════════╬════════════╬═════════════╣
║ 🔴 P0     ║ Phase 0: CLI binary        ║ 1 day    ║ Foundation ║ -           ║
║ 🔴 P0     ║ Phase 1: shanon guard      ║ 5 days   ║ Viral      ║ Phase 0     ║
║ 🔴 P0     ║ Phase 2: shanon-ci         ║ 5 days   ║ Viral      ║ Phase 0,1   ║
║ 🟠 P1     ║ Phase 3: Scoreboard        ║ 5 days   ║ Viral      ║ Phase 0     ║
║ 🟠 P1     ║ Phase 4: 20 new detectors  ║ 7 days   ║ High       ║ -           ║
║ 🟡 P2     ║ Phase 5: Token scanner     ║ 5 days   ║ Viral      ║ Phase 4     ║
║ 🟡 P2     ║ Phase 6: Firedancer compat ║ 5 days   ║ Moonshot   ║ -           ║
║ 🟡 P2     ║ Phase 7: CPI graph         ║ 5 days   ║ High       ║ -           ║
║ 🔵 P3     ║ Phase 8: APIs + monitor    ║ 7 days   ║ Revenue    ║ Phase 3     ║
║ 🔵 P3     ║ Phase 9: VS Code ext       ║ 7 days   ║ Adoption   ║ Phase 0     ║
║ ⚪ P4     ║ Phase 10: Enterprise       ║ 10 days  ║ Revenue    ║ Phase 4     ║
╚═══════════╩════════════════════════════╩══════════╩════════════╩═════════════╝
```

## CRATE DEPENDENCY MAP

```
shanon-cli (NEW Phase 0)
├── program-analyzer (EXISTING — 52 detectors)
│   └── vulnerability_db.rs (MODIFY Phase 4 — add 20 detectors)
│   └── finding_validator.rs (MODIFY Phase 4 — new validation rules)
├── shanon-guard (NEW Phase 1)
├── firedancer-monitor (EXISTING — EXTEND Phase 6)
├── cpi-analyzer (EXISTING — EXTEND Phase 7)
├── token-security-expert (EXISTING — EXTEND Phase 5)
├── shanon-verify (NEW Phase 10)
└── shanon-monitor (NEW Phase 8)

shanon-api (EXISTING — MODIFY Phases 1,3,5,7,8)
├── routes.rs (MODIFY — add new endpoints)
├── scoreboard.rs (NEW Phase 3)
├── badge.rs (NEW Phase 3)
└── main.rs (MODIFY — register new routes)

shanon-action/ (NEW Phase 2)
├── action.yml
├── Dockerfile
├── entrypoint.sh
└── annotate.js

shanon-lsp (NEW Phase 9)
└── program-analyzer (uses existing)

shanon-vscode/ (NEW Phase 9)
└── connects to shanon-lsp

orchestrator (EXISTING — MODIFY Phases 1,5,6)
└── audit_pipeline/mod.rs (MODIFY — add guard, firedancer stages)
```

## FILES MODIFIED vs CREATED SUMMARY

| Phase | Files Modified | Files Created | New Crates |
|-------|---------------|---------------|------------|
| 0 | `Cargo.toml` | 2 | `shanon-cli` |
| 1 | `Cargo.toml`, `audit_pipeline/mod.rs`, `routes.rs`, `main.rs` | 8 | `shanon-guard` |
| 2 | None | 6 | - (action dir) |
| 3 | `routes.rs`, `main.rs` | 4 | - |
| 4 | `vulnerability_db.rs`, `finding_validator.rs` | 0 | - |
| 5 | `token-security-expert/lib.rs` | 1 | - |
| 6 | `firedancer-monitor/lib.rs` | 3 | - |
| 7 | `cpi-analyzer/lib.rs` | 1 | - |
| 8 | `routes.rs`, `main.rs` | 4 | `shanon-monitor` |
| 9 | None | 4 | `shanon-lsp` |
| 10 | None | 3 | `compliance-reporter`, `shanon-verify` |
| **Total** | **~10 existing files** | **~36 new files** | **6 new crates** |
