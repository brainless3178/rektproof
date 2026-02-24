//! Token Risk Scanner — On-Chain + Source Code Token Analysis
//!
//! Scans a Solana token mint to evaluate rug-pull risk by:
//! 1. Querying on-chain state (mint/freeze authority, upgradeability, supply)
//! 2. Analyzing the token program's source code for known vulnerability patterns
//! 3. Producing a combined risk score (0-100) and rug probability

use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

// Re-export for downstream consumers
pub use program_analyzer::VulnerabilityFinding;

/// Errors for the token risk scanner
#[derive(Debug, Error)]
pub enum TokenScanError {
    #[error("RPC error: {0}")]
    Rpc(String),
    #[error("Invalid mint address: {0}")]
    InvalidMint(String),
    #[error("Account not found: {0}")]
    AccountNotFound(String),
    #[error("Deserialization error: {0}")]
    Deserialize(String),
    #[error("Analysis error: {0}")]
    Analysis(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// On-chain properties extracted from a token mint account
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnChainTokenChecks {
    /// Raw token supply in base units
    pub supply: u64,
    /// Number of decimals
    pub decimals: u8,
    /// Active mint authority (None = revoked = safe)
    pub mint_authority: Option<String>,
    /// Active freeze authority (None = revoked = safe)
    pub freeze_authority: Option<String>,
    /// Whether the program is an upgradeable BPF loader program
    pub is_upgradeable: bool,
    /// Upgrade authority pubkey if upgradeable
    pub upgrade_authority: Option<String>,
    /// Concentration: percentage of supply held by top 10 holders
    pub top_holder_concentration: f64,
    /// Whether LP tokens are locked in a known locker
    pub liquidity_locked: bool,
    /// Duration of LP lock in seconds (if locked)
    pub liquidity_lock_duration: Option<u64>,
}

impl Default for OnChainTokenChecks {
    fn default() -> Self {
        Self {
            supply: 0,
            decimals: 0,
            mint_authority: None,
            freeze_authority: None,
            is_upgradeable: false,
            upgrade_authority: None,
            top_holder_concentration: 0.0,
            liquidity_locked: false,
            liquidity_lock_duration: None,
        }
    }
}

/// Risk flags derived from on-chain analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFlags {
    /// Mint authority can create unlimited tokens
    pub can_mint: bool,
    /// Freeze authority can freeze any holder
    pub can_freeze: bool,
    /// Program code can be changed at any time
    pub is_upgradeable: bool,
    /// Single entity holds majority of supply
    pub concentrated_supply: bool,
    /// No liquidity lock detected
    pub no_liquidity_lock: bool,
    /// LP lock expires within 30 days
    pub short_liquidity_lock: bool,
}

impl RiskFlags {
    /// Count how many red flags are active
    pub fn count(&self) -> usize {
        [
            self.can_mint,
            self.can_freeze,
            self.is_upgradeable,
            self.concentrated_supply,
            self.no_liquidity_lock,
            self.short_liquidity_lock,
        ]
        .iter()
        .filter(|&&f| f)
        .count()
    }

    /// Derive from on-chain checks
    pub fn from_checks(checks: &OnChainTokenChecks) -> Self {
        Self {
            can_mint: checks.mint_authority.is_some(),
            can_freeze: checks.freeze_authority.is_some(),
            is_upgradeable: checks.is_upgradeable,
            concentrated_supply: checks.top_holder_concentration > 50.0,
            no_liquidity_lock: !checks.liquidity_locked,
            short_liquidity_lock: checks
                .liquidity_lock_duration
                .map(|d| d < 30 * 24 * 3600)
                .unwrap_or(false),
        }
    }
}

/// Complete token risk report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRiskReport {
    /// Mint address being analyzed
    pub mint_address: String,
    /// Overall risk score (0 = safe, 100 = maximum risk)
    pub risk_score: u8,
    /// Risk grade letter
    pub grade: String,
    /// On-chain token metadata
    pub on_chain_checks: OnChainTokenChecks,
    /// Named risk flags
    pub risk_flags: RiskFlags,
    /// Source code vulnerability findings (if source available)
    pub source_code_findings: Vec<VulnerabilityFinding>,
    /// Estimated rug-pull probability (0.0 to 1.0)
    pub rug_probability: f64,
    /// Human-readable summary
    pub summary: String,
}

/// Token risk scanner combining on-chain and source-code analysis
pub struct TokenRiskScanner {
    /// RPC URL for on-chain queries
    rpc_url: String,
}

impl TokenRiskScanner {
    /// Create a new scanner targeting a specific RPC endpoint
    pub fn new(rpc_url: &str) -> Self {
        Self {
            rpc_url: rpc_url.to_string(),
        }
    }

    /// Analyze a token from its on-chain data (pre-fetched) and optional source code
    ///
    /// This is the **offline** entry point used by `shanon-cli` — no RPC calls,
    /// just pure analysis of already-gathered data.
    pub fn analyze(
        &self,
        mint_address: &str,
        on_chain: OnChainTokenChecks,
        source_path: Option<&Path>,
    ) -> Result<TokenRiskReport, TokenScanError> {
        let risk_flags = RiskFlags::from_checks(&on_chain);

        // Source code analysis
        let source_code_findings = match source_path {
            Some(path) => self.analyze_source_for_rug(path)?,
            None => Vec::new(),
        };

        // Calculate composite risk score
        let risk_score = self.calculate_risk_score(&on_chain, &risk_flags, &source_code_findings);
        let rug_probability = self.calculate_rug_probability(&risk_flags, risk_score);
        let grade = score_to_grade(risk_score);
        let summary = self.generate_summary(mint_address, &risk_flags, risk_score, rug_probability);

        Ok(TokenRiskReport {
            mint_address: mint_address.to_string(),
            risk_score,
            grade,
            on_chain_checks: on_chain,
            risk_flags,
            source_code_findings,
            rug_probability,
            summary,
        })
    }

    /// Analyze source code for rug-pull-specific vulnerability patterns
    fn analyze_source_for_rug(&self, source_path: &Path) -> Result<Vec<VulnerabilityFinding>, TokenScanError> {
        let analyzer = program_analyzer::ProgramAnalyzer::new(source_path)
            .map_err(|e| TokenScanError::Analysis(e.to_string()))?;

        let findings = analyzer.scan_for_vulnerabilities();

        // Filter to rug-pull-relevant findings only
        let rug_relevant_ids: &[&str] = &[
            "SOL-001", "SOL-003", "SOL-005", "SOL-007", "SOL-010",
            "SOL-011", "SOL-017", "SOL-021", "SOL-031", "SOL-041",
            "SOL-048", "SOL-053", "SOL-054", "SOL-055", "SOL-056",
            "SOL-057", "SOL-058", "SOL-064", "SOL-067", "SOL-068",
        ];

        Ok(findings
            .into_iter()
            .filter(|f| rug_relevant_ids.contains(&f.id.as_str()))
            .collect())
    }

    /// Calculate composite risk score from multiple signal sources
    fn calculate_risk_score(
        &self,
        _on_chain: &OnChainTokenChecks,
        flags: &RiskFlags,
        source_findings: &[VulnerabilityFinding],
    ) -> u8 {
        let mut score: f64 = 0.0;

        // On-chain risk signals (max 60 points)
        if flags.can_mint {
            score += 20.0; // Unlimited minting = biggest rug vector
        }
        if flags.can_freeze {
            score += 10.0;
        }
        if flags.is_upgradeable {
            score += 10.0;
        }
        if flags.concentrated_supply {
            score += 10.0;
        }
        if flags.no_liquidity_lock {
            score += 7.0;
        }
        if flags.short_liquidity_lock {
            score += 3.0;
        }

        // Source code risk signals (max 40 points)
        let critical_count = source_findings
            .iter()
            .filter(|f| f.severity >= 4)
            .count();
        let medium_count = source_findings
            .iter()
            .filter(|f| f.severity == 3)
            .count();

        score += (critical_count as f64 * 8.0).min(30.0);
        score += (medium_count as f64 * 3.0).min(10.0);

        score.min(100.0) as u8
    }

    /// Calculate rug-pull probability from flags and score
    fn calculate_rug_probability(&self, flags: &RiskFlags, risk_score: u8) -> f64 {
        let base = risk_score as f64 / 100.0;

        // Multiplicative boosters for the most dangerous combinations
        let mut probability = base;

        // Active mint authority + concentrated supply = classic rug pattern
        if flags.can_mint && flags.concentrated_supply {
            probability = (probability * 1.5).min(0.99);
        }

        // Upgradeable + no lock = can change code at any time
        if flags.is_upgradeable && flags.no_liquidity_lock {
            probability = (probability * 1.3).min(0.99);
        }

        (probability * 100.0).round() / 100.0 // Round to 2 decimal places
    }

    /// Generate a human-readable summary of the risk analysis
    fn generate_summary(
        &self,
        mint: &str,
        flags: &RiskFlags,
        risk_score: u8,
        rug_prob: f64,
    ) -> String {
        let mut warnings = Vec::new();

        if flags.can_mint {
            warnings.push("⚠ Mint authority is ACTIVE — unlimited tokens can be created");
        }
        if flags.can_freeze {
            warnings.push("⚠ Freeze authority is ACTIVE — your tokens can be frozen");
        }
        if flags.is_upgradeable {
            warnings.push("⚠ Program is UPGRADEABLE — code can change at any time");
        }
        if flags.concentrated_supply {
            warnings.push("⚠ Supply is CONCENTRATED — top holders control >50%");
        }
        if flags.no_liquidity_lock {
            warnings.push("⚠ No liquidity lock detected");
        }
        if flags.short_liquidity_lock {
            warnings.push("⚠ Liquidity lock expires within 30 days");
        }

        let risk_label = match risk_score {
            0..=20 => "LOW RISK",
            21..=40 => "MODERATE RISK",
            41..=60 => "ELEVATED RISK",
            61..=80 => "HIGH RISK",
            _ => "CRITICAL RISK",
        };

        let warning_text = if warnings.is_empty() {
            "No red flags detected.".to_string()
        } else {
            warnings.join("\n")
        };

        format!(
            "Token Risk Analysis for {}\n\
             Risk Score: {}/100 ({})\n\
             Rug Probability: {:.0}%\n\
             Red Flags: {}/{}\n\n\
             {}",
            &mint[..8.min(mint.len())],
            risk_score,
            risk_label,
            rug_prob * 100.0,
            flags.count(),
            6,
            warning_text
        )
    }

    /// Get the configured RPC URL
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }
}

/// Convert risk score to letter grade (inverted — higher risk = worse grade)
fn score_to_grade(risk_score: u8) -> String {
    match risk_score {
        0..=10 => "A+",
        11..=20 => "A",
        21..=30 => "B",
        31..=40 => "C",
        41..=50 => "D",
        51..=70 => "E",
        _ => "F",
    }
    .to_string()
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn default_checks() -> OnChainTokenChecks {
        OnChainTokenChecks::default()
    }

    #[test]
    fn test_safe_token_low_risk() {
        let scanner = TokenRiskScanner::new("http://localhost:8899");
        let checks = OnChainTokenChecks {
            supply: 1_000_000_000,
            decimals: 9,
            mint_authority: None,          // revoked
            freeze_authority: None,        // revoked
            is_upgradeable: false,         // immutable
            upgrade_authority: None,
            top_holder_concentration: 15.0,
            liquidity_locked: true,
            liquidity_lock_duration: Some(365 * 24 * 3600),
            ..default_checks()
        };
        let report = scanner.analyze("SafeMint111111", checks, None).unwrap();
        assert!(report.risk_score <= 20);
        assert!(report.rug_probability <= 0.25);
        assert!(report.grade == "A+" || report.grade == "A");
    }

    #[test]
    fn test_rug_token_high_risk() {
        let scanner = TokenRiskScanner::new("http://localhost:8899");
        let checks = OnChainTokenChecks {
            supply: 1_000_000_000,
            decimals: 9,
            mint_authority: Some("RugPuller111".into()),
            freeze_authority: Some("RugPuller111".into()),
            is_upgradeable: true,
            upgrade_authority: Some("RugPuller111".into()),
            top_holder_concentration: 85.0,
            liquidity_locked: false,
            liquidity_lock_duration: None,
        };
        let report = scanner.analyze("RugMint222222", checks, None).unwrap();
        assert!(report.risk_score >= 50);
        assert!(report.rug_probability >= 0.5);
        assert!(report.grade == "E" || report.grade == "F");
    }

    #[test]
    fn test_risk_flags_count() {
        let flags = RiskFlags {
            can_mint: true,
            can_freeze: true,
            is_upgradeable: false,
            concentrated_supply: true,
            no_liquidity_lock: false,
            short_liquidity_lock: false,
        };
        assert_eq!(flags.count(), 3);
    }

    #[test]
    fn test_risk_flags_from_checks() {
        let checks = OnChainTokenChecks {
            mint_authority: Some("abc".into()),
            freeze_authority: None,
            is_upgradeable: true,
            top_holder_concentration: 30.0,
            liquidity_locked: true,
            liquidity_lock_duration: Some(10 * 24 * 3600), // short
            ..default_checks()
        };
        let flags = RiskFlags::from_checks(&checks);
        assert!(flags.can_mint);
        assert!(!flags.can_freeze);
        assert!(flags.is_upgradeable);
        assert!(!flags.concentrated_supply);
        assert!(!flags.no_liquidity_lock);
        assert!(flags.short_liquidity_lock);
    }

    #[test]
    fn test_score_to_grade() {
        assert_eq!(score_to_grade(0), "A+");
        assert_eq!(score_to_grade(15), "A");
        assert_eq!(score_to_grade(25), "B");
        assert_eq!(score_to_grade(35), "C");
        assert_eq!(score_to_grade(45), "D");
        assert_eq!(score_to_grade(60), "E");
        assert_eq!(score_to_grade(80), "F");
    }

    #[test]
    fn test_rug_probability_boosters() {
        let scanner = TokenRiskScanner::new("http://localhost:8899");
        // mint + concentrated = boosted
        let flags = RiskFlags {
            can_mint: true,
            can_freeze: false,
            is_upgradeable: false,
            concentrated_supply: true,
            no_liquidity_lock: false,
            short_liquidity_lock: false,
        };
        let base_prob = scanner.calculate_rug_probability(&flags, 30);
        // Same risk_score but without the combo
        let flags2 = RiskFlags {
            can_mint: true,
            can_freeze: false,
            is_upgradeable: false,
            concentrated_supply: false,
            no_liquidity_lock: false,
            short_liquidity_lock: false,
        };
        let no_boost_prob = scanner.calculate_rug_probability(&flags2, 30);
        assert!(base_prob > no_boost_prob);
    }

    #[test]
    fn test_summary_generation() {
        let scanner = TokenRiskScanner::new("http://localhost:8899");
        let flags = RiskFlags {
            can_mint: true,
            can_freeze: false,
            is_upgradeable: true,
            concentrated_supply: false,
            no_liquidity_lock: true,
            short_liquidity_lock: false,
        };
        let summary = scanner.generate_summary("TestMint123", &flags, 45, 0.55);
        assert!(summary.contains("ELEVATED RISK"));
        assert!(summary.contains("Mint authority is ACTIVE"));
        assert!(summary.contains("UPGRADEABLE"));
        assert!(summary.contains("No liquidity lock"));
    }
}
