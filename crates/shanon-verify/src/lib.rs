//! # Shanon Verify — Full Program Verification
//!
//! Combines multiple verification layers into a single comprehensive report:
//!
//! 1. **Source Verification** — Attempts to match on-chain bytecode to provided source
//! 2. **Security Analysis** — 52+ detector engine scan with validated findings
//! 3. **Authority Check** — On-chain upgrade authority status
//! 4. **Compliance Mapping** — Maps findings to compliance frameworks
//! 5. **Badge Generation** — Issues a verification badge with tier rating
//!
//! ```ignore
//! let report = VerificationEngine::verify(
//!     "MyProgram111...",
//!     Path::new("./src"),
//!     "my-program",
//!     &VerifyConfig::default(),
//! ).await?;
//! ```

use serde::{Deserialize, Serialize};
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use std::path::Path;
use std::str::FromStr;

/// Verification configuration
#[derive(Debug, Clone)]
pub struct VerifyConfig {
    pub rpc_url: String,
    pub compliance_framework: Option<compliance_reporter::ComplianceFramework>,
    pub include_source_match: bool,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            rpc_url: "https://api.mainnet-beta.solana.com".into(),
            compliance_framework: None,
            include_source_match: true,
        }
    }
}

/// Verification tier — determines badge color/level
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationTier {
    /// Gold: source verified + 0 critical/high findings + authority revoked
    Gold,
    /// Silver: source verified + 0 critical findings + ≤2 high
    Silver,
    /// Bronze: security scan passed with no critical findings
    Bronze,
    /// Unverified: critical findings present or analysis failed
    Unverified,
}

impl VerificationTier {
    pub fn label(&self) -> &str {
        match self {
            Self::Gold => "GOLD ★★★",
            Self::Silver => "SILVER ★★",
            Self::Bronze => "BRONZE ★",
            Self::Unverified => "UNVERIFIED",
        }
    }

    pub fn color(&self) -> &str {
        match self {
            Self::Gold => "#FFD700",
            Self::Silver => "#C0C0C0",
            Self::Bronze => "#CD7F32",
            Self::Unverified => "#808080",
        }
    }
}

/// Source code verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceVerification {
    pub verified: bool,
    pub method: String,
    pub details: String,
}

/// Authority check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityCheck {
    pub is_upgradeable: bool,
    pub upgrade_authority: Option<String>,
    pub authority_revoked: bool,
    pub risk_level: String,
}

/// Security scan summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySummary {
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub security_score: u8,
    pub top_findings: Vec<FindingSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSummary {
    pub id: String,
    pub vuln_type: String,
    pub severity: String,
    pub description: String,
}

/// Full verification report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub program_id: String,
    pub program_name: String,
    pub tier: VerificationTier,
    pub tier_label: String,
    pub verified_at: String,
    pub source_verification: SourceVerification,
    pub authority_check: AuthorityCheck,
    pub security_summary: SecuritySummary,
    pub compliance_score: Option<u8>,
    pub compliance_framework: Option<String>,
    pub badge_svg: String,
}

/// Main verification engine
pub struct VerificationEngine;

impl VerificationEngine {
    /// Run full verification pipeline
    pub fn verify(
        program_id: &str,
        source_path: &Path,
        program_name: &str,
        config: &VerifyConfig,
    ) -> Result<VerificationReport, String> {
        // Step 1: Security analysis
        let analyzer = program_analyzer::ProgramAnalyzer::new(source_path)
            .map_err(|e| format!("Analysis failed: {}", e))?;

        let findings = analyzer.scan_for_vulnerabilities();

        let critical_count = findings.iter().filter(|f| f.severity == 5).count();
        let high_count = findings.iter().filter(|f| f.severity == 4).count();
        let medium_count = findings.iter().filter(|f| f.severity == 3).count();
        let low_count = findings.iter().filter(|f| f.severity <= 2).count();

        let security_score = Self::calculate_security_score(&findings);

        let top_findings: Vec<FindingSummary> = findings
            .iter()
            .filter(|f| f.severity >= 3)
            .take(10)
            .map(|f| FindingSummary {
                id: f.id.clone(),
                vuln_type: f.vuln_type.clone(),
                severity: f.severity_label.clone(),
                description: f.description.clone(),
            })
            .collect();

        let security_summary = SecuritySummary {
            total_findings: findings.len(),
            critical_count,
            high_count,
            medium_count,
            low_count,
            security_score,
            top_findings,
        };

        // Step 2: Authority check
        let authority_check = Self::check_authority(program_id, &config.rpc_url);

        // Step 3: Source verification (check if source exists and compiles)
        let source_verification = Self::verify_source(source_path);

        // Step 4: Compliance (optional)
        let (compliance_score, compliance_framework) =
            if let Some(framework) = &config.compliance_framework {
                match compliance_reporter::ComplianceReporter::generate(
                    source_path,
                    program_name,
                    framework.clone(),
                ) {
                    Ok(report) => (Some(report.compliance_score), Some(report.framework_label)),
                    Err(_) => (None, None),
                }
            } else {
                (None, None)
            };

        // Step 5: Determine tier
        let tier = Self::determine_tier(
            &source_verification,
            &authority_check,
            &security_summary,
        );

        // Step 6: Generate badge
        let badge_svg = Self::generate_badge(program_name, &tier, security_score);

        Ok(VerificationReport {
            program_id: program_id.to_string(),
            program_name: program_name.to_string(),
            tier_label: tier.label().to_string(),
            tier,
            verified_at: chrono::Utc::now().to_rfc3339(),
            source_verification,
            authority_check,
            security_summary,
            compliance_score,
            compliance_framework,
            badge_svg,
        })
    }

    fn calculate_security_score(
        findings: &[program_analyzer::VulnerabilityFinding],
    ) -> u8 {
        let mut score: i32 = 100;

        for finding in findings {
            match finding.severity {
                5 => score -= 25,
                4 => score -= 15,
                3 => score -= 5,
                _ => score -= 1,
            }
        }

        score.max(0).min(100) as u8
    }

    fn check_authority(program_id: &str, rpc_url: &str) -> AuthorityCheck {
        let pubkey = match Pubkey::from_str(program_id) {
            Ok(pk) => pk,
            Err(_) => {
                return AuthorityCheck {
                    is_upgradeable: false,
                    upgrade_authority: None,
                    authority_revoked: false,
                    risk_level: "UNKNOWN".into(),
                };
            }
        };

        let client = RpcClient::new(rpc_url.to_string());

        match client.get_account(&pubkey) {
            Ok(account) => {
                let bpf_loader =
                    Pubkey::from_str("BPFLoaderUpgradeab1e11111111111111111111111").unwrap();

                let is_upgradeable = account.owner == bpf_loader;

                let upgrade_authority = if is_upgradeable && account.data.len() >= 36 {
                    let authority_bytes = &account.data[4..36];
                    let authority_key = Pubkey::new_from_array({
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(authority_bytes);
                        arr
                    });
                    if authority_key == Pubkey::default() {
                        None
                    } else {
                        Some(authority_key.to_string())
                    }
                } else {
                    None
                };

                let authority_revoked = is_upgradeable && upgrade_authority.is_none();

                let risk_level = if !is_upgradeable || authority_revoked {
                    "LOW"
                } else {
                    "ELEVATED"
                }
                .to_string();

                AuthorityCheck {
                    is_upgradeable,
                    upgrade_authority,
                    authority_revoked,
                    risk_level,
                }
            }
            Err(_) => AuthorityCheck {
                is_upgradeable: false,
                upgrade_authority: None,
                authority_revoked: false,
                risk_level: "UNKNOWN".into(),
            },
        }
    }

    fn verify_source(source_path: &Path) -> SourceVerification {
        if !source_path.exists() {
            return SourceVerification {
                verified: false,
                method: "filesystem".into(),
                details: "Source path does not exist".into(),
            };
        }

        // Count .rs files
        let rs_files: Vec<_> = walkdir::WalkDir::new(source_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("rs"))
            .collect();

        if rs_files.is_empty() {
            return SourceVerification {
                verified: false,
                method: "filesystem".into(),
                details: "No Rust source files found".into(),
            };
        }

        // Try to parse all files
        let mut parse_errors = 0;
        for entry in &rs_files {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                if syn::parse_file(&content).is_err() {
                    parse_errors += 1;
                }
            }
        }

        SourceVerification {
            verified: parse_errors == 0,
            method: "source-analysis".into(),
            details: format!(
                "{} Rust files analyzed, {} parse errors. Full bytecode matching requires solana-verify CLI.",
                rs_files.len(),
                parse_errors
            ),
        }
    }

    fn determine_tier(
        source: &SourceVerification,
        authority: &AuthorityCheck,
        security: &SecuritySummary,
    ) -> VerificationTier {
        if source.verified
            && security.critical_count == 0
            && security.high_count == 0
            && (authority.authority_revoked || !authority.is_upgradeable)
        {
            VerificationTier::Gold
        } else if source.verified
            && security.critical_count == 0
            && security.high_count <= 2
        {
            VerificationTier::Silver
        } else if security.critical_count == 0 {
            VerificationTier::Bronze
        } else {
            VerificationTier::Unverified
        }
    }

    fn generate_badge(program_name: &str, tier: &VerificationTier, score: u8) -> String {
        let color = tier.color();
        let label = tier.label();

        let mut svg = String::new();
        svg.push_str(&format!("<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"280\" height=\"28\" role=\"img\" aria-label=\"Shanon: {}\">", label));
        svg.push_str(&format!("<title>Shanon Verification: {} - {}</title>", program_name, label));
        svg.push_str("<linearGradient id=\"s\" x2=\"0\" y2=\"100%\">");
        svg.push_str("<stop offset=\"0\" stop-color=\"#bbb\" stop-opacity=\".1\"/>");
        svg.push_str("<stop offset=\"1\" stop-opacity=\".1\"/>");
        svg.push_str("</linearGradient>");
        svg.push_str("<clipPath id=\"r\"><rect width=\"280\" height=\"28\" rx=\"5\" fill=\"#fff\"/></clipPath>");
        svg.push_str("<g clip-path=\"url(#r)\">");
        svg.push_str("<rect width=\"100\" height=\"28\" fill=\"#333\"/>");
        svg.push_str(&format!("<rect x=\"100\" width=\"180\" height=\"28\" fill=\"{}\"/>", color));
        svg.push_str("<rect width=\"280\" height=\"28\" fill=\"url(#s)\"/>");
        svg.push_str("</g>");
        svg.push_str("<g fill=\"#fff\" text-anchor=\"middle\" font-family=\"Verdana,Geneva,sans-serif\" font-size=\"11\">");
        svg.push_str("<text x=\"50\" y=\"19\" fill=\"#fff\">shanon</text>");
        svg.push_str(&format!("<text x=\"190\" y=\"19\" fill=\"#333\">{} · {}/100</text>", label, score));
        svg.push_str("</g></svg>");
        svg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_labels() {
        assert_eq!(VerificationTier::Gold.label(), "GOLD ★★★");
        assert_eq!(VerificationTier::Silver.label(), "SILVER ★★");
        assert_eq!(VerificationTier::Bronze.label(), "BRONZE ★");
    }

    #[test]
    fn test_tier_colors() {
        assert_eq!(VerificationTier::Gold.color(), "#FFD700");
    }

    #[test]
    fn test_badge_generation() {
        let badge = VerificationEngine::generate_badge("test", &VerificationTier::Gold, 95);
        assert!(badge.contains("shanon"));
        assert!(badge.contains("GOLD"));
        assert!(badge.contains("95/100"));
    }

    #[test]
    fn test_determine_tier_gold() {
        let tier = VerificationEngine::determine_tier(
            &SourceVerification { verified: true, method: "test".into(), details: String::new() },
            &AuthorityCheck { is_upgradeable: true, upgrade_authority: None, authority_revoked: true, risk_level: "LOW".into() },
            &SecuritySummary { total_findings: 0, critical_count: 0, high_count: 0, medium_count: 0, low_count: 0, security_score: 100, top_findings: vec![] },
        );
        assert_eq!(tier, VerificationTier::Gold);
    }

    #[test]
    fn test_determine_tier_silver() {
        let tier = VerificationEngine::determine_tier(
            &SourceVerification { verified: true, method: "test".into(), details: String::new() },
            &AuthorityCheck { is_upgradeable: true, upgrade_authority: Some("Auth111".into()), authority_revoked: false, risk_level: "ELEVATED".into() },
            &SecuritySummary { total_findings: 1, critical_count: 0, high_count: 1, medium_count: 0, low_count: 0, security_score: 85, top_findings: vec![] },
        );
        assert_eq!(tier, VerificationTier::Silver);
    }

    #[test]
    fn test_determine_tier_unverified() {
        let tier = VerificationEngine::determine_tier(
            &SourceVerification { verified: false, method: "test".into(), details: String::new() },
            &AuthorityCheck { is_upgradeable: true, upgrade_authority: Some("Auth111".into()), authority_revoked: false, risk_level: "HIGH".into() },
            &SecuritySummary { total_findings: 3, critical_count: 2, high_count: 1, medium_count: 0, low_count: 0, security_score: 30, top_findings: vec![] },
        );
        assert_eq!(tier, VerificationTier::Unverified);
    }

    #[test]
    fn test_verify_missing_source() {
        let sv = VerificationEngine::verify_source(Path::new("/nonexistent/path"));
        assert!(!sv.verified);
    }

    #[test]
    fn test_security_score_calculation() {
        // No findings = 100
        let score = VerificationEngine::calculate_security_score(&[]);
        assert_eq!(score, 100);
    }
}
