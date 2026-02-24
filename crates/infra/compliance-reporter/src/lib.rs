//! # Compliance Reporter
//!
//! Maps Shanon's 52+ vulnerability detectors to enterprise compliance frameworks
//! and generates audit-ready compliance reports.
//!
//! ## Supported Frameworks
//! - **SOC 2 Type II** — Trust Services Criteria (CC6, CC7, CC8)
//! - **ISO 27001** — Annex A controls
//! - **OWASP Smart Contract Security** — OWASP SCS Top 10
//! - **Solana Foundation Security** — Solana-specific best practices

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Compliance framework target
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceFramework {
    SOC2,
    ISO27001,
    OWASPSCS,
    SolanaFoundation,
}

impl ComplianceFramework {
    pub fn label(&self) -> &str {
        match self {
            Self::SOC2 => "SOC 2 Type II",
            Self::ISO27001 => "ISO 27001:2022",
            Self::OWASPSCS => "OWASP Smart Contract Security",
            Self::SolanaFoundation => "Solana Foundation Security Standards",
        }
    }
}

/// A mapping from a vulnerability category to a compliance control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlMapping {
    pub control_id: String,
    pub control_name: String,
    pub framework: ComplianceFramework,
    pub description: String,
    pub status: ControlStatus,
    pub linked_detector_ids: Vec<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlStatus {
    Pass,
    Fail,
    PartialPass,
    NotApplicable,
}

/// A finding mapped to a compliance context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappedFinding {
    pub finding_id: String,
    pub vuln_type: String,
    pub severity: String,
    pub mapped_controls: Vec<String>,
    pub remediation_deadline: Option<String>,
}

/// Full compliance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub framework: ComplianceFramework,
    pub framework_label: String,
    pub program_name: String,
    pub generated_at: String,
    pub controls: Vec<ControlMapping>,
    pub mapped_findings: Vec<MappedFinding>,
    pub pass_count: usize,
    pub fail_count: usize,
    pub partial_count: usize,
    pub compliance_score: u8,
    pub summary: String,
}

/// Generate compliance reports from program analysis
pub struct ComplianceReporter;

impl ComplianceReporter {
    /// Generate a compliance report for a given framework
    pub fn generate(
        program_path: &Path,
        program_name: &str,
        framework: ComplianceFramework,
    ) -> Result<ComplianceReport, String> {
        // Run analysis
        let analyzer = program_analyzer::ProgramAnalyzer::new(program_path)
            .map_err(|e| format!("Analysis failed: {}", e))?;

        let findings = analyzer.scan_for_vulnerabilities();

        // Build control mappings for the selected framework
        let controls = Self::build_controls(&framework, &findings);

        // Map findings to controls
        let mapped_findings: Vec<MappedFinding> = findings
            .iter()
            .map(|f| {
                let mapped_controls = Self::find_matching_controls(&f.id, &framework);
                MappedFinding {
                    finding_id: f.id.clone(),
                    vuln_type: f.vuln_type.clone(),
                    severity: f.severity_label.clone(),
                    mapped_controls,
                    remediation_deadline: match f.severity {
                        5 => Some("Immediate".into()),
                        4 => Some("7 days".into()),
                        3 => Some("30 days".into()),
                        _ => Some("90 days".into()),
                    },
                }
            })
            .collect();

        let pass_count = controls.iter().filter(|c| c.status == ControlStatus::Pass).count();
        let fail_count = controls.iter().filter(|c| c.status == ControlStatus::Fail).count();
        let partial_count = controls.iter().filter(|c| c.status == ControlStatus::PartialPass).count();

        let total_applicable = controls
            .iter()
            .filter(|c| c.status != ControlStatus::NotApplicable)
            .count()
            .max(1);

        let compliance_score = ((pass_count as f64 / total_applicable as f64) * 100.0) as u8;

        let summary = format!(
            "{} compliance assessment: {}/{} controls passing ({:.0}%). {} critical findings require immediate remediation.",
            framework.label(),
            pass_count,
            total_applicable,
            compliance_score,
            findings.iter().filter(|f| f.severity >= 4).count()
        );

        Ok(ComplianceReport {
            framework_label: framework.label().to_string(),
            framework,
            program_name: program_name.to_string(),
            generated_at: chrono::Utc::now().to_rfc3339(),
            controls,
            mapped_findings,
            pass_count,
            fail_count,
            partial_count,
            compliance_score,
            summary,
        })
    }

    /// Build the control list for a framework based on findings
    fn build_controls(
        framework: &ComplianceFramework,
        findings: &[program_analyzer::VulnerabilityFinding],
    ) -> Vec<ControlMapping> {
        let control_defs = Self::framework_controls(framework);

        control_defs
            .into_iter()
            .map(|(id, name, desc, detector_ids)| {
                let has_failures = findings
                    .iter()
                    .any(|f| detector_ids.contains(&f.id.as_str()));

                let status = if has_failures {
                    ControlStatus::Fail
                } else {
                    ControlStatus::Pass
                };

                let evidence = if has_failures {
                    findings
                        .iter()
                        .filter(|f| detector_ids.contains(&f.id.as_str()))
                        .map(|f| format!("[{}] {}: {}", f.id, f.vuln_type, f.description))
                        .collect()
                } else {
                    vec!["No violations detected by automated analysis.".into()]
                };

                ControlMapping {
                    control_id: id.to_string(),
                    control_name: name.to_string(),
                    framework: framework.clone(),
                    description: desc.to_string(),
                    status,
                    linked_detector_ids: detector_ids.iter().map(|s| s.to_string()).collect(),
                    evidence,
                }
            })
            .collect()
    }

    /// Define controls for each framework
    fn framework_controls(
        framework: &ComplianceFramework,
    ) -> Vec<(&'static str, &'static str, &'static str, Vec<&'static str>)> {
        match framework {
            ComplianceFramework::SOC2 => vec![
                ("CC6.1", "Access Control", "Logical and physical access controls to protect information assets", vec!["SOL-001", "SOL-003", "SOL-007", "SOL-010"]),
                ("CC6.2", "Authorization", "Authorization mechanisms for program operations", vec!["SOL-005", "SOL-011", "SOL-031"]),
                ("CC6.3", "Input Validation", "Validation of inputs before processing", vec!["SOL-021", "SOL-041", "SOL-048"]),
                ("CC7.1", "System Monitoring", "Detection of anomalies and security events", vec!["SOL-017", "SOL-053"]),
                ("CC7.2", "Incident Response", "Processes for responding to security incidents", vec!["SOL-054", "SOL-055"]),
                ("CC8.1", "Change Management", "Controls over changes to system components", vec!["SOL-056", "SOL-057", "SOL-058"]),
            ],
            ComplianceFramework::ISO27001 => vec![
                ("A.8.3", "Access Restriction", "Access to information shall be restricted", vec!["SOL-001", "SOL-003", "SOL-007"]),
                ("A.8.9", "Configuration Management", "Configurations shall be established and maintained", vec!["SOL-010", "SOL-011"]),
                ("A.8.24", "Cryptography", "Rules for effective use of cryptography", vec!["SOL-017", "SOL-053"]),
                ("A.8.25", "Secure Development", "Rules for secure development of software", vec!["SOL-005", "SOL-021", "SOL-031", "SOL-041"]),
                ("A.8.26", "Application Security", "Security requirements in the development lifecycle", vec!["SOL-048", "SOL-054", "SOL-055", "SOL-056"]),
                ("A.8.28", "Secure Coding", "Secure coding principles shall be applied", vec!["SOL-057", "SOL-058", "SOL-064", "SOL-067"]),
            ],
            ComplianceFramework::OWASPSCS => vec![
                ("SCS-01", "Reentrancy", "Protection against reentrancy attacks", vec!["SOL-017"]),
                ("SCS-02", "Access Control", "Proper access control mechanisms", vec!["SOL-001", "SOL-003", "SOL-005", "SOL-007"]),
                ("SCS-03", "Arithmetic", "Safe arithmetic operations", vec!["SOL-021", "SOL-041"]),
                ("SCS-04", "Unchecked Return Values", "All return values properly checked", vec!["SOL-048"]),
                ("SCS-05", "Oracle Manipulation", "Secure oracle data usage", vec!["SOL-053", "SOL-054"]),
                ("SCS-06", "Flash Loan Protection", "Resistance to flash loan attacks", vec!["SOL-055"]),
                ("SCS-07", "Initialization", "Proper contract initialization", vec!["SOL-010", "SOL-011"]),
                ("SCS-08", "Cross-Program Security", "Secure cross-program invocations", vec!["SOL-031", "SOL-056", "SOL-057"]),
                ("SCS-09", "Event Emission", "Proper event logging", vec!["SOL-064"]),
                ("SCS-10", "Upgrade Safety", "Secure upgrade mechanisms", vec!["SOL-058", "SOL-067"]),
            ],
            ComplianceFramework::SolanaFoundation => vec![
                ("SF-01", "Signer Verification", "All instruction signers must be verified", vec!["SOL-001"]),
                ("SF-02", "Account Ownership", "Account ownership must be validated before access", vec!["SOL-003", "SOL-007"]),
                ("SF-03", "PDA Validation", "PDA seeds and bumps must be deterministic", vec!["SOL-005", "SOL-010"]),
                ("SF-04", "Integer Safety", "Arithmetic operations must use checked/saturating math", vec!["SOL-021", "SOL-041"]),
                ("SF-05", "CPI Safety", "Cross-program invocations must validate the target program", vec!["SOL-031", "SOL-056"]),
                ("SF-06", "Account Closure", "Closed accounts must be zeroed and reallocation prevented", vec!["SOL-011", "SOL-048"]),
                ("SF-07", "Reentrancy Guards", "State changes must precede external calls", vec!["SOL-017"]),
                ("SF-08", "Authority Management", "Authorities must be properly constrained", vec!["SOL-053", "SOL-054", "SOL-055"]),
            ],
        }
    }

    /// Find which controls a detector maps to
    fn find_matching_controls(detector_id: &str, framework: &ComplianceFramework) -> Vec<String> {
        Self::framework_controls(framework)
            .iter()
            .filter(|(_, _, _, ids)| ids.contains(&detector_id))
            .map(|(id, _, _, _)| id.to_string())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_framework_labels() {
        assert_eq!(ComplianceFramework::SOC2.label(), "SOC 2 Type II");
        assert_eq!(ComplianceFramework::ISO27001.label(), "ISO 27001:2022");
    }

    #[test]
    fn test_control_mappings() {
        let controls = ComplianceReporter::framework_controls(&ComplianceFramework::SOC2);
        assert!(!controls.is_empty());
        assert_eq!(controls[0].0, "CC6.1");
    }

    #[test]
    fn test_owasp_controls() {
        let controls = ComplianceReporter::framework_controls(&ComplianceFramework::OWASPSCS);
        assert_eq!(controls.len(), 10); // OWASP SCS Top 10
    }

    #[test]
    fn test_find_matching_controls() {
        let controls = ComplianceReporter::find_matching_controls("SOL-001", &ComplianceFramework::SOC2);
        assert!(controls.contains(&"CC6.1".to_string()));
    }

    #[test]
    fn test_generate_report() {
        let path = PathBuf::from("../program-analyzer/src");
        if path.exists() {
            let report = ComplianceReporter::generate(
                &path,
                "test-program",
                ComplianceFramework::OWASPSCS,
            );
            assert!(report.is_ok());
            let report = report.unwrap();
            assert_eq!(report.program_name, "test-program");
            assert!(report.compliance_score <= 100);
        }
    }
}
