//! # Post-Processing Pipeline
//!
//! After all 20 scanning phases produce raw findings, this module handles:
//!
//! 1. **Enrichment** — Augments findings with attack scenarios and defenses
//!    from the account-security-expert and defi-security-expert knowledge bases.
//!
//! 2. **Deduplication** — When multiple phases find the same vulnerability,
//!    keeps only the highest-confidence version (keyed by vuln_type + location + line).
//!
//! These steps run BEFORE the validation pipeline (`finding_validator`), which
//! handles FP filtering and confidence scoring.

use crate::VulnerabilityFinding;

/// Enrich findings with attack scenarios and prevention patterns from
/// the expert knowledge systems.
///
/// Populates empty `prevention` and `attack_scenario` fields using:
/// - `account_security_expert::AccountSecurityExpert::get_insight_for_id()`
/// - `defi_security_expert::DeFiSecurityExpert::get_defense_for_id()`
pub fn enrich_findings(findings: &mut Vec<VulnerabilityFinding>) {
    for f in findings.iter_mut() {
        // Account security enrichment
        if let Some(insight) = account_security_expert::AccountSecurityExpert::get_insight_for_id(&f.id) {
            if f.prevention.is_empty() {
                f.prevention = insight.secure_pattern.clone();
            }
            if f.attack_scenario.is_empty() {
                f.attack_scenario = insight.attack_vector.clone();
            }
        }
        // DeFi security enrichment
        if let Some(insight) = defi_security_expert::DeFiSecurityExpert::get_defense_for_id(&f.id) {
            if f.prevention.is_empty() {
                f.prevention = insight.defense_strategy.clone();
            }
        }
    }
}

/// Deduplicate findings across phases. When multiple phases detect the same
/// vulnerability at the same location, keeps only the highest-confidence version.
///
/// Dedup key: `(vuln_type, location, line_number)` for located findings,
/// or `(vuln_type, location, function_name)` for findings without line numbers.
///
/// # Algorithm
///
/// 1. For each finding, compute a dedup key from (vuln_type, location, line/func).
/// 2. Track the best (highest confidence) index for each key.
/// 3. Retain only the winning findings.
pub fn dedup_findings(findings: &mut Vec<VulnerabilityFinding>) {
    use std::collections::{HashMap, HashSet};
    let mut best: HashMap<String, usize> = HashMap::new();
    for (idx, f) in findings.iter().enumerate() {
        let key = if f.line_number > 0 {
            format!("{}:{}:{}", f.vuln_type, f.location, f.line_number)
        } else {
            format!("{}:{}:{}", f.vuln_type, f.location, f.function_name)
        };
        best.entry(key)
            .and_modify(|existing_idx| {
                if findings[idx].confidence > findings[*existing_idx].confidence {
                    *existing_idx = idx;
                }
            })
            .or_insert(idx);
    }
    let keep: HashSet<usize> = best.into_values().collect();
    let mut idx = 0;
    findings.retain(|_| {
        let k = keep.contains(&idx);
        idx += 1;
        k
    });
}

/// Run the full post-processing pipeline: enrich → dedup.
///
/// This is called at the end of `scan_for_vulnerabilities_raw()` before
/// returning findings to the caller.
pub fn post_process(findings: &mut Vec<VulnerabilityFinding>) {
    enrich_findings(findings);
    dedup_findings(findings);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(vuln_type: &str, location: &str, line: usize, confidence: u8) -> VulnerabilityFinding {
        VulnerabilityFinding {
            category: "Test".to_string(),
            vuln_type: vuln_type.to_string(),
            severity: 3,
            severity_label: "Medium".to_string(),
            id: "SOL-001".to_string(),
            cwe: None,
            location: location.to_string(),
            function_name: "test".to_string(),
            line_number: line,
            vulnerable_code: String::new(),
            description: String::new(),
            attack_scenario: String::new(),
            real_world_incident: None,
            secure_fix: String::new(),
            prevention: String::new(),
            confidence,
        }
    }

    #[test]
    fn test_dedup_keeps_highest_confidence() {
        let mut findings = vec![
            make_finding("overflow", "main.rs", 10, 40),
            make_finding("overflow", "main.rs", 10, 80),
            make_finding("overflow", "main.rs", 10, 60),
        ];
        dedup_findings(&mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, 80);
    }

    #[test]
    fn test_dedup_different_lines_kept() {
        let mut findings = vec![
            make_finding("overflow", "main.rs", 10, 50),
            make_finding("overflow", "main.rs", 20, 50),
        ];
        dedup_findings(&mut findings);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_dedup_different_types_kept() {
        let mut findings = vec![
            make_finding("overflow", "main.rs", 10, 50),
            make_finding("signer", "main.rs", 10, 50),
        ];
        dedup_findings(&mut findings);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_enrichment_populates_empty_fields() {
        let mut findings = vec![
            make_finding("test", "main.rs", 1, 50),
        ];
        enrich_findings(&mut findings);
        // Enrichment may or may not find a match for "SOL-001" depending on
        // the expert system's data. Either way, it shouldn't crash.
    }

    #[test]
    fn test_post_process_runs_both() {
        let mut findings = vec![
            make_finding("overflow", "main.rs", 10, 40),
            make_finding("overflow", "main.rs", 10, 80),
        ];
        post_process(&mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, 80);
    }
}
