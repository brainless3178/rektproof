//! # Finding Converters
//!
//! Converts findings from each analysis engine's native format into the
//! universal [`VulnerabilityFinding`] struct. Each converter handles:
//!
//! - Severity mapping (engine-specific → 1–5 numeric scale)
//! - SOL-xxx ID assignment (using [`vuln_registry`] ranges)
//! - CWE mapping
//! - Source location extraction
//!
//! ## Converter Ownership
//!
//! | Converter | Source Engine | SOL ID Range |
//! |-----------|-------------|-------------|
//! | [`sec3_finding_to_vulnerability`] | sec3-analyzer | SOL-070–078 |
//! | [`anchor_finding_to_vulnerability`] | anchor-security-analyzer | SOL-080–087 |
//! | [`taint_flow_to_vulnerability`] | taint-analyzer | SOL-092 |

use crate::VulnerabilityFinding;

// ─── Sec3 → VulnerabilityFinding ─────────────────────────────────────────────

/// Convert a Sec3 finding into the standard VulnerabilityFinding format.
///
/// Maps Sec3 categories to SOL-xxx IDs in the existing detector namespace,
/// preserving CWE mapping, severity, and source snippets.
///
/// # ID Collisions
///
/// Some Sec3 categories overlap with core detectors (owner, signer, integer).
/// These map to the same SOL-xxx IDs so the deduplicator can merge them.
pub fn sec3_finding_to_vulnerability(f: sec3_analyzer::Sec3Finding) -> VulnerabilityFinding {
    use sec3_analyzer::{Sec3Category, Sec3Severity};

    let (severity, severity_label) = match f.severity {
        Sec3Severity::Critical => (5, "Critical".to_string()),
        Sec3Severity::High     => (4, "High".to_string()),
        Sec3Severity::Medium   => (3, "Medium".to_string()),
        Sec3Severity::Low      => (2, "Low".to_string()),
        Sec3Severity::Info     => (1, "Info".to_string()),
    };

    let (id, category, vuln_type) = match f.category {
        Sec3Category::CloseAccountDrain => (
            "SOL-070".to_string(),
            "Account Safety".to_string(),
            "Close Account Drain".to_string(),
        ),
        Sec3Category::DuplicateMutableAccounts => (
            "SOL-071".to_string(),
            "Account Safety".to_string(),
            "Duplicate Mutable Accounts".to_string(),
        ),
        Sec3Category::UncheckedRemainingAccounts => (
            "SOL-072".to_string(),
            "Input Validation".to_string(),
            "Unchecked Remaining Accounts".to_string(),
        ),
        Sec3Category::InsecurePDADerivation => (
            "SOL-073".to_string(),
            "Cryptographic".to_string(),
            "Insecure PDA Derivation".to_string(),
        ),
        Sec3Category::ReInitialization => (
            "SOL-074".to_string(),
            "Account Safety".to_string(),
            "Re-Initialization via init_if_needed".to_string(),
        ),
        Sec3Category::ArbitraryCPI => (
            "SOL-075".to_string(),
            "Access Control".to_string(),
            "Arbitrary CPI Invocation".to_string(),
        ),
        Sec3Category::AccountConfusion => (
            "SOL-076".to_string(),
            "Type Safety".to_string(),
            "Account Type Confusion".to_string(),
        ),
        Sec3Category::MissingDiscriminator => (
            "SOL-077".to_string(),
            "Type Safety".to_string(),
            "Missing Discriminator Check".to_string(),
        ),
        Sec3Category::MissingRentExemption => (
            "SOL-078".to_string(),
            "Account Safety".to_string(),
            "Missing Rent Exemption Check".to_string(),
        ),
        // Overlap with core detectors — use existing SOL IDs for dedup
        Sec3Category::MissingOwnerCheck => (
            "SOL-012".to_string(),
            "Access Control".to_string(),
            "Missing Owner Validation".to_string(),
        ),
        Sec3Category::MissingSignerCheck => (
            "SOL-001".to_string(),
            "Access Control".to_string(),
            "Missing Signer Validation".to_string(),
        ),
        Sec3Category::IntegerOverflow => (
            "SOL-006".to_string(),
            "Arithmetic".to_string(),
            "Integer Overflow/Underflow".to_string(),
        ),
    };

    VulnerabilityFinding {
        category,
        vuln_type,
        severity,
        severity_label,
        id,
        cwe: Some(f.cwe),
        location: f.file_path,
        function_name: f.instruction,
        line_number: f.line_number,
        vulnerable_code: f.source_snippet.unwrap_or_default(),
        description: f.description,
        attack_scenario: String::new(),
        real_world_incident: None,
        secure_fix: f.fix_recommendation,
        prevention: String::new(),
        confidence: 50,
    }
}

// ─── Anchor → VulnerabilityFinding ───────────────────────────────────────────

/// Convert an Anchor security finding into the standard VulnerabilityFinding format.
///
/// Net-new Anchor detectors get SOL-080+ IDs.
/// Overlapping ones map to existing IDs for dedup.
pub fn anchor_finding_to_vulnerability(f: anchor_security_analyzer::report::AnchorFinding) -> VulnerabilityFinding {
    use anchor_security_analyzer::report::{AnchorSeverity, AnchorViolation};

    let (severity, severity_label) = match f.severity {
        AnchorSeverity::Critical => (5, "Critical".to_string()),
        AnchorSeverity::High     => (4, "High".to_string()),
        AnchorSeverity::Medium   => (3, "Medium".to_string()),
        AnchorSeverity::Low      => (2, "Low".to_string()),
    };

    let (id, category, vuln_type) = match f.violation {
        AnchorViolation::WeakConstraint => (
            "SOL-080".to_string(),
            "Anchor Safety".to_string(),
            "Weak Account Constraint".to_string(),
        ),
        AnchorViolation::InvalidTokenHook => (
            "SOL-081".to_string(),
            "Token Safety".to_string(),
            "Invalid Token-2022 Transfer Hook".to_string(),
        ),
        AnchorViolation::MissingHasOne => (
            "SOL-082".to_string(),
            "Anchor Safety".to_string(),
            "Missing has_one Constraint".to_string(),
        ),
        AnchorViolation::UnsafeConstraintExpression => (
            "SOL-083".to_string(),
            "Anchor Safety".to_string(),
            "Unsafe Constraint Expression".to_string(),
        ),
        AnchorViolation::MissingBumpValidation => (
            "SOL-084".to_string(),
            "Cryptographic".to_string(),
            "Missing Bump Validation".to_string(),
        ),
        AnchorViolation::MissingSpaceCalculation => (
            "SOL-085".to_string(),
            "Anchor Safety".to_string(),
            "Missing Space Calculation".to_string(),
        ),
        AnchorViolation::MissingRentExemption => (
            "SOL-086".to_string(),
            "Account Safety".to_string(),
            "Missing Rent Exemption".to_string(),
        ),
        AnchorViolation::UncheckedAccountType => (
            "SOL-087".to_string(),
            "Type Safety".to_string(),
            "Unchecked Account Type".to_string(),
        ),
        // Overlap with existing detectors
        AnchorViolation::MissingSignerCheck => (
            "SOL-001".to_string(),
            "Access Control".to_string(),
            "Missing Signer Validation".to_string(),
        ),
        AnchorViolation::MissingOwnerCheck => (
            "SOL-012".to_string(),
            "Access Control".to_string(),
            "Missing Owner Validation".to_string(),
        ),
        AnchorViolation::MissingPDAValidation => (
            "SOL-073".to_string(),
            "Cryptographic".to_string(),
            "Missing PDA Validation".to_string(),
        ),
        AnchorViolation::MissingCPIGuard => (
            "SOL-017".to_string(),
            "Access Control".to_string(),
            "Missing CPI Guard".to_string(),
        ),
        AnchorViolation::ReinitializationVulnerability => (
            "SOL-074".to_string(),
            "Account Safety".to_string(),
            "Reinitialization Vulnerability".to_string(),
        ),
        AnchorViolation::MissingCloseGuard => (
            "SOL-070".to_string(),
            "Account Safety".to_string(),
            "Missing Close Guard".to_string(),
        ),
    };

    let function_name = match (&f.struct_name, &f.field_name) {
        (Some(s), Some(field)) => format!("{}::{}", s, field),
        (Some(s), None) => s.clone(),
        (None, Some(field)) => field.clone(),
        (None, None) => "unknown".to_string(),
    };

    VulnerabilityFinding {
        category,
        vuln_type,
        severity,
        severity_label,
        id,
        cwe: Some(f.cwe),
        location: f.file_path,
        function_name,
        line_number: f.line_number,
        vulnerable_code: f.code_snippet,
        description: format!("{} {}", f.description, f.risk_explanation),
        attack_scenario: String::new(),
        real_world_incident: None,
        secure_fix: f.fix_recommendation,
        prevention: f.anchor_pattern,
        confidence: 50,
    }
}

// ─── TaintFlow → VulnerabilityFinding ────────────────────────────────────────

/// Convert a taint-analyzer TaintFlow into the standard VulnerabilityFinding format.
///
/// Taint flows track untrusted data from sources (instruction input, unchecked
/// accounts) to security-sensitive sinks (transfers, CPI, state writes).
pub fn taint_flow_to_vulnerability(flow: taint_analyzer::TaintFlow) -> VulnerabilityFinding {
    let (severity, severity_label) = match flow.severity {
        taint_analyzer::TaintSeverity::Critical => (5, "Critical".to_string()),
        taint_analyzer::TaintSeverity::High     => (4, "High".to_string()),
        taint_analyzer::TaintSeverity::Medium   => (3, "Medium".to_string()),
        taint_analyzer::TaintSeverity::Low      => (2, "Low".to_string()),
    };

    let path_str = flow.path.join(" → ");
    let location = flow.path.first().cloned().unwrap_or_default();

    VulnerabilityFinding {
        category: "Taint Analysis".to_string(),
        vuln_type: format!("Tainted Data Flow: {:?} → {:?}", flow.source, flow.sink),
        severity,
        severity_label,
        id: "SOL-092".to_string(),
        cwe: Some("CWE-20".to_string()),
        location,
        function_name: String::new(),
        line_number: 0,
        vulnerable_code: path_str,
        description: flow.description,
        attack_scenario: String::new(),
        real_world_incident: None,
        secure_fix: flow.recommendation,
        prevention: String::new(),
        confidence: 45,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_taint_severity_mapping() {
        let flow = taint_analyzer::TaintFlow {
            source: taint_analyzer::TaintSource::InstructionData { param_name: "amount".into() },
            sink: taint_analyzer::TaintSink::StateWrite { field: "balance".into(), location: "vault".into() },
            path: vec!["a".to_string(), "b".to_string()],
            severity: taint_analyzer::TaintSeverity::High,
            description: "test".to_string(),
            recommendation: "fix".to_string(),
        };
        let finding = taint_flow_to_vulnerability(flow);
        assert_eq!(finding.severity, 4);
        assert_eq!(finding.id, "SOL-092");
    }
}
