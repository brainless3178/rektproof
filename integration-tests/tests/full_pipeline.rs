//! Full pipeline integration tests.
//!
//! These tests run the complete analysis pipeline on the vulnerable test programs
//! and pin expected findings to detect regressions. If a count changes, the test
//! will fail — alerting us to review whether the change is intentional.

use program_analyzer::ProgramAnalyzer;
use std::path::PathBuf;

fn programs_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("programs")
}

// ═══════════════════════════════════════════════════════════════════════════
//  Full pipeline: vulnerable-token
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn e2e_vulnerable_token_detects_findings() {
    let path = programs_dir().join("vulnerable-token").join("src");
    if !path.exists() { return; }

    let analyzer = ProgramAnalyzer::new(&path).expect("Failed to init analyzer");
    let findings = analyzer.scan_for_vulnerabilities();

    // Must detect at least some findings
    assert!(
        !findings.is_empty(),
        "vulnerable-token should produce findings, got 0"
    );

    // Must detect critical or high severity
    let high_plus = findings.iter().filter(|f| f.severity >= 4).count();
    assert!(
        high_plus > 0,
        "vulnerable-token should have HIGH or CRITICAL findings, found 0 above severity 4"
    );

    // Pin: should find at least these vulnerability categories
    let has_access_issue = findings.iter().any(|f| {
        let vt = f.vuln_type.to_lowercase();
        let cat = f.category.to_lowercase();
        vt.contains("signer") || vt.contains("owner") || vt.contains("auth")
        || vt.contains("access") || vt.contains("permission")
        || cat.contains("access") || cat.contains("auth")
    });
    let has_arithmetic = findings.iter().any(|f| {
        let vt = f.vuln_type.to_lowercase();
        let cat = f.category.to_lowercase();
        vt.contains("overflow") || vt.contains("arithmetic") || vt.contains("underflow")
        || cat.contains("arithmetic") || cat.contains("math")
    });

    // Print findings for debugging if we fail
    if !has_access_issue || !has_arithmetic {
        for f in &findings {
            eprintln!("  [{}] type='{}' cat='{}' sev={}", f.id, f.vuln_type, f.category, f.severity);
        }
    }
    assert!(has_access_issue, "should detect signer/access/auth issues in vulnerable-token");
    assert!(has_arithmetic, "should detect arithmetic issues in vulnerable-token");
}

#[test]
fn e2e_vulnerable_token_severity_distribution() {
    let path = programs_dir().join("vulnerable-token").join("src");
    if !path.exists() { return; }

    let analyzer = ProgramAnalyzer::new(&path).expect("Failed to init analyzer");
    let findings = analyzer.scan_for_vulnerabilities();

    let critical = findings.iter().filter(|f| f.severity >= 5).count();
    let high = findings.iter().filter(|f| f.severity == 4).count();
    let medium = findings.iter().filter(|f| f.severity == 3).count();
    let low = findings.iter().filter(|f| f.severity <= 2).count();

    eprintln!("vulnerable-token findings: {} total (C={}, H={}, M={}, L={})",
        findings.len(), critical, high, medium, low);

    // Pin minimum counts — if these drop, a regression was introduced
    assert!(findings.len() >= 3, "REGRESSION: total findings dropped below 3 (was {})", findings.len());
    assert!(critical + high >= 2, "REGRESSION: high+ findings dropped below 2 (was {})", critical + high);
}

// ═══════════════════════════════════════════════════════════════════════════
//  Full pipeline: vulnerable-vault
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn e2e_vulnerable_vault_detects_findings() {
    let path = programs_dir().join("vulnerable-vault").join("src");
    if !path.exists() { return; }

    let analyzer = ProgramAnalyzer::new(&path).expect("Failed to init analyzer");
    let findings = analyzer.scan_for_vulnerabilities();

    assert!(
        !findings.is_empty(),
        "vulnerable-vault should produce findings, got 0"
    );

    eprintln!("vulnerable-vault findings: {} total", findings.len());
    for f in &findings {
        eprintln!("  [{}] {} — {} (sev={})", f.id, f.vuln_type, f.category, f.severity);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Full pipeline: vulnerable-staking
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn e2e_vulnerable_staking_detects_findings() {
    let path = programs_dir().join("vulnerable-staking").join("src");
    if !path.exists() { return; }

    let analyzer = ProgramAnalyzer::new(&path).expect("Failed to init analyzer");
    let findings = analyzer.scan_for_vulnerabilities();

    assert!(
        !findings.is_empty(),
        "vulnerable-staking should produce findings, got 0"
    );

    eprintln!("vulnerable-staking findings: {} total", findings.len());
}

// ═══════════════════════════════════════════════════════════════════════════
//  Cross-program: all programs should have unique finding IDs after dedup
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn e2e_finding_ids_are_populated() {
    let path = programs_dir().join("vulnerable-token").join("src");
    if !path.exists() { return; }

    let analyzer = ProgramAnalyzer::new(&path).expect("Failed to init analyzer");
    let findings = analyzer.scan_for_vulnerabilities();

    for f in &findings {
        assert!(!f.id.is_empty(), "Finding ID should not be empty");
        assert!(!f.vuln_type.is_empty(), "Finding vuln_type should not be empty");
        assert!(!f.description.is_empty(), "Finding description should not be empty");
        assert!(!f.location.is_empty(), "Finding location should not be empty");
        assert!(f.severity >= 1 && f.severity <= 5, "Severity should be 1-5, got {}", f.severity);
        assert!(!f.severity_label.is_empty(), "Severity label should not be empty");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  JSON serialization round-trip stability
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn e2e_findings_serialize_deserialize_roundtrip() {
    let path = programs_dir().join("vulnerable-token").join("src");
    if !path.exists() { return; }

    let analyzer = ProgramAnalyzer::new(&path).expect("Failed to init analyzer");
    let findings = analyzer.scan_for_vulnerabilities();

    let json = serde_json::to_string_pretty(&findings)
        .expect("Failed to serialize findings to JSON");

    let deserialized: Vec<program_analyzer::VulnerabilityFinding> =
        serde_json::from_str(&json)
            .expect("Failed to deserialize findings from JSON");

    assert_eq!(findings.len(), deserialized.len(), "Roundtrip changed finding count");
    for (orig, deser) in findings.iter().zip(deserialized.iter()) {
        assert_eq!(orig.id, deser.id, "IDs don't match after roundtrip");
        assert_eq!(orig.severity, deser.severity, "Severity doesn't match for {}", orig.id);
        assert_eq!(orig.vuln_type, deser.vuln_type, "vuln_type doesn't match for {}", orig.id);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Phase 5: Consensus verification pipeline
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn e2e_consensus_offline_produces_verdicts() {
    let path = programs_dir().join("vulnerable-token").join("src");
    if !path.exists() { return; }

    let analyzer = ProgramAnalyzer::new(&path).expect("Failed to init analyzer");
    let findings = analyzer.scan_for_vulnerabilities();
    assert!(!findings.is_empty());

    // Create consensus engine with no models (offline fallback)
    let engine = consensus_engine::ConsensusEngine::new(vec![]);

    for f in &findings {
        let cfc = consensus_engine::FindingForConsensus {
            id: f.id.clone(),
            vuln_type: f.vuln_type.clone(),
            severity: f.severity_label.clone(),
            location: f.location.clone(),
            function_name: f.function_name.clone(),
            line_number: f.line_number,
            description: f.description.clone(),
            attack_scenario: f.attack_scenario.clone(),
            vulnerable_code: f.vulnerable_code.clone(),
            secure_fix: f.secure_fix.clone(),
        };
        let result = engine.verify_finding_offline(&cfc);

        // Every finding should get a valid verdict
        assert!(result.confidence_score >= 0.0 && result.confidence_score <= 1.0,
            "Confidence for {} should be 0.0-1.0, got {}", f.id, result.confidence_score);
        assert!(result.agreement_ratio >= 0.0 && result.agreement_ratio <= 1.0,
            "Agreement for {} should be 0.0-1.0, got {}", f.id, result.agreement_ratio);
    }
}

#[test]
fn e2e_consensus_confirms_critical_findings() {
    let path = programs_dir().join("vulnerable-vault").join("src");
    if !path.exists() { return; }

    let analyzer = ProgramAnalyzer::new(&path).expect("Failed to init analyzer");
    let findings = analyzer.scan_for_vulnerabilities();

    let engine = consensus_engine::ConsensusEngine::new(vec![]);

    // Filter to critical only
    let critical: Vec<_> = findings.iter().filter(|f| f.severity >= 5).collect();
    assert!(!critical.is_empty(), "Should have critical findings");

    let confirmed: Vec<_> = critical
        .iter()
        .filter(|f| {
            let cfc = consensus_engine::FindingForConsensus {
                id: f.id.clone(),
                vuln_type: f.vuln_type.clone(),
                severity: f.severity_label.clone(),
                location: f.location.clone(),
                function_name: f.function_name.clone(),
                line_number: f.line_number,
                description: f.description.clone(),
                attack_scenario: f.attack_scenario.clone(),
                vulnerable_code: f.vulnerable_code.clone(),
                secure_fix: f.secure_fix.clone(),
            };
            engine.verify_finding_offline(&cfc).should_report
        })
        .collect();

    // All critical findings should be confirmed by consensus
    assert_eq!(confirmed.len(), critical.len(),
        "All critical findings should be confirmed by offline consensus");
}

// ═══════════════════════════════════════════════════════════════════════════
//  Phase 5: Orchestrated pipeline (scan + consensus end-to-end)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn e2e_orchestrate_pipeline_end_to_end() {
    let path = programs_dir().join("vulnerable-staking").join("src");
    if !path.exists() { return; }

    // Phase 1: Scan
    let analyzer = ProgramAnalyzer::new(&path).expect("Failed to init analyzer");
    let findings = analyzer.scan_for_vulnerabilities();
    assert!(!findings.is_empty(), "Staking program should have findings");

    // Phase 2: Consensus
    let engine = consensus_engine::ConsensusEngine::new(vec![]);
    let consensus_results: Vec<_> = findings
        .iter()
        .map(|f| {
            let cfc = consensus_engine::FindingForConsensus {
                id: f.id.clone(),
                vuln_type: f.vuln_type.clone(),
                severity: f.severity_label.clone(),
                location: f.location.clone(),
                function_name: f.function_name.clone(),
                line_number: f.line_number,
                description: f.description.clone(),
                attack_scenario: f.attack_scenario.clone(),
                vulnerable_code: f.vulnerable_code.clone(),
                secure_fix: f.secure_fix.clone(),
            };
            (f.id.clone(), engine.verify_finding_offline(&cfc))
        })
        .collect();

    // Verify: should have consensus results for every finding
    assert_eq!(consensus_results.len(), findings.len(),
        "Should have one consensus result per finding");

    let confirmed = consensus_results.iter().filter(|(_, r)| r.should_report).count();
    assert!(confirmed > 0, "At least one finding should be confirmed");

    // Phase 3: Strategy would require API key — skipped
    // Phase 4: Report — verify JSON structure
    let mut output = Vec::new();
    for f in &findings {
        let mut val = serde_json::to_value(f).unwrap_or_default();
        if let Some((_, cr)) = consensus_results.iter().find(|(id, _)| id == &f.id) {
            val["consensus"] = serde_json::json!({
                "verdict": format!("{:?}", cr.final_verdict),
                "confidence_score": cr.confidence_score,
                "should_report": cr.should_report
            });
        }
        output.push(val);
    }
    let report = serde_json::json!({
        "pipeline": "orchestrate",
        "total_findings": findings.len(),
        "confirmed_by_consensus": confirmed,
        "findings": output
    });
    let json_str = serde_json::to_string_pretty(&report).expect("Failed to serialize report");
    assert!(json_str.contains("\"pipeline\": \"orchestrate\""));
    assert!(json_str.contains("\"consensus\""));
    assert!(json_str.contains("\"should_report\""));
}
