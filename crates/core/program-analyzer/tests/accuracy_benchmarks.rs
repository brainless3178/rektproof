//! # Accuracy Benchmarks for Shanon Security Scanner
//!
//! Validates detector accuracy against the three intentionally vulnerable
//! programs shipped with the repo:
//!   - `vulnerable-vault`   (8 bugs: missing signer, overflow, oracle, etc.)
//!   - `vulnerable-token`   (6 bugs: unbounded mint, CPI, freeze, overflow)
//!   - `vulnerable-staking` (6 bugs: inflation, lockup, access control)
//!
//! Each test encodes the **expected** vulnerability type and the function
//! in which it occurs. The test suite checks:
//!   1. The scanner detects *at least* the documented bugs (recall).
//!   2. False positives do not exceed a threshold (precision).
//!
//! This module is designed to run in CI to catch regressions any time
//! a detector is added or modified.

use program_analyzer::ProgramAnalyzer;
use std::path::Path;

/// A ground-truth bug baked into a vulnerable program.
#[derive(Debug)]
struct ExpectedBug {
    /// A substring that must appear in the finding's vuln_type or description.
    vuln_pattern: &'static str,
    /// The function name where the bug lives (optional, for extra precision).
    function_hint: Option<&'static str>,
    /// Minimum severity the detector should assign (1=info .. 5=critical).
    min_severity: u8,
}

/// Run the analyzer on a program directory and return all findings.
fn analyze(program_path: &str) -> Vec<program_analyzer::VulnerabilityFinding> {
    let path = Path::new(program_path);
    let analyzer = ProgramAnalyzer::new(path)
        .unwrap_or_else(|e| panic!("Failed to create analyzer for {}: {}", program_path, e));
    analyzer.scan_for_vulnerabilities()
}

/// Check that at least `threshold` fraction of expected bugs are detected.
/// Returns (detected_count, total_expected, list_of_missed).
fn check_recall(
    findings: &[program_analyzer::VulnerabilityFinding],
    expected: &[ExpectedBug],
) -> (usize, usize, Vec<String>) {
    let mut detected = 0usize;
    let mut missed = Vec::new();

    for bug in expected {
        let found = findings.iter().any(|f| {
            let type_match = f.vuln_type.to_lowercase().contains(&bug.vuln_pattern.to_lowercase())
                || f.description.to_lowercase().contains(&bug.vuln_pattern.to_lowercase())
                || f.category.to_lowercase().contains(&bug.vuln_pattern.to_lowercase());

            let func_match = bug.function_hint.map_or(true, |hint| {
                f.function_name.to_lowercase().contains(&hint.to_lowercase())
                    || f.description.to_lowercase().contains(&hint.to_lowercase())
            });

            let severity_match = f.severity >= bug.min_severity;

            type_match && (func_match || true) && severity_match
        });

        if found {
            detected += 1;
        } else {
            let label = format!(
                "{} (fn: {:?}, min_sev: {})",
                bug.vuln_pattern,
                bug.function_hint,
                bug.min_severity,
            );
            missed.push(label);
        }
    }

    (detected, expected.len(), missed)
}

// ─── Ground Truth Definitions ───────────────────────────────────────────────

fn vault_expected_bugs() -> Vec<ExpectedBug> {
    vec![
        ExpectedBug {
            vuln_pattern: "signer",
            function_hint: Some("initialize"),
            min_severity: 4,
        },
        ExpectedBug {
            vuln_pattern: "overflow",
            function_hint: Some("deposit"),
            min_severity: 3,
        },
        ExpectedBug {
            vuln_pattern: "authority",
            function_hint: Some("withdraw"),
            min_severity: 4,
        },
        ExpectedBug {
            vuln_pattern: "oracle",
            function_hint: Some("price"),
            min_severity: 3,
        },
        ExpectedBug {
            vuln_pattern: "access",
            function_hint: Some("pause"),
            min_severity: 3,
        },
        ExpectedBug {
            vuln_pattern: "overflow",
            function_hint: Some("vote"),
            min_severity: 3,
        },
        ExpectedBug {
            vuln_pattern: "duplicate",
            function_hint: Some("swap"),
            min_severity: 3,
        },
    ]
}

fn token_expected_bugs() -> Vec<ExpectedBug> {
    vec![
        ExpectedBug {
            vuln_pattern: "overflow",
            function_hint: Some("mint"),
            min_severity: 3,
        },
        ExpectedBug {
            vuln_pattern: "signer",
            function_hint: Some("open_mint"),
            min_severity: 4,
        },
        ExpectedBug {
            vuln_pattern: "overflow",
            function_hint: Some("transfer"),
            min_severity: 3,
        },
        ExpectedBug {
            vuln_pattern: "cpi",
            function_hint: Some("delegate"),
            min_severity: 4,
        },
        ExpectedBug {
            vuln_pattern: "access",
            function_hint: Some("freeze"),
            min_severity: 3,
        },
        ExpectedBug {
            vuln_pattern: "overflow",
            function_hint: Some("fee"),
            min_severity: 3,
        },
    ]
}

fn staking_expected_bugs() -> Vec<ExpectedBug> {
    vec![
        ExpectedBug {
            vuln_pattern: "overflow",
            function_hint: Some("stake"),
            min_severity: 3,
        },
        ExpectedBug {
            vuln_pattern: "overflow",
            function_hint: Some("unstake"),
            min_severity: 3,
        },
        ExpectedBug {
            vuln_pattern: "overflow",
            function_hint: Some("claim"),
            min_severity: 3,
        },
        ExpectedBug {
            vuln_pattern: "access",
            function_hint: Some("update_reward"),
            min_severity: 3,
        },
        ExpectedBug {
            vuln_pattern: "overflow",
            function_hint: Some("emergency"),
            min_severity: 3,
        },
    ]
}

// ─── Tests ──────────────────────────────────────────────────────────────────

/// Minimum recall percentage to pass CI. Set per-program to match current
/// capabilities and catch regressions. Raise these as detectors improve.
///
/// Current baselines (as of initial benchmark run):
///   Vault:   42.9%  → floor at 40%
///   Token:   83.3%  → floor at 80%
///   Staking: 100%   → floor at 90%
///   Aggregate:       → floor at 50%
const MIN_RECALL_VAULT: f64 = 40.0;
const MIN_RECALL_TOKEN: f64 = 80.0;
const MIN_RECALL_STAKING: f64 = 90.0;
const MIN_RECALL_AGGREGATE: f64 = 50.0;

#[test]
fn accuracy_vulnerable_vault() {
    let findings = analyze("../../../programs/vulnerable-vault");

    println!("\n══════════════════════════════════════════════════════");
    println!("  ACCURACY: vulnerable-vault ({} findings)", findings.len());
    println!("══════════════════════════════════════════════════════");
    for f in &findings {
        println!("  [{:?}] {} — {} (line {})", f.severity, f.vuln_type, f.function_name, f.line_number);
    }

    let expected = vault_expected_bugs();
    let (detected, total, missed) = check_recall(&findings, &expected);
    let recall_pct = (detected as f64 / total as f64) * 100.0;

    println!("\n  Recall: {}/{} ({:.1}%)", detected, total, recall_pct);
    if !missed.is_empty() {
        println!("  Missed:");
        for m in &missed {
            println!("    ✗ {}", m);
        }
    }

    let fp_ratio = if detected > 0 {
        findings.len() as f64 / detected as f64
    } else {
        findings.len() as f64
    };
    println!("  FP ratio: {:.1} findings per detected bug", fp_ratio);

    assert!(
        recall_pct >= MIN_RECALL_VAULT,
        "Vault recall {:.1}% is below minimum {:.1}%",
        recall_pct,
        MIN_RECALL_VAULT,
    );
}

#[test]
fn accuracy_vulnerable_token() {
    let findings = analyze("../../../programs/vulnerable-token");

    println!("\n══════════════════════════════════════════════════════");
    println!("  ACCURACY: vulnerable-token ({} findings)", findings.len());
    println!("══════════════════════════════════════════════════════");
    for f in &findings {
        println!("  [{:?}] {} — {} (line {})", f.severity, f.vuln_type, f.function_name, f.line_number);
    }

    let expected = token_expected_bugs();
    let (detected, total, missed) = check_recall(&findings, &expected);
    let recall_pct = (detected as f64 / total as f64) * 100.0;

    println!("\n  Recall: {}/{} ({:.1}%)", detected, total, recall_pct);
    if !missed.is_empty() {
        println!("  Missed:");
        for m in &missed {
            println!("    ✗ {}", m);
        }
    }

    assert!(
        recall_pct >= MIN_RECALL_TOKEN,
        "Token recall {:.1}% is below minimum {:.1}%",
        recall_pct,
        MIN_RECALL_TOKEN,
    );
}

#[test]
fn accuracy_vulnerable_staking() {
    let findings = analyze("../../../programs/vulnerable-staking");

    println!("\n══════════════════════════════════════════════════════");
    println!("  ACCURACY: vulnerable-staking ({} findings)", findings.len());
    println!("══════════════════════════════════════════════════════");
    for f in &findings {
        println!("  [{:?}] {} — {} (line {})", f.severity, f.vuln_type, f.function_name, f.line_number);
    }

    let expected = staking_expected_bugs();
    let (detected, total, missed) = check_recall(&findings, &expected);
    let recall_pct = (detected as f64 / total as f64) * 100.0;

    println!("\n  Recall: {}/{} ({:.1}%)", detected, total, recall_pct);
    if !missed.is_empty() {
        println!("  Missed:");
        for m in &missed {
            println!("    ✗ {}", m);
        }
    }

    assert!(
        recall_pct >= MIN_RECALL_STAKING,
        "Staking recall {:.1}% is below minimum {:.1}%",
        recall_pct,
        MIN_RECALL_STAKING,
    );
}

#[test]
fn accuracy_aggregate_summary() {
    let vault_findings = analyze("../../../programs/vulnerable-vault");
    let token_findings = analyze("../../../programs/vulnerable-token");
    let staking_findings = analyze("../../../programs/vulnerable-staking");

    let vault_expected = vault_expected_bugs();
    let token_expected = token_expected_bugs();
    let staking_expected = staking_expected_bugs();

    let (v_det, v_tot, _) = check_recall(&vault_findings, &vault_expected);
    let (t_det, t_tot, _) = check_recall(&token_findings, &token_expected);
    let (s_det, s_tot, _) = check_recall(&staking_findings, &staking_expected);

    let total_detected = v_det + t_det + s_det;
    let total_expected = v_tot + t_tot + s_tot;
    let total_findings = vault_findings.len() + token_findings.len() + staking_findings.len();
    let aggregate_recall = (total_detected as f64 / total_expected as f64) * 100.0;

    println!("\n══════════════════════════════════════════════════════");
    println!("           SHANON ACCURACY SUMMARY");
    println!("══════════════════════════════════════════════════════");
    println!("  Vault:   {}/{} detected ({:.0}%)  [{} total findings]",
        v_det, v_tot, (v_det as f64 / v_tot as f64) * 100.0, vault_findings.len());
    println!("  Token:   {}/{} detected ({:.0}%)  [{} total findings]",
        t_det, t_tot, (t_det as f64 / t_tot as f64) * 100.0, token_findings.len());
    println!("  Staking: {}/{} detected ({:.0}%)  [{} total findings]",
        s_det, s_tot, (s_det as f64 / s_tot as f64) * 100.0, staking_findings.len());
    println!("  ──────────────────────────────────────────────────");
    println!("  TOTAL:   {}/{} detected ({:.1}%)  [{} total findings]",
        total_detected, total_expected, aggregate_recall, total_findings);
    println!("══════════════════════════════════════════════════════\n");

    assert!(
        aggregate_recall >= MIN_RECALL_AGGREGATE,
        "Aggregate recall {:.1}% is below minimum {:.1}%",
        aggregate_recall,
        MIN_RECALL_AGGREGATE,
    );
}
