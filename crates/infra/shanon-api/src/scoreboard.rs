//! Shanon Security Scoreboard — Protocol scoring and ranking
//!
//! Scores Solana protocols (0-100) based on:
//! - Static analysis findings (72 detectors)
//! - Upgrade authority status (immutable > multisig > single wallet)
//! - Source verification status
//! - Dependency security (shanon-guard)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ─── Data Types ─────────────────────────────────────────────────────────────

/// Security score for a Solana protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolScore {
    pub program_id: String,
    pub name: String,
    pub score: u8,
    pub grade: String,
    pub source_verified: bool,
    pub upgrade_authority: AuthorityStatus,
    pub findings: FindingSummary,
    pub guard_risk: u8,
    pub last_scanned: DateTime<Utc>,
    pub badge_url: String,
}

/// Upgrade authority classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuthorityStatus {
    /// Program is immutable — cannot be upgraded
    Immutable,
    /// Multisig authority (threshold, total) e.g. 3-of-5
    Multisig(u8, u8),
    /// Single wallet controls upgrades — risky
    SingleWallet,
    /// Cannot determine authority status
    Unknown,
}

impl AuthorityStatus {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Immutable => "Immutable",
            Self::Multisig(_, _) => "Multisig",
            Self::SingleWallet => "Single Wallet",
            Self::Unknown => "Unknown",
        }
    }

    pub fn risk_label(&self) -> &'static str {
        match self {
            Self::Immutable => "✅ Low Risk",
            Self::Multisig(_, _) => "🟡 Moderate",
            Self::SingleWallet => "🟠 Elevated",
            Self::Unknown => "🔴 High Risk",
        }
    }
}

/// Summary of vulnerability findings
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FindingSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total: usize,
}

/// Request to score a protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreRequest {
    pub program_id: String,
    pub name: Option<String>,
    pub repo_url: Option<String>,
}

/// Scoreboard list entry (lightweight for list view)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreboardEntry {
    pub rank: usize,
    pub program_id: String,
    pub name: String,
    pub score: u8,
    pub grade: String,
    pub authority: String,
    pub findings_total: usize,
    pub critical_count: usize,
    pub source_verified: bool,
}

// ─── Scoring Algorithm ──────────────────────────────────────────────────────

/// Calculate a protocol's security score (0-100).
///
/// Scoring breakdown:
/// - Base score: 100
/// - Critical finding:  -25 each
/// - High finding:      -15 each
/// - Medium finding:     -5 each
/// - Low finding:        -2 each
/// - Unverified source: -15
/// - Single wallet authority: -20
/// - Unknown authority: -25
/// - Guard supply chain risk: -(risk_score / 4)
pub fn calculate_protocol_score(
    findings: &FindingSummary,
    authority: &AuthorityStatus,
    source_verified: bool,
    guard_risk: u8,
) -> u8 {
    let mut score: i32 = 100;

    // Vulnerability deductions
    score -= (findings.critical as i32) * 25;
    score -= (findings.high as i32) * 15;
    score -= (findings.medium as i32) * 5;
    score -= (findings.low as i32) * 2;

    // Source verification
    if !source_verified {
        score -= 15;
    }

    // Authority status
    match authority {
        AuthorityStatus::SingleWallet => score -= 20,
        AuthorityStatus::Unknown => score -= 25,
        AuthorityStatus::Multisig(threshold, total) => {
            // Deduct more for low threshold ratios
            if *total > 0 && (*threshold as f32 / *total as f32) < 0.5 {
                score -= 10;
            }
        }
        AuthorityStatus::Immutable => {} // No deduction
    }

    // Supply chain risk from shanon-guard
    score -= (guard_risk as i32) / 4;

    score.max(0).min(100) as u8
}

/// Convert score to letter grade
pub fn score_to_grade(score: u8) -> String {
    match score {
        95..=100 => "A+".to_string(),
        90..=94 => "A".to_string(),
        85..=89 => "A-".to_string(),
        80..=84 => "B+".to_string(),
        75..=79 => "B".to_string(),
        70..=74 => "B-".to_string(),
        65..=69 => "C+".to_string(),
        60..=64 => "C".to_string(),
        50..=59 => "D".to_string(),
        _ => "F".to_string(),
    }
}

/// Build a FindingSummary from raw vulnerability findings
pub fn summarize_findings(findings: &[program_analyzer::VulnerabilityFinding]) -> FindingSummary {
    let mut summary = FindingSummary::default();
    for f in findings {
        match f.severity_label.to_uppercase().as_str() {
            "CRITICAL" => summary.critical += 1,
            "HIGH" => summary.high += 1,
            "MEDIUM" => summary.medium += 1,
            "LOW" => summary.low += 1,
            _ => summary.info += 1,
        }
    }
    summary.total = summary.critical + summary.high + summary.medium + summary.low + summary.info;
    summary
}

// ─── In-Memory Scoreboard Store ─────────────────────────────────────────────

use std::collections::HashMap;
use std::sync::RwLock;

/// Thread-safe in-memory scoreboard store
pub struct ScoreboardStore {
    scores: RwLock<HashMap<String, ProtocolScore>>,
}

impl ScoreboardStore {
    pub fn new() -> Self {
        Self {
            scores: RwLock::new(HashMap::new()),
        }
    }

    /// Insert or update a protocol score
    pub fn upsert(&self, score: ProtocolScore) {
        if let Ok(mut map) = self.scores.write() {
            map.insert(score.program_id.clone(), score);
        }
    }

    /// Get a specific protocol's score
    pub fn get(&self, program_id: &str) -> Option<ProtocolScore> {
        let map = self.scores.read().ok()?;
        map.get(program_id).cloned()
    }

    /// Get all scores sorted by rank (highest score first)
    pub fn ranked_list(&self) -> Vec<ScoreboardEntry> {
        let map = match self.scores.read() {
            Ok(m) => m,
            Err(_) => return Vec::new(),
        };
        let mut entries: Vec<_> = map
            .values()
            .map(|s| ScoreboardEntry {
                rank: 0, // assigned after sort
                program_id: s.program_id.clone(),
                name: s.name.clone(),
                score: s.score,
                grade: s.grade.clone(),
                authority: s.upgrade_authority.label().to_string(),
                findings_total: s.findings.total,
                critical_count: s.findings.critical,
                source_verified: s.source_verified,
            })
            .collect();

        entries.sort_by(|a, b| b.score.cmp(&a.score));
        for (i, entry) in entries.iter_mut().enumerate() {
            entry.rank = i + 1;
        }
        entries
    }

    pub fn count(&self) -> usize {
        self.scores.read().map(|m| m.len()).unwrap_or(0)
    }
}

impl Default for ScoreboardStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_perfect_score() {
        let findings = FindingSummary::default();
        let score = calculate_protocol_score(
            &findings,
            &AuthorityStatus::Immutable,
            true,
            0,
        );
        assert_eq!(score, 100);
    }

    #[test]
    fn test_critical_deduction() {
        let findings = FindingSummary { critical: 2, ..Default::default() };
        let score = calculate_protocol_score(
            &findings,
            &AuthorityStatus::Immutable,
            true,
            0,
        );
        assert_eq!(score, 50);
    }

    #[test]
    fn test_unverified_source() {
        let findings = FindingSummary::default();
        let score = calculate_protocol_score(
            &findings,
            &AuthorityStatus::Immutable,
            false,
            0,
        );
        assert_eq!(score, 85);
    }

    #[test]
    fn test_single_wallet_authority() {
        let findings = FindingSummary::default();
        let score = calculate_protocol_score(
            &findings,
            &AuthorityStatus::SingleWallet,
            true,
            0,
        );
        assert_eq!(score, 80);
    }

    #[test]
    fn test_unknown_authority() {
        let findings = FindingSummary::default();
        let score = calculate_protocol_score(
            &findings,
            &AuthorityStatus::Unknown,
            false,
            0,
        );
        // -25 (unknown) -15 (unverified) = 60
        assert_eq!(score, 60);
    }

    #[test]
    fn test_floor_at_zero() {
        let findings = FindingSummary { critical: 10, ..Default::default() };
        let score = calculate_protocol_score(
            &findings,
            &AuthorityStatus::Unknown,
            false,
            100,
        );
        assert_eq!(score, 0);
    }

    #[test]
    fn test_grades() {
        assert_eq!(score_to_grade(100), "A+");
        assert_eq!(score_to_grade(92), "A");
        assert_eq!(score_to_grade(75), "B");
        assert_eq!(score_to_grade(55), "D");
        assert_eq!(score_to_grade(30), "F");
    }

    #[test]
    fn test_store_operations() {
        let store = ScoreboardStore::new();
        store.upsert(ProtocolScore {
            program_id: "test123".to_string(),
            name: "Test Protocol".to_string(),
            score: 85,
            grade: "A-".to_string(),
            source_verified: true,
            upgrade_authority: AuthorityStatus::Immutable,
            findings: FindingSummary::default(),
            guard_risk: 0,
            last_scanned: Utc::now(),
            badge_url: String::new(),
        });

        assert_eq!(store.count(), 1);
        let fetched = store.get("test123").unwrap();
        assert_eq!(fetched.score, 85);

        let ranked = store.ranked_list();
        assert_eq!(ranked[0].rank, 1);
    }

    #[test]
    fn test_guard_risk_deduction() {
        let findings = FindingSummary::default();
        let score = calculate_protocol_score(
            &findings,
            &AuthorityStatus::Immutable,
            true,
            40,
        );
        // 100 - (40/4) = 90
        assert_eq!(score, 90);
    }
}
