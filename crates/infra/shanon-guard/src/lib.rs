//! # Shanon Guard — Solana Dependency Firewall
//!
//! Detects malicious, typosquatted, and vulnerable packages in Solana projects.
//!
//! ## What it checks
//!
//! | Layer        | Detail                                                |
//! |--------------|-------------------------------------------------------|
//! | **Advisory** | Known malicious packages (e.g., @solana/web3.js 1.95.6-7 backdoor) |
//! | **Typosquat**| Levenshtein distance against 70+ legitimate Solana packages |
//! | **Behavioral** | Runtime key exfiltration, clipboard hijacking, obfuscation |
//! | **Source**   | Suspicious git/path dependencies, untrusted origins     |
//!
//! ## Usage
//!
//! ```rust,no_run
//! use shanon_guard::GuardScanner;
//! use std::path::Path;
//!
//! let scanner = GuardScanner::new();
//! let report = scanner.scan_directory(Path::new("./my-solana-project"));
//! report.print_colored();
//! if report.has_critical() {
//!     std::process::exit(1);
//! }
//! ```

pub mod advisory_db;
pub mod behavioral;
pub mod cargo_scanner;
pub mod npm_scanner;
pub mod report;
pub mod typosquat;

use advisory_db::AdvisoryDatabase;
use serde::{Deserialize, Serialize};
use std::path::Path;
use walkdir::WalkDir;

/// Severity levels aligned with the rest of the Shanon platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GuardSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl GuardSeverity {
    pub fn score(&self) -> u8 {
        match self {
            Self::Critical => 25,
            Self::High => 15,
            Self::Medium => 5,
            Self::Low => 2,
        }
    }
}

/// What kind of supply chain issue was found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingCategory {
    /// Package is in the known-malicious advisory database.
    KnownMalicious,
    /// Package name is suspiciously similar to a legitimate one.
    Typosquat,
    /// Behavioral analysis found suspicious runtime patterns.
    SuspiciousBehavior,
    /// Package source (git URL, path) looks suspicious.
    SuspiciousSource,
    /// Package has a known security vulnerability (not malicious).
    KnownVulnerability,
    /// Package is deprecated or unmaintained.
    Deprecated,
}

/// A single finding from the guard scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardFinding {
    /// Package name (e.g., "@solana/web3.js" or "solana-sdk").
    pub package_name: String,
    /// Installed version.
    pub version: String,
    /// "npm" or "cargo".
    pub ecosystem: String,
    /// Severity of the finding.
    pub severity: GuardSeverity,
    /// What type of issue was found.
    pub category: FindingCategory,
    /// Short title of the finding.
    pub title: String,
    /// Detailed description.
    pub description: String,
    /// How to fix it.
    pub remediation: String,
    /// Optional CVE/advisory reference.
    pub reference: Option<String>,
    /// Which file triggered this finding.
    pub source_file: String,
}

/// Full scan report from `shanon guard`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardReport {
    /// Findings from Cargo.toml / Cargo.lock scanning.
    pub cargo_findings: Vec<GuardFinding>,
    /// Findings from package.json scanning.
    pub npm_findings: Vec<GuardFinding>,
    /// Findings from behavioral analysis of node_modules.
    pub behavioral_findings: Vec<GuardFinding>,
    /// Overall risk score (0-100): 0 = clean, 100 = critical supply chain risk.
    pub risk_score: u8,
    /// Number of Cargo.toml files scanned.
    pub cargo_files_scanned: usize,
    /// Number of package.json files scanned.
    pub npm_files_scanned: usize,
}

impl GuardReport {
    /// Returns true if no findings at all.
    pub fn is_clean(&self) -> bool {
        self.cargo_findings.is_empty()
            && self.npm_findings.is_empty()
            && self.behavioral_findings.is_empty()
    }

    /// Returns true if any critical finding exists.
    pub fn has_critical(&self) -> bool {
        self.all_findings()
            .any(|f| f.severity == GuardSeverity::Critical)
    }

    /// Returns true if any high or critical finding exists.
    pub fn has_high_or_above(&self) -> bool {
        self.all_findings()
            .any(|f| f.severity >= GuardSeverity::High)
    }

    /// Iterator over all findings.
    pub fn all_findings(&self) -> impl Iterator<Item = &GuardFinding> {
        self.cargo_findings
            .iter()
            .chain(self.npm_findings.iter())
            .chain(self.behavioral_findings.iter())
    }

    /// Total number of findings.
    pub fn total_findings(&self) -> usize {
        self.cargo_findings.len() + self.npm_findings.len() + self.behavioral_findings.len()
    }
}

impl Default for GuardReport {
    fn default() -> Self {
        Self {
            cargo_findings: Vec::new(),
            npm_findings: Vec::new(),
            behavioral_findings: Vec::new(),
            risk_score: 0,
            cargo_files_scanned: 0,
            npm_files_scanned: 0,
        }
    }
}

/// The main scanner that orchestrates all checks.
pub struct GuardScanner {
    advisory_db: AdvisoryDatabase,
}

impl Default for GuardScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl GuardScanner {
    /// Create a new scanner with the full advisory database loaded.
    pub fn new() -> Self {
        Self {
            advisory_db: AdvisoryDatabase::new(),
        }
    }

    /// Scan a directory (and its subdirectories) for supply chain risks.
    ///
    /// This walks the directory tree looking for:
    /// - `Cargo.toml` files → scanned by `cargo_scanner`
    /// - `package.json` files → scanned by `npm_scanner`
    /// - `node_modules/` directories → scanned by `behavioral` analyzer
    pub fn scan_directory(&self, path: &Path) -> GuardReport {
        let mut report = GuardReport::default();

        // Walk the directory tree (max depth 6 to avoid going too deep)
        for entry in WalkDir::new(path)
            .max_depth(6)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let entry_path = entry.path();
            let file_name = entry
                .file_name()
                .to_str()
                .unwrap_or("");

            // Skip .git, target, node_modules (we scan node_modules separately)
            if entry_path.is_dir() {
                let dir_name = file_name;
                if dir_name == ".git" || dir_name == "target" || dir_name == ".cargo" {
                    continue;
                }
            }

            if !entry_path.is_file() {
                continue;
            }

            match file_name {
                "Cargo.toml" => {
                    let findings =
                        cargo_scanner::scan_cargo_toml(entry_path, &self.advisory_db);
                    report.cargo_findings.extend(findings);
                    report.cargo_files_scanned += 1;
                }
                "package.json" => {
                    // Skip node_modules/*/package.json — only scan project-level
                    let path_str = entry_path.to_string_lossy();
                    if path_str.contains("node_modules/") {
                        continue;
                    }
                    let findings =
                        npm_scanner::scan_package_json(entry_path, &self.advisory_db);
                    report.npm_findings.extend(findings);
                    report.npm_files_scanned += 1;
                }
                _ => {}
            }
        }

        // Run behavioral analysis on node_modules if present
        let node_modules = path.join("node_modules");
        if node_modules.exists() {
            report.behavioral_findings = behavioral::scan_behavioral(path);
        }

        // Calculate risk score
        report.risk_score = self.calculate_risk_score(&report);

        report
    }

    /// Scan a single Cargo.toml file.
    pub fn scan_cargo_toml(&self, path: &Path) -> Vec<GuardFinding> {
        cargo_scanner::scan_cargo_toml(path, &self.advisory_db)
    }

    /// Scan a single package.json file.
    pub fn scan_package_json(&self, path: &Path) -> Vec<GuardFinding> {
        npm_scanner::scan_package_json(path, &self.advisory_db)
    }

    /// Calculate risk score from 0 (clean) to 100 (critical supply chain risk).
    fn calculate_risk_score(&self, report: &GuardReport) -> u8 {
        let mut score: u32 = 0;

        for finding in report.all_findings() {
            score += finding.severity.score() as u32;

            // Bonus penalty for known malicious packages
            if finding.category == FindingCategory::KnownMalicious
                && finding.severity == GuardSeverity::Critical
            {
                score += 25; // Double penalty for confirmed malware
            }
        }

        std::cmp::min(score, 100) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_scanner_creation() {
        let scanner = GuardScanner::new();
        assert!(!scanner.advisory_db.advisories.is_empty());
    }

    #[test]
    fn test_empty_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let scanner = GuardScanner::new();
        let report = scanner.scan_directory(tmp.path());
        assert!(report.is_clean());
        assert_eq!(report.risk_score, 0);
    }

    #[test]
    fn test_clean_cargo_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let cargo_path = tmp.path().join("Cargo.toml");
        let mut f = std::fs::File::create(&cargo_path).unwrap();
        write!(
            f,
            r#"[package]
name = "my-program"
version = "0.1.0"
edition = "2021"

[dependencies]
solana-sdk = "1.18"
anchor-lang = "0.30"
"#
        )
        .unwrap();

        let scanner = GuardScanner::new();
        let report = scanner.scan_directory(tmp.path());
        assert!(report.is_clean());
    }

    #[test]
    fn test_malicious_npm_package() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_path = tmp.path().join("package.json");
        let mut f = std::fs::File::create(&pkg_path).unwrap();
        write!(
            f,
            r#"{{
    "name": "test",
    "dependencies": {{
        "@solana/web3.js": "1.95.6"
    }}
}}"#
        )
        .unwrap();

        let scanner = GuardScanner::new();
        let report = scanner.scan_directory(tmp.path());
        assert!(!report.is_clean());
        assert!(report.has_critical());
        assert!(report.risk_score > 0);
    }

    #[test]
    fn test_risk_score_calculation() {
        let scanner = GuardScanner::new();
        let report = GuardReport {
            cargo_findings: vec![GuardFinding {
                package_name: "test".into(),
                version: "1.0".into(),
                ecosystem: "cargo".into(),
                severity: GuardSeverity::Critical,
                category: FindingCategory::KnownMalicious,
                title: "test".into(),
                description: "test".into(),
                remediation: "test".into(),
                reference: None,
                source_file: "Cargo.toml".into(),
            }],
            npm_findings: vec![],
            behavioral_findings: vec![],
            risk_score: 0,
            cargo_files_scanned: 1,
            npm_files_scanned: 0,
        };
        // Critical (25) + KnownMalicious bonus (25) = 50
        assert_eq!(scanner.calculate_risk_score(&report), 50);
    }
}
