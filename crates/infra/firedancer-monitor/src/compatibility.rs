//! Firedancer Compatibility Checker
//!
//! Performs static analysis of Solana program source code to detect patterns
//! that may behave differently on the Firedancer validator implementation.

use crate::compute_budget::{self, ComputeBudgetAnalysis, ComputeBudgetRisk};
use crate::runtime_diff_db::{DiffSeverity, RuntimeDiffDatabase};
use crate::syscall_analyzer::{self, SyscallUsage};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A compatibility warning for a specific runtime difference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompatWarning {
    ComputeBudgetRisk {
        syscall: String,
        detail: String,
    },
    TransactionOrderingDependency {
        detail: String,
    },
    ClockResolutionAssumption {
        detail: String,
    },
    ConcurrentAccountAccess {
        accounts: Vec<String>,
    },
    SyscallMeteringDiff {
        syscall: String,
        cu_labs: u64,
        cu_firedancer: u64,
    },
    RuntimeDifference {
        diff_id: String,
        title: String,
        severity: String,
        detail: String,
        mitigation: String,
    },
}

/// Complete Firedancer compatibility report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatReport {
    /// Compatibility score: 100 = fully compatible, 0 = many issues
    pub score: u8,
    /// Letter grade
    pub grade: String,
    /// Detected warnings
    pub warnings: Vec<CompatWarning>,
    /// Patterns detected that are known-safe on Firedancer
    pub safe_patterns: Vec<String>,
    /// Syscall usage details
    pub syscall_usages: Vec<SyscallUsage>,
    /// Compute budget analysis
    pub compute_budget: ComputeBudgetAnalysis,
    /// Number of source files analyzed
    pub files_analyzed: usize,
}

/// Firedancer compatibility checker
pub struct FiredancerCompatChecker {
    diff_db: RuntimeDiffDatabase,
}

impl FiredancerCompatChecker {
    pub fn new() -> Self {
        Self {
            diff_db: RuntimeDiffDatabase::new(),
        }
    }

    /// Analyze a program's source directory for Firedancer compatibility
    pub fn analyze_source(&self, path: &Path) -> Result<CompatReport, String> {
        if !path.exists() {
            return Err(format!("Path does not exist: {}", path.display()));
        }

        // Collect all .rs source files
        let mut sources: Vec<(String, String)> = Vec::new();
        Self::collect_rust_files(path, &mut sources);

        if sources.is_empty() {
            return Err("No Rust source files found".into());
        }

        let files_analyzed = sources.len();

        // Concatenate all source code for analysis
        let all_code: String = sources
            .iter()
            .map(|(name, content)| format!("// FILE: {}\n{}", name, content))
            .collect::<Vec<_>>()
            .join("\n\n");

        let mut warnings = Vec::new();
        let mut safe_patterns = Vec::new();

        // 1. Check runtime differences
        let triggered_diffs = self.diff_db.find_triggered_diffs(&all_code);
        for diff in triggered_diffs {
            let severity_str = match diff.severity {
                DiffSeverity::Breaking => "BREAKING",
                DiffSeverity::Risky => "RISKY",
                DiffSeverity::Info => "INFO",
            };
            warnings.push(CompatWarning::RuntimeDifference {
                diff_id: diff.id.to_string(),
                title: diff.title.to_string(),
                severity: severity_str.to_string(),
                detail: diff.description.to_string(),
                mitigation: diff.mitigation.to_string(),
            });
        }

        // 2. Analyze syscalls
        let mut all_syscall_usages = Vec::new();
        for (file, content) in &sources {
            let usages = syscall_analyzer::analyze_syscalls(file, content);
            all_syscall_usages.extend(usages);
        }

        // Flag syscalls with metering differences
        for usage in &all_syscall_usages {
            if usage.has_metering_diff {
                warnings.push(CompatWarning::SyscallMeteringDiff {
                    syscall: usage.syscall.clone(),
                    cu_labs: usage.cu_cost_labs,
                    cu_firedancer: usage.cu_cost_firedancer,
                });
            }
        }

        // 3. Compute budget analysis
        let compute_analysis = compute_budget::analyze_compute_budget(&all_code);
        if compute_analysis.risk == ComputeBudgetRisk::High {
            warnings.push(CompatWarning::ComputeBudgetRisk {
                syscall: "overall".into(),
                detail: format!(
                    "Program has only {:.1}% CU safety margin. Firedancer delta: {} CUs",
                    compute_analysis.safety_margin_pct, compute_analysis.cu_delta
                ),
            });
        }

        // 4. Check specific patterns
        self.check_ordering_dependencies(&all_code, &mut warnings);
        self.check_clock_usage(&all_code, &mut warnings);
        self.check_concurrent_access(&all_code, &mut warnings);

        // 5. Detect safe patterns
        self.detect_safe_patterns(&all_code, &mut safe_patterns);

        // Calculate compatibility score
        let score = self.calculate_score(&warnings);
        let grade = match score {
            90..=100 => "A+",
            80..=89 => "A",
            70..=79 => "B",
            60..=69 => "C",
            50..=59 => "D",
            _ => "F",
        }
        .to_string();

        Ok(CompatReport {
            score,
            grade,
            warnings,
            safe_patterns,
            syscall_usages: all_syscall_usages,
            compute_budget: compute_analysis,
            files_analyzed,
        })
    }

    /// Check for transaction ordering dependencies
    fn check_ordering_dependencies(&self, code: &str, warnings: &mut Vec<CompatWarning>) {
        if code.contains("slot_hashes") || code.contains("SlotHashes") {
            warnings.push(CompatWarning::TransactionOrderingDependency {
                detail: "Uses SlotHashes sysvar — ordering may differ on Firedancer".into(),
            });
        }
        if code.contains("recent_blockhashes") || code.contains("RecentBlockhashes") {
            warnings.push(CompatWarning::TransactionOrderingDependency {
                detail: "Uses RecentBlockhashes — blockhash ordering may differ".into(),
            });
        }
    }

    /// Check for clock resolution assumptions
    fn check_clock_usage(&self, code: &str, warnings: &mut Vec<CompatWarning>) {
        // Tight deadline checks (< 5 seconds tolerance)
        if code.contains("unix_timestamp")
            && (code.contains("+ 1") || code.contains("+ 2") || code.contains("+ 3"))
        {
            warnings.push(CompatWarning::ClockResolutionAssumption {
                detail: "Tight timestamp deadline detected (< 5s tolerance). Firedancer \
                    clock resolution may differ."
                    .into(),
            });
        }
    }

    /// Check for concurrent account access patterns
    fn check_concurrent_access(&self, code: &str, warnings: &mut Vec<CompatWarning>) {
        // If code modifies global state without locking
        if code.contains("try_borrow_mut_data")
            && !code.contains("reentrancy")
            && !code.contains("lock")
            && !code.contains("mutex")
        {
            warnings.push(CompatWarning::ConcurrentAccountAccess {
                accounts: vec!["global state accounts".into()],
            });
        }
    }

    /// Detect patterns that are known to be safe on Firedancer
    fn detect_safe_patterns(&self, code: &str, safe: &mut Vec<String>) {
        if code.contains("anchor_lang") {
            safe.push("Uses Anchor framework — account validation is Firedancer-compatible".into());
        }
        if code.contains("checked_") || code.contains("saturating_") {
            safe.push("Uses checked/saturating math — no overflow behavior differences".into());
        }
        if code.contains("#[account(") {
            safe.push("Uses Anchor account constraints — deserialization is deterministic".into());
        }
        if code.contains("require!") || code.contains("require_keys_eq!") {
            safe.push("Uses Anchor require! macros — error handling is consistent".into());
        }
    }

    /// Calculate compatibility score from warnings
    fn calculate_score(&self, warnings: &[CompatWarning]) -> u8 {
        let mut score: i32 = 100;

        for w in warnings {
            match w {
                CompatWarning::RuntimeDifference { severity, .. } => {
                    match severity.as_str() {
                        "BREAKING" => score -= 15,
                        "RISKY" => score -= 8,
                        "INFO" => score -= 2,
                        _ => score -= 5,
                    }
                }
                CompatWarning::ComputeBudgetRisk { .. } => score -= 10,
                CompatWarning::TransactionOrderingDependency { .. } => score -= 12,
                CompatWarning::ClockResolutionAssumption { .. } => score -= 5,
                CompatWarning::ConcurrentAccountAccess { .. } => score -= 8,
                CompatWarning::SyscallMeteringDiff { .. } => score -= 3,
            }
        }

        score.clamp(0, 100) as u8
    }

    /// Recursively collect .rs files from a directory
    fn collect_rust_files(dir: &Path, out: &mut Vec<(String, String)>) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().unwrap_or_default().to_str().unwrap_or("");
                if name != "target" && name != ".git" && name != "node_modules" {
                    Self::collect_rust_files(&path, out);
                }
            } else if path.extension().map_or(false, |e| e == "rs") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    let rel = path.display().to_string();
                    out.push((rel, content));
                }
            }
        }
    }
}

impl Default for FiredancerCompatChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checker_creation() {
        let checker = FiredancerCompatChecker::new();
        assert!(!checker.diff_db.all_diffs().is_empty());
    }

    #[test]
    fn test_analyze_real_program() {
        // Analyze our own vulnerable-vault test program
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("programs/vulnerable-vault");

        if path.exists() {
            let checker = FiredancerCompatChecker::new();
            let report = checker.analyze_source(&path).unwrap();
            assert!(report.score <= 100);
            assert!(report.files_analyzed > 0);
        }
    }

    #[test]
    fn test_score_calculation() {
        let checker = FiredancerCompatChecker::new();
        let warnings = vec![
            CompatWarning::RuntimeDifference {
                diff_id: "FD-001".into(),
                title: "test".into(),
                severity: "RISKY".into(),
                detail: "test".into(),
                mitigation: "test".into(),
            },
            CompatWarning::SyscallMeteringDiff {
                syscall: "sol_memcpy".into(),
                cu_labs: 10,
                cu_firedancer: 12,
            },
        ];
        let score = checker.calculate_score(&warnings);
        assert!(score < 100);
        assert!(score > 80); // minor issues
    }

    #[test]
    fn test_safe_pattern_detection() {
        let checker = FiredancerCompatChecker::new();
        let mut safe = Vec::new();
        checker.detect_safe_patterns("use anchor_lang::prelude::*; #[account(init)] fn x() { require!(true); amount.checked_add(1)?; }", &mut safe);
        assert!(safe.len() >= 3); // Anchor, checked math, account constraints
    }

    #[test]
    fn test_missing_path() {
        let checker = FiredancerCompatChecker::new();
        let result = checker.analyze_source(Path::new("/nonexistent/path"));
        assert!(result.is_err());
    }
}
