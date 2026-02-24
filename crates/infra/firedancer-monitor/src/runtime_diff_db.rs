//! Known Runtime Differences Between Solana Labs Validator and Firedancer
//!
//! This database catalogues known behavioral differences that may affect
//! program execution when migrating between validator implementations.

use serde::{Deserialize, Serialize};

/// Severity of a runtime difference
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffSeverity {
    /// Will cause different execution results
    Breaking,
    /// May cause different results under specific conditions
    Risky,
    /// Informational—behavior differs but typically safe
    Info,
}

/// A known difference between Solana Labs and Firedancer runtimes
#[derive(Debug, Clone, Serialize)]
pub struct RuntimeDiff {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: DiffSeverity,
    pub description: &'static str,
    /// Code patterns that trigger this difference
    pub trigger_patterns: &'static [&'static str],
    /// Suggested mitigation
    pub mitigation: &'static str,
}

/// Database of known Firedancer vs Solana Labs runtime differences
pub struct RuntimeDiffDatabase {
    diffs: Vec<RuntimeDiff>,
}

impl RuntimeDiffDatabase {
    pub fn new() -> Self {
        Self {
            diffs: vec![
                RuntimeDiff {
                    id: "FD-001",
                    title: "Compute Unit Metering Differences",
                    severity: DiffSeverity::Risky,
                    description: "Firedancer's SBPF interpreter meters CU differently for \
                        some syscalls, especially sol_memcpy, sol_memset, and logging. \
                        Programs near the CU limit may succeed on one validator but fail on another.",
                    trigger_patterns: &[
                        "sol_memcpy", "sol_memset", "sol_memmove",
                        "sol_log", "msg!", "sol_log_data",
                        "compute_budget", "ComputeBudget",
                    ],
                    mitigation: "Add a 10% CU safety margin. Avoid tight CU budgets.",
                },
                RuntimeDiff {
                    id: "FD-002",
                    title: "Transaction Ordering Non-Determinism",
                    severity: DiffSeverity::Breaking,
                    description: "Firedancer uses a different transaction scheduler. Programs \
                        that depend on transaction ordering within a slot (MEV, front-running \
                        protection via ordering) will behave differently.",
                    trigger_patterns: &[
                        "slot_hashes", "recent_blockhashes",
                        "SlotHashes", "RecentBlockhashes",
                        "leader_schedule",
                    ],
                    mitigation: "Never rely on transaction ordering. Use on-chain commitments \
                        with reveal phases instead.",
                },
                RuntimeDiff {
                    id: "FD-003",
                    title: "Clock Sysvar Resolution",
                    severity: DiffSeverity::Risky,
                    description: "Clock::get() timestamp resolution may differ slightly between \
                        validators. Programs using sub-second timing assumptions or tight \
                        deadline checks may behave differently.",
                    trigger_patterns: &[
                        "Clock::get()", "unix_timestamp",
                        "clock.unix_timestamp", "slot_duration",
                    ],
                    mitigation: "Use slot-based timing instead of unix_timestamp for critical \
                        deadlines. Allow >1 slot tolerance.",
                },
                RuntimeDiff {
                    id: "FD-004",
                    title: "Account Data Serialization Edge Cases",
                    severity: DiffSeverity::Risky,
                    description: "Firedancer's account data handling may differ for edge cases \
                        involving zero-length data, realloc near limits, or accounts at the \
                        10MB maximum size.",
                    trigger_patterns: &[
                        "realloc", "data_len", "MAX_PERMITTED_DATA_LENGTH",
                        "data.borrow_mut()", "try_borrow_mut_data",
                    ],
                    mitigation: "Avoid realloc in hot paths. Test with maximum-sized accounts.",
                },
                RuntimeDiff {
                    id: "FD-005",
                    title: "CPI Depth and Stack Frame Differences",
                    severity: DiffSeverity::Risky,
                    description: "Firedancer enforces CPI depth limits (4 levels) the same as \
                        Solana Labs, but stack frame memory allocation differs. Deep CPI \
                        chains with large stack frames may hit limits earlier.",
                    trigger_patterns: &[
                        "invoke(", "invoke_signed(",
                        "CpiContext", "cpi::",
                    ],
                    mitigation: "Keep CPI depth <= 3 levels. Minimize stack allocations in \
                        CPI chains.",
                },
                RuntimeDiff {
                    id: "FD-006",
                    title: "Sysvars Access Method Differences",
                    severity: DiffSeverity::Info,
                    description: "Firedancer provides sysvars via the same interface but internal \
                        caching behavior differs. Frequent sysvar reads in tight loops may \
                        have different performance characteristics.",
                    trigger_patterns: &[
                        "Sysvar::get()", "from_account_info",
                        "Rent::get()", "EpochSchedule::get()",
                    ],
                    mitigation: "Cache sysvar reads in local variables instead of calling \
                        get() repeatedly.",
                },
                RuntimeDiff {
                    id: "FD-007",
                    title: "Concurrent Account Access Scheduling",
                    severity: DiffSeverity::Breaking,
                    description: "Firedancer's parallel transaction execution may schedule \
                        read/write conflicts differently. Programs that implicitly rely on \
                        sequential execution of transactions touching the same accounts \
                        may observe different state.",
                    trigger_patterns: &[
                        "AccountInfo", "try_borrow_mut",
                        "RefMut", "borrow_mut",
                    ],
                    mitigation: "Use explicit locking mechanisms (reentrancy guards, sequence \
                        numbers) instead of relying on execution ordering.",
                },
                RuntimeDiff {
                    id: "FD-008",
                    title: "Log Output Format Differences",
                    severity: DiffSeverity::Info,
                    description: "Firedancer may format log output differently. Programs or \
                        off-chain systems that parse log messages may break.",
                    trigger_patterns: &[
                        "msg!", "sol_log", "emit!",
                        "Program log:", "Program data:",
                    ],
                    mitigation: "Use structured event emission (emit!) rather than parsing log \
                        strings. Use Anchor events for typed data.",
                },
            ],
        }
    }

    /// Get all runtime differences
    pub fn all_diffs(&self) -> &[RuntimeDiff] {
        &self.diffs
    }

    /// Find diffs triggered by patterns found in source code
    pub fn find_triggered_diffs(&self, code: &str) -> Vec<&RuntimeDiff> {
        self.diffs
            .iter()
            .filter(|diff| {
                diff.trigger_patterns
                    .iter()
                    .any(|pattern| code.contains(pattern))
            })
            .collect()
    }
}

impl Default for RuntimeDiffDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_has_entries() {
        let db = RuntimeDiffDatabase::new();
        assert!(db.all_diffs().len() >= 8);
    }

    #[test]
    fn test_pattern_matching() {
        let db = RuntimeDiffDatabase::new();
        let code = "let clock = Clock::get()?; let ts = clock.unix_timestamp;";
        let triggered = db.find_triggered_diffs(code);
        assert!(triggered.iter().any(|d| d.id == "FD-003"));
    }

    #[test]
    fn test_no_false_triggers() {
        let db = RuntimeDiffDatabase::new();
        let code = "let x = 42; let y = x + 1;";
        let triggered = db.find_triggered_diffs(code);
        assert!(triggered.is_empty());
    }
}
