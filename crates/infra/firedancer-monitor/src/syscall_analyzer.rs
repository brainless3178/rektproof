//! Syscall Usage Analyzer
//!
//! Detects syscall usage patterns in Solana program source code that may
//! behave differently under Firedancer's SBPF runtime.

use serde::{Deserialize, Serialize};

/// A detected syscall usage in source code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallUsage {
    /// Syscall name (e.g., "sol_memcpy")
    pub syscall: String,
    /// File where it was found
    pub file: String,
    /// Approximate line number
    pub line: usize,
    /// CU cost on Solana Labs validator
    pub cu_cost_labs: u64,
    /// Estimated CU cost on Firedancer (may differ)
    pub cu_cost_firedancer: u64,
    /// Whether this syscall has known metering differences
    pub has_metering_diff: bool,
}

/// Known syscall CU costs and Firedancer differences
struct SyscallInfo {
    name: &'static str,
    /// Patterns in source code that invoke this syscall
    patterns: &'static [&'static str],
    cu_labs: u64,
    cu_firedancer: u64,
}

const SYSCALL_DB: &[SyscallInfo] = &[
    SyscallInfo {
        name: "sol_memcpy",
        patterns: &["sol_memcpy", "copy_from_slice", ".copy_within"],
        cu_labs: 10,
        cu_firedancer: 12,
    },
    SyscallInfo {
        name: "sol_memset",
        patterns: &["sol_memset", ".fill(0)", "data.fill("],
        cu_labs: 10,
        cu_firedancer: 11,
    },
    SyscallInfo {
        name: "sol_memmove",
        patterns: &["sol_memmove", "ptr::copy"],
        cu_labs: 10,
        cu_firedancer: 12,
    },
    SyscallInfo {
        name: "sol_log",
        patterns: &["msg!", "sol_log(", "sol_log_64"],
        cu_labs: 100,
        cu_firedancer: 100,
    },
    SyscallInfo {
        name: "sol_log_data",
        patterns: &["sol_log_data", "emit!", "sol_log_data("],
        cu_labs: 100,
        cu_firedancer: 105,
    },
    SyscallInfo {
        name: "sol_invoke_signed",
        patterns: &["invoke_signed(", "invoke(", "CpiContext::new"],
        cu_labs: 1000,
        cu_firedancer: 1000,
    },
    SyscallInfo {
        name: "sol_create_program_address",
        patterns: &["Pubkey::create_program_address", "find_program_address"],
        cu_labs: 1500,
        cu_firedancer: 1500,
    },
    SyscallInfo {
        name: "sol_sha256",
        patterns: &["sha256", "Sha256", "hashv("],
        cu_labs: 85,
        cu_firedancer: 90,
    },
    SyscallInfo {
        name: "sol_keccak256",
        patterns: &["keccak256", "Keccak256", "keccak::hash"],
        cu_labs: 85,
        cu_firedancer: 88,
    },
    SyscallInfo {
        name: "sol_secp256k1_recover",
        patterns: &["secp256k1_recover", "Secp256k1"],
        cu_labs: 25000,
        cu_firedancer: 25000,
    },
    SyscallInfo {
        name: "sol_get_clock_sysvar",
        patterns: &["Clock::get()", "clock::Clock"],
        cu_labs: 10,
        cu_firedancer: 10,
    },
    SyscallInfo {
        name: "sol_get_rent_sysvar",
        patterns: &["Rent::get()", "rent::Rent"],
        cu_labs: 10,
        cu_firedancer: 10,
    },
];

/// Analyze source code for syscall usage patterns
pub fn analyze_syscalls(file_name: &str, code: &str) -> Vec<SyscallUsage> {
    let mut usages = Vec::new();

    for info in SYSCALL_DB {
        for pattern in info.patterns {
            for (line_idx, line) in code.lines().enumerate() {
                if line.contains(pattern) {
                    usages.push(SyscallUsage {
                        syscall: info.name.to_string(),
                        file: file_name.to_string(),
                        line: line_idx + 1,
                        cu_cost_labs: info.cu_labs,
                        cu_cost_firedancer: info.cu_firedancer,
                        has_metering_diff: info.cu_labs != info.cu_firedancer,
                    });
                    break; // one per pattern per file
                }
            }
        }
    }

    usages
}

/// Calculate total CU difference across all detected syscalls
pub fn total_cu_delta(usages: &[SyscallUsage]) -> i64 {
    usages
        .iter()
        .map(|u| u.cu_cost_firedancer as i64 - u.cu_cost_labs as i64)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_memcpy() {
        let code = "data.copy_from_slice(&src);";
        let usages = analyze_syscalls("lib.rs", code);
        assert!(usages.iter().any(|u| u.syscall == "sol_memcpy"));
    }

    #[test]
    fn test_detects_log() {
        let code = "msg!(\"Hello world\");";
        let usages = analyze_syscalls("lib.rs", code);
        assert!(usages.iter().any(|u| u.syscall == "sol_log"));
    }

    #[test]
    fn test_cu_delta() {
        let usages = vec![
            SyscallUsage {
                syscall: "sol_memcpy".into(),
                file: "a.rs".into(),
                line: 1,
                cu_cost_labs: 10,
                cu_cost_firedancer: 12,
                has_metering_diff: true,
            },
            SyscallUsage {
                syscall: "sol_log".into(),
                file: "a.rs".into(),
                line: 2,
                cu_cost_labs: 100,
                cu_cost_firedancer: 100,
                has_metering_diff: false,
            },
        ];
        assert_eq!(total_cu_delta(&usages), 2);
    }

    #[test]
    fn test_empty_code() {
        let usages = analyze_syscalls("empty.rs", "");
        assert!(usages.is_empty());
    }
}
