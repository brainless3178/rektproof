//! Compute Budget Analysis
//!
//! Detects programs that operate near compute unit limits and may be
//! affected by Firedancer's different CU metering.

use serde::{Deserialize, Serialize};

/// Compute budget risk assessment for a program
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeBudgetAnalysis {
    /// Whether the program uses RequestUnitsDeprecated or SetComputeUnitLimit
    pub sets_explicit_cu_limit: bool,
    /// Explicit CU limit value if set
    pub explicit_cu_limit: Option<u32>,
    /// Estimated CU usage based on syscall analysis
    pub estimated_cu_usage: u64,
    /// Estimated CU difference between Labs and Firedancer
    pub cu_delta: i64,
    /// Safety margin percentage: (limit - usage) / limit * 100
    pub safety_margin_pct: f64,
    /// Risk level
    pub risk: ComputeBudgetRisk,
    /// Recommendations
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComputeBudgetRisk {
    /// >20% margin — likely safe
    Safe,
    /// 10-20% margin — monitor closely
    Moderate,
    /// <10% margin — may fail on Firedancer
    High,
    /// No explicit limit set — using default 200k
    Unknown,
}

/// Default CU limit when none is explicitly set
const DEFAULT_CU_LIMIT: u32 = 200_000;

/// Analyze compute budget usage from source code
pub fn analyze_compute_budget(code: &str) -> ComputeBudgetAnalysis {
    // Detect explicit CU limit setting
    let (sets_explicit, explicit_limit) = detect_explicit_cu_limit(code);

    let effective_limit = explicit_limit.unwrap_or(DEFAULT_CU_LIMIT) as u64;

    // Estimate CU usage from syscall patterns
    let estimated_usage = estimate_cu_usage(code);

    // Calculate CU delta from Firedancer differences
    let cu_delta = estimate_firedancer_delta(code);

    // Worst-case usage on Firedancer
    let worst_case = estimated_usage as i64 + cu_delta;

    let safety_margin = if effective_limit > 0 {
        ((effective_limit as f64 - worst_case as f64) / effective_limit as f64) * 100.0
    } else {
        0.0
    };

    let risk = if !sets_explicit {
        ComputeBudgetRisk::Unknown
    } else if safety_margin > 20.0 {
        ComputeBudgetRisk::Safe
    } else if safety_margin > 10.0 {
        ComputeBudgetRisk::Moderate
    } else {
        ComputeBudgetRisk::High
    };

    let mut recommendations = Vec::new();
    if !sets_explicit {
        recommendations.push(
            "Set explicit compute unit limit with ComputeBudgetInstruction::set_compute_unit_limit()"
                .into(),
        );
    }
    if safety_margin < 10.0 && sets_explicit {
        recommendations.push(format!(
            "Increase CU limit by at least 10% (current margin: {:.1}%)",
            safety_margin
        ));
    }
    if cu_delta > 0 {
        recommendations.push(format!(
            "Firedancer may use ~{} additional CUs for this program's syscall patterns",
            cu_delta
        ));
    }
    if code.contains("msg!") || code.contains("sol_log") {
        recommendations
            .push("Remove debug logging in production to save CUs".into());
    }

    ComputeBudgetAnalysis {
        sets_explicit_cu_limit: sets_explicit,
        explicit_cu_limit: explicit_limit,
        estimated_cu_usage: estimated_usage,
        cu_delta,
        safety_margin_pct: safety_margin,
        risk,
        recommendations,
    }
}

/// Detect if the code explicitly sets a CU limit
fn detect_explicit_cu_limit(code: &str) -> (bool, Option<u32>) {
    // Look for set_compute_unit_limit or request_units patterns
    if code.contains("set_compute_unit_limit") || code.contains("RequestUnitsDeprecated") {
        // Try to extract numeric limit
        for line in code.lines() {
            if line.contains("set_compute_unit_limit") || line.contains("request_units") {
                // Simple numeric extraction
                let nums: Vec<u32> = line
                    .split(|c: char| !c.is_ascii_digit())
                    .filter_map(|s| s.parse().ok())
                    .filter(|&n| n > 1000) // CU limits are typically >1000
                    .collect();
                if let Some(&limit) = nums.first() {
                    return (true, Some(limit));
                }
            }
        }
        (true, None)
    } else {
        (false, None)
    }
}

/// Estimate CU usage from code patterns
fn estimate_cu_usage(code: &str) -> u64 {
    let mut estimate: u64 = 5000; // base cost

    // CPI calls are expensive
    let cpi_count = code.matches("invoke(").count()
        + code.matches("invoke_signed(").count()
        + code.matches("CpiContext::new").count();
    estimate += cpi_count as u64 * 1000;

    // Logging
    let log_count = code.matches("msg!").count() + code.matches("sol_log").count();
    estimate += log_count as u64 * 100;

    // PDA derivation
    let pda_count = code.matches("find_program_address").count()
        + code.matches("create_program_address").count();
    estimate += pda_count as u64 * 1500;

    // Hash operations
    let hash_count = code.matches("sha256").count()
        + code.matches("keccak").count()
        + code.matches("hashv").count();
    estimate += hash_count as u64 * 90;

    // Serialization
    let ser_count = code.matches("serialize").count()
        + code.matches("try_to_vec").count()
        + code.matches("borsh::").count();
    estimate += ser_count as u64 * 200;

    estimate
}

/// Estimate the CU difference Firedancer would introduce
fn estimate_firedancer_delta(code: &str) -> i64 {
    let mut delta: i64 = 0;

    // memcpy family: +2 CU each on Firedancer
    let mem_ops = code.matches("copy_from_slice").count()
        + code.matches("sol_memcpy").count()
        + code.matches("sol_memmove").count();
    delta += mem_ops as i64 * 2;

    // sol_log_data: +5 CU on Firedancer
    let log_data = code.matches("emit!").count() + code.matches("sol_log_data").count();
    delta += log_data as i64 * 5;

    // Hash operations: +5 CU on Firedancer
    let hash_ops = code.matches("sha256").count() + code.matches("keccak").count();
    delta += hash_ops as i64 * 5;

    delta
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_explicit_limit() {
        let code = "fn process(accounts: &[AccountInfo]) -> ProgramResult { Ok(()) }";
        let analysis = analyze_compute_budget(code);
        assert!(!analysis.sets_explicit_cu_limit);
        assert_eq!(analysis.risk, ComputeBudgetRisk::Unknown);
    }

    #[test]
    fn test_with_explicit_limit() {
        let code = "ComputeBudgetInstruction::set_compute_unit_limit(300000);";
        let analysis = analyze_compute_budget(code);
        assert!(analysis.sets_explicit_cu_limit);
        assert_eq!(analysis.explicit_cu_limit, Some(300000));
    }

    #[test]
    fn test_cu_estimation() {
        let code = "msg!(\"hello\"); msg!(\"world\"); invoke_signed(ix, accounts, seeds)?;";
        let usage = estimate_cu_usage(code);
        // base(5000) + 2*log(200) + 1*cpi(1000) = 6200
        assert!(usage >= 6000);
    }

    #[test]
    fn test_firedancer_delta() {
        let code = "data.copy_from_slice(&src); emit!(MyEvent { val: 42 });";
        let delta = estimate_firedancer_delta(code);
        assert!(delta > 0);
    }
}
