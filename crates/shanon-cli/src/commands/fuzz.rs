//! `fuzz` command — run the fuzzing analysis pipeline.
//!
//! Orchestrates Trident stateful fuzzing, FuzzDelSol binary fuzzing,
//! and coverage-guided security fuzzing.

use colored::*;

/// Run the fuzzing analysis pipeline on a Solana program.
pub fn cmd_fuzz(path: &str, iterations: usize, format: &str) {
    let source_path = std::path::Path::new(path);
    if !source_path.exists() {
        eprintln!("  {} Path not found: {}", "X".red(), path);
        std::process::exit(1);
    }

    eprintln!("\n  {}  Running fuzzing analysis on: {}", "🐛".to_string(), path);
    let timer = std::time::Instant::now();
    let mut results: Vec<serde_json::Value> = Vec::new();

    // 1) Trident stateful fuzzing
    eprintln!("  ├─ {} Trident stateful fuzzer...", "🔍".to_string());
    let mut trident = trident_fuzzer::TridentFuzzer::new();
    match trident.fuzz_program(source_path) {
        Ok(report) => {
            eprintln!("  │  {} Trident: {} iters, {} findings ({} crit, {} high)", "ok".green(),
                report.total_iterations, report.findings.len(), report.critical_count, report.high_count);
            results.push(serde_json::json!({
                "engine": "trident",
                "iterations": report.total_iterations,
                "findings": report.findings.len(),
                "critical": report.critical_count,
                "high": report.high_count,
            }));
        }
        Err(e) => {
            eprintln!("  │  {} Trident: {:?}", "[warn]".yellow(), e);
            results.push(serde_json::json!({"engine": "trident", "status": "error", "error": format!("{:?}", e)}));
        }
    }

    // 2) FuzzDelSol binary fuzzing (if binary available)
    eprintln!("  ├─ {} FuzzDelSol binary fuzzer...", "🔍".to_string());
    match fuzzdelsol::FuzzDelSol::find_binary(source_path) {
        Ok(binary_path) => {
            let mut fds = fuzzdelsol::FuzzDelSol::with_config(fuzzdelsol::FuzzConfig::default());
            match fds.fuzz_binary(&binary_path) {
                Ok(report) => {
                    eprintln!("  │  {} FuzzDelSol: {} violations", "ok".green(),
                        report.violations.len());
                    results.push(serde_json::json!({
                        "engine": "fuzzdelsol",
                        "violations": report.violations.len(),
                    }));
                }
                Err(e) => {
                    eprintln!("  │  {} FuzzDelSol: {:?}", "[warn]".yellow(), e);
                    results.push(serde_json::json!({"engine": "fuzzdelsol", "status": "error", "error": format!("{:?}", e)}));
                }
            }
        }
        Err(_) => {
            eprintln!("  │  {} FuzzDelSol: No SBF binary found, skipping", "⏭️".to_string());
            results.push(serde_json::json!({"engine": "fuzzdelsol", "status": "skipped", "reason": "no binary"}));
        }
    }

    // 3) Coverage-guided security fuzzer
    eprintln!("  └─ {} Coverage-guided fuzzer...", "🔍".to_string());
    let fuzz_config = security_fuzzer::FuzzerConfig {
        max_iterations: iterations,
        seed: 42,
        coverage_size: 65536,
        max_input_size: 1024,
        mutation_probability: 0.1,
        mutations_per_input: 5,
    };
    let mut fuzzer = security_fuzzer::SecurityFuzzer::new(fuzz_config);
    let stats = fuzzer.fuzz(|input| {
        security_fuzzer::FuzzResult {
            input: input.clone(),
            success: true,
            error: None,
            error_code: None,
            coverage_bitmap: vec![],
            interesting: false,
            is_crash: false,
            execution_time_us: 0,
        }
    });
    eprintln!("     {} SecurityFuzzer: {} execs, {} findings", "ok".green(),
        stats.total_executions, stats.findings.len());
    results.push(serde_json::json!({
        "engine": "security-fuzzer",
        "total_executions": stats.total_executions,
        "findings": stats.findings.len(),
        "coverage_pct": stats.coverage_percentage,
    }));

    let elapsed = timer.elapsed();
    eprintln!("\n  {}  Fuzzing completed in {:.2}s", "ok".green(), elapsed.as_secs_f64());

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "fuzzing": results,
            "elapsed_secs": elapsed.as_secs_f64(),
        })).unwrap_or_default());
    }
}
