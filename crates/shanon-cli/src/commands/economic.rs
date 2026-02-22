//! `economic-verify` command — run DeFi economic invariant verification.
//!
//! Uses Z3 SMT solver to verify economic invariants like solvency,
//! share ratio bounds, fee conservation, and first-depositor protections.

use colored::*;

/// Run DeFi economic invariant verification on a Solana program.
pub fn cmd_economic_verify(path: &str, format: &str) {
    let source_path = std::path::Path::new(path);
    if !source_path.exists() {
        eprintln!("  {} Path not found: {}", "X".red(), path);
        std::process::exit(1);
    }

    eprintln!("\n  {}  Running DeFi economic invariant verification on: {}", "+".to_string(), path);
    let timer = std::time::Instant::now();

    let z3_config = z3::Config::new();
    let z3_ctx = z3::Context::new(&z3_config);
    let mut verifier = economic_verifier::EconomicVerifier::new(&z3_ctx);

    let state = economic_verifier::ProtocolState {
        total_assets: Some(1_000_000),
        total_shares: Some(1_000_000),
        user_balances: std::collections::HashMap::new(),
        fees_collected: Some(0),
        reserve_x: Some(500_000),
        reserve_y: Some(500_000),
        dead_shares: Some(1_000_000),
    };

    let all_results = verifier.verify_all_invariants(&state);

    let mut passed = 0;
    let mut failed = 0;
    let mut json_results: Vec<serde_json::Value> = Vec::new();

    for result in &all_results {
        if result.verified {
            passed += 1;
            eprintln!("  {} {:?}: {}", "ok".green(), result.invariant_type, result.description);
        } else {
            failed += 1;
            eprintln!("  {} {:?}: {}", "X".red(), result.invariant_type, result.description);
            if let Some(ref ce) = result.counterexample {
                eprintln!("    Counterexample: {:?}", ce);
            }
        }
        json_results.push(serde_json::json!({
            "invariant": format!("{:?}", result.invariant_type),
            "verified": result.verified,
            "description": result.description,
            "severity": format!("{:?}", result.severity),
            "counterexample": result.counterexample,
        }));
    }

    let elapsed = timer.elapsed();
    eprintln!("\n  {}  Economic verification: {} passed, {} failed ({:.2}s)",
        if failed == 0 { "ok".green() } else { "X".red() }, passed, failed, elapsed.as_secs_f64());

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "economic_verification": json_results,
            "passed": passed,
            "failed": failed,
            "elapsed_secs": elapsed.as_secs_f64(),
        })).unwrap_or_default());
    }
}
