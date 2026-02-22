//! `verify-formal` command — run the full formal verification pipeline.
//!
//! Orchestrates Kani, Certora, Wacana concolic, Crux-MIR AST scanner,
//! and the 4-layer FV Scanner pipeline (which uses Z3 for each layer).

use colored::*;

/// Run the full formal verification pipeline on a Solana program.
pub async fn cmd_verify_formal(path: &str, format: &str) {
    let source_path = std::path::Path::new(path);
    if !source_path.exists() {
        eprintln!("  {} Path not found: {}", "X".red(), path);
        std::process::exit(1);
    }

    eprintln!("\n  {}  Running formal verification pipeline on: {}", "🔬".to_string(), path);
    let timer = std::time::Instant::now();
    let mut results: Vec<serde_json::Value> = Vec::new();

    // 1) Kani model checking (Z3 fallback when cargo-kani not installed)
    eprintln!("  ├─ {} Kani model checking...", "🔍".to_string());
    let mut kani = kani_verifier::KaniVerifier::new();
    match kani.verify_program(source_path) {
        Ok(report) => {
            let failed = report.failed_properties().len();
            let verified = report.verified_properties().len();
            eprintln!("  │  {} Kani: {} verified, {} failed", "ok".green(), verified, failed);
            results.push(serde_json::json!({
                "engine": "kani",
                "status": format!("{:?}", report.status),
                "verified_properties": verified,
                "failed_properties": failed,
            }));
        }
        Err(e) => {
            eprintln!("  │  {} Kani: {:?}", "[warn]".yellow(), e);
            results.push(serde_json::json!({"engine": "kani", "status": "error", "error": format!("{:?}", e)}));
        }
    }

    // 2) Certora prover (SBF bytecode verification, Z3 fallback)
    eprintln!("  ├─ {} Certora prover...", "🔍".to_string());
    let mut certora = certora_prover::CertoraVerifier::new();
    match certora.verify_program(source_path) {
        Ok(report) => {
            let passed = report.passed_rules().len();
            let failed = report.failed_rules().len();
            eprintln!("  │  {} Certora: {} passed, {} failed", "ok".green(), passed, failed);
            results.push(serde_json::json!({
                "engine": "certora",
                "passed_rules": passed,
                "failed_rules": failed,
            }));
        }
        Err(e) => {
            eprintln!("  │  {} Certora: {:?}", "[warn]".yellow(), e);
            results.push(serde_json::json!({"engine": "certora", "status": "error", "error": format!("{:?}", e)}));
        }
    }

    // 3) Wacana concolic analysis
    eprintln!("  ├─ {} Wacana concolic analysis...", "🔍".to_string());
    let mut wacana = wacana_analyzer::WacanaAnalyzer::new(wacana_analyzer::WacanaConfig::default());
    match wacana.analyze_program(source_path) {
        Ok(report) => {
            eprintln!("  │  {} Wacana: {} paths, {} findings", "ok".green(), report.total_paths_explored, report.findings.len());
            results.push(serde_json::json!({
                "engine": "wacana",
                "paths_explored": report.total_paths_explored,
                "findings": report.findings.len(),
            }));
        }
        Err(e) => {
            eprintln!("  │  {} Wacana: {:?}", "[warn]".yellow(), e);
            results.push(serde_json::json!({"engine": "wacana", "status": "error", "error": format!("{:?}", e)}));
        }
    }

    // 4) Crux-MIR AST analysis (syn::visit fallback — Crux-MIR not installed)
    eprintln!("  ├─ {} AST security analysis (crux-mir fallback)...", "🔍".to_string());
    let crux = crux_mir_analyzer::CruxMirAnalyzer::new();
    match crux.analyze_program(source_path).await {
        Ok(report) => {
            eprintln!("  │  {} AST Scanner: {} findings, {} instructions", "ok".green(), report.findings.len(), report.analyzed_instructions);
            results.push(serde_json::json!({
                "engine": "ast-security-scanner",
                "findings": report.findings.len(),
                "instructions_analyzed": report.analyzed_instructions,
                "backend": report.prover_backend,
            }));
        }
        Err(e) => {
            eprintln!("  │  {} AST Scanner: {:?}", "[warn]".yellow(), e);
            results.push(serde_json::json!({"engine": "ast-security-scanner", "status": "error", "error": format!("{:?}", e)}));
        }
    }

    // 5) FV Scanner - 4-layer Z3-backed verification pipeline
    //    Layer 1: Arithmetic & Logic (Kani harness + Z3 overflow proofs)
    //    Layer 2: Symbolic Execution (AST extraction + Z3 SMT proofs)
    //    Layer 3: Cross-Program Safety (account schema invariants via Z3)
    //    Layer 4: Protocol State Machine (state transition verification via Z3)
    eprintln!("  └─ {} FV Scanner (4-layer Z3 pipeline)...", "🔬".to_string());
    {
        let fv_config = fv_scanner_core::ScanConfig {
            enabled_layers: vec![1, 2, 3, 4],
            layer1_config: fv_scanner_core::Layer1Config {
                kani_enabled: false, // Kani binary typically not installed
                prusti_enabled: true,
                ..fv_scanner_core::Layer1Config::default()
            },
            layer3_config: fv_scanner_core::Layer3Config::default(),
            verbose: false,
        };
        let fv_scanner = fv_scanner_core::Scanner::new(fv_config);
        let (fv_tx, mut fv_rx) = tokio::sync::mpsc::channel(32);

        // Spawn progress listener
        let progress_handle = tokio::spawn(async move {
            while let Some(progress) = fv_rx.recv().await {
                match progress {
                    fv_scanner_core::ScanProgress::Started { layer, ref name } => {
                        eprintln!("     {} Layer {}: {}...", "⟳".to_string(), layer, name);
                    }
                    fv_scanner_core::ScanProgress::Completed { layer, success } => {
                        let icon = if success { "ok".green().to_string() } else { "X".red().to_string() };
                        eprintln!("     {} Layer {} complete", icon, layer);
                    }
                    fv_scanner_core::ScanProgress::Error { layer, ref message } => {
                        eprintln!("     {} Layer {}: {}", "[warn]".yellow(), layer, message);
                    }
                    _ => {}
                }
            }
        });

        match fv_scanner.scan_with_progress(source_path, fv_tx).await {
            Ok(fv_result) => {
                let mut fv_json = serde_json::json!({
                    "engine": "fv-scanner",
                    "scan_id": fv_result.scan_id,
                    "duration_ms": fv_result.duration_ms,
                });
                if let Some(ref l1) = fv_result.layers.layer1 {
                    fv_json["layer1"] = serde_json::json!({
                        "status": format!("{:?}", l1.status),
                        "findings": l1.findings.len(),
                    });
                }
                if let Some(ref l2) = fv_result.layers.layer2 {
                    fv_json["layer2"] = serde_json::json!({
                        "proofs": l2.z3_proofs.len(),
                    });
                }
                if let Some(ref l3) = fv_result.layers.layer3 {
                    fv_json["layer3"] = serde_json::json!({
                        "status": l3.status,
                        "invariants_checked": l3.invariants_checked,
                        "violations": l3.violations_found.len(),
                    });
                }
                if let Some(ref l4) = fv_result.layers.layer4 {
                    fv_json["layer4"] = serde_json::json!({
                        "status": l4.status,
                        "state_transitions": l4.z3_proofs.len(),
                    });
                }
                eprintln!("     {} FV Scanner: completed in {}ms", "ok".green(), fv_result.duration_ms);
                results.push(fv_json);
            }
            Err(e) => {
                eprintln!("     {} FV Scanner: {:?}", "[warn]".yellow(), e);
                results.push(serde_json::json!({"engine": "fv-scanner", "status": "error", "error": format!("{:?}", e)}));
            }
        }
        let _ = progress_handle.await;
    }

    let elapsed = timer.elapsed();
    eprintln!("\n  {}  Formal verification completed in {:.2}s", "ok".green(), elapsed.as_secs_f64());

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "formal_verification": results,
            "elapsed_secs": elapsed.as_secs_f64(),
        })).unwrap_or_default());
    }
}
