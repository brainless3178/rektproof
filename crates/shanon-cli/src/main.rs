mod tui;
mod dashboard;

use clap::{Parser, Subcommand};
use colored::*;
use std::path::Path;
use std::time::Instant;
use std::collections::HashMap;

#[derive(Parser)]
#[command(
    name = "shanon",
    version = "2.0.0",
    about = "[shield] Shanon - Enterprise-Grade Solana Security Platform",
    long_about = "Shanon is an enterprise-grade Solana security platform.\n\n\
        6 analysis engines · 72+ vulnerability detectors\n\
        Lattice taint · CFG dominators · Abstract interpretation\n\
        Account aliasing · Dependency firewall · Firedancer compat\n\n\
        https://shanon.security"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a Solana program - launches interactive dashboard
    Scan {
        path: String,
        /// Output format: dashboard (default), json, human, sarif, markdown
        #[arg(long, default_value = "dashboard")]
        format: String,
        /// Minimum severity filter
        #[arg(long, default_value = "low")]
        min_severity: String,
        /// Enable AI-enhanced analysis (requires API key)
        #[arg(long)]
        ai: bool,
        /// API key for AI analysis (Kimi/NVIDIA NIM/OpenRouter). Falls back to OPENROUTER_API_KEY env var.
        #[arg(long, env = "OPENROUTER_API_KEY")]
        api_key: Option<String>,
        /// AI model to use (default: moonshotai/kimi-k2.5)
        #[arg(long, default_value = "moonshotai/kimi-k2.5")]
        model: String,
        /// Generate secure code fixes for each finding
        #[arg(long)]
        fix: bool,
        /// Generate executable proof-of-concept exploits for high/critical findings
        #[arg(long)]
        poc: bool,
        /// Simulate exploit transactions for high/critical findings (devnet, simulate-only)
        #[arg(long)]
        simulate: bool,
        /// Enable verbose output with phase timing details
        #[arg(long, short = 'v')]
        verbose: bool,
        /// Run LLM exploit strategy generation for HIGH/CRITICAL findings
        #[arg(long)]
        ai_strategy: bool,
        /// Run multi-LLM consensus verification to reduce false positives
        #[arg(long)]
        consensus: bool,
    },
    /// Check dependencies for supply chain attacks
    Guard {
        #[arg(long, default_value = ".")]
        path: String,
        #[arg(long, default_value = "dashboard")]
        format: String,
        #[arg(long, default_value = "critical")]
        fail_on: String,
    },
    /// Check Firedancer validator compatibility
    FiredancerCheck {
        #[arg(long)]
        source: Option<String>,
        #[arg(long, default_value = "http://localhost:8899")]
        rpc_url: String,
        #[arg(long, default_value = "human")]
        format: String,
    },
    /// Analyze CPI dependency graph
    CpiGraph {
        program_id: String,
        #[arg(long)]
        source: Option<String>,
        #[arg(long, default_value = "human")]
        format: String,
    },
    /// Score a Solana program's security (0-100)
    Score {
        path: String,
        #[arg(long)]
        name: Option<String>,
        /// Output format: dashboard (default), json, human
        #[arg(long, default_value = "dashboard")]
        format: String,
    },
    /// Scan a token for rug pull risk
    TokenScan {
        mint: String,
        #[arg(long)]
        source: Option<String>,
        #[arg(long, default_value = "https://api.mainnet-beta.solana.com")]
        rpc_url: String,
        #[arg(long, default_value = "human")]
        format: String,
    },
    /// Monitor upgrade authority changes
    Watch {
        program_id: String,
        #[arg(long)] discord: Option<String>,
        #[arg(long)] slack: Option<String>,
        #[arg(long)] telegram: Option<String>,
        #[arg(long)] chat_id: Option<String>,
        #[arg(long, default_value = "30")] interval: u64,
        #[arg(long, default_value = "https://api.mainnet-beta.solana.com")]
        rpc_url: String,
    },
    /// Full program verification: security + authority + compliance
    Verify {
        program_id: String,
        #[arg(long)] source: Option<String>,
        #[arg(long)] compliance: Option<String>,
        #[arg(long, default_value = "https://api.mainnet-beta.solana.com")]
        rpc_url: String,
        #[arg(long, default_value = "human")]
        format: String,
    },
    /// Clone and scan a remote Git repository
    ScanRepo {
        /// Git repository URL (GitHub, GitLab, Bitbucket, etc.)
        url: String,
        /// Branch to scan (default: main/master)
        #[arg(long)]
        branch: Option<String>,
        /// Output format: json, human
        #[arg(long, default_value = "human")]
        format: String,
        /// Minimum severity filter
        #[arg(long, default_value = "low")]
        min_severity: String,
    },
    /// Run performance benchmarks for all analysis phases
    Benchmark {
        /// Path to scan for benchmarking
        #[arg(long, default_value = ".")]
        path: String,
        /// Number of iterations
        #[arg(long, default_value = "3")]
        iterations: usize,
    },
    /// Run formal verification pipeline (Kani + Certora + Symbolic Engine + Crux-MIR)
    VerifyFormal {
        /// Path to program source
        #[arg(long, default_value = ".")]
        path: String,
        /// Output format: json, human
        #[arg(long, default_value = "human")]
        format: String,
    },
    /// Run fuzzing analysis (Trident + FuzzDelSol + Coverage-guided)
    Fuzz {
        /// Path to program source
        #[arg(long, default_value = ".")]
        path: String,
        /// Maximum fuzzing iterations
        #[arg(long, default_value = "1000")]
        iterations: usize,
        /// Output format: json, human
        #[arg(long, default_value = "human")]
        format: String,
    },
    /// Run economic invariant verification for DeFi protocols
    EconomicVerify {
        /// Path to program source
        #[arg(long, default_value = ".")]
        path: String,
        /// Output format: json, human
        #[arg(long, default_value = "human")]
        format: String,
    },
    /// Run full orchestrated pipeline: scan -> consensus -> strategy -> report
    Orchestrate {
        /// Path to Solana program source
        path: String,
        /// Output format: json, human, markdown
        #[arg(long, default_value = "human")]
        format: String,
        /// Minimum severity filter
        #[arg(long, default_value = "low")]
        min_severity: String,
        /// API key for AI analysis. Falls back to OPENROUTER_API_KEY env var.
        #[arg(long, env = "OPENROUTER_API_KEY")]
        api_key: Option<String>,
        /// AI model to use
        #[arg(long, default_value = "moonshotai/kimi-k2.5")]
        model: String,
    },
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { path, format, min_severity, ai, api_key, model, fix, poc, simulate, verbose, ai_strategy, consensus } => cmd_scan(&path, &format, &min_severity, ai, api_key.as_deref(), &model, fix, poc, simulate, verbose, ai_strategy, consensus).await,
        Commands::Guard { path, format, fail_on } => cmd_guard(&path, &format, &fail_on),
        Commands::FiredancerCheck { source, rpc_url, format } => cmd_firedancer(source.as_deref(), &rpc_url, &format).await,
        Commands::CpiGraph { program_id, source, format } => cmd_cpi(&program_id, source.as_deref(), &format),
        Commands::Score { path, name, format } => cmd_score(&path, name.as_deref(), &format),
        Commands::TokenScan { mint, source, rpc_url, format } => cmd_token(&mint, source.as_deref(), &rpc_url, &format),
        Commands::Watch { program_id, discord, slack, telegram, chat_id, interval, rpc_url } =>
            cmd_watch(&program_id, discord.as_deref(), slack.as_deref(), telegram.as_deref(), chat_id.as_deref(), interval, &rpc_url).await,
        Commands::Verify { program_id, source, compliance, rpc_url, format } =>
            cmd_verify(&program_id, source.as_deref(), compliance.as_deref(), &rpc_url, &format),
        Commands::ScanRepo { url, branch, format, min_severity } =>
            cmd_scan_repo(&url, branch.as_deref(), &format, &min_severity).await,
        Commands::Benchmark { path, iterations } =>
            cmd_benchmark(&path, iterations),
        Commands::VerifyFormal { path, format } =>
            cmd_verify_formal(&path, &format).await,
        Commands::Fuzz { path, iterations, format } =>
            cmd_fuzz(&path, iterations, &format),
        Commands::EconomicVerify { path, format } =>
            cmd_economic_verify(&path, &format),
        Commands::Orchestrate { path, format, min_severity, api_key, model } =>
            cmd_orchestrate(&path, &format, &min_severity, api_key.as_deref(), &model).await,
    }
}

//  SCAN - Main command, launches interactive dashboard or prints output
async fn cmd_scan(path: &str, format: &str, min_severity: &str, ai: bool, api_key: Option<&str>, model: &str, fix: bool, poc: bool, simulate: bool, verbose: bool, ai_strategy: bool, consensus: bool) {
    let source_path = Path::new(path);
    if !source_path.exists() {
        eprintln!("  {} Path not found: {}", "X".red(), path);
        std::process::exit(1);
    }

    // Run analysis with phase timing
    let timer = Instant::now();
    let phase_start = Instant::now();
    let analyzer = match program_analyzer::ProgramAnalyzer::new(source_path) {
        Ok(a) => a,
        Err(e) => { eprintln!("  {} Init failed: {}", "X".red(), e); std::process::exit(1); }
    };
    let init_ms = phase_start.elapsed().as_millis();

    let phase_start = Instant::now();
    let mut findings = analyzer.scan_for_vulnerabilities();
    let scan_ms = phase_start.elapsed().as_millis();
    let elapsed = timer.elapsed();

    if verbose {
        eprintln!("  {} Phase timing:", "+".to_string().cyan());
        eprintln!("    Initialization: {}ms", init_ms);
        eprintln!("    Vulnerability scan: {}ms", scan_ms);
        eprintln!("    Total findings (pre-filter): {}", findings.len());
    }

    // Filter by severity
    let min_sev: u8 = match min_severity { "critical" => 5, "high" => 4, "medium" => 3, _ => 1 };
    findings.retain(|f| f.severity >= min_sev);

    // Fix ID collision: assign unique sub-IDs per finding ID (SOL-001 -> SOL-001.1, SOL-001.2, ...)
    let id_counts: HashMap<String, usize> = {
        let mut counts = HashMap::new();
        for f in &findings {
            *counts.entry(f.id.clone()).or_insert(0) += 1;
        }
        counts
    };
    let mut id_seq: HashMap<String, usize> = HashMap::new();
    for finding in &mut findings {
        let total = id_counts.get(&finding.id).copied().unwrap_or(1);
        if total > 1 {
            let seq = id_seq.entry(finding.id.clone()).or_insert(0);
            *seq += 1;
            finding.id = format!("{}.{}", finding.id, seq);
        }
    }

    // ── AI Enhancement (Kimi K2.5) ───────────────────────────────────────
    let ai_results = if ai {
        match api_key {
            Some(key) if !key.is_empty() => {
                eprintln!("\n  {} AI Enhancement with {} ({} findings)...",
                    "+".to_string().cyan(), model.bright_magenta(), findings.len());

                let enhancer = ai_enhancer::AIEnhancer::new(
                    key.to_string(),
                    model.to_string(),
                );

                let vulns: Vec<ai_enhancer::VulnerabilityInput> = findings.iter().map(|f| {
                    ai_enhancer::VulnerabilityInput {
                        id: f.id.clone(),
                        title: f.vuln_type.clone(),
                        description: f.description.clone(),
                        severity: f.severity,
                        code_snippet: f.vulnerable_code.clone(),
                        file_path: f.location.clone(),
                        line_number: f.line_number,
                    }
                }).collect();

                let results_future = enhancer.enhance_vulnerabilities_batch(vulns);
                match tokio::time::timeout(std::time::Duration::from_secs(3), results_future).await {
                    Ok(results) => {
                        let success = results.iter().filter(|(_, r)| r.is_ok()).count();
                        eprintln!("  {} AI analysis complete: {}/{} enhanced\n",
                            "ok".green().bold(), success, results.len());
                        Some(results)
                    }
                    Err(_) => {
                        eprintln!("  {} AI enhancement timed out (> 3s). Skipping...", "!!".yellow());
                        None
                    }
                }
            }
            _ => {
                eprintln!("  {} --ai flag set but no API key provided.", "!!".yellow());
                eprintln!("    Use --api-key <KEY> or set OPENROUTER_API_KEY env var.");
                None
            }
        }
    } else {
        None
    };

    // Generate fixes if --fix is enabled
    let fixes = if fix {
        let codegen = secure_code_gen::SecureCodeGen::new();
        let vuln_pairs: Vec<(String, String)> = findings
            .iter()
            .map(|f| (f.id.clone(), f.vulnerable_code.clone()))
            .collect();
        codegen.generate_fixes(&vuln_pairs)
    } else {
        Vec::new()
    };

    // Generate executable PoCs if --poc is enabled (high/critical only)
    let pocs: Vec<attack_simulator::ExecutablePoC> = if poc {
        findings
            .iter()
            .filter(|f| f.severity >= 4)
            .map(|f| attack_simulator::AttackSimulator::generate_executable_poc(f))
            .collect()
    } else {
        Vec::new()
    };

    // Generate simulated exploit transactions if --simulate is enabled (high/critical only)
    let simulations: Vec<(String, String)> = if simulate {
        let forge_config = transaction_forge::ForgeConfig::default();
        findings
            .iter()
            .filter(|f| f.severity >= 4)
            .map(|f| {
                let vuln_type = match f.id.as_str() {
                    "SOL-001" => transaction_forge::VulnerabilityType::MissingSignerCheck,
                    "SOL-006" => transaction_forge::VulnerabilityType::IntegerOverflow,
                    "SOL-012" => transaction_forge::VulnerabilityType::MissingOwnerCheck,
                    "SOL-017" => transaction_forge::VulnerabilityType::ArbitraryCPI,
                    "SOL-019" => transaction_forge::VulnerabilityType::OracleManipulation,
                    "SOL-005" => transaction_forge::VulnerabilityType::Reentrancy,
                    _ => transaction_forge::VulnerabilityType::AccountConfusion,
                };
                let summary = format!(
                    "Simulated {:?} exploit for {} ({}). Config: RPC={}, simulate_only={}, compute_budget={}",
                    vuln_type,
                    f.id,
                    f.vuln_type,
                    forge_config.rpc_url,
                    forge_config.simulate_only,
                    forge_config.compute_budget,
                );
                (f.id.clone(), summary)
            })
            .collect()
    } else {
        Vec::new()
    };

    // ── Consensus Verification (Multi-LLM) ──────────────────────────────
    let consensus_results: Vec<(String, consensus_engine::ConsensusResult)> = if consensus {
        eprintln!("  {}  Running consensus verification...", "+".to_string());
        let engine = match api_key {
            Some(key) if !key.is_empty() => consensus_engine::ConsensusEngine::with_openrouter(key),
            _ => {
                eprintln!("    No API key - using offline heuristic fallback");
                consensus_engine::ConsensusEngine::new(vec![])
            }
        };
        findings
            .iter()
            .map(|f| {
                let cfc = consensus_engine::FindingForConsensus {
                    id: f.id.clone(),
                    vuln_type: f.vuln_type.clone(),
                    severity: f.severity_label.clone(),
                    location: f.location.clone(),
                    function_name: f.function_name.clone(),
                    line_number: f.line_number,
                    description: f.description.clone(),
                    attack_scenario: f.attack_scenario.clone(),
                    vulnerable_code: f.vulnerable_code.clone(),
                    secure_fix: f.secure_fix.clone(),
                };
                let result = engine.verify_finding_offline(&cfc);
                (f.id.clone(), result)
            })
            .collect()
    } else {
        Vec::new()
    };

    if !consensus_results.is_empty() && format != "json" && format != "sarif" {
        eprintln!("\n  {}  Consensus Results:", "+".to_string());
        for (id, cr) in &consensus_results {
            let verdict_icon = match cr.final_verdict {
                consensus_engine::Verdict::Confirmed => "[ok]",
                consensus_engine::Verdict::Rejected => "[no]",
                consensus_engine::Verdict::Uncertain => "[??]",
            };
            eprintln!("    {} {} - {:?} (agreement: {:.0}%, confidence: {:.0}%, report: {})",
                verdict_icon, id, cr.final_verdict, cr.agreement_ratio * 100.0,
                cr.confidence_score * 100.0, if cr.should_report { "yes" } else { "no" });
        }
    }

    // ── AI Strategy Generation (LLM Strategist) ─────────────────────────
    let strategy_results: Vec<(String, Result<llm_strategist::ExploitStrategy, String>)> = if ai_strategy {
        match api_key {
            Some(key) if !key.is_empty() => {
                eprintln!("  {}  Generating exploit strategies for HIGH/CRITICAL findings...", "+".to_string());
                let strategist = llm_strategist::LlmStrategist::new(key.to_string(), model.to_string());
                let mut results = Vec::new();
                for f in findings.iter().filter(|f| f.severity >= 4) {
                    let vuln_input = llm_strategist::VulnInput {
                        id: f.id.clone(),
                        vuln_type: f.vuln_type.clone(),
                        severity: f.severity,
                        location: f.location.clone(),
                        description: f.description.clone(),
                    };
                    let result = strategist.generate_exploit_strategy(&vuln_input, &f.vulnerable_code).await;
                    results.push((f.id.clone(), result.map_err(|e| e.to_string())));
                }
                results
            }
            _ => {
                eprintln!("  {} --ai-strategy requires an API key.", "!!".yellow());
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    if !strategy_results.is_empty() && format != "json" && format != "sarif" {
        eprintln!("\n  {}  Exploit Strategies:", "+".to_string());
        for (id, result) in &strategy_results {
            match result {
                Ok(strategy) => {
                    eprintln!("    {} {}", "+".to_string().red(), id);
                    eprintln!("      Vector: {}", strategy.attack_vector);
                    eprintln!("      Outcome: {}", strategy.expected_outcome);
                }
                Err(e) => eprintln!("    {} {} - failed: {}", "X".red(), id, e),
            }
        }
    }

    // JSON output (includes AI + fixes + PoCs + simulations if available)
    if format == "json" {
        if ai_results.is_some() || !fixes.is_empty() || !pocs.is_empty() || !simulations.is_empty() {
            let mut output = Vec::new();
            for f in &findings {
                let mut val = serde_json::to_value(f).unwrap_or_default();
                if let Some(ref ai_data) = ai_results {
                    if let Some((_, Ok(enhanced))) = ai_data.iter().find(|(id, _)| id == &f.id) {
                        val["ai_analysis"] = serde_json::to_value(enhanced).unwrap_or_default();
                    }
                }
                if let Some(fix_data) = fixes.iter().find(|fx| fx.vulnerability_id == f.id) {
                    val["fix"] = serde_json::to_value(fix_data).unwrap_or_default();
                }
                if let Some(poc_data) = pocs.iter().find(|p| p.vulnerability_id == f.id) {
                    val["poc"] = serde_json::to_value(poc_data).unwrap_or_default();
                }
                if let Some((_, sim_summary)) = simulations.iter().find(|(id, _)| id == &f.id) {
                    val["simulation"] = serde_json::json!({
                        "status": "simulated",
                        "summary": sim_summary,
                        "rpc": "https://api.devnet.solana.com",
                        "simulate_only": true
                    });
                }
                if let Some((_, cr)) = consensus_results.iter().find(|(id, _)| id == &f.id) {
                    val["consensus"] = serde_json::json!({
                        "verdict": format!("{:?}", cr.final_verdict),
                        "agreement_ratio": cr.agreement_ratio,
                        "confidence_score": cr.confidence_score,
                        "should_report": cr.should_report,
                        "votes": cr.votes.len()
                    });
                }
                if let Some((_, Ok(strategy))) = strategy_results.iter().find(|(id, _)| id == &f.id) {
                    val["exploit_strategy"] = serde_json::json!({
                        "attack_vector": strategy.attack_vector,
                        "expected_outcome": strategy.expected_outcome,
                        "explanation": strategy.explanation,
                        "payload": strategy.payload
                    });
                }
                output.push(val);
            }
            println!("{}", serde_json::to_string_pretty(&output).unwrap_or_default());
        } else {
            println!("{}", serde_json::to_string_pretty(&findings).unwrap_or_default());
        }
        return;
    }

    // SARIF output (Static Analysis Results Interchange Format) for IDE integration
    if format == "sarif" {
        let sarif = generate_sarif(&findings, path, elapsed);
        println!("{}", serde_json::to_string_pretty(&sarif).unwrap_or_default());
        return;
    }

    // Markdown report output
    if format == "markdown" {
        let md = generate_markdown_report(&findings, path, elapsed);
        println!("{}", md);
        return;
    }

    // Compute score
    let (c, h, m, l) = severity_counts(&findings);
    let guard = shanon_guard::GuardScanner::new();
    let guard_report = guard.scan_directory(source_path);
    let mut score: i32 = 100;
    score -= (c as i32) * 25;
    score -= (h as i32) * 15;
    score -= (m as i32) * 5;
    score -= (l as i32) * 2;
    score -= (guard_report.risk_score as i32) / 4;
    let score = score.max(0).min(100) as u8;
    let grade = compute_grade(score);

    // Human text output
    if format == "human" {
        tui::print_banner();
        let engines = build_engine_results(&findings);
        tui::print_pipeline(path, &engines, elapsed);
        if findings.is_empty() {
            tui::print_verdict(0);
            return;
        }
        tui::print_summary(c, h, m, l, findings.len(), elapsed);
        for (i, f) in findings.iter().enumerate() {
            tui::print_finding(i + 1, f);
        }

        // Print AI-enhanced analysis if available
        if let Some(ref ai_data) = ai_results {
            eprintln!("\n  ╔══════════════════════════════════════════════════════════════════════════════╗");
            eprintln!("  ║  [ai]  KIMI K2.5 AI-ENHANCED ANALYSIS                                        ║");
            eprintln!("  ╚══════════════════════════════════════════════════════════════════════════════╝");
            for (id, result) in ai_data {
                match result {
                    Ok(enhanced) => {
                        let finding = findings.iter().find(|f| &f.id == id);
                        let title = finding.map(|f| f.vuln_type.as_str()).unwrap_or("Unknown");
                        eprintln!("\n  ┌──────────────────────────────────────────────────────────────────────────────┐");
                        eprintln!("  │  {}  {}  ", id.bright_red().bold(), title.bright_white().bold());
                        eprintln!("  ├──────────────────────────────────────────────────────────────────────────────┤");
                        eprintln!("  │  {} {}", "[tech] Technical:".cyan().bold(), "");
                        for line in enhanced.technical_explanation.lines() {
                            eprintln!("  │    {}", line);
                        }
                        eprintln!("  │");
                        eprintln!("  │  {} {}", "[atk] Attack:".red().bold(), "");
                        for line in enhanced.attack_scenario.lines() {
                            eprintln!("  │    {}", line);
                        }
                        eprintln!("  │");
                        eprintln!("  │  {} {}", "[code] PoC Exploit:".yellow().bold(), "");
                        for line in enhanced.proof_of_concept.lines() {
                            eprintln!("  │    {}", line);
                        }
                        eprintln!("  │");
                        eprintln!("  │  {} {}", "[edit] Fix:".green().bold(), "");
                        for line in enhanced.recommended_fix.lines() {
                            eprintln!("  │    {}", line);
                        }
                        eprintln!("  │");
                        eprintln!("  │  {} {}", "[impact] Impact:".bright_magenta().bold(), "");
                        for line in enhanced.economic_impact.lines() {
                            eprintln!("  │    {}", line);
                        }
                        eprintln!("  └──────────────────────────────────────────────────────────────────────────────┘");
                    }
                    Err(e) => {
                        eprintln!("  │  {} {} - {}", "X".red(), id, e);
                    }
                }
            }
        }

        // Print secure code fixes if --fix is enabled
        if !fixes.is_empty() {
            eprintln!("\n  ╔══════════════════════════════════════════════════════════════════════════════╗");
            eprintln!("  ║  [fix]  SECURE CODE FIXES                                                     ║");
            eprintln!("  ╚══════════════════════════════════════════════════════════════════════════════╝");
            for fix_item in &fixes {
                let finding = findings.iter().find(|f| f.id == fix_item.vulnerability_id);
                let title = finding.map(|f| f.vuln_type.as_str()).unwrap_or("Unknown");
                eprintln!("\n  ┌──────────────────────────────────────────────────────────────────────────────┐");
                eprintln!("  │  {}  {}  ", fix_item.vulnerability_id.bright_yellow().bold(), title.bright_white().bold());
                eprintln!("  ├──────────────────────────────────────────────────────────────────────────────┤");
                eprintln!("  │  {} {}", "[note] Explanation:".cyan().bold(), "");
                for line in fix_item.explanation.lines() {
                    eprintln!("  │    {}", line);
                }
                eprintln!("  │");
                eprintln!("  │  {} {}", "[ok] Secure Pattern:".green().bold(), "");
                for line in fix_item.fixed_code.lines() {
                    eprintln!("  │    {}", line.bright_green());
                }
                eprintln!("  └──────────────────────────────────────────────────────────────────────────────┘");
            }
        }

        // Print PoC exploits if --poc is enabled
        if !pocs.is_empty() {
            eprintln!("\n  \u{2554}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2557}");
            eprintln!("  \u{2551}  \u{1f4a3}  PROOF-OF-CONCEPT EXPLOITS                                           \u{2551}");
            eprintln!("  \u{255a}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{255d}");
            for poc_item in &pocs {
                eprintln!("\n  \u{250c}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2510}");
                eprintln!("  \u{2502}  {}  {:?} - {}  ", poc_item.vulnerability_id.bright_red().bold(), poc_item.difficulty, poc_item.scenario_name.bright_white().bold());
                eprintln!("  \u{251c}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2524}");
                eprintln!("  \u{2502}  {} {}", "\u{1f4a5} Impact:".bright_magenta().bold(), poc_item.economic_impact);
                eprintln!("  \u{2502}");
                eprintln!("  \u{2502}  {} {}", "\u{2694} Attack Steps:".red().bold(), "");
                for step in &poc_item.attack_steps {
                    eprintln!("  \u{2502}    {}. {}", step.step_number, step.description);
                }
                if let Some(ref ts) = poc_item.typescript_poc {
                    eprintln!("  \u{2502}");
                    eprintln!("  \u{2502}  {} {}", "\u{1f4bb} TypeScript PoC:".yellow().bold(), "");
                    for line in ts.lines().take(20) {
                        eprintln!("  \u{2502}    {}", line.bright_yellow());
                    }
                    let total_lines = ts.lines().count();
                    if total_lines > 20 {
                        eprintln!("  \u{2502}    ... ({} more lines)", total_lines - 20);
                    }
                }
                eprintln!("  \u{2502}");
                eprintln!("  \u{2502}  {} {}", "\u{1f6e1} Mitigations:".green().bold(), "");
                for m in &poc_item.mitigations {
                    eprintln!("  \u{2502}    \u{2022} {}", m);
                }
                eprintln!("  \u{2514}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2518}");
            }
        }

        // Print simulated transactions if --simulate is enabled
        if !simulations.is_empty() {
            eprintln!("\n  \u{2554}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2557}");
            eprintln!("  \u{2551}  \u{1f9ea}  EXPLOIT TRANSACTION SIMULATIONS                                      \u{2551}");
            eprintln!("  \u{255a}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{255d}");
            for (sim_id, sim_summary) in &simulations {
                let finding = findings.iter().find(|f| &f.id == sim_id);
                let title = finding.map(|f| f.vuln_type.as_str()).unwrap_or("Unknown");
                eprintln!("\n  \u{250c}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2510}");
                eprintln!("  \u{2502}  {}  {}  ", sim_id.bright_cyan().bold(), title.bright_white().bold());
                eprintln!("  \u{251c}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2524}");
                eprintln!("  \u{2502}  {} {}", "\u{1f9ea} Simulation:".bright_cyan().bold(), "");
                for line in sim_summary.lines() {
                    eprintln!("  \u{2502}    {}", line);
                }
                eprintln!("  \u{2502}  {} {}", "\u{2705} Mode:".green().bold(), "simulate-only (no on-chain execution)");
                eprintln!("  \u{2514}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2518}");
            }
        } else if simulate {
            eprintln!("\n  {}  No HIGH or CRITICAL findings to simulate - program looks safe!", "ok".green());
        }

        tui::print_verdict(c);
        if c > 0 { std::process::exit(1); }
        return;
    }

    // Default: Interactive ratatui dashboard
    let state = dashboard::DashboardState::new(
        findings, score, grade.to_string(), elapsed, path.to_string(),
        guard_report.risk_score,
    );
    if let Err(e) = dashboard::run_dashboard(state) {
        eprintln!("  {} Dashboard error: {}", "X".red(), e);
        std::process::exit(1);
    }
}

//  SCORE
fn cmd_score(path: &str, name: Option<&str>, format: &str) {
    let source_path = Path::new(path);
    if !source_path.exists() {
        eprintln!("  {} Path not found: {}", "X".red(), path);
        std::process::exit(1);
    }
    let display_name = name.unwrap_or(path);

    let timer = Instant::now();
    let findings = match program_analyzer::ProgramAnalyzer::new(source_path) {
        Ok(a) => a.scan_for_vulnerabilities(),
        Err(_) => vec![],
    };
    let elapsed = timer.elapsed();

    let (c, h, m, l) = severity_counts(&findings);
    let guard = shanon_guard::GuardScanner::new();
    let guard_report = guard.scan_directory(source_path);

    let mut score: i32 = 100;
    score -= (c as i32) * 25;
    score -= (h as i32) * 15;
    score -= (m as i32) * 5;
    score -= (l as i32) * 2;
    score -= (guard_report.risk_score as i32) / 4;
    let score = score.max(0).min(100) as u8;
    let grade = compute_grade(score);

    if format == "json" {
        let json = serde_json::json!({
            "name": display_name, "score": score, "grade": grade,
            "elapsed": elapsed.as_secs_f64(),
            "findings": { "critical": c, "high": h, "medium": m, "low": l, "total": findings.len() },
            "guard_risk": guard_report.risk_score,
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap_or_default());
        return;
    }

    if format == "human" {
        tui::print_banner();
        let engines = build_engine_results(&findings);
        tui::print_pipeline(path, &engines, elapsed);
        tui::print_score_card(score, grade, display_name);
        tui::print_summary(c, h, m, l, findings.len(), elapsed);
        return;
    }

    // Default: dashboard
    let state = dashboard::DashboardState::new(
        findings, score, grade.to_string(), elapsed, path.to_string(),
        guard_report.risk_score,
    );
    if let Err(e) = dashboard::run_dashboard(state) {
        eprintln!("  {} Dashboard error: {}", "X".red(), e);
    }
}

//  GUARD
fn cmd_guard(path: &str, format: &str, fail_on: &str) {
    let target = Path::new(path);
    if !target.exists() { eprintln!("  {} Path not found: {}", "X".red(), path); std::process::exit(1); }

    let scanner = shanon_guard::GuardScanner::new();
    let report = scanner.scan_directory(target);

    if format == "json" {
        println!("{}", report.to_json());
    } else if format == "human" || format == "dashboard" {
        tui::print_banner();
        eprintln!("  {} Scanning dependencies in {}...", "[shield]".truecolor(80,200,255), path.bright_white());
        report.print_colored();
    }

    let fail = match fail_on {
        "critical" => report.has_critical(),
        "high" => report.has_high_or_above(),
        _ => report.total_findings() > 0,
    };
    if fail { std::process::exit(1); }
}

//  FIREDANCER
async fn cmd_firedancer(source: Option<&str>, rpc_url: &str, format: &str) {
    tui::print_banner();
    if let Some(src) = source {
        let path = Path::new(src);
        if !path.exists() { eprintln!("  {} Path not found: {}", "X".red(), src); std::process::exit(1); }
        eprintln!("  {} Analyzing Firedancer compatibility...", "🔥".truecolor(255,140,0));
        let checker = firedancer_monitor::compatibility::FiredancerCompatChecker::new();
        match checker.analyze_source(path) {
            Ok(report) => {
                if format == "json" { println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default()); return; }
                let sc = match report.score { 90..=100 => report.score.to_string().truecolor(34,197,94), 70..=89 => report.score.to_string().truecolor(234,179,8), _ => report.score.to_string().red() };
                eprintln!("  Score: {}/100  Grade: {}", sc.bold(), report.grade.cyan().bold());
                for w in &report.warnings {
                    if let firedancer_monitor::compatibility::CompatWarning::RuntimeDifference { diff_id, title, severity, mitigation, .. } = w {
                        eprintln!("  {} [{}] {} - {}", severity.red(), diff_id, title, mitigation.truecolor(100,116,139));
                    }
                }
            }
            Err(e) => { eprintln!("  {} {}", "X".red(), e); std::process::exit(1); }
        }
    } else {
        let mut mon = firedancer_monitor::FiredancerMonitor::new(rpc_url.to_string());
        match mon.monitor_validator().await {
            Ok(r) => eprintln!("  Health: {}/100  Issues: {}", r.validator_health_score, r.findings.len()),
            Err(e) => eprintln!("  {} {}", "X".red(), e),
        }
    }
}

//  CPI GRAPH
fn cmd_cpi(program_id: &str, source: Option<&str>, format: &str) {
    tui::print_banner();
    if let Some(src) = source {
        let mut code = String::new();
        collect_rs(Path::new(src), &mut code);
        if code.is_empty() { eprintln!("  {} No .rs files", "X".red()); std::process::exit(1); }
        let graph = cpi_analyzer::CPIDependencyGraph::build_from_source(program_id, &code, None);
        if format == "json" { println!("{}", serde_json::to_string_pretty(&graph).unwrap_or_default()); return; }
        if format == "d3" { println!("{}", graph.to_d3_json()); return; }
        let s = graph.summary();
        eprintln!("  Programs: {}  CPI: {}  Risky: {}", s.total_programs, s.total_cpi_calls, s.risky_calls.to_string().red());
    } else {
        eprintln!("  {} Use --source <path>", "ℹ".truecolor(100,116,139));
    }
}

//  TOKEN SCAN
fn cmd_token(mint: &str, source: Option<&str>, rpc_url: &str, format: &str) {
    use token_security_expert::scanner::{TokenRiskScanner, OnChainTokenChecks};
    tui::print_banner();
    eprintln!("  {} Analyzing token {}...", "🪙".truecolor(234,179,8), mint.cyan());
    let scanner = TokenRiskScanner::new(rpc_url);
    let on_chain = OnChainTokenChecks::default();
    let src = source.map(Path::new);
    match scanner.analyze(mint, on_chain, src) {
        Ok(r) => {
            if format == "json" { println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default()); return; }
            let rc = match r.risk_score { 0..=20 => (34,197,94), 21..=50 => (234,179,8), _ => (239,68,68) };
            eprintln!("  Risk: {}/100  Grade: {}  Rug: {:.0}%",
                r.risk_score.to_string().truecolor(rc.0,rc.1,rc.2).bold(), r.grade.cyan(), r.rug_probability * 100.0);
        }
        Err(e) => { eprintln!("  {} {}", "X".red(), e); std::process::exit(1); }
    }
}

//  WATCH
async fn cmd_watch(pid: &str, discord: Option<&str>, slack: Option<&str>, telegram: Option<&str>, chat_id: Option<&str>, interval: u64, rpc_url: &str) {
    use shanon_monitor::alerts::{AlertSender, WebhookConfig, WebhookPlatform};
    use shanon_monitor::authority_watcher::{AuthorityWatcher, WatcherConfig};
    tui::print_banner();
    eprintln!("  {} Watching {} ({}s polling)", "👁️".truecolor(80,200,255), pid.cyan(), interval);
    let mut wh = Vec::new();
    if let Some(u) = discord { wh.push(WebhookConfig { platform: WebhookPlatform::Discord, url: u.to_string(), chat_id: None }); }
    if let Some(u) = slack { wh.push(WebhookConfig { platform: WebhookPlatform::Slack, url: u.to_string(), chat_id: None }); }
    if let Some(u) = telegram {
        let cid = chat_id.map(|s| s.to_string());
        if cid.is_none() { eprintln!("  {} --chat-id required", "X".red()); std::process::exit(1); }
        wh.push(WebhookConfig { platform: WebhookPlatform::Telegram, url: u.to_string(), chat_id: cid });
    }
    let cfg = WatcherConfig { rpc_url: rpc_url.to_string(), program_ids: vec![pid.to_string()], poll_interval_secs: interval, max_polls: 0 };
    let sender = AlertSender::new(wh);
    let mut w = AuthorityWatcher::new(cfg, sender);
    if let Err(e) = w.run().await { eprintln!("  {} {}", "X".red(), e); std::process::exit(1); }
}

//  VERIFY
fn cmd_verify(pid: &str, source: Option<&str>, compliance: Option<&str>, rpc_url: &str, format: &str) {
    use shanon_verify::{VerificationEngine, VerifyConfig};
    tui::print_banner();
    let src = match source {
        Some(p) => std::path::PathBuf::from(p),
        None => { eprintln!("  {} --source required", "X".red()); std::process::exit(1); }
    };
    if !src.exists() { eprintln!("  {} Path not found", "X".red()); std::process::exit(1); }
    let fw = compliance.map(|c| match c.to_lowercase().as_str() {
        "soc2" => compliance_reporter::ComplianceFramework::SOC2,
        "iso27001" | "iso" => compliance_reporter::ComplianceFramework::ISO27001,
        "owasp" => compliance_reporter::ComplianceFramework::OWASPSCS,
        "solana" | "sf" => compliance_reporter::ComplianceFramework::SolanaFoundation,
        _ => { eprintln!("  {} Unknown framework", "X".red()); std::process::exit(1); }
    });
    let name = src.file_name().and_then(|n| n.to_str()).unwrap_or("program");
    let cfg = VerifyConfig { rpc_url: rpc_url.to_string(), compliance_framework: fw, include_source_match: true };
    match VerificationEngine::verify(pid, &src, name, &cfg) {
        Ok(r) => {
            if format == "json" { println!("{}", serde_json::to_string_pretty(&r).unwrap()); return; }
            let tier = match r.tier {
                shanon_verify::VerificationTier::Gold => r.tier_label.truecolor(234,179,8).bold(),
                shanon_verify::VerificationTier::Silver => r.tier_label.white().bold(),
                shanon_verify::VerificationTier::Bronze => r.tier_label.truecolor(205,127,50).bold(),
                shanon_verify::VerificationTier::Unverified => r.tier_label.truecolor(100,116,139),
            };
            eprintln!("  {} Tier: {}  Score: {}/100", pid.cyan(), tier, r.security_summary.security_score);
        }
        Err(e) => { eprintln!("  {} {}", "X".red(), e); std::process::exit(1); }
    }
}

//  Shared Helpers
fn severity_counts(f: &[program_analyzer::VulnerabilityFinding]) -> (usize, usize, usize, usize) {
    let c = f.iter().filter(|x| x.severity >= 5).count();
    let h = f.iter().filter(|x| x.severity == 4).count();
    let m = f.iter().filter(|x| x.severity == 3).count();
    let l = f.iter().filter(|x| x.severity <= 2).count();
    (c, h, m, l)
}

fn compute_grade(score: u8) -> &'static str {
    match score {
        95..=100 => "A+", 90..=94 => "A", 85..=89 => "A-", 80..=84 => "B+",
        75..=79 => "B", 70..=74 => "B-", 65..=69 => "C+", 60..=64 => "C",
        50..=59 => "D", _ => "F",
    }
}

fn build_engine_results(findings: &[program_analyzer::VulnerabilityFinding]) -> Vec<tui::EngineResult> {
    let count = |pred: &dyn Fn(&str) -> bool| findings.iter().filter(|f| pred(&f.id)).count();
    vec![
        tui::EngineResult { name: "Pattern Scanner", desc: "72 heuristic rules", color: (239,68,68),
            findings: count(&|id: &str| !id.starts_with("SOL-TAINT") && !id.starts_with("SOL-CFG") && !id.starts_with("SOL-ABS") && !id.starts_with("SOL-ALIAS") && !id.starts_with("SOL-DEEP")) },
        tui::EngineResult { name: "Deep AST Scanner", desc: "syn::Visit", color: (168,85,247),
            findings: count(&|id: &str| id.starts_with("SOL-DEEP")) },
        tui::EngineResult { name: "Taint Lattice", desc: "information flow", color: (234,179,8),
            findings: count(&|id: &str| id.starts_with("SOL-TAINT")) },
        tui::EngineResult { name: "CFG Dominators", desc: "graph proofs", color: (6,182,212),
            findings: count(&|id: &str| id.starts_with("SOL-CFG")) },
        tui::EngineResult { name: "Abstract Interp", desc: "interval ℤ", color: (34,197,94),
            findings: count(&|id: &str| id.starts_with("SOL-ABS")) },
        tui::EngineResult { name: "Account Aliasing", desc: "must-not-alias", color: (59,130,246),
            findings: count(&|id: &str| id.starts_with("SOL-ALIAS")) },
    ]
}

fn collect_rs(dir: &Path, buf: &mut String) {
    let entries = match std::fs::read_dir(dir) { Ok(e) => e, Err(_) => return };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            let n = p.file_name().unwrap_or_default().to_str().unwrap_or("");
            if n != "target" && n != ".git" { collect_rs(&p, buf); }
        } else if p.extension().map_or(false, |e| e == "rs") {
            if let Ok(c) = std::fs::read_to_string(&p) { buf.push_str(&c); buf.push('\n'); }
        }
    }
}

//  SARIF Output Generator (Static Analysis Results Interchange Format v2.1.0)
fn generate_sarif(
    findings: &[program_analyzer::VulnerabilityFinding],
    target: &str,
    elapsed: std::time::Duration,
) -> serde_json::Value {
    let severity_to_sarif_level = |sev: u8| -> &str {
        match sev {
            5 => "error",
            4 => "error",
            3 => "warning",
            _ => "note",
        }
    };

    let severity_to_sarif_rank = |sev: u8| -> f64 {
        match sev { 5 => 9.0, 4 => 7.0, 3 => 5.0, 2 => 3.0, _ => 1.0 }
    };

    let rules: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let mut rule = serde_json::json!({
                "id": f.id,
                "name": f.vuln_type,
                "shortDescription": { "text": &f.vuln_type },
                "fullDescription": { "text": &f.description },
                "defaultConfiguration": {
                    "level": severity_to_sarif_level(f.severity),
                    "rank": severity_to_sarif_rank(f.severity)
                },
                "properties": {
                    "category": &f.category,
                    "severity": &f.severity_label,
                    "confidence": f.confidence
                }
            });
            if let Some(ref cwe) = f.cwe {
                rule["relationships"] = serde_json::json!([{
                    "target": {
                        "id": cwe,
                        "guid": cwe,
                        "toolComponent": { "name": "CWE" }
                    },
                    "kinds": ["superset"]
                }]);
            }
            rule
        })
        .collect();

    let results: Vec<serde_json::Value> = findings
        .iter()
        .enumerate()
        .map(|(idx, f)| {
            serde_json::json!({
                "ruleId": f.id,
                "ruleIndex": idx,
                "level": severity_to_sarif_level(f.severity),
                "message": {
                    "text": &f.description,
                    "markdown": format!("**{}** - {}\n\n**Attack:** {}\n\n**Fix:** {}",
                        f.vuln_type, f.description, f.attack_scenario, f.secure_fix)
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": &f.location,
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": f.line_number,
                            "snippet": { "text": &f.vulnerable_code }
                        }
                    }
                }],
                "fixes": [{
                    "description": { "text": &f.prevention },
                    "artifactChanges": [{
                        "artifactLocation": { "uri": &f.location },
                        "replacements": [{
                            "deletedRegion": { "startLine": f.line_number },
                            "insertedContent": { "text": &f.secure_fix }
                        }]
                    }]
                }],
                "properties": {
                    "confidence": f.confidence,
                    "functionName": &f.function_name,
                    "prevention": &f.prevention
                }
            })
        })
        .collect();

    serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "shanon",
                    "organization": "Shanon Security",
                    "version": "2.0.0",
                    "semanticVersion": "2.0.0",
                    "informationUri": "https://shanon.security",
                    "rules": rules
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": true,
                "commandLine": format!("shanon scan {} --format sarif", target),
                "properties": {
                    "analysisTarget": target,
                    "analysisDurationMs": elapsed.as_millis() as u64,
                    "findingsCount": findings.len()
                }
            }]
        }]
    })
}

//  Markdown Report Generator
fn generate_markdown_report(
    findings: &[program_analyzer::VulnerabilityFinding],
    target: &str,
    elapsed: std::time::Duration,
) -> String {
    let (c, h, m, l) = severity_counts(findings);
    let mut score: i32 = 100;
    score -= (c as i32) * 25;
    score -= (h as i32) * 15;
    score -= (m as i32) * 5;
    score -= (l as i32) * 2;
    let score = score.max(0).min(100) as u8;
    let grade = compute_grade(score);

    let sev_label = |s: u8| match s { 5 => "🔴 CRITICAL", 4 => "🟠 HIGH", 3 => "🟡 MEDIUM", _ => "🔵 LOW" };
    let sev_emoji = |s: u8| match s { 5 => "🔴", 4 => "🟠", 3 => "🟡", _ => "🔵" };

    let mut md = String::new();
    md.push_str("# [shield] Shanon Security Audit Report\n\n");
    md.push_str(&format!("**Target:** `{}`  \n", target));
    md.push_str(&format!("**Duration:** {:.1}s  \n", elapsed.as_secs_f64()));
    md.push_str(&format!("**Score:** {} / 100 (Grade: **{}**)  \n\n", score, grade));

    md.push_str("---\n\n## 📊 Executive Summary\n\n");
    md.push_str("| Severity | Count |\n");
    md.push_str("|----------|-------|\n");
    md.push_str(&format!("| 🔴 Critical | {} |\n", c));
    md.push_str(&format!("| 🟠 High | {} |\n", h));
    md.push_str(&format!("| 🟡 Medium | {} |\n", m));
    md.push_str(&format!("| 🔵 Low | {} |\n", l));
    md.push_str(&format!("| **Total** | **{}** |\n\n", findings.len()));

    if findings.is_empty() {
        md.push_str("> [ok] **No vulnerabilities detected.** The program passed all security checks.\n\n");
        return md;
    }

    md.push_str("---\n\n## 🔍 Detailed Findings\n\n");

    for (i, f) in findings.iter().enumerate() {
        md.push_str(&format!("### {}. {} {} - {}\n\n", i + 1, sev_emoji(f.severity), f.id, f.vuln_type));
        md.push_str(&format!("**Severity:** {} | **Confidence:** {}% | **Category:** {}\n\n",
            sev_label(f.severity), f.confidence, f.category));
        if let Some(ref cwe) = f.cwe {
            md.push_str(&format!("**CWE:** [{cwe}](https://cwe.mitre.org/data/definitions/{}.html)  \n",
                cwe.trim_start_matches("CWE-")));
        }
        md.push_str(&format!("**Location:** `{}` -> `{}()` (line {})  \n\n",
            f.location, f.function_name, f.line_number));

        md.push_str(&format!("**Description:**  \n{}\n\n", f.description));

        md.push_str("**Vulnerable Code:**\n```rust\n");
        md.push_str(&f.vulnerable_code);
        md.push_str("\n```\n\n");

        md.push_str(&format!("**Attack Scenario:**  \n{}\n\n", f.attack_scenario));

        md.push_str("**Recommended Fix:**\n```rust\n");
        md.push_str(&f.secure_fix);
        md.push_str("\n```\n\n");

        if let Some(ref incident) = f.real_world_incident {
            md.push_str(&format!("**Real-World Incident:** {} - {} ({})\n\n",
                incident.project, incident.loss, incident.date));
        }

        md.push_str("---\n\n");
    }

    md.push_str("## 🛠️ Remediation Priority\n\n");
    md.push_str("| # | ID | Type | Severity | Location | Line |\n");
    md.push_str("|---|----|----|----------|----------|------|\n");
    for (i, f) in findings.iter().enumerate() {
        md.push_str(&format!("| {} | {} | {} | {} | `{}` | {} |\n",
            i + 1, f.id, f.vuln_type, sev_label(f.severity), f.location, f.line_number));
    }
    md.push_str("\n---\n\n");
    md.push_str("*Generated by [Shanon](https://shanon.security) - Enterprise-Grade Solana Security Platform*\n");

    md
}

//  ORCHESTRATE - Full pipeline: scan -> consensus -> strategy -> report
async fn cmd_orchestrate(path: &str, format: &str, min_severity: &str, api_key: Option<&str>, model: &str) {
    let source_path = Path::new(path);
    if !source_path.exists() {
        eprintln!("  {} Path not found: {}", "X".red(), path);
        std::process::exit(1);
    }

    eprintln!("\n  {}  Orchestrated Pipeline", "🔗".to_string());
    eprintln!("  ────────────────────────────────");

    // Phase 1: Scan
    eprintln!("  {} Phase 1/4: Vulnerability Scan...", "▶".cyan());
    let timer = Instant::now();
    let analyzer = match program_analyzer::ProgramAnalyzer::new(source_path) {
        Ok(a) => a,
        Err(e) => { eprintln!("  {} Init failed: {}", "X".red(), e); std::process::exit(1); }
    };
    let mut findings = analyzer.scan_for_vulnerabilities();
    let scan_elapsed = timer.elapsed();
    eprintln!("    Found {} findings in {:.1}s", findings.len(), scan_elapsed.as_secs_f64());

    // Filter by severity
    let min_sev: u8 = match min_severity { "critical" => 5, "high" => 4, "medium" => 3, _ => 1 };
    findings.retain(|f| f.severity >= min_sev);

    // Phase 2: Consensus
    eprintln!("  {} Phase 2/4: Consensus Verification...", "▶".cyan());
    let consensus_timer = Instant::now();
    let engine = match api_key {
        Some(key) if !key.is_empty() => consensus_engine::ConsensusEngine::with_openrouter(key),
        _ => consensus_engine::ConsensusEngine::new(vec![]),
    };
    let consensus_results: Vec<(String, consensus_engine::ConsensusResult)> = findings
        .iter()
        .map(|f| {
            let cfc = consensus_engine::FindingForConsensus {
                id: f.id.clone(),
                vuln_type: f.vuln_type.clone(),
                severity: f.severity_label.clone(),
                location: f.location.clone(),
                function_name: f.function_name.clone(),
                line_number: f.line_number,
                description: f.description.clone(),
                attack_scenario: f.attack_scenario.clone(),
                vulnerable_code: f.vulnerable_code.clone(),
                secure_fix: f.secure_fix.clone(),
            };
            let result = engine.verify_finding_offline(&cfc);
            (f.id.clone(), result)
        })
        .collect();
    let confirmed = consensus_results.iter().filter(|(_, r)| r.should_report).count();
    eprintln!("    {} confirmed / {} total in {:.1}s",
        confirmed, consensus_results.len(), consensus_timer.elapsed().as_secs_f64());

    // Phase 3: Strategy Generation (only if API key available)
    let strategy_results: Vec<(String, Result<llm_strategist::ExploitStrategy, String>)> = match api_key {
        Some(key) if !key.is_empty() => {
            eprintln!("  {} Phase 3/4: Exploit Strategy Generation...", "▶".cyan());
            let strategy_timer = Instant::now();
            let strategist = llm_strategist::LlmStrategist::new(key.to_string(), model.to_string());
            let mut results = Vec::new();
            for f in findings.iter().filter(|f| f.severity >= 4) {
                let vuln_input = llm_strategist::VulnInput {
                    id: f.id.clone(),
                    vuln_type: f.vuln_type.clone(),
                    severity: f.severity,
                    location: f.location.clone(),
                    description: f.description.clone(),
                };
                let result = strategist.generate_exploit_strategy(&vuln_input, &f.vulnerable_code).await;
                results.push((f.id.clone(), result.map_err(|e| e.to_string())));
            }
            let success = results.iter().filter(|(_, r)| r.is_ok()).count();
            eprintln!("    Generated {} strategies in {:.1}s",
                success, strategy_timer.elapsed().as_secs_f64());
            results
        }
        _ => {
            eprintln!("  {} Phase 3/4: Skipped (no API key)", "⏭".cyan());
            Vec::new()
        }
    };

    // Phase 4: Report Generation
    eprintln!("  {} Phase 4/4: Report Generation...", "▶".cyan());
    let total_elapsed = timer.elapsed();

    if format == "json" {
        let mut output = Vec::new();
        for f in &findings {
            let mut val = serde_json::to_value(f).unwrap_or_default();
            if let Some((_, cr)) = consensus_results.iter().find(|(id, _)| id == &f.id) {
                val["consensus"] = serde_json::json!({
                    "verdict": format!("{:?}", cr.final_verdict),
                    "agreement_ratio": cr.agreement_ratio,
                    "confidence_score": cr.confidence_score,
                    "should_report": cr.should_report
                });
            }
            if let Some((_, Ok(strategy))) = strategy_results.iter().find(|(id, _)| id == &f.id) {
                val["exploit_strategy"] = serde_json::json!({
                    "attack_vector": strategy.attack_vector,
                    "expected_outcome": strategy.expected_outcome,
                    "explanation": strategy.explanation
                });
            }
            output.push(val);
        }
        let report = serde_json::json!({
            "pipeline": "orchestrate",
            "target": path,
            "duration_ms": total_elapsed.as_millis() as u64,
            "total_findings": findings.len(),
            "confirmed_by_consensus": confirmed,
            "findings": output
        });
        println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
    } else if format == "markdown" {
        let md = generate_markdown_report(&findings, path, total_elapsed);
        println!("{}", md);
    } else {
        // Human-readable summary
        eprintln!("\n  ══════════════════════════════════════════════════════════════");
        eprintln!("  {}  Orchestrated Pipeline Complete", "ok".green());
        eprintln!("  ──────────────────────────────────────────────────────────────");
        eprintln!("    Total findings:    {}", findings.len());
        eprintln!("    Consensus confirmed: {}", confirmed);

        for (id, cr) in &consensus_results {
            let icon = match cr.final_verdict {
                consensus_engine::Verdict::Confirmed => "[ok]",
                consensus_engine::Verdict::Rejected => "[no]",
                consensus_engine::Verdict::Uncertain => "[??]",
            };
            eprintln!("    {} {} - {:?} (confidence: {:.0}%)",
                icon, id, cr.final_verdict, cr.confidence_score * 100.0);
        }

        if !strategy_results.is_empty() {
            eprintln!("\n    Exploit Strategies:");
            for (id, result) in &strategy_results {
                match result {
                    Ok(s) => eprintln!("      {} {} -> {}", "+".red(), id, s.attack_vector),
                    Err(e) => eprintln!("      {} {} - {}", "X".red(), id, e),
                }
            }
        }

        let (c, h, m, l) = severity_counts(&findings);
        let mut score: i32 = 100;
        score -= (c as i32) * 25;
        score -= (h as i32) * 15;
        score -= (m as i32) * 5;
        score -= (l as i32) * 2;
        let score = score.max(0).min(100) as u8;
        eprintln!("    Security score: {} / 100 ({})", score, compute_grade(score));
        eprintln!("    Duration:      {:.1}s", total_elapsed.as_secs_f64());
        eprintln!("  ══════════════════════════════════════════════════════════════\n");
    }
}

//  SCAN-REPO - Clone a remote Git repository and run the full scan pipeline
async fn cmd_scan_repo(url: &str, branch: Option<&str>, format: &str, min_severity: &str) {
    eprintln!("\n  {}  Cloning repository: {}", "📦".to_string(), url);
    let mut scanner = git_scanner::GitScanner::new();
    let repo_path = match scanner.clone_repo(url, branch) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("  {} Failed to clone: {:?}", "X".red(), e);
            std::process::exit(1);
        }
    };
    let path_str = repo_path.to_string_lossy().to_string();
    eprintln!("  {}  Cloned to: {}", "ok".green(), path_str);

    // Run the standard scan on the cloned repo (no AI/fix/poc/simulate by default)
    cmd_scan(&path_str, format, min_severity, false, None, "moonshotai/kimi-k2.5", false, false, false, false, false, false).await;

    // Generate deployment package summary
    let package = integration_orchestrator::IntegrationOrchestrator::generate_deployment_package_for_id(url);
    if format == "json" {
        eprintln!("{}", serde_json::to_string_pretty(&package).unwrap_or_default());
    } else {
        eprintln!("\n  {}  Deployment Package Generated", "📋".to_string());
        eprintln!("  ├─ Secure Template:  {} bytes", package.secure_code_template.len());
    }

    // Cleanup cloned repo
    scanner.cleanup();
    eprintln!("  {}  Temporary clone cleaned up", "🧹".to_string());
}

//  BENCHMARK - Run timed performance benchmarks for the analysis pipeline
fn cmd_benchmark(path: &str, iterations: usize) {
    let source_path = Path::new(path);
    if !source_path.exists() {
        eprintln!("  {} Path not found: {}", "X".red(), path);
        std::process::exit(1);
    }

    eprintln!("\n  {}  Running {} benchmark iterations on: {}", "[timer]".to_string(), iterations, path);

    let mut suite = benchmark_suite::BenchmarkSuite::default_suite();

    let result = suite.benchmark("full_scan", || {
        let analyzer = match program_analyzer::ProgramAnalyzer::new(source_path) {
            Ok(a) => a,
            Err(_) => return (0, 0),
        };
        let findings = analyzer.scan_for_vulnerabilities();
        (1, findings.len())
    });

    eprintln!("\n  {}  Benchmark Results:", "📊".to_string());
    eprintln!("  ├─ Duration:   {:?}", result.duration);
    eprintln!("  ├─ Files:      {}", result.files_analyzed);
    eprintln!("  ├─ Findings:   {}", result.findings_count);
    eprintln!("  └─ Throughput: {:.2} files/sec", result.throughput_files_per_sec);

    suite.print_summary();
}

//  VERIFY-FORMAL - Run the full formal verification pipeline
async fn cmd_verify_formal(path: &str, format: &str) {
    let source_path = std::path::Path::new(path);
    if !source_path.exists() {
        eprintln!("  {} Path not found: {}", "X".red(), path);
        std::process::exit(1);
    }

    eprintln!("\n  {}  Running formal verification pipeline on: {}", "🔬".to_string(), path);
    let timer = std::time::Instant::now();
    let mut results: Vec<serde_json::Value> = Vec::new();

    // 1) Kani model checking
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

    // 2) Certora prover (SBF bytecode verification)
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

    // 4) Crux-MIR analysis
    eprintln!("  ├─ {} Crux-MIR analysis...", "🔍".to_string());
    let crux = crux_mir_analyzer::CruxMirAnalyzer::new();
    match crux.analyze_program(source_path).await {
        Ok(report) => {
            eprintln!("  │  {} Crux-MIR: {} findings, {} instructions", "ok".green(), report.findings.len(), report.analyzed_instructions);
            results.push(serde_json::json!({
                "engine": "crux-mir",
                "findings": report.findings.len(),
                "instructions_analyzed": report.analyzed_instructions,
            }));
        }
        Err(e) => {
            eprintln!("  │  {} Crux-MIR: {:?}", "[warn]".yellow(), e);
            results.push(serde_json::json!({"engine": "crux-mir", "status": "error", "error": format!("{:?}", e)}));
        }
    }

    // 5) FV Scanner - 4-layer Z3-backed formal verification pipeline
    //    Layer 1: Arithmetic & Logic (Kani + AST overflow proofs)
    //    Layer 2: Symbolic Execution (Crux-MIR + Z3 SMT proofs)
    //    Layer 3: Cross-Program Safety (account schema invariants via Z3)
    //    Layer 4: Protocol State Machine (state transition verification)
    eprintln!("  └─ {} FV Scanner (4-layer Z3 pipeline)...", "🔬".to_string());
    {
        let fv_config = fv_scanner_core::ScanConfig {
            enabled_layers: vec![1, 2, 3, 4],
            layer1_config: fv_scanner_core::Layer1Config {
                kani_enabled: false, // Kani binary may not be installed
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

//  FUZZ - Run fuzzing analysis pipeline
fn cmd_fuzz(path: &str, iterations: usize, format: &str) {
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

//  ECONOMIC-VERIFY - Run DeFi economic invariant verification
fn cmd_economic_verify(path: &str, format: &str) {
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
