mod tui;
mod dashboard;

use clap::{Parser, Subcommand};
use colored::*;
use std::path::Path;
use std::time::Instant;

#[derive(Parser)]
#[command(
    name = "shanon",
    version = "2.0.0",
    about = "🛡️ Shanon — Enterprise-Grade Solana Security Platform",
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
    /// Scan a Solana program — launches interactive dashboard
    Scan {
        path: String,
        /// Output format: dashboard (default), json, human
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
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { path, format, min_severity, ai, api_key, model } => cmd_scan(&path, &format, &min_severity, ai, api_key.as_deref(), &model).await,
        Commands::Guard { path, format, fail_on } => cmd_guard(&path, &format, &fail_on),
        Commands::FiredancerCheck { source, rpc_url, format } => cmd_firedancer(source.as_deref(), &rpc_url, &format).await,
        Commands::CpiGraph { program_id, source, format } => cmd_cpi(&program_id, source.as_deref(), &format),
        Commands::Score { path, name, format } => cmd_score(&path, name.as_deref(), &format),
        Commands::TokenScan { mint, source, rpc_url, format } => cmd_token(&mint, source.as_deref(), &rpc_url, &format),
        Commands::Watch { program_id, discord, slack, telegram, chat_id, interval, rpc_url } =>
            cmd_watch(&program_id, discord.as_deref(), slack.as_deref(), telegram.as_deref(), chat_id.as_deref(), interval, &rpc_url).await,
        Commands::Verify { program_id, source, compliance, rpc_url, format } =>
            cmd_verify(&program_id, source.as_deref(), compliance.as_deref(), &rpc_url, &format),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  SCAN — Main command, launches interactive dashboard or prints output
// ═══════════════════════════════════════════════════════════════════════════
async fn cmd_scan(path: &str, format: &str, min_severity: &str, ai: bool, api_key: Option<&str>, model: &str) {
    let source_path = Path::new(path);
    if !source_path.exists() {
        eprintln!("  {} Path not found: {}", "✗".red(), path);
        std::process::exit(1);
    }

    // Run analysis
    let timer = Instant::now();
    let analyzer = match program_analyzer::ProgramAnalyzer::new(source_path) {
        Ok(a) => a,
        Err(e) => { eprintln!("  {} Init failed: {}", "✗".red(), e); std::process::exit(1); }
    };
    let mut findings = analyzer.scan_for_vulnerabilities();
    let elapsed = timer.elapsed();

    // Filter by severity
    let min_sev: u8 = match min_severity { "critical" => 5, "high" => 4, "medium" => 3, _ => 1 };
    findings.retain(|f| f.severity >= min_sev);

    // ── AI Enhancement (Kimi K2.5) ───────────────────────────────────────
    let ai_results = if ai {
        match api_key {
            Some(key) if !key.is_empty() => {
                eprintln!("\n  {} AI Enhancement with {} ({} findings)...",
                    "🧠".to_string().cyan(), model.bright_magenta(), findings.len());

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
                            "✓".green().bold(), success, results.len());
                        Some(results)
                    }
                    Err(_) => {
                        eprintln!("  {} AI enhancement timed out (> 3s). Skipping...", "⚠".yellow());
                        None
                    }
                }
            }
            _ => {
                eprintln!("  {} --ai flag set but no API key provided.", "⚠".yellow());
                eprintln!("    Use --api-key <KEY> or set OPENROUTER_API_KEY env var.");
                None
            }
        }
    } else {
        None
    };

    // JSON output (includes AI if available)
    if format == "json" {
        if let Some(ref ai_data) = ai_results {
            // Merge AI analysis into a combined JSON output
            let mut output = Vec::new();
            for f in &findings {
                let mut val = serde_json::to_value(f).unwrap_or_default();
                if let Some((_, Ok(enhanced))) = ai_data.iter().find(|(id, _)| id == &f.id) {
                    val["ai_analysis"] = serde_json::to_value(enhanced).unwrap_or_default();
                }
                output.push(val);
            }
            println!("{}", serde_json::to_string_pretty(&output).unwrap_or_default());
        } else {
            println!("{}", serde_json::to_string_pretty(&findings).unwrap_or_default());
        }
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
            eprintln!("  ║  🧠  KIMI K2.5 AI-ENHANCED ANALYSIS                                        ║");
            eprintln!("  ╚══════════════════════════════════════════════════════════════════════════════╝");
            for (id, result) in ai_data {
                match result {
                    Ok(enhanced) => {
                        let finding = findings.iter().find(|f| &f.id == id);
                        let title = finding.map(|f| f.vuln_type.as_str()).unwrap_or("Unknown");
                        eprintln!("\n  ┌──────────────────────────────────────────────────────────────────────────────┐");
                        eprintln!("  │  {}  {}  ", id.bright_red().bold(), title.bright_white().bold());
                        eprintln!("  ├──────────────────────────────────────────────────────────────────────────────┤");
                        eprintln!("  │  {} {}", "⚙ Technical:".cyan().bold(), "");
                        for line in enhanced.technical_explanation.lines() {
                            eprintln!("  │    {}", line);
                        }
                        eprintln!("  │");
                        eprintln!("  │  {} {}", "⚔ Attack:".red().bold(), "");
                        for line in enhanced.attack_scenario.lines() {
                            eprintln!("  │    {}", line);
                        }
                        eprintln!("  │");
                        eprintln!("  │  {} {}", "💻 PoC Exploit:".yellow().bold(), "");
                        for line in enhanced.proof_of_concept.lines() {
                            eprintln!("  │    {}", line);
                        }
                        eprintln!("  │");
                        eprintln!("  │  {} {}", "✏ Fix:".green().bold(), "");
                        for line in enhanced.recommended_fix.lines() {
                            eprintln!("  │    {}", line);
                        }
                        eprintln!("  │");
                        eprintln!("  │  {} {}", "💰 Impact:".bright_magenta().bold(), "");
                        for line in enhanced.economic_impact.lines() {
                            eprintln!("  │    {}", line);
                        }
                        eprintln!("  └──────────────────────────────────────────────────────────────────────────────┘");
                    }
                    Err(e) => {
                        eprintln!("  │  {} {} — {}", "✗".red(), id, e);
                    }
                }
            }
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
        eprintln!("  {} Dashboard error: {}", "✗".red(), e);
        std::process::exit(1);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  SCORE
// ═══════════════════════════════════════════════════════════════════════════
fn cmd_score(path: &str, name: Option<&str>, format: &str) {
    let source_path = Path::new(path);
    if !source_path.exists() {
        eprintln!("  {} Path not found: {}", "✗".red(), path);
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
        eprintln!("  {} Dashboard error: {}", "✗".red(), e);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  GUARD
// ═══════════════════════════════════════════════════════════════════════════
fn cmd_guard(path: &str, format: &str, fail_on: &str) {
    let target = Path::new(path);
    if !target.exists() { eprintln!("  {} Path not found: {}", "✗".red(), path); std::process::exit(1); }

    let scanner = shanon_guard::GuardScanner::new();
    let report = scanner.scan_directory(target);

    if format == "json" {
        println!("{}", report.to_json());
    } else if format == "human" || format == "dashboard" {
        tui::print_banner();
        eprintln!("  {} Scanning dependencies in {}...", "🛡️".truecolor(80,200,255), path.bright_white());
        report.print_colored();
    }

    let fail = match fail_on {
        "critical" => report.has_critical(),
        "high" => report.has_high_or_above(),
        _ => report.total_findings() > 0,
    };
    if fail { std::process::exit(1); }
}

// ═══════════════════════════════════════════════════════════════════════════
//  FIREDANCER
// ═══════════════════════════════════════════════════════════════════════════
async fn cmd_firedancer(source: Option<&str>, rpc_url: &str, format: &str) {
    tui::print_banner();
    if let Some(src) = source {
        let path = Path::new(src);
        if !path.exists() { eprintln!("  {} Path not found: {}", "✗".red(), src); std::process::exit(1); }
        eprintln!("  {} Analyzing Firedancer compatibility...", "🔥".truecolor(255,140,0));
        let checker = firedancer_monitor::compatibility::FiredancerCompatChecker::new();
        match checker.analyze_source(path) {
            Ok(report) => {
                if format == "json" { println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default()); return; }
                let sc = match report.score { 90..=100 => report.score.to_string().truecolor(34,197,94), 70..=89 => report.score.to_string().truecolor(234,179,8), _ => report.score.to_string().red() };
                eprintln!("  Score: {}/100  Grade: {}", sc.bold(), report.grade.cyan().bold());
                for w in &report.warnings {
                    if let firedancer_monitor::compatibility::CompatWarning::RuntimeDifference { diff_id, title, severity, mitigation, .. } = w {
                        eprintln!("  {} [{}] {} — {}", severity.red(), diff_id, title, mitigation.truecolor(100,116,139));
                    }
                }
            }
            Err(e) => { eprintln!("  {} {}", "✗".red(), e); std::process::exit(1); }
        }
    } else {
        let mut mon = firedancer_monitor::FiredancerMonitor::new(rpc_url.to_string());
        match mon.monitor_validator().await {
            Ok(r) => eprintln!("  Health: {}/100  Issues: {}", r.validator_health_score, r.findings.len()),
            Err(e) => eprintln!("  {} {}", "✗".red(), e),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  CPI GRAPH
// ═══════════════════════════════════════════════════════════════════════════
fn cmd_cpi(program_id: &str, source: Option<&str>, format: &str) {
    tui::print_banner();
    if let Some(src) = source {
        let mut code = String::new();
        collect_rs(Path::new(src), &mut code);
        if code.is_empty() { eprintln!("  {} No .rs files", "✗".red()); std::process::exit(1); }
        let graph = cpi_analyzer::CPIDependencyGraph::build_from_source(program_id, &code, None);
        if format == "json" { println!("{}", serde_json::to_string_pretty(&graph).unwrap_or_default()); return; }
        if format == "d3" { println!("{}", graph.to_d3_json()); return; }
        let s = graph.summary();
        eprintln!("  Programs: {}  CPI: {}  Risky: {}", s.total_programs, s.total_cpi_calls, s.risky_calls.to_string().red());
    } else {
        eprintln!("  {} Use --source <path>", "ℹ".truecolor(100,116,139));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  TOKEN SCAN
// ═══════════════════════════════════════════════════════════════════════════
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
        Err(e) => { eprintln!("  {} {}", "✗".red(), e); std::process::exit(1); }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  WATCH
// ═══════════════════════════════════════════════════════════════════════════
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
        if cid.is_none() { eprintln!("  {} --chat-id required", "✗".red()); std::process::exit(1); }
        wh.push(WebhookConfig { platform: WebhookPlatform::Telegram, url: u.to_string(), chat_id: cid });
    }
    let cfg = WatcherConfig { rpc_url: rpc_url.to_string(), program_ids: vec![pid.to_string()], poll_interval_secs: interval, max_polls: 0 };
    let sender = AlertSender::new(wh);
    let mut w = AuthorityWatcher::new(cfg, sender);
    if let Err(e) = w.run().await { eprintln!("  {} {}", "✗".red(), e); std::process::exit(1); }
}

// ═══════════════════════════════════════════════════════════════════════════
//  VERIFY
// ═══════════════════════════════════════════════════════════════════════════
fn cmd_verify(pid: &str, source: Option<&str>, compliance: Option<&str>, rpc_url: &str, format: &str) {
    use shanon_verify::{VerificationEngine, VerifyConfig};
    tui::print_banner();
    let src = match source {
        Some(p) => std::path::PathBuf::from(p),
        None => { eprintln!("  {} --source required", "✗".red()); std::process::exit(1); }
    };
    if !src.exists() { eprintln!("  {} Path not found", "✗".red()); std::process::exit(1); }
    let fw = compliance.map(|c| match c.to_lowercase().as_str() {
        "soc2" => compliance_reporter::ComplianceFramework::SOC2,
        "iso27001" | "iso" => compliance_reporter::ComplianceFramework::ISO27001,
        "owasp" => compliance_reporter::ComplianceFramework::OWASPSCS,
        "solana" | "sf" => compliance_reporter::ComplianceFramework::SolanaFoundation,
        _ => { eprintln!("  {} Unknown framework", "✗".red()); std::process::exit(1); }
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
        Err(e) => { eprintln!("  {} {}", "✗".red(), e); std::process::exit(1); }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Shared Helpers
// ═══════════════════════════════════════════════════════════════════════════
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
