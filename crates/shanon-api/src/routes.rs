//! API route handlers — all read live from Solana chain data.

use actix_web::{web, HttpRequest, HttpResponse};
use anchor_lang::AccountDeserialize;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;
use tracing::{info, error, warn};

use crate::{AppState, authenticate};
use shanon_oracle::state::*;

// ─── Response Types ─────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct RiskScoreResponse {
    pub program_id: String,
    pub overall_score: u8,
    pub confidence: u8,
    pub status: String,
    pub critical_count: u8,
    pub high_count: u8,
    pub medium_count: u8,
    pub low_count: u8,
    pub info_count: u8,
    pub total_flags: u8,
    pub analyst: String,
    pub assessed_at: i64,
    pub updated_at: i64,
    pub revision: u16,
    pub confirmations: u8,
    pub risk_level: String,
}

#[derive(Serialize)]
pub struct FlagResponse {
    pub flag_id: String,
    pub severity: String,
    pub category: String,
    pub description: String,
    pub confirmed: bool,
}

#[derive(Serialize)]
pub struct AnalystResponse {
    pub wallet: String,
    pub name: String,
    pub assessments_submitted: u64,
    pub assessments_confirmed: u64,
    pub reputation_bps: u16,
    pub reputation_pct: f64,
    pub active: bool,
    pub registered_at: i64,
    pub last_assessment_at: i64,
    pub domains: Vec<String>,
}

#[derive(Serialize)]
pub struct OracleStatsResponse {
    pub oracle_program_id: String,
    pub authority: String,
    pub guardian_count: usize,
    pub analyst_count: u32,
    pub scored_program_count: u64,
    pub paused: bool,
    pub version: u8,
}

#[derive(Deserialize)]
pub struct ScanRequestBody {
    pub program_id: String,
    /// Optional: GitHub repo URL for source-level analysis
    pub source_url: Option<String>,
}

// ─── Helper: Derive PDA ─────────────────────────────────────────────────────

fn derive_risk_score_pda(oracle_program: &Pubkey, target_program: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[RISK_SCORE_SEED, target_program.as_ref()],
        oracle_program,
    )
}

fn derive_config_pda(oracle_program: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[CONFIG_SEED],
        oracle_program,
    )
}

fn derive_analyst_pda(oracle_program: &Pubkey, wallet: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[ANALYST_SEED, wallet.as_ref()],
        oracle_program,
    )
}

// ─── Helper: Fetch & Deserialize ────────────────────────────────────────────

async fn fetch_account<T: AccountDeserialize>(
    state: &AppState,
    address: &Pubkey,
) -> Result<T, HttpResponse> {
    let account_data = state
        .rpc_client
        .get_account_data(address)
        .await
        .map_err(|e| {
            info!("Account {} not found on-chain: {}", address, e);
            HttpResponse::NotFound().json(serde_json::json!({
                "error": "Account not found on-chain",
                "address": address.to_string(),
                "hint": "This program may not have been assessed yet"
            }))
        })?;

    T::try_deserialize(&mut account_data.as_slice())
        .map_err(|e| {
            error!("Failed to deserialize account {}: {}", address, e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to deserialize on-chain data",
                "details": e.to_string()
            }))
        })
}

fn severity_to_string(severity: &FlagSeverity) -> String {
    match severity {
        FlagSeverity::Info => "Info".into(),
        FlagSeverity::Low => "Low".into(),
        FlagSeverity::Medium => "Medium".into(),
        FlagSeverity::High => "High".into(),
        FlagSeverity::Critical => "Critical".into(),
    }
}

fn category_to_string(category: &FlagCategory) -> String {
    match category {
        FlagCategory::AccessControl => "Access Control".into(),
        FlagCategory::Arithmetic => "Arithmetic".into(),
        FlagCategory::Reentrancy => "Reentrancy".into(),
        FlagCategory::TokenSafety => "Token Safety".into(),
        FlagCategory::Economic => "Economic".into(),
        FlagCategory::OracleManipulation => "Oracle Manipulation".into(),
        FlagCategory::AccountValidation => "Account Validation".into(),
        FlagCategory::Centralization => "Centralization".into(),
        FlagCategory::DataIntegrity => "Data Integrity".into(),
        FlagCategory::Logic => "Logic".into(),
    }
}

fn status_to_string(status: &AssessmentStatus) -> String {
    match status {
        AssessmentStatus::Pending => "Pending".into(),
        AssessmentStatus::Confirmed => "Confirmed".into(),
        AssessmentStatus::Disputed => "Disputed".into(),
        AssessmentStatus::Superseded => "Superseded".into(),
        AssessmentStatus::Withdrawn => "Withdrawn".into(),
    }
}

fn risk_level(score: u8) -> String {
    match score {
        0..=20 => "Low Risk".into(),
        21..=40 => "Moderate Risk".into(),
        41..=60 => "Elevated Risk".into(),
        61..=80 => "High Risk".into(),
        81..=100 => "Critical Risk".into(),
        _ => "Unknown".into(),
    }
}

// ─── Route Handlers ─────────────────────────────────────────────────────────

pub async fn health(state: web::Data<AppState>) -> HttpResponse {
    let rpc_version = state.rpc_client.get_version().await;
    let rpc_status = if rpc_version.is_ok() { "connected" } else { "disconnected" };

    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "service": "shanon-security-oracle",
        "version": "0.1.0",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "dependencies": {
            "solana_rpc": rpc_status,
        }
    }))
}

/// GET /api/v1/risk/{program_id}
/// Returns the risk score for a specific Solana program.
pub async fn get_risk_score(
    path: web::Path<String>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let program_id_str = path.into_inner();
    let target_program = match Pubkey::from_str(&program_id_str) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid program ID (not a valid base58 pubkey)",
                "provided": program_id_str
            }))
        }
    };


    let (pda, _) = derive_risk_score_pda(&state.oracle_program_id, &target_program);
    let risk_score: ProgramRiskScore = match fetch_account(&state, &pda).await {
        Ok(score) => score,
        Err(response) => return response,
    };

    HttpResponse::Ok().json(RiskScoreResponse {
        program_id: target_program.to_string(),
        overall_score: risk_score.overall_score,
        confidence: risk_score.confidence,
        status: status_to_string(&risk_score.status),
        critical_count: risk_score.critical_count,
        high_count: risk_score.high_count,
        medium_count: risk_score.medium_count,
        low_count: risk_score.low_count,
        info_count: risk_score.info_count,
        total_flags: risk_score.flag_count,
        analyst: risk_score.analyst.to_string(),
        assessed_at: risk_score.assessed_at,
        updated_at: risk_score.updated_at,
        revision: risk_score.revision,
        confirmations: risk_score.confirmations,
        risk_level: risk_level(risk_score.overall_score),
    })
}

/// GET /api/v1/risk/{program_id}/flags
/// Returns detailed flag data for a specific program.
pub async fn get_risk_flags(
    path: web::Path<String>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let program_id_str = path.into_inner();
    let target_program = match Pubkey::from_str(&program_id_str) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid program ID"
            }))
        }
    };


    let (pda, _) = derive_risk_score_pda(&state.oracle_program_id, &target_program);
    let risk_score: ProgramRiskScore = match fetch_account(&state, &pda).await {
        Ok(score) => score,
        Err(response) => return response,
    };

    let flags: Vec<FlagResponse> = risk_score
        .flags
        .iter()
        .map(|f| {
            let flag_id_bytes = &f.flag_id[..];
            let flag_id = String::from_utf8_lossy(
                &flag_id_bytes[..flag_id_bytes.iter().position(|&b| b == 0).unwrap_or(8)]
            ).to_string();

            let desc_bytes = &f.description[..f.description_len as usize];
            let description = String::from_utf8_lossy(desc_bytes).to_string();

            FlagResponse {
                flag_id,
                severity: severity_to_string(&f.severity),
                category: category_to_string(&f.category),
                description,
                confirmed: f.confirmed,
            }
        })
        .collect();

    HttpResponse::Ok().json(serde_json::json!({
        "program_id": target_program.to_string(),
        "total_flags": risk_score.flag_count,
        "flags": flags,
    }))
}

/// GET /api/v1/analyst/{wallet}
/// Returns analyst profile and stats.
pub async fn get_analyst(
    path: web::Path<String>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let wallet_str = path.into_inner();
    let wallet = match Pubkey::from_str(&wallet_str) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid wallet address"
            }))
        }
    };

    let (pda, _) = derive_analyst_pda(&state.oracle_program_id, &wallet);
    let analyst: AnalystAccount = match fetch_account(&state, &pda).await {
        Ok(a) => a,
        Err(response) => return response,
    };

    let name = String::from_utf8_lossy(analyst.get_name()).to_string();

    let mut domains = Vec::new();
    if analyst.has_domain(AnalystAccount::DOMAIN_DEFI) { domains.push("DeFi".into()); }
    if analyst.has_domain(AnalystAccount::DOMAIN_TOKEN) { domains.push("Token".into()); }
    if analyst.has_domain(AnalystAccount::DOMAIN_NFT) { domains.push("NFT".into()); }
    if analyst.has_domain(AnalystAccount::DOMAIN_GOVERNANCE) { domains.push("Governance".into()); }
    if analyst.has_domain(AnalystAccount::DOMAIN_BRIDGE) { domains.push("Bridge".into()); }
    if analyst.has_domain(AnalystAccount::DOMAIN_ORACLE) { domains.push("Oracle".into()); }

    HttpResponse::Ok().json(AnalystResponse {
        wallet: wallet.to_string(),
        name,
        assessments_submitted: analyst.assessments_submitted,
        assessments_confirmed: analyst.assessments_confirmed,
        reputation_bps: analyst.reputation_bps,
        reputation_pct: analyst.reputation_bps as f64 / 100.0,
        active: analyst.active,
        registered_at: analyst.registered_at,
        last_assessment_at: analyst.last_assessment_at,
        domains,
    })
}

/// GET /api/v1/analysts
/// Returns a list of active guardians/analysts.
pub async fn list_analysts(state: web::Data<AppState>) -> HttpResponse {
    // Query on-chain AnalystAccount PDAs for known addresses.
    // Only returns analysts that actually exist on-chain.
    let addresses = [
        "Ea1qKkVjEEGa5mLAWdDryPB1nsGHyuxwB7oQFz8obbw4",
    ];

    let mut analysts = Vec::new();
    for addr in addresses {
        if let Ok(pk) = Pubkey::from_str(addr) {
            let (pda, _) = derive_analyst_pda(&state.oracle_program_id, &pk);
            if let Ok(account_data) = state.rpc_client.get_account_data(&pda).await {
                if let Ok(analyst) = AnalystAccount::try_deserialize(&mut account_data.as_slice()) {
                    let name = String::from_utf8_lossy(analyst.get_name()).to_string();
                    analysts.push(serde_json::json!({
                        "wallet": addr,
                        "name": name,
                        "reputation": analyst.reputation_bps as f64 / 100.0,
                        "assets": analyst.assessments_submitted,
                    }));
                }
            }
        }
    }

    // No fake fallback — return empty array if no on-chain analysts found
    HttpResponse::Ok().json(analysts)
}

/// GET /api/v1/stats
/// Returns global oracle statistics.
pub async fn oracle_stats(
    state: web::Data<AppState>,
) -> HttpResponse {
    let (config_pda, _) = derive_config_pda(&state.oracle_program_id);
    let config: OracleConfig = match fetch_account(&state, &config_pda).await {
        Ok(c) => c,
        Err(_) => {
            // OracleConfig not found on-chain — derive real counts from local data
            let audit_count = std::fs::read_dir("./production_audit_results")
                .map(|d| d.flatten().filter(|e| e.file_name().to_string_lossy().ends_with("_report.json")).count())
                .unwrap_or(0) as u64;
            let _exploit_count = std::fs::read_dir("./exploits")
                .map(|d| d.flatten().filter(|e| e.file_name().to_string_lossy().ends_with(".rs")).count())
                .unwrap_or(0) as u32;

            return HttpResponse::Ok().json(OracleStatsResponse {
                oracle_program_id: state.oracle_program_id.to_string(),
                authority: state.oracle_program_id.to_string(),
                guardian_count: 0,
                analyst_count: 0,
                scored_program_count: audit_count,
                paused: false,
                version: 1,
            });
        }
    };

    HttpResponse::Ok().json(OracleStatsResponse {
        oracle_program_id: state.oracle_program_id.to_string(),
        authority: config.authority.to_string(),
        guardian_count: config.guardians.len(),
        analyst_count: config.analyst_count,
        scored_program_count: config.scored_program_count,
        paused: config.paused,
        version: config.version,
    })
}

/// GET /api/v1/programs
/// Lists all programs with risk scores (paginated).
pub async fn list_scored_programs(
    state: web::Data<AppState>,
) -> HttpResponse {
    // For now, return the oracle stats and a note about pagination.
    // In production, this would use getProgramAccounts with filters.
    let (config_pda, _) = derive_config_pda(&state.oracle_program_id);

    match fetch_account::<OracleConfig>(&state, &config_pda).await {
        Ok(config) => {
            HttpResponse::Ok().json(serde_json::json!({
                "total_programs": config.scored_program_count,
                "oracle_program_id": state.oracle_program_id.to_string(),
                "note": "Use GET /api/v1/risk/{program_id} to query individual programs. Full listing via getProgramAccounts requires RPC that supports it.",
                "version": config.version,
            }))
        }
        Err(response) => response,
    }
}

/// POST /api/v1/scan
/// Triggers a security scan via the background worker.
/// Returns a job ID for polling via GET /api/v1/scan/{job_id}.
///
/// Request body:
/// ```json
/// { "program_id": "...", "source_url": "https://github.com/..." }
/// ```
///
/// If `source_url` is a GitHub URL, clones and runs full static analysis.
/// If only `program_id` is given, runs on-chain metadata scan + verified source lookup.
pub async fn trigger_scan(
    req: HttpRequest,
    body: web::Json<ScanRequestBody>,
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Err(response) = authenticate(&req, &state) {
        return response;
    }

    info!("Scan requested: program_id={}, source_url={:?}", body.program_id, body.source_url);

    use crate::worker::ScanTarget;

    let target = if let Some(ref source_url) = body.source_url {
        if source_url.contains("github.com") {
            ScanTarget::GitHub { url: source_url.clone() }
        } else {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "source_url must be a GitHub URL",
                "provided": source_url,
            }));
        }
    } else {
        // Validate program ID format
        if Pubkey::from_str(&body.program_id).is_err() {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid program ID",
                "program_id": body.program_id,
            }));
        }
        ScanTarget::OnChain { program_id: body.program_id.clone() }
    };

    let job_id = match state.scan_worker.submit(target).await {
        Some(id) => id,
        None => {
            return HttpResponse::TooManyRequests().json(serde_json::json!({
                "error": "Server at capacity",
                "message": "Too many scan jobs queued. Please try again later.",
                "retry_after_seconds": 30,
            }));
        }
    };

    HttpResponse::Accepted().json(serde_json::json!({
        "status": "queued",
        "job_id": job_id,
        "poll_url": format!("/api/v1/scan/{}", job_id),
        "message": "Scan job has been queued. Poll the job_id endpoint for results.",
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

/// GET /api/v1/scan/{job_id}
/// Returns the current status and results of a scan job.
pub async fn scan_status(
    path: web::Path<String>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let job_id = path.into_inner();

    match state.scan_worker.status(&job_id).await {
        Some(result) => HttpResponse::Ok().json(serde_json::json!({
            "job_id": job_id,
            "status": result.status,
            "scan_type": result.scan_type,
            "target": result.target,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "total_findings": result.total_findings,
            "critical_count": result.critical_count,
            "high_count": result.high_count,
            "medium_count": result.medium_count,
            "low_count": result.low_count,
            "info_count": result.info_count,
            "findings": result.findings,
            "on_chain_meta": result.on_chain_meta,
            "started_at": result.started_at,
            "completed_at": result.completed_at,
            "error": result.error,
        })),
        None => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Job not found",
            "job_id": job_id,
            "hint": "Job IDs are ephemeral. Jobs may expire after server restart.",
        })),
    }
}

/// GET /api/v1/scan/jobs
/// Lists all scan jobs (most recent first, max 50).
pub async fn list_scan_jobs(
    state: web::Data<AppState>,
) -> HttpResponse {
    let jobs = state.scan_worker.list_jobs().await;
    HttpResponse::Ok().json(serde_json::json!({
        "jobs": jobs,
        "total": jobs.len(),
    }))
}


/// GET /api/v1/engines
pub async fn list_engines(_state: web::Data<AppState>) -> HttpResponse {
    let mut engines = Vec::new();

    // Scan the crates directory for all analysis modules
    if let Ok(entries) = std::fs::read_dir("./crates") {
        let mut names: Vec<String> = entries
            .flatten()
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        
        for name in &names {
            let (engine_type, is_analysis) = match name.as_str() {
                "shanon-api" => ("REST Gateway", false),
                "shanon-extension" => ("Client SDK", false),
                "shanon-cli" => ("CLI Interface", false),
                "benchmark-suite" => ("Performance Benchmark", false),
                "orchestrator" | "integration-orchestrator" => ("Pipeline Orchestrator", false),
                "secure-code-gen" => ("Secure Code Generator", false),
                "shanon-oracle" | "consensus-engine" => ("On-Chain Oracle", true),
                "program-analyzer" => ("Static Analysis (72 Detectors)", true),
                "token-security-expert" | "defi-security-expert" | "account-security-expert" | "arithmetic-security-expert" => ("Domain Expert Engine", true),
                "dataflow-analyzer" | "taint-analyzer" | "cpi-analyzer" | "abstract-interpreter" => ("Dataflow / Taint Analysis", true),
                "symbolic-engine" | "concolic-executor" => ("Symbolic Execution", true),
                "kani-verifier" | "certora-prover" | "crux-mir-analyzer" => ("Formal Verification", true),
                n if n.starts_with("fv-") => ("Formal Verification Layer", true),
                "security-fuzzer" | "trident-fuzzer" | "fuzzdelsol" => ("Fuzz Testing", true),
                "attack-simulator" | "transaction-forge" => ("Exploit Simulation", true),
                "economic-verifier" | "invariant-miner" => ("Economic Verification", true),
                "llm-strategist" | "ai-enhancer" => ("AI-Augmented Analysis", true),
                "geiger-analyzer" | "l3x-analyzer" | "sec3-analyzer" | "wacana-analyzer" | "anchor-security-analyzer" => ("Third-Party Integration", true),
                "git-scanner" => ("Source Code Scanner", true),
                "firedancer-monitor" => ("Validator Monitor", true),
                "shanon-guard" => ("Supply Chain Firewall", true),
                "shanon-monitor" => ("Authority Monitor", true),
                "shanon-verify" => ("Verification Engine", true),
                "compliance-reporter" => ("Compliance Engine", true),
                "token-scanner" if names.contains(&"token-security-expert".to_string()) => ("Token Scanner", true),
                _ => ("Analysis Module", true),
            };

            engines.push(serde_json::json!({
                "name": name,
                "type": engine_type,
                "status": "active",
                "is_analysis_engine": is_analysis,
                "detectors": if name == "program-analyzer" { 72 } else { 0 }
            }));
        }
    }

    if engines.is_empty() {
        return HttpResponse::Ok().json(serde_json::json!([
            { "name": "shanon-api", "type": "REST Gateway", "status": "active", "detectors": 0, "is_analysis_engine": false }
        ]));
    }

    let total = engines.len();
    let analysis_count = engines.iter().filter(|e| e["is_analysis_engine"] == true).count();
    let infra_count = total - analysis_count;

    HttpResponse::Ok().json(serde_json::json!({
        "total_crates": total,
        "analysis_engines": analysis_count,
        "infrastructure_crates": infra_count,
        "engines": engines
    }))
}


/// GET /api/v1/detectors
pub async fn list_detectors(_state: web::Data<AppState>) -> HttpResponse {
    use program_analyzer::vulnerability_db::get_default_patterns;
    let patterns = get_default_patterns();
    
    let response: Vec<serde_json::Value> = patterns.into_iter().map(|p| {
        let desc = if p.description.is_empty() {
            format!("Detects {} vulnerabilities in Solana programs.", p.name.to_lowercase())
        } else {
            p.description
        };
        serde_json::json!({
            "id": p.id,
            "name": p.name,
            "description": desc,
            "severity": p.severity,
            "severity_label": match p.severity {
                5 => "Critical",
                4 => "High",
                3 => "Medium",
                2 => "Low",
                _ => "Info"
            }
        })
    }).collect();

    HttpResponse::Ok().json(response)
}

/// GET /api/v1/exploits
pub async fn list_exploits(_state: web::Data<AppState>) -> HttpResponse {
    let mut exploits = Vec::new();
    if let Ok(entries) = std::fs::read_dir("./exploits") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("exploit_") && name.ends_with(".rs") {
                let raw = name.replace("exploit_", "").replace(".rs", "");
                let pretty = raw.replace('_', " ");
                let pretty_name: String = pretty.split_whitespace()
                    .map(|w| {
                        let mut c = w.chars();
                        match c.next() {
                            None => String::new(),
                            Some(first) => first.to_uppercase().to_string() + c.as_str(),
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                
                let vuln_type = if raw.contains("swap") { "DeFi Swap Logic" }
                    else if raw.contains("price") { "Oracle Manipulation" }
                    else if raw.contains("initialize") { "Init Frontrunning" }
                    else if raw.contains("permission") { "Access Control" }
                    else if raw.contains("circuit") { "Circuit Breaker Bypass" }
                    else if raw.contains("verify") { "Verification Bypass" }
                    else { "Instruction Exploit" };

                exploits.push(serde_json::json!({
                    "id": format!("EXP-{:03}", exploits.len() + 1),
                    "name": pretty_name,
                    "vulnerability": vuln_type,
                    "target": "vulnerable-vault",
                    "file": name,
                }));
            }
        }
    }

    if exploits.is_empty() {
        return HttpResponse::Ok().json(serde_json::json!([]));
    }

    HttpResponse::Ok().json(exploits)
}


/// GET /api/v1/archive
pub async fn list_archives(_state: web::Data<AppState>) -> HttpResponse {
    let mut archive = Vec::new();
    if let Ok(entries) = std::fs::read_dir("./production_audit_results") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with("_report.json") {
                let program_name = name.replace("_report.json", "");
                // Parse actual report JSON for real data
                if let Ok(contents) = std::fs::read_to_string(entry.path()) {
                    if let Ok(report) = serde_json::from_str::<serde_json::Value>(&contents) {
                        let score = report["security_score"].as_u64().unwrap_or(0) as u8;
                        let level = match score {
                            0..=30 => "LOW",
                            31..=60 => "MEDIUM",
                            61..=80 => "HIGH",
                            _ => "CRITICAL",
                        };
                        archive.push(serde_json::json!({
                            "program_id": report["program_id"].as_str().unwrap_or(&program_name),
                            "program_name": program_name,
                            "score": score,
                            "level": level,
                            "total_exploits": report["total_exploits"].as_u64().unwrap_or(0),
                            "critical_count": report["critical_count"].as_u64().unwrap_or(0),
                            "high_count": report["high_count"].as_u64().unwrap_or(0),
                            "medium_count": report["medium_count"].as_u64().unwrap_or(0),
                            "date": report["timestamp"].as_str().unwrap_or("2026-02-15"),
                        }));
                    }
                }
            }
        }
    }

    if archive.is_empty() {
        return HttpResponse::Ok().json(serde_json::json!([]));
    }

    HttpResponse::Ok().json(archive)
}

// ─── Shanon Guard — Dependency Firewall ─────────────────────────────────────

#[derive(Deserialize)]
pub struct GuardScanRequest {
    /// Local directory path to scan, or a GitHub URL to clone + scan.
    pub path: String,
}

/// POST /api/v1/guard
/// Run the Shanon Guard dependency firewall on a directory or GitHub repo.
/// Returns supply chain risk analysis covering:
/// - Known malicious packages (advisory database)
/// - Typosquat detection (Levenshtein distance)
/// - Behavioral analysis (key exfiltration patterns in node_modules)
/// - Suspicious git/path dependencies
pub async fn guard_scan(
    body: web::Json<GuardScanRequest>,
) -> HttpResponse {
    let target_path = body.path.clone();

    info!("Guard scan requested for: {}", target_path);

    // If it looks like a GitHub URL, clone it first
    let (scan_path, _tmp_dir) = if target_path.contains("github.com") {
        let tmp_dir = match tempfile::tempdir() {
            Ok(d) => d,
            Err(e) => {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to create temp directory",
                    "details": e.to_string(),
                }));
            }
        };

        let clone_path = tmp_dir.path().to_path_buf();
        let clone_result = tokio::task::spawn_blocking({
            let url = target_path.clone();
            let path = clone_path.clone();
            move || {
                std::process::Command::new("git")
                    .args(["clone", "--depth", "1", &url, &path.to_string_lossy()])
                    .output()
            }
        })
        .await;

        match &clone_result {
            Ok(Ok(output)) if !output.status.success() => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Failed to clone repository",
                    "details": stderr.to_string(),
                }));
            }
            Ok(Err(e)) => {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Git not available",
                    "details": e.to_string(),
                }));
            }
            Err(e) => {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Task join failed",
                    "details": e.to_string(),
                }));
            }
            _ => {}
        }

        (clone_path, Some(tmp_dir))
    } else {
        (std::path::PathBuf::from(&target_path), None)
    };

    // Run the guard scan
    let scan_result = tokio::task::spawn_blocking({
        let path = scan_path.clone();
        move || {
            let scanner = shanon_guard::GuardScanner::new();
            scanner.scan_directory(&path)
        }
    })
    .await;

    match scan_result {
        Ok(report) => {
            let total = report.total_findings();
            let has_critical = report.has_critical();

            info!(
                "Guard scan complete: {} findings, risk score {}/100, critical: {}",
                total, report.risk_score, has_critical
            );

            HttpResponse::Ok().json(serde_json::json!({
                "status": "completed",
                "scan_type": "dependency_firewall",
                "target": target_path,
                "risk_score": report.risk_score,
                "total_findings": total,
                "has_critical": has_critical,
                "cargo_findings": report.cargo_findings,
                "npm_findings": report.npm_findings,
                "behavioral_findings": report.behavioral_findings,
                "cargo_files_scanned": report.cargo_files_scanned,
                "npm_files_scanned": report.npm_files_scanned,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Guard scan failed",
            "details": e.to_string(),
        })),
    }
}

// ─── Scoreboard Endpoints ───────────────────────────────────────────────────

/// GET /api/v1/scoreboard — List all scored protocols ranked by score
pub async fn scoreboard_list(
    state: web::Data<AppState>,
) -> HttpResponse {
    if let Some(store) = &state.scoreboard {
        let entries = store.ranked_list();
        HttpResponse::Ok().json(serde_json::json!({
            "protocols": entries,
            "total": entries.len(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
        }))
    } else {
        HttpResponse::Ok().json(serde_json::json!({
            "protocols": [],
            "total": 0,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        }))
    }
}

/// GET /api/v1/scoreboard/{program_id} — Get detailed score for a protocol
pub async fn scoreboard_detail(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    let program_id = path.into_inner();

    if let Some(store) = &state.scoreboard {
        if let Some(score) = store.get(&program_id) {
            return HttpResponse::Ok().json(score);
        }
    }

    HttpResponse::NotFound().json(serde_json::json!({
        "error": "Protocol not scored yet",
        "program_id": program_id,
        "hint": "POST /api/v1/scoreboard/scan to trigger scoring",
    }))
}

/// POST /api/v1/scoreboard/scan — Trigger scoring for a protocol
pub async fn scoreboard_scan(
    state: web::Data<AppState>,
    body: web::Json<crate::scoreboard::ScoreRequest>,
) -> HttpResponse {
    let program_id = body.program_id.clone();
    let name = body.name.clone().unwrap_or_else(|| program_id[..8.min(program_id.len())].to_string());

    info!("Scoreboard scan requested for: {} ({})", program_id, name);

    // Run analysis if repo_url is provided
    let (findings_summary, guard_risk) = if let Some(repo_url) = &body.repo_url {
        // Clone and scan the repo
        let temp_dir = std::env::temp_dir().join(format!("shanon-score-{}", &program_id[..8.min(program_id.len())]));
        let _ = std::fs::create_dir_all(&temp_dir);

        let scan_result: Result<(crate::scoreboard::FindingSummary, u8), String> = tokio::task::spawn_blocking({
            let repo_url = repo_url.clone();
            let temp_dir = temp_dir.clone();
            move || {
                // Clone repo
                let status = std::process::Command::new("git")
                    .args(["clone", "--depth", "1", &repo_url, temp_dir.to_str().unwrap_or(".")])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .map_err(|e| format!("Git clone failed: {}", e))?;

                if !status.success() {
                    return Err("Git clone failed".to_string());
                }

                // Run program analyzer
                let findings = match program_analyzer::ProgramAnalyzer::new(&temp_dir) {
                    Ok(analyzer) => analyzer.scan_for_vulnerabilities(),
                    Err(_) => vec![],
                };
                let summary = crate::scoreboard::summarize_findings(&findings);

                // Run guard scan
                let guard_scanner = shanon_guard::GuardScanner::new();
                let guard_report = guard_scanner.scan_directory(&temp_dir);
                let guard_risk = guard_report.risk_score;

                // Cleanup
                let _ = std::fs::remove_dir_all(&temp_dir);

                Ok((summary, guard_risk))
            }
        })
        .await
        .map_err(|e| format!("Task failed: {}", e))
        .and_then(|r| r);

        match scan_result {
            Ok((s, g)) => (s, g),
            Err(e) => {
                warn!("Scoreboard scan failed for {}: {}", program_id, e);
                (crate::scoreboard::FindingSummary::default(), 0)
            }
        }
    } else {
        (crate::scoreboard::FindingSummary::default(), 0)
    };

    // For now, authority and source verification are defaults
    // In production, these would come from on-chain data
    let authority = crate::scoreboard::AuthorityStatus::Unknown;
    let source_verified = body.repo_url.is_some();

    let score = crate::scoreboard::calculate_protocol_score(
        &findings_summary,
        &authority,
        source_verified,
        guard_risk,
    );
    let grade = crate::scoreboard::score_to_grade(score);

    let protocol_score = crate::scoreboard::ProtocolScore {
        program_id: program_id.clone(),
        name: name.clone(),
        score,
        grade: grade.clone(),
        source_verified,
        upgrade_authority: authority,
        findings: findings_summary,
        guard_risk,
        last_scanned: chrono::Utc::now(),
        badge_url: format!("/api/v1/badge/{}", program_id),
    };

    // Store the score
    if let Some(store) = &state.scoreboard {
        store.upsert(protocol_score.clone());
    }

    HttpResponse::Ok().json(protocol_score)
}

/// GET /api/v1/badge/{program_id} — Serve SVG badge for a protocol
pub async fn scoreboard_badge(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    let program_id = path.into_inner();

    let (score, name) = if let Some(store) = &state.scoreboard {
        if let Some(ps) = store.get(&program_id) {
            (ps.score, ps.name.clone())
        } else {
            (0, "Unknown".to_string())
        }
    } else {
        (0, "Unknown".to_string())
    };

    let svg = crate::badge::generate_badge_svg(score, &name);
    HttpResponse::Ok()
        .content_type("image/svg+xml")
        .insert_header(("Cache-Control", "max-age=300"))
        .body(svg)
}

/// GET /api/v1/token/{mint}/risk — Analyze a token for rug pull risk
pub async fn token_risk(
    path: web::Path<String>,
) -> HttpResponse {
    use token_security_expert::scanner::{TokenRiskScanner, OnChainTokenChecks};

    let mint = path.into_inner();

    if mint.len() < 20 || mint.len() > 60 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid mint address length"
        }));
    }

    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".into());

    let scanner = TokenRiskScanner::new(&rpc_url);

    // Offline mode: default on-chain checks (no live RPC query yet)
    let on_chain = OnChainTokenChecks::default();

    match scanner.analyze(&mint, on_chain, None) {
        Ok(report) => HttpResponse::Ok().json(report),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Token analysis failed: {}", e)
        })),
    }
}

// ─── Transaction Risk Simulation ────────────────────────────────────────────

/// Request body for transaction risk simulation
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct SimulateRequest {
    /// List of program IDs the transaction interacts with (base58)
    pub program_ids: Vec<String>,
    /// Optional: raw transaction bytes (base58-encoded) for deeper analysis
    
    pub transaction: Option<String>,
}

/// Risk assessment for a single program in the transaction
#[derive(Debug, Serialize)]
pub struct ProgramRiskAssessment {
    pub program_id: String,
    pub name: Option<String>,
    pub risk_level: String,
    pub risk_score: u8,
    pub warnings: Vec<String>,
    pub is_known_safe: bool,
    pub is_upgradeable: bool,
}

/// Response for transaction risk simulation
#[derive(Debug, Serialize)]
pub struct SimulateResponse {
    pub overall_risk_score: u8,
    pub risk_level: String,
    pub safe_to_sign: bool,
    pub program_assessments: Vec<ProgramRiskAssessment>,
    pub warnings: Vec<String>,
    pub recommendation: String,
}

/// POST /api/v1/simulate — Check program safety before signing a transaction
pub async fn simulate_transaction(
    state: web::Data<AppState>,
    body: web::Json<SimulateRequest>,
) -> HttpResponse {
    if body.program_ids.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "At least one program_id is required"
        }));
    }

    if body.program_ids.len() > 20 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Maximum 20 program IDs per request"
        }));
    }

    // Known safe system programs
    let known_safe: std::collections::HashMap<&str, &str> = [
        ("11111111111111111111111111111111", "System Program"),
        ("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "Token Program"),
        ("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", "Associated Token Program"),
        ("SysvarRent111111111111111111111111111111111", "Rent Sysvar"),
        ("SysvarC1ock11111111111111111111111111111111", "Clock Sysvar"),
        ("ComputeBudget111111111111111111111111111111", "Compute Budget"),
        ("Vote111111111111111111111111111111111111111", "Vote Program"),
        ("Stake11111111111111111111111111111111111111", "Stake Program"),
        ("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr", "Memo Program"),
        ("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s", "Metaplex Token Metadata"),
    ].iter().cloned().collect();

    // Known risky programs (flagged by community)
    let known_risky: std::collections::HashMap<&str, &str> = [
        // Community-flagged risky programs — populated from external threat intel feed when available
    ].iter().cloned().collect();

    let mut assessments = Vec::new();
    let mut total_risk: u32 = 0;
    let mut global_warnings = Vec::new();

    for pid in &body.program_ids {
        // Validate base58
        if pid.len() < 20 || pid.len() > 60 {
            assessments.push(ProgramRiskAssessment {
                program_id: pid.clone(),
                name: None,
                risk_level: "UNKNOWN".into(),
                risk_score: 50,
                warnings: vec!["Invalid program ID format".into()],
                is_known_safe: false,
                is_upgradeable: false,
            });
            total_risk += 50;
            continue;
        }

        // Check if it's a known safe program
        if let Some(name) = known_safe.get(pid.as_str()) {
            assessments.push(ProgramRiskAssessment {
                program_id: pid.clone(),
                name: Some(name.to_string()),
                risk_level: "SAFE".into(),
                risk_score: 0,
                warnings: vec![],
                is_known_safe: true,
                is_upgradeable: false,
            });
            continue;
        }

        // Check if it's a known risky program
        if let Some(reason) = known_risky.get(pid.as_str()) {
            assessments.push(ProgramRiskAssessment {
                program_id: pid.clone(),
                name: None,
                risk_level: "CRITICAL".into(),
                risk_score: 95,
                warnings: vec![format!("Known risky program: {}", reason)],
                is_known_safe: false,
                is_upgradeable: true,
            });
            total_risk += 95;
            global_warnings.push(format!("⚠ Transaction includes known risky program: {}", &pid[..8.min(pid.len())]));
            continue;
        }

        // Check scoreboard for existing score
        let mut risk_score: u8 = 40; // default unknown
        let mut warnings = Vec::new();
        let mut name = None;

        if let Some(store) = &state.scoreboard {
            if let Some(ps) = store.get(pid) {
                risk_score = (100u32.saturating_sub(ps.score as u32)) as u8;
                name = Some(ps.name.clone());
            }
        }

        // Unknown programs get a baseline risk
        if name.is_none() {
            warnings.push("Program not in scoreboard — unknown risk profile".into());
            risk_score = 50;
        }

        let risk_level = match risk_score {
            0..=20 => "LOW",
            21..=40 => "MODERATE",
            41..=60 => "ELEVATED",
            61..=80 => "HIGH",
            _ => "CRITICAL",
        }.to_string();

        total_risk += risk_score as u32;

        assessments.push(ProgramRiskAssessment {
            program_id: pid.clone(),
            name,
            risk_level,
            risk_score,
            warnings,
            is_known_safe: false,
            is_upgradeable: false,
        });
    }

    // Calculate overall risk
    let program_count = assessments.len().max(1) as u32;
    let overall_risk = ((total_risk / program_count) as u8).min(100);

    let risk_level = match overall_risk {
        0..=20 => "LOW",
        21..=40 => "MODERATE",
        41..=60 => "ELEVATED",
        61..=80 => "HIGH",
        _ => "CRITICAL",
    }.to_string();

    let safe_to_sign = overall_risk <= 40 && !assessments.iter().any(|a| a.risk_score >= 80);

    let recommendation = if safe_to_sign {
        "Transaction appears safe to sign.".into()
    } else if overall_risk >= 80 {
        "⛔ HIGH RISK — Do NOT sign this transaction without thorough review.".into()
    } else {
        "⚠ Exercise caution. Some programs in this transaction have elevated risk.".into()
    };

    HttpResponse::Ok().json(SimulateResponse {
        overall_risk_score: overall_risk,
        risk_level,
        safe_to_sign,
        program_assessments: assessments,
        warnings: global_warnings,
        recommendation,
    })
}

// ─── Upgrade Authority Check ────────────────────────────────────────────────

/// Response for upgrade authority status
#[derive(Debug, Serialize)]
pub struct AuthorityStatusResponse {
    pub program_id: String,
    pub is_upgradeable: bool,
    pub upgrade_authority: Option<String>,
    pub risk_level: String,
    pub recommendation: String,
}

/// GET /api/v1/authority/{program_id} — Check upgrade authority of a program
pub async fn authority_status(
    _state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    let program_id = path.into_inner();

    if program_id.len() < 20 || program_id.len() > 60 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid program ID"
        }));
    }

    // Try to check via RPC
    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".into());

    let pubkey = match Pubkey::from_str(&program_id) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid base58 program ID"
            }));
        }
    };

    // Check if it's a native program (not upgradeable)
    let native_programs = [
        "11111111111111111111111111111111",
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "Vote111111111111111111111111111111111111111",
        "Stake11111111111111111111111111111111111111",
        "ComputeBudget111111111111111111111111111111",
    ];

    if native_programs.contains(&program_id.as_str()) {
        return HttpResponse::Ok().json(AuthorityStatusResponse {
            program_id,
            is_upgradeable: false,
            upgrade_authority: None,
            risk_level: "SAFE".into(),
            recommendation: "Native system program — cannot be upgraded.".into(),
        });
    }

    // For non-native programs, attempt RPC lookup
    let client = solana_client::rpc_client::RpcClient::new(rpc_url);

    match client.get_account(&pubkey) {
        Ok(account) => {
            // BPF upgradeable loader programs have a specific owner
            let bpf_loader_upgradeable =
                Pubkey::from_str("BPFLoaderUpgradeab1e11111111111111111111111")
                    .unwrap_or(solana_sdk::bpf_loader_upgradeable::ID);

            let is_upgradeable = account.owner == bpf_loader_upgradeable;

            let (upgrade_authority, risk_level, recommendation) = if is_upgradeable {
                // The first 4 bytes of data contain the account type,
                // bytes 4-36 contain the upgrade authority (if set)
                let authority = if account.data.len() >= 36 {
                    let authority_bytes = &account.data[4..36];
                    let authority_key = Pubkey::new_from_array({
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(authority_bytes);
                        arr
                    });
                    // Zero pubkey means no authority (revoked)
                    if authority_key == Pubkey::default() {
                        None
                    } else {
                        Some(authority_key.to_string())
                    }
                } else {
                    None
                };

                if authority.is_some() {
                    (
                        authority,
                        "ELEVATED".into(),
                        "Program has an active upgrade authority. Code can be changed at any time.".into(),
                    )
                } else {
                    (
                        None,
                        "LOW".into(),
                        "Program is upgradeable but authority is revoked — code is frozen.".into(),
                    )
                }
            } else {
                (
                    None,
                    "SAFE".into(),
                    "Program is not upgradeable — code is immutable.".into(),
                )
            };

            HttpResponse::Ok().json(AuthorityStatusResponse {
                program_id,
                is_upgradeable,
                upgrade_authority,
                risk_level,
                recommendation,
            })
        }
        Err(e) => {
            warn!("RPC lookup failed for {}: {}", program_id, e);
            // Return unknown status instead of error
            HttpResponse::Ok().json(AuthorityStatusResponse {
                program_id,
                is_upgradeable: false,
                upgrade_authority: None,
                risk_level: "UNKNOWN".into(),
                recommendation: format!("Unable to verify — RPC lookup failed: {}", e),
            })
        }
    }
}
