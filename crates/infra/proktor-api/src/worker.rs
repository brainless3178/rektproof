//! Background scan worker — processes security scans asynchronously.
//!
//! Architecture:
//! - Jobs are submitted via `ScanWorker::submit()`, which returns a job ID immediately
//! - A tokio task picks up each job and runs the analysis
//! - Callers poll `ScanWorker::status()` to get results
//!
//! Scan types:
//! 1. **GitHub source scan** — clone repo, run ProgramAnalyzer (full AST + CFG + interprocedural)
//! 2. **On-chain program scan** — fetch program metadata, check upgrade authority,
//!    attempt verified source lookup, run analysis if source found

use program_analyzer::VulnerabilityFinding;
use serde::{Deserialize, Serialize};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};
use tracing::{error, info, warn};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Unique identifier for a scan job (UUID v4 hex string)
pub type JobId = String;

/// What kind of scan to run
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ScanTarget {
    /// Clone a GitHub repo and run full static analysis
    GitHub { url: String },
    /// Analyze an on-chain program by its program ID
    OnChain { program_id: String },
}

/// Current state of a scan job
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed,
}

/// A single finding serialized for the API response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingJson {
    pub flag_id: String,
    pub severity: String,
    pub severity_num: u8,
    pub category: String,
    pub description: String,
    pub location: String,
    pub function_name: String,
    pub line: usize,
    pub vulnerable_code: String,
    pub fix: String,
    pub confidence: u8,
    pub confidence_label: String,
}

/// On-chain program metadata gathered without source code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnChainMeta {
    pub program_id: String,
    pub executable: bool,
    pub upgradeable: bool,
    pub upgrade_authority: Option<String>,
    pub data_len: usize,
    pub owner: String,
    /// Whether we found verified source code
    pub source_verified: bool,
    /// Where the source came from (if found)
    pub source_origin: Option<String>,
}

/// Complete result of a scan job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub status: JobStatus,
    pub scan_type: String,
    pub target: String,
    /// Overall risk score 0-100
    pub risk_score: u32,
    pub risk_level: String,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub findings: Vec<FindingJson>,
    /// On-chain metadata (only for on-chain scans)
    pub on_chain_meta: Option<OnChainMeta>,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub error: Option<String>,
}

/// Internal job state
#[derive(Debug, Clone)]
struct ScanJob {
    id: JobId,
    target: ScanTarget,
    status: JobStatus,
    result: Option<ScanResult>,
    created_at: chrono::DateTime<chrono::Utc>,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Worker
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Maximum number of scan jobs running simultaneously.
/// Each job clones a repo + runs full AST analysis, so this bounds
/// peak memory to ~4 × (repo size + analyzer working set).
const MAX_CONCURRENT_SCANS: usize = 4;

/// Maximum number of jobs stored (queued + completed). Prevents
/// unbounded memory growth from job metadata/results.
const MAX_TOTAL_JOBS: usize = 100;

#[derive(Clone)]
pub struct ScanWorker {
    jobs: Arc<RwLock<HashMap<JobId, ScanJob>>>,
    rpc_client: Arc<RpcClient>,
    /// Limits concurrent scan executions to prevent OOM
    scan_semaphore: Arc<Semaphore>,
}

impl ScanWorker {
    pub fn new(rpc_client: Arc<RpcClient>) -> Self {
        Self {
            jobs: Arc::new(RwLock::new(HashMap::new())),
            rpc_client,
            scan_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_SCANS)),
        }
    }

    /// Submit a new scan job. Returns the job ID immediately.
    /// Returns `None` if the server is at capacity.
    pub async fn submit(&self, target: ScanTarget) -> Option<JobId> {
        // Reject if too many jobs are stored (prevents memory exhaustion)
        {
            let jobs = self.jobs.read().await;
            if jobs.len() >= MAX_TOTAL_JOBS {
                warn!("Job queue full ({} jobs), rejecting submission", jobs.len());
                return None;
            }
        }

        let job_id = generate_job_id();
        let job = ScanJob {
            id: job_id.clone(),
            target: target.clone(),
            status: JobStatus::Queued,
            result: None,
            created_at: chrono::Utc::now(),
        };

        {
            let mut jobs = self.jobs.write().await;
            jobs.insert(job_id.clone(), job);
        }

        // Spawn background task — acquires semaphore permit before executing
        let worker = self.clone();
        let jid = job_id.clone();
        let semaphore = self.scan_semaphore.clone();
        tokio::spawn(async move {
            // Wait for a permit (blocks if MAX_CONCURRENT_SCANS are running)
            let _permit = semaphore.acquire().await.expect("semaphore closed");
            worker.execute_job(jid).await;
            // permit drops here, releasing the slot
        });

        info!("Job {} queued: {:?}", job_id, target);
        Some(job_id)
    }

    /// Get the current status and result of a job.
    pub async fn status(&self, job_id: &str) -> Option<ScanResult> {
        let jobs = self.jobs.read().await;
        let job = jobs.get(job_id)?;

        if let Some(ref result) = job.result {
            Some(result.clone())
        } else {
            // Job is queued or running — return a partial result
            Some(ScanResult {
                status: job.status.clone(),
                scan_type: match &job.target {
                    ScanTarget::GitHub { .. } => "github_source".into(),
                    ScanTarget::OnChain { .. } => "on_chain".into(),
                },
                target: match &job.target {
                    ScanTarget::GitHub { url } => url.clone(),
                    ScanTarget::OnChain { program_id } => program_id.clone(),
                },
                risk_score: 0,
                risk_level: "Pending".into(),
                total_findings: 0,
                critical_count: 0,
                high_count: 0,
                medium_count: 0,
                low_count: 0,
                info_count: 0,
                findings: vec![],
                on_chain_meta: None,
                started_at: job.created_at.to_rfc3339(),
                completed_at: None,
                error: None,
            })
        }
    }

    /// List all jobs (most recent first, limited to last 50)
    pub async fn list_jobs(&self) -> Vec<serde_json::Value> {
        let jobs = self.jobs.read().await;
        let mut entries: Vec<_> = jobs.values().collect();
        entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        entries.iter().take(50).map(|j| {
            serde_json::json!({
                "job_id": j.id,
                "status": j.status,
                "target": match &j.target {
                    ScanTarget::GitHub { url } => url.clone(),
                    ScanTarget::OnChain { program_id } => program_id.clone(),
                },
                "scan_type": match &j.target {
                    ScanTarget::GitHub { .. } => "github_source",
                    ScanTarget::OnChain { .. } => "on_chain",
                },
                "created_at": j.created_at.to_rfc3339(),
            })
        }).collect()
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Job execution
    // ─────────────────────────────────────────────────────────────────────

    async fn execute_job(&self, job_id: JobId) {
        // Mark as running
        {
            let mut jobs = self.jobs.write().await;
            if let Some(job) = jobs.get_mut(&job_id) {
                job.status = JobStatus::Running;
            }
        }

        let target = {
            let jobs = self.jobs.read().await;
            match jobs.get(&job_id) {
                Some(j) => j.target.clone(),
                None => return,
            }
        };

        let result = match target {
            ScanTarget::GitHub { ref url } => self.execute_github_scan(url).await,
            ScanTarget::OnChain { ref program_id } => {
                self.execute_onchain_scan(program_id).await
            }
        };

        // Store result
        {
            let mut jobs = self.jobs.write().await;
            if let Some(job) = jobs.get_mut(&job_id) {
                match result {
                    Ok(r) => {
                        job.status = JobStatus::Completed;
                        info!(
                            "Job {} completed: {} findings, risk {}/100",
                            job_id, r.total_findings, r.risk_score
                        );
                        job.result = Some(r);
                    }
                    Err(e) => {
                        job.status = JobStatus::Failed;
                        error!("Job {} failed: {}", job_id, e);
                        job.result = Some(ScanResult {
                            status: JobStatus::Failed,
                            scan_type: match &job.target {
                                ScanTarget::GitHub { .. } => "github_source".into(),
                                ScanTarget::OnChain { .. } => "on_chain".into(),
                            },
                            target: match &job.target {
                                ScanTarget::GitHub { url } => url.clone(),
                                ScanTarget::OnChain { program_id } => program_id.clone(),
                            },
                            risk_score: 0,
                            risk_level: "Unknown".into(),
                            total_findings: 0,
                            critical_count: 0,
                            high_count: 0,
                            medium_count: 0,
                            low_count: 0,
                            info_count: 0,
                            findings: vec![],
                            on_chain_meta: None,
                            started_at: job.created_at.to_rfc3339(),
                            completed_at: Some(chrono::Utc::now().to_rfc3339()),
                            error: Some(e),
                        });
                    }
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    //  GitHub source scan
    // ─────────────────────────────────────────────────────────────────────

    async fn execute_github_scan(&self, repo_url: &str) -> Result<ScanResult, String> {
        use std::process::Command;

        let repo_name = repo_url
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or("unknown")
            .trim_end_matches(".git")
            .to_string();

        info!("[worker] Cloning {} ...", repo_url);

        let tmp_dir = tempfile::tempdir().map_err(|e| format!("tempdir: {}", e))?;
        let clone_path = tmp_dir.path().to_path_buf();

        // Clone (blocking, in spawn_blocking)
        let url = repo_url.to_string();
        let path = clone_path.clone();
        let output = tokio::task::spawn_blocking(move || {
            Command::new("git")
                .args(["clone", "--depth", "1", &url, &path.to_string_lossy()])
                .output()
        })
        .await
        .map_err(|e| format!("join: {}", e))?
        .map_err(|e| format!("git: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("git clone failed: {}", stderr));
        }

        info!("[worker] Clone complete, analyzing {} ...", repo_name);

        // Run analysis
        let path = clone_path.clone();
        let findings = tokio::task::spawn_blocking(move || run_analysis(&path))
            .await
            .map_err(|e| format!("join: {}", e))?;

        let result = build_scan_result(
            "github_source",
            repo_url,
            findings,
            None,
        );

        Ok(result)
    }

    // ─────────────────────────────────────────────────────────────────────
    //  On-chain program scan
    // ─────────────────────────────────────────────────────────────────────

    async fn execute_onchain_scan(&self, program_id_str: &str) -> Result<ScanResult, String> {
        let program_id: Pubkey = program_id_str
            .parse()
            .map_err(|_| format!("Invalid program ID: {}", program_id_str))?;

        info!("[worker] Fetching on-chain data for {} ...", program_id);

        // Step 1: Fetch program account
        let account = self
            .rpc_client
            .get_account(&program_id)
            .await
            .map_err(|e| format!("RPC error: {}", e))?;

        if !account.executable {
            return Err(format!("{} is not an executable program", program_id));
        }

        // Step 2: Check if upgradeable (BPF Upgradeable Loader)
        let bpf_upgradeable_loader =
            solana_sdk::bpf_loader_upgradeable::id();
        let is_upgradeable = account.owner == bpf_upgradeable_loader;

        let mut upgrade_authority: Option<String> = None;

        if is_upgradeable {
            // The program account contains a pointer to ProgramData
            // ProgramData account = findProgramAddress([program_id], BPFUpgradeableLoaderID)
            let (programdata_address, _) = Pubkey::find_program_address(
                &[program_id.as_ref()],
                &bpf_upgradeable_loader,
            );

            if let Ok(pd_account) = self.rpc_client.get_account(&programdata_address).await {
                // ProgramData layout: 4 bytes (state) + 8 bytes (slot) + 1 byte (has_authority) + 32 bytes (authority)
                if pd_account.data.len() > 45 {
                    let has_authority = pd_account.data[12] == 1;
                    if has_authority {
                        let auth_bytes = &pd_account.data[13..45];
                        let auth_pubkey = Pubkey::try_from(auth_bytes)
                            .map(|p| p.to_string())
                            .unwrap_or_else(|_| "unknown".into());
                        upgrade_authority = Some(auth_pubkey);
                    }
                }
            }
        }

        let on_chain_meta = OnChainMeta {
            program_id: program_id.to_string(),
            executable: true,
            upgradeable: is_upgradeable,
            upgrade_authority: upgrade_authority.clone(),
            data_len: account.data.len(),
            owner: account.owner.to_string(),
            source_verified: false,
            source_origin: None,
        };

        // Step 3: Try to find verified source code
        let source_findings =
            self.try_source_lookup(&program_id, &mut on_chain_meta.clone()).await;

        match source_findings {
            Some((findings, mut meta)) => {
                // Found source — full analysis
                meta.source_verified = true;
                let result = build_scan_result(
                    "on_chain_with_source",
                    program_id_str,
                    findings,
                    Some(meta),
                );
                Ok(result)
            }
            None => {
                // No source found — on-chain metadata only
                info!(
                    "[worker] No verified source found for {}. Reporting on-chain metadata only.",
                    program_id
                );

                // Generate metadata-based findings
                let mut findings = Vec::new();

                if is_upgradeable {
                    if let Some(ref auth) = upgrade_authority {
                        // Upgradeable with a single EOA authority is a risk
                        findings.push(VulnerabilityFinding {
                            category: "Governance Security".into(),
                            vuln_type: "Single Upgrade Authority".into(),
                            severity: 3,
                            severity_label: "MEDIUM".into(),
                            id: "SOL-META-01".into(),
                            cwe: Some("CWE-269".into()),
                            location: program_id.to_string(),
                            function_name: String::new(),
                            line_number: 0,
                            vulnerable_code: format!("upgrade_authority: {}", auth),
                            description: format!(
                                "Program is upgradeable with authority {}. \
                                 A compromised or malicious authority can replace the \
                                 program code at any time. Consider using a multisig \
                                 or DAO governance for the upgrade authority.",
                                auth
                            ),
                            attack_scenario:
                                "Upgrade authority key is compromised. Attacker deploys \
                                 malicious program that drains all funds."
                                    .into(),
                            real_world_incident: Some(
                                program_analyzer::Incident {
                                    project: "Mango Markets".into(),
                                    loss: "$114M".into(),
                                    date: "2022-10".into(),
                                },
                            ),
                            secure_fix:
                                "Use a multisig (e.g., Squads) as the upgrade authority. \
                                 Consider freezing the program after audit."
                                    .into(),
                            confidence: 65,
                            prevention:
                                "Use multisig upgrade authority. Implement timelocks for upgrades."
                                    .into(),
                        });
                    }
                } else {
                    // Non-upgradeable: immutable, which is generally safer
                    // but means bugs can't be fixed
                    findings.push(VulnerabilityFinding {
                        category: "Program Lifecycle".into(),
                        vuln_type: "Immutable Program".into(),
                        severity: 1,
                        severity_label: "INFO".into(),
                        id: "SOL-META-02".into(),
                        cwe: None,
                        location: program_id.to_string(),
                        function_name: String::new(),
                        line_number: 0,
                        vulnerable_code: String::new(),
                        description:
                            "Program is immutable (non-upgradeable). Bugs cannot be patched \
                             without migrating to a new program address."
                                .into(),
                        attack_scenario: String::new(),
                        real_world_incident: None,
                        secure_fix: "Ensure thorough audit before making a program immutable."
                            .into(),
                        confidence: 95,
                        prevention: "Complete full security audit before freezing program.".into(),
                    });
                }

                let result = build_scan_result(
                    "on_chain_metadata",
                    program_id_str,
                    findings,
                    Some(on_chain_meta),
                );
                Ok(result)
            }
        }
    }

    /// Try to find verified source code for a program.
    /// Checks: Anchor verified builds registry, known SPL mappings.
    async fn try_source_lookup(
        &self,
        program_id: &Pubkey,
        meta: &mut OnChainMeta,
    ) -> Option<(Vec<VulnerabilityFinding>, OnChainMeta)> {
        let pid_str = program_id.to_string();

        // ── 1. Known SPL program mappings ────────────────────────────────
        let spl_mapping = known_spl_source(&pid_str);
        if let Some(repo_path) = spl_mapping {
            info!("[worker] Known SPL program, checking local source at {}", repo_path);
            let path = PathBuf::from(&repo_path);
            if path.exists() {
                let findings = run_analysis(&path);
                meta.source_verified = true;
                meta.source_origin = Some(format!("local_spl:{}", repo_path));
                return Some((findings, meta.clone()));
            }
        }

        // ── 2. Anchor Verified Builds API ────────────────────────────────
        let anchor_url = format!(
            "https://anchor.projectserum.com/api/v0/program/{}/latest",
            pid_str
        );

        match reqwest::get(&anchor_url).await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(repo_url) = body["repository"].as_str() {
                        info!("[worker] Found verified build: repo={}", repo_url);
                        // Clone and analyze
                        let tmp_dir = tempfile::tempdir().ok()?;
                        let clone_path = tmp_dir.path().to_path_buf();
                        let url = repo_url.to_string();
                        let path = clone_path.clone();

                        let output = tokio::task::spawn_blocking(move || {
                            std::process::Command::new("git")
                                .args(["clone", "--depth", "1", &url, &path.to_string_lossy()])
                                .output()
                        })
                        .await
                        .ok()?
                        .ok()?;

                        if output.status.success() {
                            let findings = tokio::task::spawn_blocking({
                                let p = clone_path.clone();
                                move || run_analysis(&p)
                            })
                            .await
                            .ok()?;

                            meta.source_verified = true;
                            meta.source_origin =
                                Some(format!("anchor_verified:{}", repo_url));
                            return Some((findings, meta.clone()));
                        }
                    }
                }
            }
            _ => {
                // Not in Anchor registry — that's fine
            }
        }

        // ── 3. OtterSec Verified Builds ──────────────────────────────────
        let otter_url = format!(
            "https://verify.osec.io/status/{}",
            pid_str
        );

        match reqwest::get(&otter_url).await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if body["is_verified"].as_bool() == Some(true) {
                        if let Some(repo_url) = body["repo_url"].as_str() {
                            info!("[worker] OtterSec verified: repo={}", repo_url);
                            let tmp_dir = tempfile::tempdir().ok()?;
                            let clone_path = tmp_dir.path().to_path_buf();
                            let url = repo_url.to_string();
                            let path = clone_path.clone();

                            let output = tokio::task::spawn_blocking(move || {
                                std::process::Command::new("git")
                                    .args([
                                        "clone",
                                        "--depth",
                                        "1",
                                        &url,
                                        &path.to_string_lossy(),
                                    ])
                                    .output()
                            })
                            .await
                            .ok()?
                            .ok()?;

                            if output.status.success() {
                                let findings = tokio::task::spawn_blocking({
                                    let p = clone_path.clone();
                                    move || run_analysis(&p)
                                })
                                .await
                                .ok()?;

                                meta.source_verified = true;
                                meta.source_origin =
                                    Some(format!("ottersec_verified:{}", repo_url));
                                return Some((findings, meta.clone()));
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        None
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn generate_job_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    // Simple unique ID: timestamp + random suffix
    format!("scan-{:x}-{:04x}", nanos, rand_u16())
}

fn rand_u16() -> u16 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let s = RandomState::new();
    let mut h = s.build_hasher();
    h.write_u8(0);
    h.finish() as u16
}

/// Run the full ProgramAnalyzer pipeline on a directory.
/// Handles both top-level analysis and subdirectory search.
fn run_analysis(path: &std::path::Path) -> Vec<VulnerabilityFinding> {
    match program_analyzer::ProgramAnalyzer::new(path) {
        Ok(analyzer) => analyzer.scan_for_vulnerabilities(),
        Err(_) => {
            // Top-level failed — search for Rust subdirectories
            find_and_analyze_rust_dirs(path)
        }
    }
}

/// Recursively find directories containing .rs files and analyze them.
fn find_and_analyze_rust_dirs(root: &std::path::Path) -> Vec<VulnerabilityFinding> {
    let mut all_findings = Vec::new();

    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let has_rust_files = std::fs::read_dir(&path)
                    .map(|rd| {
                        rd.flatten().any(|e| {
                            e.path()
                                .extension()
                                .map(|ext| ext == "rs")
                                .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false);

                let has_src_dir = path.join("src").is_dir();

                if has_rust_files || has_src_dir {
                    if let Ok(analyzer) = program_analyzer::ProgramAnalyzer::new(&path) {
                        all_findings.extend(analyzer.scan_for_vulnerabilities());
                    }
                }

                all_findings.extend(find_and_analyze_rust_dirs(&path));
            }
        }
    }

    all_findings
}

/// Convert findings into a ScanResult with computed scores.
fn build_scan_result(
    scan_type: &str,
    target: &str,
    findings: Vec<VulnerabilityFinding>,
    on_chain_meta: Option<OnChainMeta>,
) -> ScanResult {
    let critical_count = findings.iter().filter(|f| f.severity >= 5).count();
    let high_count = findings.iter().filter(|f| f.severity == 4).count();
    let medium_count = findings.iter().filter(|f| f.severity == 3).count();
    let low_count = findings.iter().filter(|f| f.severity == 2).count();
    let info_count = findings.iter().filter(|f| f.severity <= 1).count();
    let total = findings.len();

    let risk_score: u32 = std::cmp::min(
        100,
        (critical_count as u32 * 15)
            + (high_count as u32 * 8)
            + (medium_count as u32 * 4)
            + (low_count as u32 * 2)
            + (info_count as u32),
    );

    let risk_level = match risk_score {
        0..=20 => "Low",
        21..=40 => "Moderate",
        41..=60 => "Elevated",
        61..=80 => "High",
        _ => "Critical",
    };

    let findings_json: Vec<FindingJson> = findings
        .iter()
        .take(200)
        .map(|f| {
            let confidence_label = match f.confidence {
                70..=100 => "confirmed",
                40..=69 => "likely",
                _ => "possible",
            };
            FindingJson {
                flag_id: f.id.clone(),
                severity: f.severity_label.clone(),
                severity_num: f.severity as u8,
                category: f.category.clone(),
                description: f.description.chars().take(1000).collect(),
                location: f.location.clone(),
                function_name: f.function_name.clone(),
                line: f.line_number,
                vulnerable_code: f.vulnerable_code.chars().take(500).collect(),
                fix: f.secure_fix.chars().take(500).collect(),
                confidence: f.confidence as u8,
                confidence_label: confidence_label.into(),
            }
        })
        .collect();

    ScanResult {
        status: JobStatus::Completed,
        scan_type: scan_type.into(),
        target: target.into(),
        risk_score,
        risk_level: risk_level.into(),
        total_findings: total,
        critical_count,
        high_count,
        medium_count,
        low_count,
        info_count,
        findings: findings_json,
        on_chain_meta,
        started_at: chrono::Utc::now().to_rfc3339(),
        completed_at: Some(chrono::Utc::now().to_rfc3339()),
        error: None,
    }
}

/// Map well-known program IDs to local source directories.
fn known_spl_source(program_id: &str) -> Option<&'static str> {
    match program_id {
        // SPL Token
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" => {
            Some("./real_exploits/spl/token/program/src")
        }
        // SPL Token 2022
        "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb" => {
            Some("./real_exploits/spl/token/program-2022/src")
        }
        // Token Lending
        "LendZqTs7gn5CTSJU1jWKhKuVpjJGom45nnwPb2AMTi" => {
            Some("./real_exploits/spl/token-lending/program/src")
        }
        _ => None,
    }
}
