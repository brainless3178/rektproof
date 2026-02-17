use serde::{Deserialize, Serialize};
use symbolic_engine::proof_engine::ProofResult;

use crate::enhanced_comprehensive::EnhancedSecurityReport;
use anchor_security_analyzer::report::AnchorAnalysisReport;
use certora_prover::CertoraVerificationReport;
use crux_mir_analyzer::CruxReport;
use fuzzdelsol::FuzzDelSolReport;
use geiger_analyzer::report::GeigerAnalysisReport;
use kani_verifier::KaniVerificationReport;
use l3x_analyzer::report::L3xAnalysisReport;
use sec3_analyzer::Sec3AnalysisReport;
use trident_fuzzer::report::TridentFuzzReport;
use wacana_analyzer::report::WacanaReport;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub program_id: String,
    pub total_exploits: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub exploits: Vec<ConfirmedExploit>,
    pub timestamp: String,
    pub security_score: u8,
    pub logic_integrity: f32,
    pub deployment_advice: Option<String>,
    pub logic_invariants: Vec<llm_strategist::LogicInvariant>,
    pub enhanced_report: Option<EnhancedSecurityReport>,
    pub kani_report: Option<KaniVerificationReport>,
    pub certora_report: Option<CertoraVerificationReport>,
    pub wacana_report: Option<WacanaReport>,
    pub trident_report: Option<TridentFuzzReport>,
    pub fuzzdelsol_report: Option<FuzzDelSolReport>,
    pub sec3_report: Option<Sec3AnalysisReport>,
    pub l3x_report: Option<L3xAnalysisReport>,
    pub geiger_report: Option<GeigerAnalysisReport>,
    pub anchor_report: Option<AnchorAnalysisReport>,
    pub crux_report: Option<CruxReport>,
    pub proof_engine_results: Vec<ProofResult>,

    // Engine execution status — tracks what actually ran vs failed
    pub engine_status: EngineStatus,

    // Professional High-Fidelity Fields
    pub total_value_at_risk_usd: f64,
    pub scan_scope: Vec<String>,
    pub standards_compliance: std::collections::HashMap<String, Vec<(String, bool)>>,
    pub model_consensus: Vec<(String, bool, String)>,
    pub overall_risk_score: f32,
    pub technical_risk: f32,
    pub financial_risk: f32,
    pub scan_command: String,
    pub network_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExploitState {
    Discovered,
    Triaged,
    Fixed,
    Verified,
    Ignored,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixMetadata {
    pub estimated_time_mins: u32,
    pub technical_complexity: String,
    pub breaking_change: bool,
    pub affected_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmedExploit {
    pub category: String,
    pub vulnerability_type: String,
    pub severity: u8,
    pub severity_label: String,
    pub id: String,
    pub cwe: Option<String>,
    pub instruction: String,
    pub line_number: usize,
    pub proof_tx: String,
    pub error_code: u32,
    pub description: String,
    pub attack_scenario: String,
    pub secure_fix: String,
    pub prevention: String,
    pub attack_simulation: Option<String>,

    // Lifecycle & State
    pub state: ExploitState,
    pub fix_metadata: Option<FixMetadata>,

    // AI & Risk Metrics
    pub confidence_score: u8,
    pub confidence_reasoning: Vec<String>,
    pub risk_priority: String,
    pub priority_index: u8,
    pub exploit_gas_estimate: u64,
    pub exploit_steps: Vec<String>,
    pub exploit_complexity: String,
    pub value_at_risk_usd: f64,
    pub cve_reference: Option<String>,
    pub historical_hack_context: Option<String>,
    pub mitigation_diff: Option<String>,

    // Proof Receipts
    pub proof_receipt: Option<ExploitProofReceipt>,

    pub vulnerability_type_enhanced: Option<String>,
    pub description_enhanced: Option<String>,
    pub attack_scenario_enhanced: Option<String>,
    pub fix_suggestion_enhanced: Option<String>,
    pub economic_impact: Option<String>,
    pub ai_explanation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitProofReceipt {
    pub transaction_signature: String,
    pub devnet_pda: String,
    pub funds_drained_lamports: u64,
    pub actual_gas_cost: u64,
    pub execution_logs: Vec<String>,
}

/// Tracks which analysis engines actually ran and whether they succeeded.
/// Used by `print_final_summary` to show honest verification badges.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EngineStatus {
    pub z3_symbolic_ran: bool,
    pub z3_symbolic_ok: bool,
    pub on_chain_proving_ran: bool,
    pub on_chain_proving_ok: bool,
    pub on_chain_registry_ran: bool,
    pub on_chain_registry_ok: bool,
    pub kani_ran: bool,
    pub kani_ok: bool,
    pub certora_ran: bool,
    pub certora_ok: bool,
    pub wacana_ran: bool,
    pub wacana_ok: bool,
    pub trident_ran: bool,
    pub trident_real_fuzz: bool,
    pub fuzzdelsol_ran: bool,
    pub fuzzdelsol_real_fuzz: bool,
    pub sec3_ran: bool,
    pub sec3_ok: bool,
    pub l3x_ran: bool,
    pub l3x_ok: bool,
    pub geiger_ran: bool,
    pub geiger_ok: bool,
    pub anchor_ran: bool,
    pub anchor_ok: bool,
    pub crux_ran: bool,
    pub crux_ok: bool,
    pub core_analyzer_ran: bool,
    pub core_analyzer_ok: bool,
    pub taint_ran: bool,
    pub taint_ok: bool,
    pub defi_proof_ran: bool,
    pub defi_proof_ok: bool,
}
