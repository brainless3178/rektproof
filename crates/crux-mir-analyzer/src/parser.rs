use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CruxAnalysisReport {
    pub program_path: PathBuf,
    pub timestamp: String,
    pub prover_backend: String,
    pub exploration_depth: u32,
    pub total_paths: u64,
    pub findings: Vec<CruxFinding>,
    pub execution_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CruxFinding {
    pub id: String,
    pub category: CruxCategory,
    pub description: String,
    pub file_path: String,
    pub line_number: u32,
    pub mir_instruction: Option<String>,
    pub severity: u8,
    pub contradiction_witness: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CruxCategory {
    PathExplorationFailure,
    LogicContradiction,
    ResourceExhaustion,
    InvalidStateTransition,
    CustomPropertyViolation,
}

impl CruxCategory {
    pub fn as_str(&self) -> &str {
        match self {
            Self::PathExplorationFailure => "Path Exploration Failure",
            Self::LogicContradiction => "Contract Logic Contradiction",
            Self::ResourceExhaustion => "Resource Exhaustion",
            Self::InvalidStateTransition => "Invalid State Transition",
            Self::CustomPropertyViolation => "Custom Property Violation",
        }
    }
}

pub enum CruxResult {
    Verified,
    CounterexampleFound(CruxFinding),
    ResourceLimitExceeded,
    ToolError(String),
}
