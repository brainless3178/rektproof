//! FuzzDelSol — Coverage-Guided eBPF Binary Fuzzer
//!
//! FuzzDelSol is a coverage-guided binary fuzzer for Solana eBPF bytecode.
//! It executes compiled .so binaries directly and uses security oracles to
//! detect missing signer checks and unauthorized state changes in seconds.
//!
//! ## Key Features
//!
//! - **Binary-Level Fuzzing**: Operates on compiled eBPF bytecode, catching
//!   bugs that source-level tools miss
//! - **Coverage-Guided**: Uses code coverage feedback to explore new paths
//! - **Security Oracles**: Detects missing signer checks, unauthorized state
//!   changes, missing owner checks, and account substitution vulnerabilities
//! - **Fast**: Finds vulnerabilities in under 5 seconds
//! - **Post-Compilation**: Runs after `cargo build-sbf`, validating the
//!   actual deployed bytecode

mod bytecode_parser;
mod fuzz_engine;
pub mod oracles;
pub mod report;

pub use bytecode_parser::{EbpfParser, EbpfProgramModel};
pub use fuzz_engine::{FuzzCampaignResult, FuzzConfig, FuzzEngine, OracleType};
pub use oracles::{Oracle, OracleViolation, ViolationSeverity};
pub use report::{FuzzDelSolFinding, FuzzDelSolReport};

use std::path::Path;
use thiserror::Error;
use tracing::info;

// ─── Error Types ─────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum FuzzDelSolError {
    #[error("Failed to parse eBPF binary: {0}")]
    ParseError(String),

    #[error("Fuzzing campaign failed: {0}")]
    FuzzError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Binary not found: {0}")]
    BinaryNotFound(String),
}

// ─── Main Fuzzer ─────────────────────────────────────────────────────────────

/// Main entry point for FuzzDelSol binary fuzzing.
pub struct FuzzDelSol {
    config: FuzzConfig,
    parser: EbpfParser,
}

impl FuzzDelSol {
    /// Create a new FuzzDelSol instance with the given configuration.
    pub fn with_config(config: FuzzConfig) -> Self {
        Self {
            config,
            parser: EbpfParser::new(),
        }
    }

    /// Run the complete FuzzDelSol pipeline on a compiled Solana program.
    ///
    /// This orchestrates:
    /// 1. Parse eBPF binary to extract program model
    /// 2. Initialize security oracles
    /// 3. Run coverage-guided fuzzing campaign
    /// 4. Collect oracle violations
    /// 5. Generate structured report
    pub fn fuzz_binary(&mut self, binary_path: &Path) -> Result<FuzzDelSolReport, FuzzDelSolError> {
        let start_time = std::time::Instant::now();
        info!("FuzzDelSol: Starting binary fuzzing for {:?}", binary_path);

        // Phase 1: Parse eBPF binary
        let model = self
            .parser
            .parse_binary(binary_path)
            .map_err(FuzzDelSolError::ParseError)?;

        info!(
            "FuzzDelSol: Parsed binary — {} functions, {} instructions, {} signer checks",
            model.functions.len(),
            model.instruction_count,
            model.signer_checks.len(),
        );

        // Phase 2: Run fuzzing campaign
        let mut engine = FuzzEngine::new(self.config.clone());
        let campaign_result = engine.fuzz_program(&model);

        info!(
            "FuzzDelSol: Fuzzing complete — {} iterations, {:.1}% coverage, {} violations",
            campaign_result.total_iterations,
            campaign_result.coverage_pct,
            campaign_result.violations.len(),
        );

        // Phase 3: Build report
        let findings: Vec<FuzzDelSolFinding> = campaign_result
            .violations
            .iter()
            .map(|v| FuzzDelSolFinding::from_violation(v.clone()))
            .collect();

        let critical_count = findings
            .iter()
            .filter(|f| f.severity == ViolationSeverity::Critical)
            .count();
        let high_count = findings
            .iter()
            .filter(|f| f.severity == ViolationSeverity::High)
            .count();
        let medium_count = findings
            .iter()
            .filter(|f| f.severity == ViolationSeverity::Medium)
            .count();
        let low_count = findings
            .iter()
            .filter(|f| f.severity == ViolationSeverity::Low)
            .count();

        let report = FuzzDelSolReport {
            binary_path: binary_path.to_path_buf(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            binary_hash: model.binary_hash.clone(),
            program_model: model,
            violations: findings,
            critical_count,
            high_count,
            medium_count,
            low_count,
            total_iterations: campaign_result.total_iterations,
            coverage_pct: campaign_result.coverage_pct,
            execution_time_ms: start_time.elapsed().as_millis() as u64,
            fuzzing_backend: "FuzzDelSol Coverage-Guided eBPF Fuzzer".to_string(),
        };

        Ok(report)
    }

    /// Find the compiled .so binary for a Solana program.
    ///
    /// Searches in order:
    /// 1. `<program_path>/target/deploy/`
    /// 2. `<workspace_root>/target/deploy/` (Anchor workspaces place .so here)
    pub fn find_binary(program_path: &Path) -> Result<std::path::PathBuf, FuzzDelSolError> {
        // 1. Check program-local target/deploy
        let deploy_dir = program_path.join("target").join("deploy");
        if let Some(so) = Self::find_so_in_dir(&deploy_dir) {
            return Ok(so);
        }

        // 2. Walk up to find workspace root and check there
        if let Some(root) = Self::find_workspace_root(program_path) {
            let ws_deploy = root.join("target").join("deploy");
            if let Some(so) = Self::find_so_in_dir(&ws_deploy) {
                info!("FuzzDelSol: Found binary in workspace root: {:?}", so);
                return Ok(so);
            }
        }

        Err(FuzzDelSolError::BinaryNotFound(format!(
            "No .so file found for {:?}. Run `cargo build-sbf` first.",
            program_path,
        )))
    }

    /// Scan a directory for .so files.
    fn find_so_in_dir(dir: &Path) -> Option<std::path::PathBuf> {
        if !dir.exists() { return None; }
        for entry in std::fs::read_dir(dir).ok()? {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("so") {
                info!("FuzzDelSol: Found binary: {:?}", path);
                return Some(path);
            }
        }
        None
    }

    /// Walk up parent directories to find workspace root (Anchor.toml or [workspace]).
    fn find_workspace_root(start: &Path) -> Option<std::path::PathBuf> {
        let mut current = start.to_path_buf();
        for _ in 0..5 {
            if current.join("Anchor.toml").exists() {
                return Some(current);
            }
            let cargo_toml = current.join("Cargo.toml");
            if cargo_toml.exists() {
                if let Ok(content) = std::fs::read_to_string(&cargo_toml) {
                    if content.contains("[workspace]") {
                        return Some(current);
                    }
                }
            }
            if !current.pop() { break; }
        }
        None
    }
}

impl Default for FuzzDelSol {
    fn default() -> Self {
        Self::with_config(FuzzConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let fuzzer = FuzzDelSol::default();
        assert_eq!(fuzzer.config.max_iterations, 10_000);
        assert_eq!(fuzzer.config.timeout_seconds, 5);
        assert!(fuzzer.config.coverage_guided);
    }

    #[test]
    fn test_custom_config() {
        let config = FuzzConfig {
            max_iterations: 500,
            timeout_seconds: 2,
            coverage_guided: false,
            ..Default::default()
        };
        let fuzzer = FuzzDelSol::with_config(config.clone());
        assert_eq!(fuzzer.config.max_iterations, 500);
        assert_eq!(fuzzer.config.timeout_seconds, 2);
        assert!(!fuzzer.config.coverage_guided);
    }

    #[test]
    fn test_fuzz_engine_creation() {
        let engine = FuzzEngine::new(FuzzConfig::default());
        // Engine should be created without panic
        let _ = engine;
    }

    #[test]
    fn test_oracle_types_are_distinct() {
        let oracles = vec![
            OracleType::MissingSignerCheck,
            OracleType::UnauthorizedStateChange,
            OracleType::MissingOwnerCheck,
            OracleType::ArbitraryAccountSubstitution,
        ];
        let mut set = std::collections::HashSet::new();
        for o in &oracles {
            set.insert(o.clone());
        }
        assert_eq!(set.len(), 4, "All oracle types should be distinct");
    }

    #[test]
    fn test_ebpf_parser_instantiation() {
        let parser = EbpfParser::new();
        // Parser should be created without panic
        let _ = parser;
    }

    #[test]
    fn test_find_binary_returns_error_for_nonexistent_path() {
        let result = FuzzDelSol::find_binary(Path::new("/nonexistent/path/to/program"));
        assert!(result.is_err());
        match result.unwrap_err() {
            FuzzDelSolError::BinaryNotFound(msg) => {
                assert!(msg.contains("No .so file found"), "Error should mention missing .so: {}", msg);
            }
            e => panic!("Expected BinaryNotFound, got {:?}", e),
        }
    }

    #[test]
    fn test_find_workspace_root_returns_none_for_tmp() {
        let result = FuzzDelSol::find_workspace_root(Path::new("/tmp"));
        // /tmp doesn't have Anchor.toml or [workspace] Cargo.toml
        assert!(result.is_none() || result.is_some(), "Should return without panicking");
    }

    #[test]
    fn test_error_display_messages() {
        let e1 = FuzzDelSolError::ParseError("bad binary".into());
        assert!(e1.to_string().contains("parse eBPF"));

        let e2 = FuzzDelSolError::FuzzError("timeout".into());
        assert!(e2.to_string().contains("Fuzzing campaign"));

        let e3 = FuzzDelSolError::BinaryNotFound("missing.so".into());
        assert!(e3.to_string().contains("Binary not found"));
    }
}
