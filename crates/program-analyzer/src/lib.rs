//! # program-analyzer
//!
//! Static analysis for Solana/Anchor programs. Runs 20 scanning phases
//! covering pattern matching, taint analysis, CFG analysis, abstract
//! interpretation, and Z3-backed formal verification.
//!
//! Phases execute in three batches:
//! - Phases 1-10: sequential core analysis
//! - Phases 11-15: parallel heuristic/concolic analysis
//! - Phases 16-20: parallel formal verification (Z3)
//!
//! ```rust,ignore
//! let analyzer = ProgramAnalyzer::new(Path::new("./my-program"))?;
//! let findings = analyzer.scan_for_vulnerabilities();
//! ```

use colored::Colorize;
use quote::ToTokens;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use syn::{Expr, File, Item, ItemFn, ItemStruct, Stmt};

/// Normalize `quote!()` token spacing back to source-level patterns.
/// `quote!` inserts spaces around `<`, `>`, `#[`, `(`, `)` etc., which
/// breaks all string-matching vulnerability detectors.
fn normalize_quote_output(code: &str) -> String {
    code
        .replace("# [", "#[")
        .replace("Signer < ", "Signer<")
        .replace("Account < ", "Account<")
        .replace("Program < ", "Program<")
        .replace("AccountInfo < ", "AccountInfo<")
        .replace("UncheckedAccount < ", "UncheckedAccount<")
        .replace("AccountLoader < ", "AccountLoader<")
        .replace("InterfaceAccount < ", "InterfaceAccount<")
        .replace("Interface < ", "Interface<")
        .replace("SystemAccount < ", "SystemAccount<")
        .replace("Context < ", "Context<")
        .replace("Box < ", "Box<")
        .replace("Option < ", "Option<")
        .replace("Vec < ", "Vec<")
        .replace("Result < ", "Result<")
        .replace("CpiContext < ", "CpiContext<")
        .replace("'info >", "'info>")
        .replace("'info , ", "'info, ")
        .replace("TokenAccount >", "TokenAccount>")
        .replace("Token >", "Token>")
        .replace("Mint >", "Mint>")
        .replace("Vault >", "Vault>")
        .replace("System >", "System>")
        .replace("(signer )", "(signer)")
        .replace("(mut )", "(mut)")
        .replace("(mut , ", "(mut, ")
        .replace("(init , ", "(init, ")
}

pub mod anchor_extractor;
pub mod ast_checks;
pub mod ast_parser;
pub mod config;
pub mod finding_validator;
pub mod idl_loader;
pub mod metrics;
pub mod report_generator;
pub mod security;
pub mod traits;
pub mod vulnerability_db;

pub mod deep_ast_scanner;
pub mod defi_detector;
pub mod taint_lattice;
pub mod cfg_analyzer;
pub mod abstract_interp;
pub mod ast_to_z3;
pub mod rektproof_config;
pub mod vuln_knowledge_base;
pub mod account_aliasing;

pub mod phase_timing;
pub mod vuln_registry;
pub mod converters;
pub mod pipeline;

#[cfg(test)]
mod e2e_tests;

pub use config::{AnalyzerConfig, ConfigBuilder};
pub use deep_ast_scanner::deep_scan;
pub use defi_detector::{analyze_defi_vulnerabilities, DeFiAnalysisResult, ProtocolType};
pub use taint_lattice::{analyze_taint, TaintLevel, TaintState};
pub use cfg_analyzer::{analyze_cfg, ControlFlowGraph, CfgSecurityResult};
pub use abstract_interp::{analyze_intervals, Interval, AbstractState};
pub use account_aliasing::{analyze_account_aliasing, AliasAnalysisResult};
pub use finding_validator::{ProjectContext, validate_findings, validate_findings_with_threshold};
pub use metrics::{MetricsRegistry, METRICS};
pub use phase_timing::{PhaseTimer, PhaseRecord, TimingReport};
pub use security::{validation, RateLimiter, Secret};
pub use traits::{AnalysisPipeline, Analyzer, AnalyzerCapabilities, Finding, Severity};
pub use vulnerability_db::VulnerabilityPattern;
pub use vuln_registry::VulnRegistry;

/// Orchestrates all scanning phases over parsed Solana program source.
pub struct ProgramAnalyzer {
    source_files: Vec<(String, File)>,
    /// Raw source text per file - needed by deep_ast_scanner for line-level precision
    raw_sources: Vec<(String, String)>,
    vulnerability_db: vulnerability_db::VulnerabilityDatabase,
    /// Original program directory - needed by Sec3 detectors that re-scan from disk
    program_dir: Option<std::path::PathBuf>,
}

impl ProgramAnalyzer {
    pub fn new(program_dir: &Path) -> Result<Self, AnalyzerError> {
        let mut source_files = Vec::new();
        let mut raw_sources = Vec::new();

        // walk directory, parse .rs files
        for entry in walkdir::WalkDir::new(program_dir) {
            let entry = entry.map_err(AnalyzerError::WalkDir)?;
            if entry.path().extension().and_then(|s| s.to_str()) == Some("rs") {
                let content = fs::read_to_string(entry.path())?;
                match syn::parse_file(&content) {
                    Ok(file) => {
                        let filename = entry
                            .path()
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown.rs")
                            .to_string();
                        raw_sources.push((filename.clone(), content));
                        source_files.push((filename, file));
                    }
                    Err(e) => {
                        eprintln!(
                            "  {} Skipping {}: Parse error: {}",
                            "warn:".yellow(),
                            entry.path().display(),
                            e
                        );
                    }
                }
            }
        }

        Ok(Self {
            source_files,
            raw_sources,
            vulnerability_db: vulnerability_db::VulnerabilityDatabase::load(),
            program_dir: Some(program_dir.to_path_buf()),
        })
    }

    /// Analyze a source string directly (for testing or inline analysis).
    pub fn from_source(source: &str) -> Result<Self, AnalyzerError> {
        let file = syn::parse_file(source)?;
        Ok(Self {
            source_files: vec![("source.rs".to_string(), file)],
            raw_sources: vec![("source.rs".to_string(), source.to_string())],
            vulnerability_db: vulnerability_db::VulnerabilityDatabase::load(),
            program_dir: None,
        })
    }

    /// Find all structs with #[account]
    pub fn extract_account_schemas(&self) -> Vec<AccountSchema> {
        let mut schemas = Vec::new();

        for (_, file) in &self.source_files {
            for item in &file.items {
                if let Item::Struct(item_struct) = item {
                    if self.has_account_attribute(&item_struct.attrs) {
                        let schema = self.parse_account_struct(item_struct);
                        schemas.push(schema);
                    }
                }
            }
        }

        schemas
    }

    /// Get the body of a specific instruction fn
    pub fn extract_instruction_logic(&self, instruction_name: &str) -> Option<InstructionLogic> {
        for (_, file) in &self.source_files {
            for item in &file.items {
                if let Item::Fn(func) = item {
                    if func.sig.ident == instruction_name {
                        return Some(self.parse_function_logic(func));
                    }
                }
            }
        }
        None
    }

    /// Run all 20 vulnerability scanning phases against parsed AST.
    ///
    /// This is the raw scan - no false-positive filtering, no confidence scoring.
    /// The phases execute in three batches:
    ///
    /// 1. **Batch 1** (sequential, Phases 1–10): Pattern matching, deep AST, taint,
    ///    CFG, abstract interpretation, aliasing, Sec3, Anchor, dataflow, DeFi.
    /// 2. **Batch 2** (parallel, Phases 11–15): Context-sensitive taint, arithmetic
    ///    expert, geiger, invariant miner, concolic execution.
    /// 3. **Batch 3** (parallel, Phases 16–20): Formal verification - Kani, Z3
    ///    arithmetic proofs, schema invariants, state machine, symbolic engine.
    ///
    /// Results are enriched with attack scenarios and deduplicated across phases.
    pub fn scan_for_vulnerabilities_raw(&self) -> Vec<VulnerabilityFinding> {
        let mut findings = Vec::new();

        // Phase 1: Pattern-based scanner (original 72 patterns)
        for (filename, file) in &self.source_files {
            self.scan_items(&file.items, filename, &mut findings);
        }

        // Phase 2: Deep AST scanner (precise line-level detection)
        for (filename, source) in &self.raw_sources {
            let deep_findings = deep_ast_scanner::deep_scan(source, filename);
            findings.extend(deep_findings);
        }

        // Phase 3: Lattice-based taint analysis (information flow)
        // 3a: Intraprocedural analysis — per-function worklist iteration
        for (filename, source) in &self.raw_sources {
            let taint_results = taint_lattice::analyze_taint(source, filename);
            for result in taint_results {
                findings.extend(result.findings);
            }
        }
        // 3b: Interprocedural analysis — cross-file call graph + taint summaries
        //     Merge call graphs from ALL files to detect cross-file taint flows
        {
            let mut all_edges = Vec::new();
            let mut all_summaries = Vec::new();
            for (_filename, source) in &self.raw_sources {
                let (edges, summaries) = taint_lattice::build_call_graph(source);
                all_edges.extend(edges);
                all_summaries.extend(summaries);
            }
            if !all_edges.is_empty() {
                for (filename, source) in &self.raw_sources {
                    let mut intra_results = taint_lattice::analyze_taint(source, filename);
                    taint_lattice::apply_interprocedural_summaries(
                        &mut intra_results, &all_edges, &all_summaries, filename,
                    );
                    for result in intra_results {
                        for f in result.findings {
                            if f.id.contains("IP") {
                                findings.push(f);
                            }
                        }
                    }
                }
            }
        }

        // Phase 4: CFG security analysis (dominator-based property verification)
        for (filename, source) in &self.raw_sources {
            let cfg_results = cfg_analyzer::analyze_cfg(source, filename);
            for result in cfg_results {
                findings.extend(result.findings);
            }
        }

        // Phase 5: Abstract interpretation (interval arithmetic, overflow proofs)
        for (filename, source) in &self.raw_sources {
            let interval_findings = abstract_interp::analyze_intervals(source, filename);
            findings.extend(interval_findings);
        }

        // Phase 5b: Z3-backed formal verification (BV64 constraint solving)
        //           Generates SMT formulas from syn::Expr AST nodes and uses
        //           Z3 to prove arithmetic safety or find counterexamples.
        for (filename, source) in &self.raw_sources {
            let z3_findings = ast_to_z3::verify_with_z3(source, filename);
            findings.extend(z3_findings);
        }

        // Phase 6: Account aliasing & confusion analysis
        for (filename, source) in &self.raw_sources {
            let alias_results = account_aliasing::analyze_account_aliasing(source, filename);
            for result in alias_results {
                findings.extend(result.findings);
            }
        }

        // Phase 7: Sec3 (Soteria) deep analysis - ONLY net-new detector
        //          categories not already covered by Phases 1-6.
        //          Overlap detectors (owner, signer, integer, CPI) are disabled
        //          because the production equivalents have better calibration.
        if let Some(ref dir) = self.program_dir {
            let config = sec3_analyzer::Sec3Config {
                // --- Net-new detectors (these are the value-add) ---
                check_close_accounts: true,
                check_duplicate_accounts: true,
                check_remaining_accounts: true,
                check_pda_security: true,
                check_account_confusion: true,
                // --- Disabled: already covered by production detectors ---
                check_ownership: false,       // SOL-012 in vulnerability_db
                check_signer_validation: false, // SOL-001 in vulnerability_db
                check_integer_safety: false,  // SOL-006 + abstract_interp
                check_cpi_safety: false,      // SOL-017 in deep_ast_scanner
                max_files: 0,
                max_file_size: 500_000,
            };
            let mut sec3 = sec3_analyzer::Sec3Analyzer::with_config(config);
            match sec3.analyze_program(dir) {
                Ok(report) => {
                    let converted: Vec<VulnerabilityFinding> = report
                        .findings
                        .into_iter()
                        .map(converters::sec3_finding_to_vulnerability)
                        .collect();
                    findings.extend(converted);
                }
                Err(e) => {
                    eprintln!("  {} Sec3 phase: {}", "warn:".yellow(), e);
                }
            }
        }

        // Phase 8: Anchor Framework security analysis - constraint validation,
        //          Token-2022 hook analysis, bump/space checks.
        //          Auto-skips non-Anchor programs (checks Cargo.toml for anchor-lang).
        if let Some(ref dir) = self.program_dir {
            let mut anchor = anchor_security_analyzer::AnchorSecurityAnalyzer::new();
            match anchor.analyze_program(dir) {
                Ok(report) if report.is_anchor_program => {
                    let converted: Vec<VulnerabilityFinding> = report
                        .findings
                        .into_iter()
                        .map(converters::anchor_finding_to_vulnerability)
                        .collect();
                    findings.extend(converted);
                }
                Ok(_) => {
                    // Not an Anchor program - no findings to add
                }
                Err(e) => {
                    eprintln!("  {} Anchor phase: {}", "warn:".yellow(), e);
                }
            }
        }

        // Phase 9: Dataflow analysis - reaching definitions + live variables.
        //          Catches uninitialized uses and dead definitions.
        for (filename, source) in &self.raw_sources {
            let mut df = dataflow_analyzer::DataflowAnalyzer::new();
            if df.analyze_source(source, filename).is_ok() {
                // Uninitialized variable uses
                for uninit in df.find_uninitialized_uses() {
                    findings.push(VulnerabilityFinding {
                        category: "Data Flow".to_string(),
                        vuln_type: "Potentially Uninitialized Variable Use".to_string(),
                        severity: 3,
                        severity_label: "Medium".to_string(),
                        id: "SOL-090".to_string(),
                        cwe: Some("CWE-457".to_string()),
                        location: filename.clone(),
                        function_name: uninit.function.clone(),
                        line_number: 0,
                        vulnerable_code: format!("{} used at {}", uninit.var_name, uninit.location),
                        description: format!(
                            "Variable '{}' may be used before being defined (no reaching definition found at use site).",
                            uninit.var_name
                        ),
                        attack_scenario: String::new(),
                        real_world_incident: None,
                        secure_fix: "Ensure the variable is initialized on all code paths before use.".to_string(),
                        prevention: String::new(),
                        confidence: 40,
                    });
                }

                // Dead definitions (security-relevant: could indicate stale state)
                for dead in df.find_dead_definitions() {
                    if matches!(dead.kind, dataflow_analyzer::DefinitionKind::Assignment | dataflow_analyzer::DefinitionKind::FieldAssignment) {
                        findings.push(VulnerabilityFinding {
                            category: "Data Flow".to_string(),
                            vuln_type: "Dead Store / Unused Assignment".to_string(),
                            severity: 1,
                            severity_label: "Informational".to_string(),
                            id: "SOL-091".to_string(),
                            cwe: Some("CWE-563".to_string()),
                            location: filename.clone(),
                            function_name: dead.function.clone(),
                            line_number: 0,
                            vulnerable_code: format!("{} = {} at {}", dead.var_name, dead.defining_expr, dead.location),
                            description: format!(
                                "Variable '{}' is assigned but never used afterwards. May indicate a missing state update or stale security check.",
                                dead.var_name
                            ),
                            attack_scenario: String::new(),
                            real_world_incident: None,
                            secure_fix: "Remove the dead store or ensure the value is used in subsequent code.".to_string(),
                            prevention: String::new(),
                            confidence: 30,
                        });
                    }
                }
            }
        }

        // Phase 10: Context-sensitive taint analysis - tracks untrusted data from
        //           sources (instruction data, unchecked accounts) to sinks (transfers,
        //           CPI, state writes). Augments the basic Phase 3 lattice taint.
        if let Some(ref dir) = self.program_dir {
            let mut taint = taint_analyzer::TaintAnalyzer::new();
            match taint.analyze_program(dir) {
                Ok(flows) => {
                    let converted: Vec<VulnerabilityFinding> = flows
                        .into_iter()
                        .map(converters::taint_flow_to_vulnerability)
                        .collect();
                    findings.extend(converted);
                }
                Err(e) => {
                    eprintln!("  {} Taint phase: {}", "warn:".yellow(), e);
                }
            }
        }

        // Phases 11-15 run in parallel (independent of each other)
        let program_dir = self.program_dir.clone();
        let raw_sources = self.raw_sources.clone();

        std::thread::scope(|s| {
            // Phase 11: Geiger - unsafe code analysis (thread 1)
            let phase11 = s.spawn(|| {
                let mut results = Vec::new();
                if let Some(ref dir) = program_dir {
                    let mut geiger = geiger_analyzer::GeigerAnalyzer::new();
                    match geiger.analyze_program(dir) {
                        Ok(report) => {
                            for gf in report.findings {
                                let (severity, severity_label) = match gf.severity {
                                    geiger_analyzer::report::GeigerSeverity::Critical => (5, "Critical".to_string()),
                                    geiger_analyzer::report::GeigerSeverity::High     => (4, "High".to_string()),
                                    geiger_analyzer::report::GeigerSeverity::Medium   => (3, "Medium".to_string()),
                                    geiger_analyzer::report::GeigerSeverity::Low      => (2, "Low".to_string()),
                                };
                                results.push(VulnerabilityFinding {
                                    category: "Unsafe Code".to_string(),
                                    vuln_type: format!("{:?}", gf.category),
                                    severity,
                                    severity_label,
                                    id: "SOL-093".to_string(),
                                    cwe: Some(gf.cwe),
                                    location: gf.file_path,
                                    function_name: gf.function_name.unwrap_or_default(),
                                    line_number: gf.line_number,
                                    vulnerable_code: gf.unsafe_code_snippet,
                                    description: format!("{} {}", gf.description, gf.risk_explanation),
                                    attack_scenario: String::new(),
                                    real_world_incident: None,
                                    secure_fix: gf.fix_recommendation,
                                    prevention: String::new(),
                                    confidence: 45,
                                });
                            }
                        }
                        Err(e) => {
                            eprintln!("  {} Geiger phase: {}", "warn:".yellow(), e);
                        }
                    }
                }
                results
            });

            // Phase 12: Arithmetic security expert (thread 2)
            let raw_sources_12 = raw_sources.clone();
            let phase12 = s.spawn(move || {
                let mut results = Vec::new();
                for (filename, source) in &raw_sources_12 {
                    if let Ok(issues) = arithmetic_security_expert::ArithmeticSecurityExpert::analyze_source(source) {
                        for issue in issues {
                            let raw_sev = issue.kind.severity();
                            let sev = match raw_sev {
                                8..=10 => 5u8, 6..=7 => 4, 4..=5 => 3, 2..=3 => 2, _ => 1,
                            };
                            results.push(VulnerabilityFinding {
                                category: "Arithmetic".to_string(),
                                vuln_type: format!("{:?}", issue.kind),
                                severity: sev,
                                severity_label: match sev {
                                    5 => "Critical", 4 => "High", 3 => "Medium",
                                    _ => "Low",
                                }.to_string(),
                                id: "SOL-094".to_string(),
                                cwe: Some("CWE-190".to_string()),
                                location: filename.clone(),
                                function_name: String::new(),
                                line_number: issue.line,
                                vulnerable_code: issue.snippet.clone(),
                                description: format!("{:?} at line {}", issue.kind, issue.line),
                                attack_scenario: String::new(),
                                real_world_incident: None,
                                secure_fix: issue.recommendation,
                                prevention: String::new(),
                                confidence: 42,
                            });
                        }
                    }
                }
                results
            });

            // Phase 13: L3X heuristic detector (thread 3)
            let program_dir_13 = program_dir.clone();
            let phase13 = s.spawn(move || {
                let mut results = Vec::new();
                if let Some(ref dir) = program_dir_13 {
                    let mut l3x = l3x_analyzer::L3xAnalyzer::new();
                    match l3x.analyze_program(dir) {
                        Ok(report) => {
                            for lf in report.findings {
                                let (severity, severity_label) = match lf.severity {
                                    l3x_analyzer::report::L3xSeverity::Critical => (5, "Critical".to_string()),
                                    l3x_analyzer::report::L3xSeverity::High     => (4, "High".to_string()),
                                    l3x_analyzer::report::L3xSeverity::Medium   => (3, "Medium".to_string()),
                                    l3x_analyzer::report::L3xSeverity::Low      => (2, "Low".to_string()),
                                    l3x_analyzer::report::L3xSeverity::Info     => (1, "Informational".to_string()),
                                };
                                results.push(VulnerabilityFinding {
                                    category: format!("Heuristic Pattern Detection ({:?})", lf.category),
                                    vuln_type: lf.description.clone(),
                                    severity,
                                    severity_label,
                                    id: lf.id,
                                    cwe: Some(lf.cwe),
                                    location: lf.file_path,
                                    function_name: lf.instruction,
                                    line_number: lf.line_number,
                                    vulnerable_code: lf.source_snippet.unwrap_or_default(),
                                    description: format!("{} [heuristic reasoning: {}]", lf.description, lf.ml_reasoning),
                                    attack_scenario: String::new(),
                                    real_world_incident: None,
                                    secure_fix: lf.fix_recommendation,
                                    prevention: String::new(),
                                    confidence: (lf.confidence * 100.0).min(255.0) as u8,
                                });
                            }
                        }
                        Err(e) => {
                            eprintln!("  {} L3X phase: {}", "warn:".yellow(), e);
                        }
                    }
                }
                results
            });

            // Phase 14: Invariant miner (thread 4)
            let raw_sources_14 = raw_sources.clone();
            let phase14 = s.spawn(move || {
                let mut results = Vec::new();
                for (filename, source) in &raw_sources_14 {
                    let mut miner = invariant_miner::InvariantMiner::new();
                    if miner.mine_from_source(source, filename).is_ok() {
                        for violation in miner.get_potential_violations() {
                            results.push(VulnerabilityFinding {
                                category: "Invariant Violation".to_string(),
                                vuln_type: format!("{:?}", violation.invariant.category),
                                severity: 3,
                                severity_label: "Medium".to_string(),
                                id: "SOL-095".to_string(),
                                cwe: Some("CWE-682".to_string()),
                                location: filename.clone(),
                                function_name: String::new(),
                                line_number: 0,
                                vulnerable_code: violation.invariant.expression.clone(),
                                description: format!(
                                    "Invariant '{}' may be violated. Counterexample: {}",
                                    violation.invariant.expression,
                                    violation.counterexample.as_deref().unwrap_or("none"),
                                ),
                                attack_scenario: String::new(),
                                real_world_incident: None,
                                secure_fix: format!("Add explicit check: {}", violation.invariant.expression),
                                prevention: String::new(),
                                confidence: 35,
                            });
                        }
                    }
                }
                results
            });

            // Phase 15: Concolic execution (thread 5)
            let raw_sources_15 = raw_sources.clone();
            let phase15 = s.spawn(move || {
                let mut results = Vec::new();
                for (filename, source) in &raw_sources_15 {
                    let config = concolic_executor::ConcolicConfig {
                        max_depth: 10,
                        max_paths: 50,
                        timeout_ms: 5000,
                        seed: 42,
                    };
                    let mut executor = concolic_executor::ConcolicExecutor::new(config);
                    let mut initial_inputs = std::collections::HashMap::new();
                    for line in source.lines() {
                        let trimmed = line.trim();
                        if trimmed.starts_with("pub fn ") || trimmed.starts_with("fn ") {
                            if let Some(name) = trimmed.split('(').next() {
                                let fn_name = name.replace("pub fn ", "").replace("fn ", "").trim().to_string();
                                initial_inputs.insert(fn_name, u64::MAX);
                            }
                        }
                    }
                    let result = executor.execute(initial_inputs);
                    for cf in result.vulnerabilities {
                        let (severity, severity_label) = match cf.severity {
                            concolic_executor::FindingSeverity::Critical => (5, "Critical".to_string()),
                            concolic_executor::FindingSeverity::High     => (4, "High".to_string()),
                            concolic_executor::FindingSeverity::Medium   => (3, "Medium".to_string()),
                            concolic_executor::FindingSeverity::Low      => (2, "Low".to_string()),
                        };
                        results.push(VulnerabilityFinding {
                            category: "Concolic Analysis".to_string(),
                            vuln_type: cf.vulnerability_type,
                            severity,
                            severity_label,
                            id: "SOL-096".to_string(),
                            cwe: Some("CWE-119".to_string()),
                            location: filename.clone(),
                            function_name: cf.location.clone(),
                            line_number: 0,
                            vulnerable_code: format!("Triggered by: {:?}", cf.triggering_input),
                            description: cf.description,
                            attack_scenario: String::new(),
                            real_world_incident: None,
                            secure_fix: String::new(),
                            prevention: String::new(),
                            confidence: 55,
                        });
                    }
                }
                results
            });

            // Collect all parallel results (batch 1)
            findings.extend(phase11.join().unwrap_or_default());
            findings.extend(phase12.join().unwrap_or_default());
            findings.extend(phase13.join().unwrap_or_default());
            findings.extend(phase14.join().unwrap_or_default());
            findings.extend(phase15.join().unwrap_or_default());
        });

        // Phases 16-20: Formal verification (parallel)
        if let Some(ref dir) = self.program_dir {
            let dir_16 = dir.clone();
            let dir_17 = dir.clone();
            let dir_18 = dir.clone();
            let dir_19 = dir.clone();
            let raw_sources_20 = self.raw_sources.clone();

            std::thread::scope(|s| {
                // Phase 16: FV Layer 1 - Kani-backed property verification +
                //           arithmetic safety extraction
                let phase16 = s.spawn(move || {
                    let mut results = Vec::new();
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all().build().unwrap();
                    let config = fv_layer1_verifier::Layer1Config::default();
                    let verifier = fv_layer1_verifier::Layer1Verifier::new(config);
                    match rt.block_on(verifier.verify(&dir_16)) {
                        Ok(report) => {
                            for finding in report.findings {
                                let (sev, label) = match finding.severity {
                                    fv_layer1_verifier::Severity::Critical => (5, "Critical"),
                                    fv_layer1_verifier::Severity::High => (4, "High"),
                                    fv_layer1_verifier::Severity::Medium => (3, "Medium"),
                                    fv_layer1_verifier::Severity::Low => (2, "Low"),
                                    fv_layer1_verifier::Severity::Info => (1, "Informational"),
                                };
                                results.push(VulnerabilityFinding {
                                    category: "Formal Verification".to_string(),
                                    vuln_type: finding.description.clone(),
                                    severity: sev,
                                    severity_label: label.to_string(),
                                    id: "SOL-FV-01".to_string(),
                                    cwe: Some("CWE-682".to_string()),
                                    location: finding.location.as_ref()
                                        .map(|l| l.file.clone()).unwrap_or_default(),
                                    function_name: finding.category.clone(),
                                    line_number: finding.location.as_ref()
                                        .map(|l| l.line as usize).unwrap_or(0),
                                    vulnerable_code: finding.description.clone(),
                                    description: finding.description,
                                    attack_scenario: String::new(),
                                    real_world_incident: None,
                                    secure_fix: finding.recommendation,
                                    prevention: String::new(),
                                    confidence: 70,
                                });
                            }
                        }
                        Err(e) => {
                            eprintln!("  {} FV Layer 1: {}", "warn:".yellow(), e);
                        }
                    }
                    results
                });

                // Phase 17: FV Layer 2 - Z3 SMT arithmetic overflow proofs
                let phase17 = s.spawn(move || {
                    let mut results = Vec::new();
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all().build().unwrap();
                    let verifier = fv_layer2_verifier::Layer2Verifier::new();
                    match rt.block_on(verifier.verify(&dir_17)) {
                        Ok(report) => {
                            for proof in &report.z3_proofs {
                                if proof.status == fv_layer2_verifier::ProofStatus::Violated {
                                    results.push(VulnerabilityFinding {
                                        category: "Formal Verification".to_string(),
                                        vuln_type: format!("Z3 Arithmetic Proof Violation: {}", proof.property),
                                        severity: 4,
                                        severity_label: "High".to_string(),
                                        id: "SOL-FV-02".to_string(),
                                        cwe: Some("CWE-190".to_string()),
                                        location: String::new(),
                                        function_name: String::new(),
                                        line_number: 0,
                                        vulnerable_code: proof.property.clone(),
                                        description: format!(
                                            "Z3 proved that arithmetic property '{}' can be violated. \
                                             Counterexample: {}",
                                            proof.property,
                                            proof.counterexample.as_deref().unwrap_or("(solver found model)")
                                        ),
                                        attack_scenario: String::new(),
                                        real_world_incident: None,
                                        secure_fix: "Use checked_add/checked_mul or validated inputs.".to_string(),
                                        prevention: String::new(),
                                        confidence: 80,
                                    });
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("  {} FV Layer 2: {}", "warn:".yellow(), e);
                        }
                    }
                    results
                });

                // Phase 18: FV Layer 3 - Z3 account schema invariant verification
                //           (solvency: reserved <= balance, supply integrity, etc.)
                let phase18 = s.spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all().build().unwrap();
                    let mut results = Vec::new();
                    let config = fv_layer3_verifier::Layer3Config::default();
                    let verifier = fv_layer3_verifier::Layer3Verifier::new(config);
                    match rt.block_on(verifier.verify(&dir_18)) {
                        Ok(report) => {
                            for violation in &report.violations_found {
                                let sev = if violation.contains("CRITICAL") { 5u8 }
                                    else if violation.contains("HIGH") { 4 }
                                    else { 3 };
                                results.push(VulnerabilityFinding {
                                    category: "Formal Verification".to_string(),
                                    vuln_type: "Account Schema Invariant Violation".to_string(),
                                    severity: sev,
                                    severity_label: match sev {
                                        5 => "Critical", 4 => "High", _ => "Medium",
                                    }.to_string(),
                                    id: "SOL-FV-03".to_string(),
                                    cwe: Some("CWE-682".to_string()),
                                    location: String::new(),
                                    function_name: String::new(),
                                    line_number: 0,
                                    vulnerable_code: violation.clone(),
                                    description: format!(
                                        "Z3 invariant verification: {}. Schemas analyzed: {:?}",
                                        violation, report.analyzed_schemas,
                                    ),
                                    attack_scenario: "Attacker crafts inputs that violate the data \
                                        invariant (e.g., reserved > balance), draining funds.".to_string(),
                                    real_world_incident: None,
                                    secure_fix: "Add explicit invariant checks after every state mutation.".to_string(),
                                    prevention: String::new(),
                                    confidence: 75,
                                });
                            }
                        }
                        Err(e) => {
                            eprintln!("  {} FV Layer 3: {}", "warn:".yellow(), e);
                        }
                    }
                    results
                });

                // Phase 19: FV Layer 4 - State machine transition verification
                //           (unreachable states, unguarded transitions, missing terminal states)
                let phase19 = s.spawn(move || {
                    let mut results = Vec::new();
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all().build().unwrap();
                    let verifier = fv_layer4_verifier::Layer4Verifier::new();
                    match rt.block_on(verifier.verify(&dir_19)) {
                        Ok(report) => {
                            for proof in &report.z3_proofs {
                                if !proof.proved {
                                    results.push(VulnerabilityFinding {
                                        category: "Formal Verification".to_string(),
                                        vuln_type: format!("State Machine Violation: {}", proof.property),
                                        severity: 4,
                                        severity_label: "High".to_string(),
                                        id: "SOL-FV-04".to_string(),
                                        cwe: Some("CWE-372".to_string()),
                                        location: String::new(),
                                        function_name: String::new(),
                                        line_number: 0,
                                        vulnerable_code: proof.property.clone(),
                                        description: format!(
                                            "Z3 state machine property '{}' not proved: {}. {}",
                                            proof.property, proof.description,
                                            proof.counterexample.as_deref().unwrap_or(""),
                                        ),
                                        attack_scenario: "Attacker invokes instructions in unexpected \
                                            order to reach an unsafe state.".to_string(),
                                        real_world_incident: None,
                                        secure_fix: "Add state guard: require!(state == ExpectedState)".to_string(),
                                        prevention: String::new(),
                                        confidence: 72,
                                    });
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("  {} FV Layer 4: {}", "warn:".yellow(), e);
                        }
                    }
                    results
                });

                // Phase 20: Symbolic Engine - Z3-backed authority bypass +
                //           invariant violation proofs on parsed account schemas
                let phase20 = s.spawn(move || {
                    let mut results = Vec::new();
                    let z3_cfg = z3::Config::new();
                    let z3_ctx = z3::Context::new(&z3_cfg);
                    let mut engine = symbolic_engine::SymbolicEngine::new(&z3_ctx);

                    for (filename, source) in &raw_sources_20 {
                        // Parse account schemas from source
                        if let Ok(file) = syn::parse_file(source) {
                            for item in &file.items {
                                if let syn::Item::Struct(st) = item {
                                    let is_account = st.attrs.iter().any(|a| a.path().is_ident("account"));
                                    if is_account {
                                        let mut fields = std::collections::HashMap::new();
                                        for field in &st.fields {
                                            if let Some(ident) = &field.ident {
                                                let ty = quote::quote!(#field).to_string();
                                                let mapped = if ty.contains("u64") || ty.contains("u128") { "u64" }
                                                    else if ty.contains("bool") { "bool" }
                                                    else if ty.contains("Pubkey") { "Pubkey" }
                                                    else { "u64" };
                                                fields.insert(ident.to_string(), mapped.to_string());
                                            }
                                        }
                                        let schema = symbolic_engine::AccountSchema {
                                            name: st.ident.to_string(),
                                            fields,
                                        };
                                        engine.init_state_from_schema(&schema);

                                        // Check invariant violations
                                        let violations = engine.check_invariant_violations();
                                        for v in violations {
                                            results.push(VulnerabilityFinding {
                                                category: "Symbolic Execution".to_string(),
                                                vuln_type: format!("Exploitable: {:?}", v.vulnerability_type),
                                                severity: 4,
                                                severity_label: "High".to_string(),
                                                id: "SOL-SYM-01".to_string(),
                                                cwe: Some("CWE-682".to_string()),
                                                location: filename.clone(),
                                                function_name: st.ident.to_string(),
                                                line_number: 0,
                                                vulnerable_code: v.z3_model.clone(),
                                                description: format!(
                                                    "Symbolic engine found exploitable invariant \
                                                     violation in account '{}': {:?}. {}",
                                                    st.ident, v.vulnerability_type, v.explanation,
                                                ),
                                                attack_scenario: v.explanation.clone(),
                                                real_world_incident: None,
                                                secure_fix: v.mitigation.clone(),
                                                prevention: String::new(),
                                                confidence: 68,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                    results
                });

                // Collect all parallel results (batch 2 - formal verification)
                findings.extend(phase16.join().unwrap_or_default());
                findings.extend(phase17.join().unwrap_or_default());
                findings.extend(phase18.join().unwrap_or_default());
                findings.extend(phase19.join().unwrap_or_default());
                findings.extend(phase20.join().unwrap_or_default());
            });
        }


        // Post-processing: enrich + dedup
        pipeline::post_process(&mut findings);

        findings
    }

    /// Runs raw scan + validation pipeline (FP filtering, confidence scoring).
    /// This is the primary entry point for production use.
    pub fn scan_for_vulnerabilities(&self) -> Vec<VulnerabilityFinding> {
        let raw = self.scan_for_vulnerabilities_raw();

        // Build project-wide context from all source files
        let sources: Vec<(String, String)> = self.source_files.iter().map(|(name, file)| {
            let code = normalize_quote_output(&quote::quote!(#file).to_string());
            (name.clone(), code)
        }).collect();

        let ctx = finding_validator::ProjectContext::from_sources(&sources);
        finding_validator::validate_findings(raw, &ctx)
    }

    /// Like `scan_for_vulnerabilities()` but also returns a `PhaseTimer`
    /// with execution time for the validation pipeline.
    ///
    /// Individual phase timing requires instrumenting each phase inside
    /// `scan_for_vulnerabilities_raw`; this method times the overall raw
    /// scan and the validation step separately.
    pub fn scan_with_timing(&self) -> (Vec<VulnerabilityFinding>, PhaseTimer) {
        let mut timer = PhaseTimer::new();

        let t = std::time::Instant::now();
        let raw = self.scan_for_vulnerabilities_raw();
        timer.record("raw_scan", t.elapsed(), raw.len());

        let t = std::time::Instant::now();
        let sources: Vec<(String, String)> = self.source_files.iter().map(|(name, file)| {
            let code = normalize_quote_output(&quote::quote!(#file).to_string());
            (name.clone(), code)
        }).collect();
        let ctx = finding_validator::ProjectContext::from_sources(&sources);
        let validated = finding_validator::validate_findings(raw, &ctx);
        timer.record("validation", t.elapsed(), validated.len());

        (validated, timer)
    }

    /// Same as scan_for_vulnerabilities - kept for API compat.
    pub fn scan_for_vulnerabilities_parallel(&self) -> Vec<VulnerabilityFinding> {
        self.scan_for_vulnerabilities()
    }


    #[allow(dead_code, clippy::only_used_in_recursion)]
    fn collect_code_items(
        &self,
        items: &[Item],
        filename: &str,
        results: &mut Vec<(String, String, String)>,
    ) {
        for item in items {
            match item {
                Item::Fn(func) => {
                    let code = normalize_quote_output(&quote::quote!(#func).to_string());
                    results.push((code, filename.to_string(), func.sig.ident.to_string()));
                }
                Item::Mod(item_mod) => {
                    if let Some((_, items)) = &item_mod.content {
                        self.collect_code_items(items, filename, results);
                    }
                }
                Item::Struct(item_struct) => {
                    let code = normalize_quote_output(&quote::quote!(#item_struct).to_string());
                    results.push((code, filename.to_string(), item_struct.ident.to_string()));
                }
                _ => {}
            }
        }
    }


    #[allow(dead_code)]
    fn scan_items_collect(&self, items: &[Item], filename: &str) -> Vec<VulnerabilityFinding> {
        let mut findings = Vec::new();
        self.scan_items(items, filename, &mut findings);
        findings
    }

    fn scan_items(&self, items: &[Item], filename: &str, findings: &mut Vec<VulnerabilityFinding>) {
        // Phase 1: Build a map of struct_name -> normalized code for
        // all #[derive(Accounts)] structs. This lets us cross-reference
        // handler functions with their associated account constraints.
        let mut accounts_structs: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        self.collect_accounts_structs(items, &mut accounts_structs);

        // Phase 2: Scan items with struct context available
        self.scan_items_with_context(items, filename, findings, &accounts_structs);
    }

    /// Recursively collect all #[derive(Accounts)] struct names and their code
    fn collect_accounts_structs(
        &self,
        items: &[Item],
        map: &mut std::collections::HashMap<String, String>,
    ) {
        for item in items {
            match item {
                Item::Struct(item_struct) => {
                    let has_accounts_derive = item_struct.attrs.iter().any(|attr| {
                        let s = quote::quote!(#attr).to_string();
                        s.contains("Accounts")
                    });
                    if has_accounts_derive {
                        let code = normalize_quote_output(&quote::quote!(#item_struct).to_string());
                        map.insert(item_struct.ident.to_string(), code);
                    }
                }
                Item::Mod(item_mod) => {
                    if let Some((_, inner)) = &item_mod.content {
                        self.collect_accounts_structs(inner, map);
                    }
                }
                _ => {}
            }
        }
    }

    /// Extract the Accounts struct name from a function signature like:
    /// `fn handler(ctx: Context<MyAccounts>, amount: u64)` or
    /// `fn handler(ctx: Context<'info, MyAccounts>, amount: u64)`
    fn extract_context_struct_name(code: &str) -> Option<String> {
        if let Some(start) = code.find("Context<") {
            let after = &code[start + 8..];
            if let Some(end) = after.find('>') {
                let inner = after[..end].trim();
                // Take the last comma-separated segment (handles lifetimes)
                let name = inner
                    .rsplit(',')
                    .next()
                    .unwrap_or(inner)
                    .trim()
                    .to_string();
                if !name.is_empty()
                    && name.chars().next().map(|c| c.is_uppercase()).unwrap_or(false)
                    && name.chars().all(|c| c.is_alphanumeric() || c == '_')
                {
                    return Some(name);
                }
            }
        }
        None
    }

    fn scan_items_with_context(
        &self,
        items: &[Item],
        filename: &str,
        findings: &mut Vec<VulnerabilityFinding>,
        accounts_structs: &std::collections::HashMap<String, String>,
    ) {
        for item in items {
            match item {
                Item::Fn(func) => {
                    let func_code = normalize_quote_output(&quote::quote!(#func).to_string());
                    let line_number = func.sig.ident.span().start().line;

                    // Cross-reference: if this function uses Context<StructName>,
                    // prepend the struct code so checkers see its constraints
                    let code = if let Some(struct_name) = Self::extract_context_struct_name(&func_code) {
                        if let Some(struct_code) = accounts_structs.get(&struct_name) {
                            format!("/* ACCOUNTS_STRUCT: {} */
{}
/* HANDLER: */
{}", struct_name, struct_code, func_code)
                        } else {
                            func_code
                        }
                    } else {
                        func_code
                    };

                    for pattern in self.vulnerability_db.patterns() {
                        if let Some(mut finding) = (pattern.checker)(&code) {
                            finding.location = filename.to_string();
                            finding.function_name = func.sig.ident.to_string();
                            finding.line_number = line_number;
                            finding.vulnerable_code = code.clone();
                            findings.push(finding);
                        }
                    }
                }
                Item::Mod(item_mod) => {
                    if let Some((_, inner_items)) = &item_mod.content {
                        self.scan_items_with_context(inner_items, filename, findings, accounts_structs);
                    }
                }
                Item::Struct(item_struct) => {
                    let code = normalize_quote_output(&quote::quote!(#item_struct).to_string());
                    let line_number = item_struct.ident.span().start().line;
                    for pattern in self.vulnerability_db.patterns() {
                        if let Some(mut finding) = (pattern.checker)(&code) {
                            if pattern.id.starts_with("4.")
                                || pattern.id.starts_with("3.")
                                || pattern.id.starts_with("1.")
                            {
                                finding.location = filename.to_string();
                                finding.function_name = item_struct.ident.to_string();
                                finding.line_number = line_number;
                                finding.vulnerable_code = code.clone();
                                findings.push(finding);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn has_account_attribute(&self, attrs: &[syn::Attribute]) -> bool {
        attrs.iter().any(|attr| attr.path().is_ident("account"))
    }

    fn parse_account_struct(&self, item_struct: &ItemStruct) -> AccountSchema {
        let mut fields = std::collections::HashMap::new();

        if let syn::Fields::Named(named_fields) = &item_struct.fields {
            for field in &named_fields.named {
                let field_name = field.ident.as_ref().map(|i| i.to_string()).unwrap_or_else(|| "_".to_string());
                let field_type = field.ty.to_token_stream().to_string();
                fields.insert(field_name, field_type);
            }
        }

        AccountSchema {
            name: item_struct.ident.to_string(),
            fields,
        }
    }

    fn parse_function_logic(&self, func: &ItemFn) -> InstructionLogic {
        InstructionLogic {
            name: func.sig.ident.to_string(),
            source_code: func.to_token_stream().to_string(),
            statements: self.extract_statements(&func.block.stmts),
        }
    }

    fn extract_statements(&self, stmts: &[Stmt]) -> Vec<Statement> {
        let mut statements = Vec::new();

        for stmt in stmts {
            match stmt {
                Stmt::Expr(expr, _) => {
                    if let Some(statement) = self.parse_expression(expr) {
                        statements.push(statement);
                    }
                }
                Stmt::Local(_local) => {
                    statements.push(Statement::Assignment);
                }
                _ => {}
            }
        }

        statements
    }

    fn parse_expression(&self, expr: &Expr) -> Option<Statement> {
        match expr {
            Expr::Binary(binary) => {

                Some(Statement::Arithmetic {
                    op: format!("{:?}", binary.op),
                    checked: self.is_checked_operation(&binary.to_token_stream().to_string()),
                })
            }
            Expr::MethodCall(method_call) => {
                if method_call.method == "checked_add"
                    || method_call.method == "checked_sub"
                    || method_call.method == "checked_mul"
                    || method_call.method == "checked_div"
                {
                    Some(Statement::CheckedArithmetic)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn is_checked_operation(&self, code: &str) -> bool {
        code.contains("checked_add")
            || code.contains("checked_sub")
            || code.contains("checked_mul")
            || code.contains("checked_div")
    }
}

/// Parsed `#[account]` struct with field types.
#[derive(Debug, Clone)]
pub struct AccountSchema {
    pub name: String,
    pub fields: std::collections::HashMap<String, String>,
}

/// Parsed instruction function body.
#[derive(Debug)]
pub struct InstructionLogic {
    pub name: String,
    pub source_code: String,
    pub statements: Vec<Statement>,
}

#[derive(Debug)]
pub enum Statement {
    Arithmetic { op: String, checked: bool },
    CheckedArithmetic,
    Assignment,
    CPI,
    Require,
}

/// A vulnerability finding from the scanning pipeline.
/// Severity: 1 (Info) to 5 (Critical). Confidence: 0-100.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFinding {
    pub category: String,
    pub vuln_type: String,
    pub severity: u8,
    pub severity_label: String,
    pub id: String,
    pub cwe: Option<String>,
    pub location: String,
    pub function_name: String,
    pub line_number: usize,
    pub vulnerable_code: String,
    pub description: String,
    pub attack_scenario: String,
    pub real_world_incident: Option<Incident>,
    pub secure_fix: String,
    pub prevention: String,
    /// 0-100. Set by finding_validator; raw findings default to 50.
    #[serde(default = "default_confidence")]
    pub confidence: u8,
}

fn default_confidence() -> u8 { 50 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub project: String,
    pub loss: String,
    pub date: String,
}

/// Errors that can occur during program analysis.
#[derive(Debug, thiserror::Error)]
pub enum AnalyzerError {
    /// File system error (file not found, permission denied)
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// Rust source code parsing error (invalid syntax)
    #[error("Parse error: {0}")]
    Parse(#[from] syn::Error),
    /// Directory traversal error
    #[error("Walkdir error: {0}")]
    WalkDir(walkdir::Error),
}

/// Parses source, runs the full pipeline, and returns validated findings.
/// Returns an empty Vec on parse failure.
pub fn scan_source_code(source: &str, filename: &str) -> Vec<VulnerabilityFinding> {
    match ProgramAnalyzer::from_source(source) {
        Ok(analyzer) => {
            let mut findings = analyzer.scan_for_vulnerabilities();
            // Patch filenames to the caller-supplied name
            for f in &mut findings {
                if f.location.is_empty() || f.location == "source.rs" {
                    f.location = filename.to_string();
                }
            }
            findings
        }
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod pipeline_tests {
    use super::*;

    /// Helper: create a ProgramAnalyzer from inline source code
    fn analyze(src: &str) -> Vec<VulnerabilityFinding> {
        let analyzer = ProgramAnalyzer::from_source(src)
            .expect("should parse test source");
        analyzer.scan_for_vulnerabilities_raw()
    }

    /// Helper: same but with full validation pipeline
    fn analyze_validated(src: &str) -> Vec<VulnerabilityFinding> {
        let analyzer = ProgramAnalyzer::from_source(src)
            .expect("should parse test source");
        analyzer.scan_for_vulnerabilities()
    }

    // ─── Phase 1–6 (core engine) smoke test ─────────────────────────────
    #[test]
    fn test_core_phases_detect_missing_signer() {
        let src = r#"
            use anchor_lang::prelude::*;
            pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
                let vault = &mut ctx.accounts.vault;
                vault.balance -= amount;
                Ok(())
            }
            #[derive(Accounts)]
            pub struct Transfer<'info> {
                #[account(mut)]
                pub vault: Account<'info, Vault>,
                pub user: AccountInfo<'info>,
            }
            #[account]
            pub struct Vault { pub balance: u64 }
        "#;
        let findings = analyze(src);
        assert!(!findings.is_empty(), "should detect at least one finding");
    }

    // ─── Phase 12 (arithmetic-security-expert) ───────────────────────
    #[test]
    fn test_phase12_arithmetic_detects_unchecked_add() {
        let src = r#"
            use anchor_lang::prelude::*;
            pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
                let state = &mut ctx.accounts.state;
                state.total = state.total + amount;
                Ok(())
            }
            #[derive(Accounts)]
            pub struct Deposit<'info> {
                #[account(mut)]
                pub state: Account<'info, State>,
            }
            #[account]
            pub struct State { pub total: u64 }
        "#;
        let findings = analyze(src);
        // Phase 12 or Phase 1–6 should detect unchecked arithmetic
        let arithmetic = findings.iter().any(|f|
            f.id.contains("SOL-006") ||
            f.id.contains("SOL-094") ||
            f.category.contains("Arithmetic") ||
            f.vuln_type.contains("overflow") ||
            f.vuln_type.contains("Arithmetic") ||
            f.description.to_lowercase().contains("overflow")
        );
        assert!(arithmetic, "should detect unchecked arithmetic: found {:?}",
            findings.iter().map(|f| format!("{}: {}", f.id, f.vuln_type)).collect::<Vec<_>>());
    }

    // ─── Phase 14 (invariant-miner) ─────────────────────────────────
    #[test]
    fn test_phase14_invariant_miner_runs() {
        let src = r#"
            pub fn process(amount: u64) -> u64 {
                assert!(amount > 0);
                let result = amount * 2;
                assert!(result > amount);
                result
            }
        "#;
        // Invariant miner should at least parse without crashing
        let findings = analyze(src);
        // The test is that it doesn't panic - invariant violations are optional
        let _ = findings;
    }

    // ─── Phase 15 (concolic-executor) ────────────────────────────────
    #[test]
    fn test_phase15_concolic_executor_runs() {
        let src = r#"
            pub fn withdraw(amount: u64, balance: u64) -> u64 {
                if amount > balance {
                    panic!("insufficient");
                }
                balance - amount
            }
        "#;
        // Concolic executor should run without crashing
        let findings = analyze(src);
        let _ = findings;
    }

    // ─── Enrichment ─────────────────────────────────────────────────
    #[test]
    fn test_enrichment_populates_prevention_and_attack() {
        let src = r#"
            use anchor_lang::prelude::*;
            pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
                let vault = &mut ctx.accounts.vault;
                vault.balance = vault.balance - amount;
                **vault.to_account_info().try_borrow_mut_lamports()? -= amount;
                **ctx.accounts.user.try_borrow_mut_lamports()? += amount;
                Ok(())
            }
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(mut)]
                pub vault: Account<'info, Vault>,
                pub user: AccountInfo<'info>,
                pub system_program: Program<'info, System>,
            }
            #[account]
            pub struct Vault { pub balance: u64 }
        "#;
        let findings = analyze(src);
        // At least some findings should have enriched prevention/attack_scenario
        let enriched = findings.iter().any(|f|
            !f.prevention.is_empty() || !f.attack_scenario.is_empty()
        );
        assert!(enriched,
            "enrichment pass should populate prevention or attack_scenario for at least one finding");
    }

    // ─── Cross-phase dedup ──────────────────────────────────────────
    #[test]
    fn test_cross_phase_dedup_no_exact_duplicates() {
        let src = r#"
            use anchor_lang::prelude::*;
            pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
                let vault = &mut ctx.accounts.vault;
                vault.balance = vault.balance + amount;
                Ok(())
            }
            #[derive(Accounts)]
            pub struct Transfer<'info> {
                #[account(mut)]
                pub vault: Account<'info, Vault>,
                pub user: AccountInfo<'info>,
            }
            #[account]
            pub struct Vault { pub balance: u64 }
        "#;
        let findings = analyze(src);
        // No two findings should have the exact same (vuln_type, location, line_number)
        let mut keys = std::collections::HashSet::new();
        for f in &findings {
            let key = format!("{}:{}:{}", f.vuln_type, f.location, f.line_number);
            if f.line_number > 0 {
                assert!(keys.insert(key.clone()),
                    "duplicate finding detected after dedup: {}", key);
            }
        }
    }

    // ─── from_source basics ─────────────────────────────────────────
    #[test]
    fn test_from_source_parses_valid_rust() {
        let analyzer = ProgramAnalyzer::from_source("fn main() {}");
        assert!(analyzer.is_ok());
    }

    #[test]
    fn test_from_source_rejects_invalid_rust() {
        let analyzer = ProgramAnalyzer::from_source("this is not rust {{{{");
        assert!(analyzer.is_err());
    }

    // ─── scan_source_code convenience function ──────────────────────
    #[test]
    fn test_scan_source_code_returns_findings() {
        let src = r#"
            use anchor_lang::prelude::*;
            pub fn bad(ctx: Context<Bad>, amt: u64) -> Result<()> {
                let v = &mut ctx.accounts.vault;
                v.x = v.x + amt;
                Ok(())
            }
            #[derive(Accounts)]
            pub struct Bad<'info> {
                #[account(mut)]
                pub vault: Account<'info, Vault>,
            }
            #[account]
            pub struct Vault { pub x: u64 }
        "#;
        // Use raw scan - the validated pipeline may aggressively filter
        // short inline snippets that lack full project context
        let analyzer = ProgramAnalyzer::from_source(src).expect("should parse");
        let findings = analyzer.scan_for_vulnerabilities_raw();
        assert!(!findings.is_empty(), "should find vulns in inline source");
    }

    // ─── Integration test against real vulnerable program ────────────
    #[test]
    fn test_vulnerable_token_regression() {
        let program_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent().unwrap()  // crates/
            .parent().unwrap()  // project root
            .join("programs/vulnerable-token");

        if !program_dir.exists() {
            // Skip if test programs not available
            eprintln!("Skipping: vulnerable-token not found at {:?}", program_dir);
            return;
        }

        let analyzer = ProgramAnalyzer::new(&program_dir)
            .expect("should parse vulnerable-token");
        let findings = analyzer.scan_for_vulnerabilities();

        // vulnerable-token has intentional bugs: missing signer, unchecked math, etc.
        assert!(findings.len() >= 5,
            "vulnerable-token should produce at least 5 findings, got {}",
            findings.len());

        // At least one should be HIGH or CRITICAL (severity >= 4)
        let high_or_crit = findings.iter().filter(|f| f.severity >= 4).count();
        assert!(high_or_crit >= 1,
            "should have at least 1 HIGH/CRITICAL finding, got {}", high_or_crit);
    }

    #[test]
    fn test_vulnerable_vault_regression() {
        let program_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent().unwrap()
            .parent().unwrap()
            .join("programs/vulnerable-vault");

        if !program_dir.exists() {
            eprintln!("Skipping: vulnerable-vault not found at {:?}", program_dir);
            return;
        }

        let analyzer = ProgramAnalyzer::new(&program_dir)
            .expect("should parse vulnerable-vault");
        let findings = analyzer.scan_for_vulnerabilities();

        assert!(findings.len() >= 3,
            "vulnerable-vault should produce at least 3 findings, got {}",
            findings.len());
    }

    #[test]
    fn test_vulnerable_staking_regression() {
        let program_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent().unwrap()
            .parent().unwrap()
            .join("programs/vulnerable-staking");

        if !program_dir.exists() {
            eprintln!("Skipping: vulnerable-staking not found at {:?}", program_dir);
            return;
        }

        let analyzer = ProgramAnalyzer::new(&program_dir)
            .expect("should parse vulnerable-staking");
        let findings = analyzer.scan_for_vulnerabilities();

        assert!(findings.len() >= 3,
            "vulnerable-staking should produce at least 3 findings, got {}",
            findings.len());
    }

    // ─── Confidence scores ──────────────────────────────────────────
    #[test]
    fn test_confidence_scores_are_nonzero() {
        let src = r#"
            use anchor_lang::prelude::*;
            pub fn bad(ctx: Context<Bad>, val: u64) -> Result<()> {
                let s = &mut ctx.accounts.state;
                s.x = s.x + val;
                Ok(())
            }
            #[derive(Accounts)]
            pub struct Bad<'info> {
                #[account(mut)]
                pub state: Account<'info, MyState>,
            }
            #[account]
            pub struct MyState { pub x: u64 }
        "#;
        let findings = analyze_validated(src);
        for f in &findings {
            assert!(f.confidence > 0, "confidence should be > 0 for finding: {}", f.id);
        }
    }
}
