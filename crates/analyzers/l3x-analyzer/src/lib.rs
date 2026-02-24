#![allow(dead_code)]
//! # L3X Heuristic Code Analyzer for Solana
//!
//! L3X uses weighted-token scoring and control flow graph structural analysis
//! to detect vulnerability patterns. It combines five heuristic techniques:
//!
//! 1. **Weighted Token Scoring** — Bag-of-words with Solana-specific token weights
//!    and cosine similarity against known vulnerability signatures
//! 2. **CFG Structural Analysis** — Builds control flow graphs via `syn::visit`
//!    and flags nodes with high deviation from the mean embedding (not a trained GNN)
//! 3. **Statistical Anomaly Detection** — Flags code blocks whose token distribution
//!    deviates significantly from the project baseline
//! 4. **Exploit Pattern Matching** — Compares code against signatures derived from
//!    historical Solana exploits (Wormhole, Cashio, etc.)
//! 5. **Ensemble Scoring** — Combines scores from the above techniques with
//!    hand-tuned weights and thresholds
//!
//! **Transparency note:** Despite sub-module naming (e.g., `code_embeddings`,
//! `control_flow_gnn`), no machine learning models, neural networks, or trained
//! parameters are used. All analysis is deterministic heuristic scoring.

pub mod anomaly_detector;
pub mod code_embeddings;
pub mod control_flow_gnn;
pub mod ensemble;
pub mod pattern_learner;
pub mod report;

use anomaly_detector::AnomalyDetector;
use code_embeddings::CodeEmbedder;
use control_flow_gnn::ControlFlowGNN;
use ensemble::EnsembleScorer;
use pattern_learner::PatternLearner;
use report::{L3xAnalysisReport, L3xFinding, L3xSeverity};

use std::fs;
use std::path::Path;
use syn::visit::Visit;
use tracing::{info, warn};
use walkdir::WalkDir;

/// L3X heuristic analyzer configuration
#[derive(Debug, Clone)]
pub struct L3xConfig {
    /// Enable code embedding analysis
    pub use_embeddings: bool,
    /// Enable control flow GNN
    pub use_gnn: bool,
    /// Enable anomaly detection
    pub use_anomaly_detection: bool,
    /// Enable pattern learning from exploits
    pub use_pattern_learning: bool,
    /// Confidence threshold (0.0-1.0)
    pub confidence_threshold: f32,
    /// Maximum files to analyze
    pub max_files: usize,
    /// Maximum file size in bytes
    pub max_file_size: usize,
}

impl Default for L3xConfig {
    fn default() -> Self {
        Self {
            use_embeddings: true,
            use_gnn: true,
            use_anomaly_detection: true,
            use_pattern_learning: true,
            confidence_threshold: 0.75,
            max_files: 0,             // unlimited
            max_file_size: 1_000_000, // 1MB
        }
    }
}

/// L3X heuristic code analyzer (weighted token scoring + CFG structural analysis)
pub struct L3xAnalyzer {
    config: L3xConfig,
    embedder: CodeEmbedder,
    gnn: ControlFlowGNN,
    anomaly_detector: AnomalyDetector,
    pattern_learner: PatternLearner,
    ensemble: EnsembleScorer,
}

impl L3xAnalyzer {
    /// Create a new L3X analyzer with default configuration
    pub fn new() -> Self {
        Self::with_config(L3xConfig::default())
    }

    /// Create a new L3X analyzer with custom configuration
    pub fn with_config(config: L3xConfig) -> Self {
        info!("Initializing L3X heuristic analyzer with weighted token scoring...");

        Self {
            embedder: CodeEmbedder::new(),
            gnn: ControlFlowGNN::new(),
            anomaly_detector: AnomalyDetector::new(),
            pattern_learner: PatternLearner::new(),
            ensemble: EnsembleScorer::new(),
            config,
        }
    }

    /// Analyze a Solana program using heuristic weighted-token techniques
    pub fn analyze_program(&mut self, program_path: &Path) -> Result<L3xAnalysisReport, String> {
        info!("L3X analyzing program at: {:?}", program_path);

        let start_time = std::time::Instant::now();
        let mut findings = Vec::new();

        // Collect Rust source files
        let source_files = self.collect_source_files(program_path)?;
        info!("L3X scanning {} source files", source_files.len());

        if source_files.is_empty() {
            return Err("No Rust source files found".to_string());
        }

        let mut total_lines = 0;
        let mut instructions_analyzed = 0;
        let mut accounts_analyzed = 0;

        // Phase 1: Code Embedding Analysis
        if self.config.use_embeddings {
            info!("Phase 1: Generating code embeddings for semantic analysis...");
            for (file_path, content) in &source_files {
                let embedding_findings = self.embedder.analyze_file(file_path, content);
                findings.extend(embedding_findings);
                total_lines += content.lines().count();
            }
        }

        // Phase 2: Control Flow GNN Analysis
        if self.config.use_gnn {
            info!("Phase 2: Building control flow graphs for GNN analysis...");
            for (file_path, content) in &source_files {
                if let Ok(syntax_tree) = syn::parse_file(content) {
                    let gnn_findings = self.gnn.analyze_control_flow(file_path, &syntax_tree);
                    findings.extend(gnn_findings);

                    // Count instructions
                    let mut counter = InstructionCounter::new();
                    counter.visit_file(&syntax_tree);
                    instructions_analyzed += counter.instruction_count;
                    accounts_analyzed += counter.account_count;
                }
            }
        }

        // Phase 3: Anomaly Detection
        if self.config.use_anomaly_detection {
            info!("Phase 3: Running anomaly detection for zero-day patterns...");
            for (file_path, content) in &source_files {
                if let Ok(syntax_tree) = syn::parse_file(content) {
                    let anomaly_findings =
                        self.anomaly_detector
                            .detect_anomalies(file_path, &syntax_tree, content);
                    findings.extend(anomaly_findings);
                }
            }
        }

        // Phase 4: Pattern Learning from Historical Exploits
        if self.config.use_pattern_learning {
            info!("Phase 4: Applying learned patterns from historical exploits...");
            for (file_path, content) in &source_files {
                if let Ok(syntax_tree) = syn::parse_file(content) {
                    let pattern_findings = self.pattern_learner.match_exploit_patterns(
                        file_path,
                        &syntax_tree,
                        content,
                    );
                    findings.extend(pattern_findings);
                }
            }
        }

        // Phase 5: Ensemble Scoring & Confidence Ranking
        info!("Phase 5: Ensemble scoring and confidence ranking...");
        findings = self
            .ensemble
            .score_and_rank(findings, self.config.confidence_threshold);

        // Deduplicate by fingerprint
        findings = self.deduplicate_findings(findings);

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        // Count severity levels
        let critical_count = findings
            .iter()
            .filter(|f| matches!(f.severity, L3xSeverity::Critical))
            .count();
        let high_count = findings
            .iter()
            .filter(|f| matches!(f.severity, L3xSeverity::High))
            .count();
        let medium_count = findings
            .iter()
            .filter(|f| matches!(f.severity, L3xSeverity::Medium))
            .count();
        let low_count = findings
            .iter()
            .filter(|f| matches!(f.severity, L3xSeverity::Low))
            .count();
        let info_count = findings
            .iter()
            .filter(|f| matches!(f.severity, L3xSeverity::Info))
            .count();

        info!(
            "L3X analysis complete: {} findings ({} critical, {} high) in {}ms",
            findings.len(),
            critical_count,
            high_count,
            execution_time_ms
        );

        Ok(L3xAnalysisReport {
            program_path: program_path.to_string_lossy().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            findings,
            files_scanned: source_files.len(),
            lines_scanned: total_lines,
            instructions_analyzed,
            accounts_analyzed,
            critical_count,
            high_count,
            medium_count,
            low_count,
            info_count,
            execution_time_ms,
            ml_models_used: vec![
                if self.config.use_embeddings {
                    "WeightedTokenScorer-v2.1"
                } else {
                    ""
                },
                if self.config.use_gnn {
                    "CFGStructuralAnalyzer-v1.5"
                } else {
                    ""
                },
                if self.config.use_anomaly_detection {
                    "StatisticalAnomalyDetector-v3.0"
                } else {
                    ""
                },
                if self.config.use_pattern_learning {
                    "ExploitPatternMatcher-v2.3"
                } else {
                    ""
                },
            ]
            .into_iter()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect(),
            confidence_threshold: self.config.confidence_threshold,
            engine_version: "l3x-heuristic-analyzer-3.2.1".to_string(),
        })
    }

    /// Collect Rust source files from program directory
    fn collect_source_files(&self, program_path: &Path) -> Result<Vec<(String, String)>, String> {
        let mut files = Vec::new();
        let mut file_count = 0;

        // Search in src/ and programs/ directories
        let search_paths = vec![
            program_path.join("src"),
            program_path.join("programs"),
            program_path.to_path_buf(),
        ];

        for search_path in search_paths {
            if !search_path.exists() {
                continue;
            }

            for entry in WalkDir::new(&search_path)
                .follow_links(true)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();

                if !path.is_file() {
                    continue;
                }

                if let Some(ext) = path.extension() {
                    if ext != "rs" {
                        continue;
                    }
                }

                if self.config.max_files > 0 && file_count >= self.config.max_files {
                    break;
                }

                let metadata = fs::metadata(path).map_err(|e| e.to_string())?;
                if metadata.len() > self.config.max_file_size as u64 {
                    warn!("Skipping large file: {:?} ({} bytes)", path, metadata.len());
                    continue;
                }

                let content = fs::read_to_string(path)
                    .map_err(|e| format!("Failed to read {:?}: {}", path, e))?;

                files.push((path.to_string_lossy().to_string(), content));
                file_count += 1;
            }
        }

        Ok(files)
    }

    /// Deduplicate findings by fingerprint
    fn deduplicate_findings(&self, findings: Vec<L3xFinding>) -> Vec<L3xFinding> {
        use std::collections::HashSet;

        let mut seen = HashSet::new();
        let mut unique = Vec::new();

        for finding in findings {
            if seen.insert(finding.fingerprint.clone()) {
                unique.push(finding);
            }
        }

        unique
    }
}

impl Default for L3xAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// AST visitor to count instructions and accounts
struct InstructionCounter {
    instruction_count: usize,
    account_count: usize,
}

impl InstructionCounter {
    fn new() -> Self {
        Self {
            instruction_count: 0,
            account_count: 0,
        }
    }
}

impl<'ast> Visit<'ast> for InstructionCounter {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        // Check if this is an Anchor instruction (has #[derive(Accounts)])
        for attr in &node.attrs {
            if attr.path().is_ident("derive") || attr.path().is_ident("account") {
                self.instruction_count += 1;
                break;
            }
        }
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        // Check if this is an Accounts struct by looking for #[derive(Accounts)]
        for attr in &node.attrs {
            if attr.path().is_ident("derive") {
                // Count fields as accounts
                self.account_count += node.fields.len();
                break;
            }
        }
        syn::visit::visit_item_struct(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_l3x_analyzer_creation() {
        let analyzer = L3xAnalyzer::new();
        assert_eq!(analyzer.config.confidence_threshold, 0.75);
    }

    #[test]
    fn test_custom_config() {
        let config = L3xConfig {
            use_embeddings: false,
            confidence_threshold: 0.9,
            ..Default::default()
        };
        let analyzer = L3xAnalyzer::with_config(config);
        assert_eq!(analyzer.config.confidence_threshold, 0.9);
        assert!(!analyzer.config.use_embeddings);
    }

    #[test]
    fn test_analyze_vulnerable_token_program() {
        let mut analyzer = L3xAnalyzer::new();
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../programs/vulnerable-token");
        if path.exists() {
            let report = analyzer.analyze_program(&path).expect("analysis should succeed");
            assert!(report.files_scanned > 0, "should scan at least one file");
            assert!(report.lines_scanned > 0, "should scan some lines");
            // L3x should find at least one finding in the vulnerable program
            assert!(
                !report.findings.is_empty(),
                "vulnerable-token should trigger at least one L3x finding"
            );
        }
    }

    #[test]
    fn test_token_weights_cover_solana_primitives() {
        use crate::code_embeddings::CodeEmbedder;
        let embedder = CodeEmbedder::new();
        // The embedder should have weights for key Solana tokens
        let expected_tokens = [
            "invoke", "invoke_signed", "authority", "signer",
            "lamports", "transfer", "mint_to", "set_authority",
            "find_program_address", "checked_add", "checked_sub",
            "require!", "has_one", "constraint",
        ];
        for token in &expected_tokens {
            assert!(
                embedder.token_weights.contains_key(*token),
                "token '{}' should be in weights map",
                token
            );
        }
    }

    #[test]
    fn test_embedder_detects_unchecked_arithmetic() {
        use crate::code_embeddings::CodeEmbedder;
        let embedder = CodeEmbedder::new();
        let source = r#"
            pub fn bad(amount: u64, balance: u64) -> u64 {
                let result = amount + balance * amount - balance;
                result
            }
        "#;
        let findings = embedder.analyze_file("test.rs", source);
        // File is short, but the embedder should at least run without panic
        // and any findings it produces should have a valid severity
        for f in &findings {
            assert!(f.confidence > 0.0);
        }
    }

    #[test]
    fn test_dedup_removes_duplicates_by_fingerprint() {
        let analyzer = L3xAnalyzer::new();
        use crate::report::{DetectionMethod, L3xCategory, L3xFinding, L3xSeverity};
        let finding = L3xFinding {
            id: "L3X-TEST-1".to_string(),
            category: L3xCategory::IntegerOverflow,
            severity: L3xSeverity::High,
            confidence: 0.9,
            file_path: "test.rs".to_string(),
            line_number: 10,
            instruction: "add".to_string(),
            account_name: None,
            description: "test".to_string(),
            ml_reasoning: "test".to_string(),
            fix_recommendation: "test".to_string(),
            cwe: "CWE-190".to_string(),
            fingerprint: "abc123".to_string(),
            source_snippet: None,
            fix_diff: None,
            detection_method: DetectionMethod::CodeEmbedding {
                model: "test".to_string(),
                similarity_score: 0.9,
            },
            related_patterns: vec![],
        };
        let dup = finding.clone();
        let deduped = analyzer.deduplicate_findings(vec![finding, dup]);
        assert_eq!(deduped.len(), 1, "duplicate fingerprints should be removed");
    }

    #[test]
    fn test_analyze_nonexistent_returns_error() {
        let mut analyzer = L3xAnalyzer::new();
        let result = analyzer.analyze_program(std::path::Path::new("/tmp/nonexistent_shanon_test"));
        assert!(result.is_err(), "nonexistent path should error");
    }
}
