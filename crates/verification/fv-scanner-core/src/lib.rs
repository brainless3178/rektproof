#![allow(dead_code)]
use std::path::Path;
use serde::{Deserialize, Serialize};
use anyhow::Result;
use tokio::sync::mpsc;
use chrono::Utc;

pub use fv_layer1_verifier::{Layer1Verifier, Layer1Report, Layer1Config, Severity, Finding as Layer1Finding, Location as Layer1Location};
pub use fv_layer2_verifier::{Layer2Verifier, Layer2Report};
pub use fv_layer3_verifier::{Layer3Verifier, Layer3Report, Layer3Config};
pub use fv_layer4_verifier::{Layer4Verifier, Layer4Report};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub enabled_layers: Vec<u8>,
    pub layer1_config: Layer1Config,
    pub layer3_config: Layer3Config,
    pub verbose: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            enabled_layers: vec![1, 2, 3, 4],
            layer1_config: Layer1Config::default(),
            layer3_config: Layer3Config::default(),
            verbose: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: String,
    pub timestamp: String,
    pub target: String,
    pub layers: LayerResults,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerResults {
    pub layer1: Option<Layer1Report>,
    pub layer2: Option<Layer2Report>,
    pub layer3: Option<Layer3Report>,
    pub layer4: Option<Layer4Report>,
}

#[derive(Debug, Clone)]
pub enum ScanProgress {
    Started { layer: u8, name: String },
    Progress { layer: u8, percent: u8, message: String },
    Completed { layer: u8, success: bool },
    Error { layer: u8, message: String },
}

pub struct Scanner {
    config: ScanConfig,
}

impl Scanner {
    pub fn new(config: ScanConfig) -> Self {
        Self { config }
    }

    pub async fn scan_with_progress(&self, target: &Path, tx: mpsc::Sender<ScanProgress>) -> Result<ScanResult> {
        let scan_id = format!("scan_{}", Utc::now().timestamp());
        let start = std::time::Instant::now();

        let mut layers = LayerResults {
            layer1: None,
            layer2: None,
            layer3: None,
            layer4: None,
        };

        if self.config.enabled_layers.contains(&1) {
            let _ = tx.send(ScanProgress::Started { layer: 1, name: "Arithmetic & Logic".into() }).await;
            let verifier = Layer1Verifier::new(self.config.layer1_config.clone());
            if let Ok(report) = verifier.verify(target).await {
                layers.layer1 = Some(report);
                let _ = tx.send(ScanProgress::Completed { layer: 1, success: true }).await;
            }
        }

        if self.config.enabled_layers.contains(&2) {
            let _ = tx.send(ScanProgress::Started { layer: 2, name: "Deep Symbolic Exploration".into() }).await;
            let verifier = Layer2Verifier::new();
            if let Ok(report) = verifier.verify(target).await {
                layers.layer2 = Some(report);
                let _ = tx.send(ScanProgress::Completed { layer: 2, success: true }).await;
            }
        }

        if self.config.enabled_layers.contains(&3) {
            let _ = tx.send(ScanProgress::Started { layer: 3, name: "Cross-Program Safety".into() }).await;
            let verifier = Layer3Verifier::new(self.config.layer3_config.clone());
            if let Ok(report) = verifier.verify(target).await {
                layers.layer3 = Some(report);
                let _ = tx.send(ScanProgress::Completed { layer: 3, success: true }).await;
            }
        }

        if self.config.enabled_layers.contains(&4) {
            let _ = tx.send(ScanProgress::Started { layer: 4, name: "Protocol Design Guarantee".into() }).await;
            let verifier = Layer4Verifier::new();
            if let Ok(report) = verifier.verify(target).await {
                layers.layer4 = Some(report);
                let _ = tx.send(ScanProgress::Completed { layer: 4, success: true }).await;
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(ScanResult {
            scan_id,
            timestamp: Utc::now().to_rfc3339(),
            target: target.display().to_string(),
            layers,
            duration_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_default_config() {
        let config = ScanConfig::default();
        assert_eq!(config.enabled_layers, vec![1, 2, 3, 4]);
        assert!(!config.verbose);
    }

    #[test]
    fn test_scanner_creation() {
        let scanner = Scanner::new(ScanConfig::default());
        let _ = &scanner;
    }

    #[tokio::test]
    async fn test_full_scan_on_vulnerable_token() {
        let program_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent().unwrap()
            .parent().unwrap()
            .parent().unwrap()
            .join("programs")
            .join("vulnerable-token")
            .join("src");

        if !program_path.exists() {
            return; // skip if test programs are missing
        }

        let config = ScanConfig {
            enabled_layers: vec![1, 2, 3, 4],
            layer1_config: Layer1Config {
                kani_enabled: false, // Kani not installed
                prusti_enabled: true,
                ..Layer1Config::default()
            },
            layer3_config: Layer3Config::default(),
            verbose: false,
        };

        let scanner = Scanner::new(config);
        let (tx, mut rx) = mpsc::channel(32);

        let result = scanner.scan_with_progress(&program_path, tx).await.unwrap();

        // Verify scan structure
        assert!(!result.scan_id.is_empty());
        assert!(result.target.contains("vulnerable-token"));
        assert!(result.duration_ms < 60_000);

        // At least some layers should have produced results
        let has_any_layer = result.layers.layer1.is_some()
            || result.layers.layer2.is_some()
            || result.layers.layer3.is_some()
            || result.layers.layer4.is_some();
        assert!(has_any_layer, "at least one layer should produce results");
    }

    #[tokio::test]
    async fn test_single_layer_scan() {
        let config = ScanConfig {
            enabled_layers: vec![2], // only layer 2
            layer1_config: Layer1Config::default(),
            layer3_config: Layer3Config::default(),
            verbose: false,
        };

        let scanner = Scanner::new(config);
        let (tx, _rx) = mpsc::channel(32);
        let tmp = std::env::temp_dir().join("fv_core_single");
        std::fs::create_dir_all(&tmp).unwrap();

        let result = scanner.scan_with_progress(&tmp, tx).await.unwrap();
        assert!(result.layers.layer1.is_none(), "layer 1 should not run");
        assert!(result.layers.layer3.is_none(), "layer 3 should not run");
        assert!(result.layers.layer4.is_none(), "layer 4 should not run");
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_scan_result_serialization() {
        let result = ScanResult {
            scan_id: "scan_12345".to_string(),
            timestamp: "2026-01-01".to_string(),
            target: "/test/program".to_string(),
            layers: LayerResults {
                layer1: None,
                layer2: None,
                layer3: None,
                layer4: None,
            },
            duration_ms: 500,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("scan_12345"));
        let deser: ScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.duration_ms, 500);
        assert!(deser.layers.layer1.is_none());
    }
}

