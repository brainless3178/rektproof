//! # Configuration File Support
//!
//! Supports `.rektproof.toml` configuration files for CI-friendly operation.
//!
//! ## Example `.rektproof.toml`
//!
//! ```toml
//! [scan]
//! min_severity = "medium"      # Minimum severity to report
//! format = "sarif"             # Output format: json, sarif, markdown, human, dashboard
//! fail_on = "high"             # Exit with error code if findings at this level
//! exclude_tests = true         # Skip test code (default: true)
//! max_findings = 100           # Cap findings to prevent noise
//!
//! [engines]
//! pattern_scanner = true
//! deep_ast = true
//! taint_analysis = true
//! cfg_analysis = true
//! abstract_interp = true
//! z3_verification = true       # Requires Z3 installed
//! account_aliasing = true
//!
//! [ignore]
//! ids = ["SOL-091"]            # Suppress specific finding IDs
//! paths = ["tests/", "scripts/"]  # Skip these directories
//! functions = ["test_*"]       # Skip functions matching these patterns
//! ```

use serde::Deserialize;
use std::path::Path;

/// Top-level configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RektproofConfig {
    pub scan: ScanConfig,
    pub engines: EngineConfig,
    pub ignore: IgnoreConfig,
}

/// Scan settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    /// Minimum severity to report: "low", "medium", "high", "critical"
    pub min_severity: String,
    /// Output format: "json", "sarif", "markdown", "human", "dashboard"
    pub format: String,
    /// Exit with error if findings at this level: "any", "medium", "high", "critical"
    pub fail_on: String,
    /// Skip test code
    pub exclude_tests: bool,
    /// Maximum findings to report (0 = unlimited)
    pub max_findings: usize,
}

/// Which engines to enable.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct EngineConfig {
    pub pattern_scanner: bool,
    pub deep_ast: bool,
    pub taint_analysis: bool,
    pub cfg_analysis: bool,
    pub abstract_interp: bool,
    pub z3_verification: bool,
    pub account_aliasing: bool,
}

/// Ignore rules.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct IgnoreConfig {
    /// Finding IDs to suppress
    pub ids: Vec<String>,
    /// Paths to skip
    pub paths: Vec<String>,
    /// Function name patterns to skip
    pub functions: Vec<String>,
}

impl Default for RektproofConfig {
    fn default() -> Self {
        Self {
            scan: ScanConfig::default(),
            engines: EngineConfig::default(),
            ignore: IgnoreConfig::default(),
        }
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            min_severity: "low".into(),
            format: "dashboard".into(),
            fail_on: "high".into(),
            exclude_tests: true,
            max_findings: 0,
        }
    }
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            pattern_scanner: true,
            deep_ast: true,
            taint_analysis: true,
            cfg_analysis: true,
            abstract_interp: true,
            z3_verification: true,
            account_aliasing: true,
        }
    }
}

impl Default for IgnoreConfig {
    fn default() -> Self {
        Self {
            ids: Vec::new(),
            paths: vec!["tests/".into(), "scripts/".into()],
            functions: Vec::new(),
        }
    }
}

impl RektproofConfig {
    /// Load configuration from `.rektproof.toml` in the given directory.
    /// Falls back to defaults if the file doesn't exist.
    pub fn load(project_dir: &Path) -> Self {
        let config_path = project_dir.join(".rektproof.toml");
        if config_path.exists() {
            match std::fs::read_to_string(&config_path) {
                Ok(content) => {
                    match toml::from_str::<RektproofConfig>(&content) {
                        Ok(config) => return config,
                        Err(e) => {
                            eprintln!("Warning: Failed to parse .rektproof.toml: {}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Warning: Failed to read .rektproof.toml: {}", e);
                }
            }
        }
        Self::default()
    }

    /// Get the minimum severity as a numeric value.
    pub fn min_severity_num(&self) -> u8 {
        match self.scan.min_severity.as_str() {
            "critical" => 5,
            "high" => 4,
            "medium" => 3,
            "low" => 2,
            _ => 1,
        }
    }

    /// Check if a finding ID should be ignored.
    pub fn is_ignored_id(&self, id: &str) -> bool {
        self.ignore.ids.iter().any(|ignored| id == ignored)
    }

    /// Check if a path should be ignored.
    pub fn is_ignored_path(&self, path: &str) -> bool {
        self.ignore.paths.iter().any(|ignored| path.contains(ignored))
    }

    /// Check if a function should be ignored.
    pub fn is_ignored_function(&self, func_name: &str) -> bool {
        self.ignore.functions.iter().any(|pattern| {
            if pattern.ends_with('*') {
                let prefix = &pattern[..pattern.len() - 1];
                func_name.starts_with(prefix)
            } else {
                func_name == pattern
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = RektproofConfig::default();
        assert_eq!(cfg.scan.min_severity, "low");
        assert!(cfg.engines.pattern_scanner);
        assert!(cfg.engines.z3_verification);
        assert_eq!(cfg.min_severity_num(), 2);
    }

    #[test]
    fn test_parse_toml() {
        let toml_str = r#"
            [scan]
            min_severity = "high"
            format = "json"
            fail_on = "critical"

            [engines]
            z3_verification = false

            [ignore]
            ids = ["SOL-091", "SOL-092"]
            paths = ["tests/"]
        "#;
        let cfg: RektproofConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.scan.min_severity, "high");
        assert_eq!(cfg.scan.format, "json");
        assert!(!cfg.engines.z3_verification);
        assert_eq!(cfg.ignore.ids.len(), 2);
        assert_eq!(cfg.min_severity_num(), 4);
    }

    #[test]
    fn test_ignore_patterns() {
        let mut cfg = RektproofConfig::default();
        cfg.ignore.ids = vec!["SOL-091".into()];
        cfg.ignore.functions = vec!["test_*".into(), "helper".into()];

        assert!(cfg.is_ignored_id("SOL-091"));
        assert!(!cfg.is_ignored_id("SOL-001"));
        assert!(cfg.is_ignored_function("test_foo"));
        assert!(cfg.is_ignored_function("helper"));
        assert!(!cfg.is_ignored_function("process"));
    }

    #[test]
    fn test_load_missing_file() {
        let cfg = RektproofConfig::load(Path::new("/nonexistent"));
        // Should fall back to defaults
        assert_eq!(cfg.scan.min_severity, "low");
    }
}
