use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::VulnerabilityFinding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportGenerator {
    // Placeholder configuration fields
    pub output_format: String,
    pub include_code_snippets: bool,
}

/// GitHub Check Run annotation format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubAnnotation {
    pub path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub annotation_level: String, // "failure", "warning", "notice"
    pub title: String,
    pub message: String,
    pub raw_details: Option<String>,
}

impl ReportGenerator {
    pub fn new(output_format: String, include_code_snippets: bool) -> Self {
        Self {
            output_format,
            include_code_snippets,
        }
    }

    pub fn generate_report<T: Serialize>(
        &self,
        data: &T,
        output_path: &Path,
    ) -> Result<(), std::io::Error> {
        let content = if self.output_format == "json" {
            serde_json::to_string_pretty(data)?
        } else {
            // Fallback for non-JSON: currently unimplemented or default serialization
            format!("{:#?}", serde_json::to_value(data)?)
        };

        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(output_path, content)?;
        Ok(())
    }

    /// Convert vulnerability findings to GitHub Check Run annotation format.
    ///
    /// These can be used with the GitHub Checks API to create inline
    /// annotations on pull requests and commits.
    pub fn to_github_annotations(findings: &[VulnerabilityFinding]) -> Vec<GitHubAnnotation> {
        findings
            .iter()
            .map(|f| {
                let level = match f.severity_label.to_uppercase().as_str() {
                    "CRITICAL" | "HIGH" => "failure".to_string(),
                    "MEDIUM" => "warning".to_string(),
                    _ => "notice".to_string(),
                };

                GitHubAnnotation {
                    path: f.location.clone(),
                    start_line: f.line_number.max(1),
                    end_line: f.line_number.max(1),
                    annotation_level: level,
                    title: format!("{} — {}", f.id, f.vuln_type),
                    message: format!(
                        "{}\n\nFix: {}",
                        f.description, f.secure_fix
                    ),
                    raw_details: if f.vulnerable_code.is_empty() {
                        None
                    } else {
                        Some(f.vulnerable_code.clone())
                    },
                }
            })
            .collect()
    }
}

