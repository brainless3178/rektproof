#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct IntegrationOrchestrator;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentPackage {
    pub architecture_review: String,
    pub secure_code_template: String,
    pub testing_framework_template: String,
    pub deployment_protocol: String,
    pub pre_deployment_checklist: Vec<String>,
    pub source_files_scanned: usize,
}

impl IntegrationOrchestrator {
    /// Create a new IntegrationOrchestrator
    pub fn new() -> anyhow::Result<Self> {
        Ok(IntegrationOrchestrator)
    }

    /// Generate deployment package from a program ID string
    pub fn generate_deployment_package_for_id(program_id: &str) -> DeploymentPackage {
        DeploymentPackage {
            architecture_review: format!("Architecture review for program: {}", program_id),
            secure_code_template: "pub fn secure_instruction(ctx: Context<Secure>) -> Result<()> {\n    // Implementation\n    Ok(())\n}".to_string(),
            testing_framework_template: "import * as anchor from \"@coral-xyz/anchor\";\n\ndescribe(\"security-tests\", () => {\n  it(\"fails to exploit\", async () => {\n    // Test logic\n  });\n});".to_string(),
            deployment_protocol: "1. Build program\n2. Run security suite\n3. Deploy to devnet\n4. Verify on-chain".to_string(),
            pre_deployment_checklist: vec![
                "All tests passing".to_string(),
                "No high/critical vulnerabilities".to_string(),
                "Correct program ID in declare_id!".to_string(),
            ],
            source_files_scanned: 0,
        }
    }

    /// Generate deployment package by scanning a local directory
    pub fn generate_deployment_package(&self, program_path: &Path) -> anyhow::Result<DeploymentPackage> {
        // Count source files in the directory
        let mut source_count = 0;
        if program_path.is_dir() {
            for entry in walkdir::WalkDir::new(program_path)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
            {
                if let Some(ext) = entry.path().extension() {
                    if ext == "rs" || ext == "ts" || ext == "js" {
                        source_count += 1;
                    }
                }
            }
        }

        // Try to extract program ID from declare_id!()
        let program_id = self.extract_program_id(program_path)
            .unwrap_or_else(|| "Unknown".to_string());

        let mut pkg = Self::generate_deployment_package_for_id(&program_id);
        pkg.source_files_scanned = source_count;
        pkg.architecture_review = format!(
            "Architecture review for program: {}\n\nSource files scanned: {}\nProgram path: {}",
            program_id, source_count, program_path.display()
        );

        Ok(pkg)
    }

    /// Extract program ID from declare_id!() in source files
    fn extract_program_id(&self, program_path: &Path) -> Option<String> {
        if !program_path.is_dir() {
            return None;
        }

        for entry in walkdir::WalkDir::new(program_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |ext| ext == "rs"))
        {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                if let Some(start) = content.find("declare_id!(\"") {
                    let remaining = &content[start + 13..];
                    if let Some(end) = remaining.find('"') {
                        return Some(remaining[..end].to_string());
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_deployment_package() {
        let pkg = IntegrationOrchestrator::generate_deployment_package_for_id("TestProg111");
        assert!(pkg.architecture_review.contains("TestProg111"));
        assert!(!pkg.secure_code_template.is_empty());
        assert!(!pkg.testing_framework_template.is_empty());
        assert!(!pkg.deployment_protocol.is_empty());
        assert!(!pkg.pre_deployment_checklist.is_empty());
    }

    #[test]
    fn test_deployment_package_checklist() {
        let pkg = IntegrationOrchestrator::generate_deployment_package_for_id("test");
        assert!(pkg
            .pre_deployment_checklist
            .iter()
            .any(|c| c.contains("tests passing")));
        assert!(pkg
            .pre_deployment_checklist
            .iter()
            .any(|c| c.contains("vulnerabilities")));
    }

    #[test]
    fn test_deployment_package_serialization() {
        let pkg = IntegrationOrchestrator::generate_deployment_package_for_id("test");
        let json = serde_json::to_string(&pkg).unwrap();
        let deserialized: DeploymentPackage = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.pre_deployment_checklist.len(),
            pkg.pre_deployment_checklist.len()
        );
    }

    #[test]
    fn test_new_constructor() {
        let orch = IntegrationOrchestrator::new();
        assert!(orch.is_ok());
    }
}
