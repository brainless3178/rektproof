//! Cargo.toml / Cargo.lock Scanner
//!
//! Parses Rust dependency manifests and checks each dependency against
//! the advisory database and typosquat detector.


use std::path::Path;

use crate::advisory_db::{AdvisoryDatabase, PackageEcosystem};
use crate::typosquat::check_typosquat_cargo;
use crate::{GuardFinding, GuardSeverity, FindingCategory};

/// Scan a Cargo.toml file for supply chain risks.
pub fn scan_cargo_toml(path: &Path, advisory_db: &AdvisoryDatabase) -> Vec<GuardFinding> {
    let mut findings = Vec::new();

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return findings,
    };

    let table: toml::Table = match content.parse() {
        Ok(t) => t,
        Err(_) => return findings,
    };

    // Collect all dependency tables
    let dep_tables = [
        "dependencies",
        "dev-dependencies",
        "build-dependencies",
    ];

    for dep_table_name in &dep_tables {
        let deps = match table.get(*dep_table_name) {
            Some(toml::Value::Table(t)) => t,
            _ => continue,
        };

        for (name, value) in deps {
            let version = extract_version(value);
            let source_file = path.display().to_string();

            // 1. Check advisory database
            let advisories = advisory_db.check(name, &version, PackageEcosystem::Cargo);
            for advisory in advisories {
                findings.push(GuardFinding {
                    package_name: name.clone(),
                    version: version.clone(),
                    ecosystem: "cargo".into(),
                    severity: match advisory.severity {
                        crate::advisory_db::AdvisorySeverity::Critical => GuardSeverity::Critical,
                        crate::advisory_db::AdvisorySeverity::High => GuardSeverity::High,
                        crate::advisory_db::AdvisorySeverity::Medium => GuardSeverity::Medium,
                        crate::advisory_db::AdvisorySeverity::Low => GuardSeverity::Low,
                    },
                    category: FindingCategory::KnownMalicious,
                    title: advisory.title.clone(),
                    description: advisory.description.clone(),
                    remediation: advisory.remediation.clone(),
                    reference: advisory.reference.clone(),
                    source_file: source_file.clone(),
                });
            }

            // 2. Check for typosquats
            if let Some(warning) = check_typosquat_cargo(name) {
                findings.push(GuardFinding {
                    package_name: name.clone(),
                    version: version.clone(),
                    ecosystem: "cargo".into(),
                    severity: GuardSeverity::High,
                    category: FindingCategory::Typosquat,
                    title: format!(
                        "Possible typosquat: `{}` looks like `{}`",
                        warning.suspicious_name, warning.likely_target
                    ),
                    description: format!(
                        "The crate `{}` has {:.0}% string similarity to the legitimate \
                         crate `{}`. This could be a typosquat attack.",
                        name,
                        warning.similarity * 100.0,
                        warning.likely_target
                    ),
                    remediation: format!(
                        "Verify you intended to use `{}` and not `{}`. \
                         Check the crate's author and repository URL on crates.io.",
                        name, warning.likely_target
                    ),
                    reference: None,
                    source_file: source_file.clone(),
                });
            }

            // 3. Check for path dependencies pointing outside the workspace (suspicious)
            if let Some(toml::Value::Table(dep_table)) = Some(value).filter(|v| v.is_table()) {
                if let Some(toml::Value::String(dep_path)) = dep_table.get("path") {
                    if dep_path.contains("..") && dep_path.matches("..").count() > 2 {
                        findings.push(GuardFinding {
                            package_name: name.clone(),
                            version: version.clone(),
                            ecosystem: "cargo".into(),
                            severity: GuardSeverity::Medium,
                            category: FindingCategory::SuspiciousSource,
                            title: format!("Deep path dependency: `{}`", name),
                            description: format!(
                                "The crate `{}` uses a deeply nested relative path (`{}`). \
                                 Excessive parent directory traversal in path dependencies \
                                 can indicate dependency confusion or staging attacks.",
                                name, dep_path
                            ),
                            remediation: "Verify this path dependency is intentional and \
                                points to trusted code."
                                .into(),
                            reference: None,
                            source_file: source_file.clone(),
                        });
                    }
                }

                // 4. Check for git dependencies from non-standard sources
                if let Some(toml::Value::String(git_url)) = dep_table.get("git") {
                    let trusted_orgs = [
                        "github.com/solana-labs",
                        "github.com/coral-xyz",
                        "github.com/metaplex-foundation",
                        "github.com/project-serum",
                        "github.com/anza-xyz",
                    ];
                    let is_trusted = trusted_orgs.iter().any(|org| git_url.contains(org));
                    if !is_trusted && git_url.contains("github.com") {
                        findings.push(GuardFinding {
                            package_name: name.clone(),
                            version: version.clone(),
                            ecosystem: "cargo".into(),
                            severity: GuardSeverity::Low,
                            category: FindingCategory::SuspiciousSource,
                            title: format!("Git dependency from non-standard org: `{}`", name),
                            description: format!(
                                "The crate `{}` is pulled from `{}` which is not a recognized \
                                 Solana ecosystem organization. While not necessarily malicious, \
                                 git dependencies from unknown sources should be audited.",
                                name, git_url
                            ),
                            remediation: "Audit the source repository before using it. \
                                Prefer crates.io published versions when available."
                                .into(),
                            reference: None,
                            source_file: source_file.clone(),
                        });
                    }
                }
            }
        }
    }

    // 5. Workspace-level dependency scanning
    if let Some(toml::Value::Table(workspace)) = table.get("workspace") {
        if let Some(toml::Value::Table(ws_deps)) = workspace.get("dependencies") {
            for (name, value) in ws_deps {
                let version = extract_version(value);
                let advisories = advisory_db.check(name, &version, PackageEcosystem::Cargo);
                for advisory in advisories {
                    findings.push(GuardFinding {
                        package_name: name.clone(),
                        version: version.clone(),
                        ecosystem: "cargo".into(),
                        severity: match advisory.severity {
                            crate::advisory_db::AdvisorySeverity::Critical => GuardSeverity::Critical,
                            crate::advisory_db::AdvisorySeverity::High => GuardSeverity::High,
                            crate::advisory_db::AdvisorySeverity::Medium => GuardSeverity::Medium,
                            crate::advisory_db::AdvisorySeverity::Low => GuardSeverity::Low,
                        },
                        category: FindingCategory::KnownMalicious,
                        title: advisory.title.clone(),
                        description: advisory.description.clone(),
                        remediation: advisory.remediation.clone(),
                        reference: advisory.reference.clone(),
                        source_file: path.display().to_string(),
                    });
                }
            }
        }
    }

    findings
}

/// Extract version string from a TOML dependency value.
/// Supports both `dep = "1.0"` and `dep = { version = "1.0", ... }`.
fn extract_version(value: &toml::Value) -> String {
    match value {
        toml::Value::String(v) => v.clone(),
        toml::Value::Table(t) => t
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("*")
            .to_string(),
        _ => "*".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_version_string() {
        let val = toml::Value::String("1.0.0".into());
        assert_eq!(extract_version(&val), "1.0.0");
    }

    #[test]
    fn test_extract_version_table() {
        let mut t = toml::map::Map::new();
        t.insert("version".into(), toml::Value::String("2.0".into()));
        let val = toml::Value::Table(t);
        assert_eq!(extract_version(&val), "2.0");
    }

    #[test]
    fn test_extract_version_path_only() {
        let mut t = toml::map::Map::new();
        t.insert("path".into(), toml::Value::String("../foo".into()));
        let val = toml::Value::Table(t);
        assert_eq!(extract_version(&val), "*");
    }
}
