//! Behavioral Analysis Scanner
//!
//! Scans JS/TS source files in node_modules for runtime indicators of
//! key exfiltration, clipboard hijacking, and other malicious behavior.
//! This catches packages that pass advisory/typosquat checks but contain
//! obfuscated malicious code.

use std::path::Path;

use crate::{FindingCategory, GuardFinding, GuardSeverity};

/// Patterns that indicate private key exfiltration.
const KEY_EXFIL_PATTERNS: &[(&str, &str)] = &[
    ("secretKey", "Accesses secretKey (private key bytes)"),
    ("Keypair.fromSecretKey", "Reconstructs keypair from secret bytes"),
    ("Keypair.fromSeed", "Reconstructs keypair from seed"),
    ("process.env.PRIVATE", "Reads private key from environment"),
    ("process.env.SECRET", "Reads secret from environment"),
    ("process.env.SOLANA", "Reads Solana config from environment"),
    (".solana/id.json", "Accesses Solana CLI keypair file"),
];

/// Patterns that indicate data exfiltration (combined with key access).
const EXFIL_PATTERNS: &[(&str, &str)] = &[
    ("XMLHttpRequest", "Uses XMLHttpRequest for outbound data"),
    ("navigator.sendBeacon", "Uses sendBeacon for stealthy exfiltration"),
    (".postMessage(", "Uses postMessage for cross-origin data leak"),
];

/// Patterns that indicate clipboard hijacking (crypto address replacement).
const CLIPBOARD_PATTERNS: &[(&str, &str)] = &[
    ("clipboard", "Accesses clipboard API"),
    ("writeText(", "Writes to clipboard (address replacement)"),
    ("readText(", "Reads from clipboard (address monitoring)"),
    ("execCommand('copy'", "Legacy clipboard write"),
];

/// Patterns indicating heavy obfuscation.
const OBFUSCATION_PATTERNS: &[(&str, &str)] = &[
    ("\\x", "Hex-escaped strings (obfuscation)"),
    ("\\u00", "Unicode-escaped strings (obfuscation)"),
    ("String.fromCharCode", "Dynamic string construction"),
    ("eval(", "Dynamic code evaluation"),
    ("Function(", "Dynamic function construction"),
    ("require('child_process')", "Spawns child processes"),
];

/// Scan JavaScript/TypeScript files in a directory for
/// behavioral indicators of malicious code.
pub fn scan_behavioral(dir: &Path) -> Vec<GuardFinding> {
    let mut findings = Vec::new();

    // Only scan specific directories where malicious code hides
    let scan_targets = [
        dir.join("node_modules"),
        dir.join("scripts"),
        dir.join("dist"),
    ];

    for target in &scan_targets {
        if target.exists() {
            scan_directory_recursive(target, &mut findings, 0);
        }
    }

    findings
}

fn scan_directory_recursive(dir: &Path, findings: &mut Vec<GuardFinding>, depth: usize) {
    // Limit recursion to avoid infinite loops and performance issues
    if depth > 4 {
        return;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();

        if path.is_dir() {
            // Skip known safe large directories
            let dirname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if dirname == ".git" || dirname == "test" || dirname == "tests" || dirname == "__tests__" {
                continue;
            }
            scan_directory_recursive(&path, findings, depth + 1);
        } else if path.is_file() {
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");
            if matches!(ext, "js" | "mjs" | "cjs" | "ts") {
                scan_js_file(&path, findings);
            }
        }
    }
}

fn scan_js_file(path: &Path, findings: &mut Vec<GuardFinding>) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Skip minified files that are just large single lines (usually safe library bundles)
    let line_count = content.lines().count();
    if line_count <= 3 && content.len() > 10000 {
        return; // Likely a minified bundle
    }

    let source_file = path.display().to_string();

    // Check for key access + network exfiltration combo (CRITICAL)
    let has_key_access = KEY_EXFIL_PATTERNS
        .iter()
        .any(|(pat, _)| content.contains(pat));
    let has_network = content.contains("fetch(")
        || content.contains("axios")
        || content.contains("http.request")
        || content.contains("https.request")
        || EXFIL_PATTERNS.iter().any(|(pat, _)| content.contains(pat));

    if has_key_access && has_network {
        let key_patterns: Vec<&str> = KEY_EXFIL_PATTERNS
            .iter()
            .filter(|(pat, _)| content.contains(pat))
            .map(|(_, desc)| *desc)
            .collect();

        findings.push(GuardFinding {
            package_name: extract_package_name(path),
            version: "unknown".into(),
            ecosystem: "npm".into(),
            severity: GuardSeverity::Critical,
            category: FindingCategory::SuspiciousBehavior,
            title: "KEY EXFILTRATION: Private key access + network call detected".into(),
            description: format!(
                "This file accesses private key material AND makes network requests. \
                 This is the classic pattern used in supply chain attacks like the \
                 @solana/web3.js backdoor.\n\nKey access patterns: {}\nFile: {}",
                key_patterns.join(", "),
                source_file
            ),
            remediation: "IMMEDIATELY remove this package and rotate all keys on affected machines."
                .into(),
            reference: None,
            source_file: source_file.clone(),
        });
        return; // Critical finding — no need to check further patterns
    }

    // Check for clipboard hijacking
    let clipboard_hits: Vec<&str> = CLIPBOARD_PATTERNS
        .iter()
        .filter(|(pat, _)| content.contains(pat))
        .map(|(_, desc)| *desc)
        .collect();

    if clipboard_hits.len() >= 2 {
        findings.push(GuardFinding {
            package_name: extract_package_name(path),
            version: "unknown".into(),
            ecosystem: "npm".into(),
            severity: GuardSeverity::High,
            category: FindingCategory::SuspiciousBehavior,
            title: "Clipboard hijacking indicators detected".into(),
            description: format!(
                "Multiple clipboard access patterns found, suggesting possible \
                 crypto address replacement attack.\nPatterns: {}\nFile: {}",
                clipboard_hits.join(", "),
                path.display()
            ),
            remediation: "Review the clipboard access logic. Legitimate packages rarely \
                need both read and write clipboard access."
                .into(),
            reference: None,
            source_file: source_file.clone(),
        });
    }

    // Check for heavy obfuscation (suspicious in a Solana package)
    let obf_hits: Vec<&str> = OBFUSCATION_PATTERNS
        .iter()
        .filter(|(pat, _)| content.contains(pat))
        .map(|(_, desc)| *desc)
        .collect();

    if obf_hits.len() >= 3 {
        findings.push(GuardFinding {
            package_name: extract_package_name(path),
            version: "unknown".into(),
            ecosystem: "npm".into(),
            severity: GuardSeverity::Medium,
            category: FindingCategory::SuspiciousBehavior,
            title: "Heavily obfuscated code in Solana package".into(),
            description: format!(
                "This file uses multiple obfuscation techniques: {}. \
                 Legitimate Solana packages rarely need this level of obfuscation.\nFile: {}",
                obf_hits.join(", "),
                path.display()
            ),
            remediation: "Inspect the deobfuscated code. Consider using an alternative package."
                .into(),
            reference: None,
            source_file,
        });
    }
}

/// Try to extract the package name from a file path in node_modules.
fn extract_package_name(path: &Path) -> String {
    let path_str = path.to_string_lossy();

    // Look for node_modules/<package_name> or node_modules/@scope/name
    if let Some(idx) = path_str.find("node_modules/") {
        let after = &path_str[idx + 13..];
        if after.starts_with('@') {
            // Scoped package: @scope/name
            let parts: Vec<&str> = after.splitn(3, '/').collect();
            if parts.len() >= 2 {
                return format!("{}/{}", parts[0], parts[1]);
            }
        } else {
            // Unscoped: name
            if let Some(name) = after.split('/').next() {
                return name.to_string();
            }
        }
    }

    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_package_name_scoped() {
        let path = Path::new("/project/node_modules/@solana/web3.js/lib/index.js");
        assert_eq!(extract_package_name(path), "@solana/web3.js");
    }

    #[test]
    fn test_extract_package_name_unscoped() {
        let path = Path::new("/project/node_modules/lodash/index.js");
        assert_eq!(extract_package_name(path), "lodash");
    }
}
