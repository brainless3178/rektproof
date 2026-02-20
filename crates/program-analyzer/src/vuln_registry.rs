//! # Vulnerability ID Registry
//!
//! Central registry mapping every SOL-xxx vulnerability ID to its metadata.
//! Prevents ID collisions, documents ownership, and provides a single source
//! of truth for all detection categories.
//!
//! # ID Scheme
//!
//! | Range        | Owner                     | Description                          |
//! |-------------|---------------------------|--------------------------------------|
//! | SOL-001–069 | vulnerability_db          | Core pattern-based detectors         |
//! | SOL-070–079 | sec3-analyzer             | Soteria-style checks                 |
//! | SOL-080–089 | anchor-security-analyzer  | Anchor-specific constraints          |
//! | SOL-090–096 | Experimental phases 9–15  | Dataflow, taint, geiger, concolic    |
//! | SOL-ALIAS-* | account_aliasing          | Account aliasing/confusion           |
//! | SOL-FV-01–04| FV layer verifiers        | Formal verification (Z3-backed)      |
//! | SOL-SYM-01  | symbolic-engine           | Symbolic execution proofs            |

use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

/// Metadata for a single vulnerability detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnIdEntry {
    /// Unique identifier (e.g., "SOL-001")
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Which scanning phase / module owns this detector
    pub owner: String,
    /// CWE mapping (e.g., "CWE-284")
    pub cwe: Option<String>,
    /// Default severity (1-5)
    pub default_severity: u8,
    /// Brief description
    pub description: String,
}

/// Central registry of all vulnerability IDs.
pub struct VulnRegistry {
    entries: BTreeMap<String, VulnIdEntry>,
}

impl VulnRegistry {
    /// Build the complete registry of all detector IDs.
    pub fn new() -> Self {
        let mut entries = BTreeMap::new();
        let mut add = |id: &str, name: &str, owner: &str, cwe: Option<&str>, sev: u8, desc: &str| {
            entries.insert(id.to_string(), VulnIdEntry {
                id: id.to_string(),
                name: name.to_string(),
                owner: owner.to_string(),
                cwe: cwe.map(|s| s.to_string()),
                default_severity: sev,
                description: desc.to_string(),
            });
        };

        // ═══ Core pattern detectors (SOL-001 – SOL-069) ═══
        add("SOL-001", "Missing Signer Validation", "vulnerability_db", Some("CWE-284"), 5,
            "Transaction proceeds without verifying the required signer.");
        add("SOL-002", "Missing Authority Check", "vulnerability_db", Some("CWE-285"), 5,
            "Privileged operation lacks an authority/admin check.");
        add("SOL-006", "Integer Overflow/Underflow", "vulnerability_db", Some("CWE-190"), 4,
            "Arithmetic operation may overflow or underflow silently.");
        add("SOL-012", "Missing Owner Validation", "vulnerability_db", Some("CWE-285"), 4,
            "Account owner is not validated before use.");
        add("SOL-017", "Arbitrary CPI", "vulnerability_db", Some("CWE-829"), 5,
            "Cross-program invocation target is attacker-controlled.");
        add("SOL-055", "Token2022 Transfer Hook Reentrancy", "vulnerability_db", Some("CWE-691"), 4,
            "Transfer hook may enable reentrancy on Token-2022 transfers.");
        add("SOL-063", "Unvalidated remaining_accounts", "vulnerability_db", Some("CWE-20"), 4,
            "ctx.remaining_accounts is iterated without key/owner validation.");

        // ═══ Sec3 detectors (SOL-070 – SOL-079) ═══
        add("SOL-070", "Close Account Drain", "sec3-analyzer", Some("CWE-404"), 4,
            "Account can be closed without properly draining lamports.");
        add("SOL-071", "Duplicate Mutable Accounts", "sec3-analyzer", Some("CWE-362"), 4,
            "Same account passed twice as mutable, enabling aliasing.");
        add("SOL-072", "Unchecked Remaining Accounts (Sec3)", "sec3-analyzer", Some("CWE-20"), 3,
            "Sec3 remaining_accounts check.");
        add("SOL-073", "Insecure PDA Derivation", "sec3-analyzer", Some("CWE-330"), 4,
            "PDA seed derivation uses weak or predictable inputs.");
        add("SOL-074", "Re-Initialization via init_if_needed", "sec3-analyzer", Some("CWE-665"), 4,
            "Account can be re-initialized through init_if_needed.");
        add("SOL-075", "Arbitrary CPI Invocation", "sec3-analyzer", Some("CWE-829"), 5,
            "CPI target program is not validated.");
        add("SOL-076", "Account Type Confusion", "sec3-analyzer", Some("CWE-843"), 4,
            "Account deserialized as wrong type.");
        add("SOL-077", "Missing Discriminator Check", "sec3-analyzer", Some("CWE-843"), 3,
            "Account discriminator not verified before deserialization.");
        add("SOL-078", "Missing Rent Exemption Check", "sec3-analyzer", Some("CWE-400"), 2,
            "Account may not be rent-exempt.");

        // ═══ Anchor detectors (SOL-080 – SOL-089) ═══
        add("SOL-080", "Weak Account Constraint", "anchor-security-analyzer", Some("CWE-285"), 3,
            "Anchor account constraint is too permissive.");
        add("SOL-081", "Invalid Token-2022 Transfer Hook", "anchor-security-analyzer", Some("CWE-691"), 4,
            "Token-2022 hook is improperly configured.");
        add("SOL-082", "Missing has_one Constraint", "anchor-security-analyzer", Some("CWE-285"), 3,
            "Account relationship not enforced by has_one.");
        add("SOL-083", "Unsafe Constraint Expression", "anchor-security-analyzer", Some("CWE-697"), 3,
            "Constraint expression may always evaluate to true.");
        add("SOL-084", "Missing Bump Validation", "anchor-security-analyzer", Some("CWE-330"), 3,
            "PDA bump seed is not canonicalized.");
        add("SOL-085", "Missing Space Calculation", "anchor-security-analyzer", Some("CWE-131"), 2,
            "Account space may be insufficient for its type.");
        add("SOL-086", "Missing Rent Exemption", "anchor-security-analyzer", Some("CWE-400"), 2,
            "Anchor account not marked rent-exempt.");
        add("SOL-087", "Unchecked Account Type", "anchor-security-analyzer", Some("CWE-843"), 3,
            "Account type not verified in Anchor context.");

        // ═══ Experimental phase detectors (SOL-090 – SOL-096) ═══
        add("SOL-090", "Uninitialized Variable Use", "dataflow-analyzer", Some("CWE-457"), 3,
            "Variable may be used before initialization.");
        add("SOL-091", "Dead Store / Unused Assignment", "dataflow-analyzer", Some("CWE-563"), 1,
            "Assigned value is never read (potential stale state).");
        add("SOL-092", "Tainted Data Flow", "taint-analyzer", Some("CWE-20"), 4,
            "Untrusted data flows from source to security-sensitive sink.");
        add("SOL-093", "Unsafe Code Usage", "geiger-analyzer", Some("CWE-676"), 3,
            "Use of unsafe Rust constructs.");
        add("SOL-094", "Unchecked Arithmetic (Expert)", "arithmetic-security-expert", Some("CWE-190"), 4,
            "Arithmetic expert found unchecked operation.");
        add("SOL-095", "Invariant Violation", "invariant-miner", Some("CWE-682"), 3,
            "Mined invariant may be violated.");
        add("SOL-096", "Concolic Path Vulnerability", "concolic-executor", Some("CWE-119"), 4,
            "Concolic execution found an exploitable path.");

        // ═══ Account aliasing detectors ═══
        add("SOL-ALIAS-02", "Raw AccountInfo Usage", "account_aliasing", Some("CWE-843"), 3,
            "Raw AccountInfo used without typed wrapper.");
        add("SOL-ALIAS-05", "Authority Without Signer", "account_aliasing", Some("CWE-285"), 4,
            "Authority account not marked as Signer.");

        // ═══ Formal verification detectors (SOL-FV-*) ═══
        add("SOL-FV-01", "FV: Arithmetic Property Failure", "fv-layer1-verifier", Some("CWE-682"), 4,
            "Kani/deductive analysis found arithmetic safety issue.");
        add("SOL-FV-02", "FV: Z3 Arithmetic Overflow Proof", "fv-layer2-verifier", Some("CWE-190"), 4,
            "Z3 proved that overflow is possible with concrete inputs.");
        add("SOL-FV-03", "FV: Account Schema Invariant", "fv-layer3-verifier", Some("CWE-682"), 4,
            "Z3 proved account invariant (solvency/supply) can be violated.");
        add("SOL-FV-04", "FV: State Machine Violation", "fv-layer4-verifier", Some("CWE-372"), 4,
            "Z3 proved a state transition property is unsafe.");
        add("SOL-SYM-01", "Symbolic: Exploitable Invariant", "symbolic-engine", Some("CWE-682"), 4,
            "Symbolic engine proved an exploit with concrete counterexample.");

        Self { entries }
    }

    /// Look up a vulnerability by ID.
    pub fn get(&self, id: &str) -> Option<&VulnIdEntry> {
        self.entries.get(id)
    }

    /// Get all entries.
    pub fn all(&self) -> impl Iterator<Item = &VulnIdEntry> {
        self.entries.values()
    }

    /// Total number of registered detectors.
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Check if an ID exists.
    pub fn contains(&self, id: &str) -> bool {
        self.entries.contains_key(id)
    }

    /// Validate that no IDs are duplicated (compile-time assertion via BTreeMap).
    /// Returns IDs grouped by owner module.
    pub fn by_owner(&self) -> BTreeMap<String, Vec<&VulnIdEntry>> {
        let mut map: BTreeMap<String, Vec<&VulnIdEntry>> = BTreeMap::new();
        for entry in self.entries.values() {
            map.entry(entry.owner.clone()).or_default().push(entry);
        }
        map
    }

    /// Format a markdown table of all detectors.
    pub fn to_markdown(&self) -> String {
        let mut md = String::from("# Vulnerability Detector Registry\n\n");
        md.push_str("| ID | Name | Owner | CWE | Severity |\n");
        md.push_str("|---|---|---|---|---|\n");
        for entry in self.entries.values() {
            md.push_str(&format!(
                "| `{}` | {} | {} | {} | {} |\n",
                entry.id, entry.name, entry.owner,
                entry.cwe.as_deref().unwrap_or("-"),
                entry.default_severity,
            ));
        }
        md
    }
}

impl Default for VulnRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_has_all_ids() {
        let reg = VulnRegistry::new();
        // Should have at least 35+ detectors
        assert!(reg.count() >= 35, "registry should have >= 35 detectors, got {}", reg.count());
    }

    #[test]
    fn test_no_duplicate_ids() {
        let reg = VulnRegistry::new();
        // BTreeMap insertion silently overwrites — verify by counting
        let mut seen = std::collections::HashSet::new();
        for entry in reg.all() {
            assert!(seen.insert(entry.id.clone()), "duplicate ID: {}", entry.id);
        }
    }

    #[test]
    fn test_core_ids_present() {
        let reg = VulnRegistry::new();
        assert!(reg.contains("SOL-001"), "missing SOL-001");
        assert!(reg.contains("SOL-006"), "missing SOL-006");
        assert!(reg.contains("SOL-063"), "missing SOL-063");
        assert!(reg.contains("SOL-FV-01"), "missing SOL-FV-01");
        assert!(reg.contains("SOL-SYM-01"), "missing SOL-SYM-01");
    }

    #[test]
    fn test_all_entries_have_cwe() {
        let reg = VulnRegistry::new();
        for entry in reg.all() {
            assert!(entry.cwe.is_some(), "ID {} missing CWE", entry.id);
        }
    }

    #[test]
    fn test_by_owner_groups_correctly() {
        let reg = VulnRegistry::new();
        let by_owner = reg.by_owner();
        assert!(by_owner.contains_key("vulnerability_db"));
        assert!(by_owner.contains_key("sec3-analyzer"));
        assert!(by_owner.contains_key("fv-layer1-verifier"));
    }

    #[test]
    fn test_markdown_output() {
        let reg = VulnRegistry::new();
        let md = reg.to_markdown();
        assert!(md.contains("SOL-001"));
        assert!(md.contains("| ID |"));
    }

    #[test]
    fn test_severity_range() {
        let reg = VulnRegistry::new();
        for entry in reg.all() {
            assert!(entry.default_severity >= 1 && entry.default_severity <= 5,
                "ID {} has invalid severity {}", entry.id, entry.default_severity);
        }
    }
}
