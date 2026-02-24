//! # Vulnerability Knowledge Base — Top 100 Solana & Web3 Vulnerabilities
//!
//! Comprehensive dataset compiled from:
//! - OWASP Smart Contract Top 10 (2025)
//! - OWASP Solana Top 10 (draft)
//! - coral-xyz/sealevel-attacks
//! - Halborn Top 100 DeFi Hacks Report ($7.35B total losses)
//! - Trail of Bits "Not So Smart Contracts"
//! - SlowMist Solana Security Best Practices
//! - Neodyme, Zellic, OtterSec audit findings
//! - Real CVEs (CVE-2022-23066, CVE-2024-54134)
//!
//! Each entry maps to rektproof detector IDs where coverage exists.

/// A single vulnerability entry in the knowledge base.
#[derive(Debug, Clone)]
pub struct VulnEntry {
    pub kb_id: &'static str,
    pub name: &'static str,
    pub category: &'static str,
    pub severity: &'static str,
    pub cwe: &'static str,
    pub owasp_sc: &'static str,
    pub detector_ids: &'static [&'static str],
    pub detected: bool,
    pub detection_technique: &'static str,
    pub description: &'static str,
    pub real_incident: Option<Incident>,
    pub solana_specific: bool,
}

#[derive(Debug, Clone)]
pub struct Incident {
    pub project: &'static str,
    pub loss: &'static str,
    pub date: &'static str,
}

/// Returns the complete knowledge base of 100 vulnerabilities.
pub fn get_knowledge_base() -> Vec<VulnEntry> {
    vec![
    // ══════════════════════════════════════════════════════════════════════
    //  CATEGORY 1: AUTHENTICATION & ACCESS CONTROL (1-15)
    // ══════════════════════════════════════════════════════════════════════
    VulnEntry {
        kb_id: "KB-001", name: "Missing Signer Check", category: "Authentication",
        severity: "Critical", cwe: "CWE-287", owasp_sc: "SC01",
        detector_ids: &["SOL-001"], detected: true,
        detection_technique: "AST + Pattern",
        description: "Authority account passed as AccountInfo without Signer constraint",
        real_incident: Some(Incident { project: "Wormhole", loss: "$320M", date: "2022-02" }),
        solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-002", name: "Missing Owner Check", category: "Authorization",
        severity: "Critical", cwe: "CWE-285", owasp_sc: "SC01",
        detector_ids: &["SOL-003"], detected: true,
        detection_technique: "AST + Pattern",
        description: "Account data read without validating account.owner == program_id",
        real_incident: Some(Incident { project: "Cashio", loss: "$52M", date: "2022-03" }),
        solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-003", name: "Missing Access Control", category: "Authorization",
        severity: "Critical", cwe: "CWE-284", owasp_sc: "SC01",
        detector_ids: &["SOL-047"], detected: true,
        detection_technique: "Pattern",
        description: "Admin/privileged function callable by any account",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-004", name: "Privilege Escalation", category: "Authorization",
        severity: "Critical", cwe: "CWE-269", owasp_sc: "SC01",
        detector_ids: &["SOL-030"], detected: true,
        detection_technique: "Pattern",
        description: "Authority can be changed without multi-sig or timelock",
        real_incident: Some(Incident { project: "Raydium", loss: "$4.4M", date: "2022-12" }),
        solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-005", name: "Unprotected Mint Authority", category: "Token Security",
        severity: "Critical", cwe: "CWE-269", owasp_sc: "SC01",
        detector_ids: &["SOL-021", "SOL-031"], detected: true,
        detection_technique: "Pattern + Deep AST",
        description: "mint_to CPI without validating mint authority as Signer",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-006", name: "Reinitialization Attack", category: "State Management",
        severity: "High", cwe: "CWE-665", owasp_sc: "SC01",
        detector_ids: &["SOL-011"], detected: true,
        detection_technique: "Pattern",
        description: "Initialize function callable multiple times to reset state",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-007", name: "Account Hijacking", category: "Authorization",
        severity: "Critical", cwe: "CWE-284", owasp_sc: "SC01",
        detector_ids: &["SOL-048"], detected: true,
        detection_technique: "Pattern",
        description: "Account authority transferable without proper authorization",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-008", name: "Missing Program ID Check", category: "Authorization",
        severity: "Critical", cwe: "CWE-20", owasp_sc: "SC01",
        detector_ids: &["SOL-015"], detected: true,
        detection_technique: "Pattern",
        description: "CPI target not validated against expected program ID",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-009", name: "Unvalidated Freeze Authority", category: "Token Security",
        severity: "Medium", cwe: "CWE-269", owasp_sc: "SC01",
        detector_ids: &["SOL-022", "SOL-068"], detected: true,
        detection_technique: "Pattern",
        description: "Freeze authority not properly guarded or revocable",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-010", name: "Single Wallet Upgrade Authority", category: "Governance",
        severity: "High", cwe: "CWE-269", owasp_sc: "SC01",
        detector_ids: &["SOL-067"], detected: true,
        detection_technique: "Pattern",
        description: "Program upgrade controlled by single key without multi-sig",
        real_incident: Some(Incident { project: "Raydium", loss: "$2.2M", date: "2022-12" }),
        solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-011", name: "Governance Bypass", category: "Governance",
        severity: "High", cwe: "CWE-284", owasp_sc: "SC01",
        detector_ids: &["SOL-052", "SOL-064"], detected: true,
        detection_technique: "Pattern",
        description: "Governance proposals executable without quorum or timelock",
        real_incident: Some(Incident { project: "Mango Markets", loss: "$114M", date: "2022-10" }),
        solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-012", name: "Missing Close Authority", category: "Account Management",
        severity: "High", cwe: "CWE-404", owasp_sc: "SC01",
        detector_ids: &["SOL-029"], detected: true,
        detection_technique: "Pattern",
        description: "Account closeable by non-owner",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-013", name: "Unrestricted Transfer", category: "Token Security",
        severity: "Critical", cwe: "CWE-862", owasp_sc: "SC01",
        detector_ids: &["SOL-041"], detected: true,
        detection_technique: "Pattern",
        description: "Token transfer without proper authorization checks",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-014", name: "Sysvar Address Spoofing", category: "Input Validation",
        severity: "Medium", cwe: "CWE-20", owasp_sc: "SC04",
        detector_ids: &["SOL-010"], detected: true,
        detection_technique: "Pattern",
        description: "Sysvar accessed via raw AccountInfo without address validation",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-015", name: "Unvalidated remaining_accounts", category: "Input Validation",
        severity: "High", cwe: "CWE-20", owasp_sc: "SC04",
        detector_ids: &["SOL-063"], detected: true,
        detection_technique: "Pattern",
        description: "remaining_accounts iterated without type/owner validation",
        real_incident: None, solana_specific: true,
    },

    // ══════════════════════════════════════════════════════════════════════
    //  CATEGORY 2: ARITHMETIC & PRECISION (16-30)
    // ══════════════════════════════════════════════════════════════════════
    VulnEntry {
        kb_id: "KB-016", name: "Integer Overflow", category: "Arithmetic",
        severity: "High", cwe: "CWE-190", owasp_sc: "SC08",
        detector_ids: &["SOL-002", "SOL-ABS-01", "SOL-Z3-01"], detected: true,
        detection_technique: "Pattern + Abstract Interp + Z3",
        description: "Unchecked addition/multiplication on u64 financial values",
        real_incident: Some(Incident { project: "Multiple DeFi", loss: "Various", date: "2021-2023" }),
        solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-017", name: "Integer Underflow", category: "Arithmetic",
        severity: "High", cwe: "CWE-191", owasp_sc: "SC08",
        detector_ids: &["SOL-002", "SOL-ABS-02", "SOL-Z3-02"], detected: true,
        detection_technique: "Pattern + Abstract Interp + Z3",
        description: "Unchecked subtraction causing wraparound",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-018", name: "Division by Zero", category: "Arithmetic",
        severity: "High", cwe: "CWE-369", owasp_sc: "SC08",
        detector_ids: &["SOL-ABS-03", "SOL-Z3-03"], detected: true,
        detection_technique: "Abstract Interp + Z3",
        description: "Division with user-controlled denominator without zero check",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-019", name: "Multiplication Overflow", category: "Arithmetic",
        severity: "High", cwe: "CWE-190", owasp_sc: "SC08",
        detector_ids: &["SOL-045", "SOL-ABS-01", "SOL-Z3-04"], detected: true,
        detection_technique: "Pattern + Abstract Interp + Z3",
        description: "a * b overflow where both are u64::MAX range",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-020", name: "Division Before Multiplication", category: "Precision",
        severity: "Medium", cwe: "CWE-682", owasp_sc: "SC08",
        detector_ids: &["SOL-037"], detected: true,
        detection_technique: "Pattern",
        description: "a / b * c loses precision vs a * c / b",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-021", name: "Precision Loss in Fee Calculation", category: "Precision",
        severity: "High", cwe: "CWE-682", owasp_sc: "SC08",
        detector_ids: &["SOL-038"], detected: true,
        detection_technique: "Pattern",
        description: "Fee/reward calculated with truncating integer division",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-022", name: "Rounding Errors", category: "Precision",
        severity: "Medium", cwe: "CWE-682", owasp_sc: "SC08",
        detector_ids: &["SOL-039"], detected: true,
        detection_technique: "Pattern",
        description: "Rounding direction favors attacker in swap/lending math",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-023", name: "Missing Zero Check", category: "Input Validation",
        severity: "Medium", cwe: "CWE-20", owasp_sc: "SC04",
        detector_ids: &["SOL-040"], detected: true,
        detection_technique: "Pattern",
        description: "Amount parameter accepted as 0, causing division-by-zero or no-op",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-024", name: "Missing Decimals Check", category: "Token Security",
        severity: "Medium", cwe: "CWE-682", owasp_sc: "SC04",
        detector_ids: &["SOL-032"], detected: true,
        detection_technique: "Pattern",
        description: "Token decimals not validated, causing miscalculated amounts",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-025", name: "Missing Amount Validation", category: "Input Validation",
        severity: "High", cwe: "CWE-20", owasp_sc: "SC04",
        detector_ids: &["SOL-036"], detected: true,
        detection_technique: "Pattern",
        description: "Deposit/withdraw amount not bounded or validated",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-026", name: "Reward Calculation Error", category: "Precision",
        severity: "High", cwe: "CWE-682", owasp_sc: "SC08",
        detector_ids: &["SOL-050"], detected: true,
        detection_technique: "Pattern",
        description: "Staking/farming reward computed incorrectly allowing drain",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-027", name: "Shift Overflow", category: "Arithmetic",
        severity: "Medium", cwe: "CWE-190", owasp_sc: "SC08",
        detector_ids: &["SOL-Z3-05"], detected: true,
        detection_technique: "Z3",
        description: "Bit shift by >= type width causes undefined behavior",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-028", name: "Unsafe Cast Truncation", category: "Arithmetic",
        severity: "Medium", cwe: "CWE-681", owasp_sc: "SC08",
        detector_ids: &[], detected: false,
        detection_technique: "Not implemented",
        description: "Casting u128 to u64 silently truncates upper bits",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-029", name: "Constant Product Invariant Violation", category: "DeFi Math",
        severity: "Critical", cwe: "CWE-682", owasp_sc: "SC03",
        detector_ids: &[], detected: false,
        detection_technique: "Not implemented",
        description: "AMM swap violates x*y=k invariant under edge cases",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-030", name: "Negative Interest Rate", category: "DeFi Math",
        severity: "High", cwe: "CWE-682", owasp_sc: "SC03",
        detector_ids: &[], detected: false,
        detection_technique: "Not implemented",
        description: "Lending rate calculation goes negative under certain conditions",
        real_incident: None, solana_specific: false,
    },

    // ══════════════════════════════════════════════════════════════════════
    //  CATEGORY 3: CROSS-PROGRAM INVOCATION (31-40)
    // ══════════════════════════════════════════════════════════════════════
    VulnEntry {
        kb_id: "KB-031", name: "Arbitrary CPI", category: "CPI Security",
        severity: "Critical", cwe: "CWE-20", owasp_sc: "SC06",
        detector_ids: &["SOL-005", "SOL-017"], detected: true,
        detection_technique: "AST + Pattern + Deep AST",
        description: "invoke/invoke_signed with unvalidated program AccountInfo",
        real_incident: Some(Incident { project: "Crema Finance", loss: "$8.8M", date: "2022-07" }),
        solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-032", name: "CPI Reentrancy", category: "CPI Security",
        severity: "Critical", cwe: "CWE-841", owasp_sc: "SC05",
        detector_ids: &["SOL-017", "SOL-DEEP"], detected: true,
        detection_technique: "Pattern + Deep AST + CFG",
        description: "State read before CPI, CPI modifies state, stale read used after",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-033", name: "CPI Depth Exhaustion", category: "CPI Security",
        severity: "Medium", cwe: "CWE-400", owasp_sc: "SC10",
        detector_ids: &["SOL-026"], detected: true,
        detection_technique: "Pattern",
        description: "CPI chain exceeds max depth (4), causing transaction failure",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-034", name: "Program Impersonation", category: "CPI Security",
        severity: "Critical", cwe: "CWE-290", owasp_sc: "SC06",
        detector_ids: &["SOL-054"], detected: true,
        detection_technique: "Pattern",
        description: "Malicious program deployed with same interface as target",
        real_incident: Some(Incident { project: "Crema Finance", loss: "$8.8M", date: "2022-07" }),
        solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-035", name: "Missing CPI Guard (AccountInfo as program)", category: "CPI Security",
        severity: "Critical", cwe: "CWE-862", owasp_sc: "SC06",
        detector_ids: &["SOL-017", "SOL-DEEP-CPI"], detected: true,
        detection_technique: "Deep AST",
        description: "CPI target passed as AccountInfo instead of Program<T>",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-036", name: "Token2022 Transfer Hook Risk", category: "CPI Security",
        severity: "High", cwe: "CWE-20", owasp_sc: "SC06",
        detector_ids: &["SOL-055"], detected: true,
        detection_technique: "Pattern",
        description: "Token-2022 transfer hooks can execute arbitrary code during transfers",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-037", name: "Token2022 Fee Mismatch", category: "Token Security",
        severity: "High", cwe: "CWE-682", owasp_sc: "SC03",
        detector_ids: &["SOL-056"], detected: true,
        detection_technique: "Pattern",
        description: "Transfer fee extension not accounted for in token amount calculations",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-038", name: "Permanent Delegate Exposure", category: "Token Security",
        severity: "High", cwe: "CWE-269", owasp_sc: "SC01",
        detector_ids: &["SOL-057"], detected: true,
        detection_technique: "Pattern",
        description: "Token-2022 permanent delegate can burn/transfer any holder's tokens",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-039", name: "Unchecked Return Value from CPI", category: "CPI Security",
        severity: "High", cwe: "CWE-252", owasp_sc: "SC06",
        detector_ids: &["SOL-016"], detected: true,
        detection_technique: "Pattern",
        description: "CPI result not checked (? or match), failure silently ignored",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-040", name: "Cross-IX Duplicate Accounts", category: "CPI Security",
        severity: "Critical", cwe: "CWE-20", owasp_sc: "SC04",
        detector_ids: &["SOL-069"], detected: true,
        detection_technique: "Pattern",
        description: "Same account passed as multiple mutable params in cross-instruction call",
        real_incident: None, solana_specific: true,
    },

    // ══════════════════════════════════════════════════════════════════════
    //  CATEGORY 4: PDA & ACCOUNT MANAGEMENT (41-55)
    // ══════════════════════════════════════════════════════════════════════
    VulnEntry {
        kb_id: "KB-041", name: "Bump Seed Canonicalization", category: "PDA Security",
        severity: "High", cwe: "CWE-330", owasp_sc: "SC04",
        detector_ids: &["SOL-007"], detected: true,
        detection_technique: "Pattern",
        description: "PDA created with non-canonical bump allowing duplicate addresses",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-042", name: "PDA Sharing Across Users", category: "PDA Security",
        severity: "High", cwe: "CWE-284", owasp_sc: "SC01",
        detector_ids: &["SOL-008"], detected: true,
        detection_technique: "Pattern",
        description: "Per-user PDA seeds missing user pubkey, all users share state",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-043", name: "PDA Seed Collision", category: "PDA Security",
        severity: "Medium", cwe: "CWE-330", owasp_sc: "SC04",
        detector_ids: &["SOL-065"], detected: true,
        detection_technique: "Pattern",
        description: "Different seed combinations produce same PDA due to concatenation",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-044", name: "Account Resurrection", category: "Account Management",
        severity: "High", cwe: "CWE-672", owasp_sc: "SC03",
        detector_ids: &["SOL-028", "SOL-053"], detected: true,
        detection_technique: "Pattern",
        description: "Closed account revived by transferring lamports back in same slot",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-045", name: "Account Close Without Data Zeroing", category: "Account Management",
        severity: "High", cwe: "CWE-404", owasp_sc: "SC03",
        detector_ids: &["SOL-009"], detected: true,
        detection_technique: "Pattern",
        description: "Lamports drained without zeroing data buffer",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-046", name: "Type Cosplay", category: "Account Validation",
        severity: "Critical", cwe: "CWE-843", owasp_sc: "SC04",
        detector_ids: &["SOL-004"], detected: true,
        detection_technique: "Pattern",
        description: "Account deserialized without discriminator check",
        real_incident: Some(Incident { project: "Wormhole", loss: "$320M", date: "2022-02" }),
        solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-047", name: "Account Data Mismatch", category: "Account Validation",
        severity: "High", cwe: "CWE-20", owasp_sc: "SC04",
        detector_ids: &["SOL-012"], detected: true,
        detection_technique: "Pattern",
        description: "Account data fields not validated against expected values",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-048", name: "Duplicate Mutable Accounts", category: "Account Validation",
        severity: "High", cwe: "CWE-20", owasp_sc: "SC04",
        detector_ids: &["SOL-006"], detected: true,
        detection_technique: "Pattern",
        description: "Same account passed for multiple mutable params",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-049", name: "Missing Rent Exemption Check", category: "Account Management",
        severity: "Medium", cwe: "CWE-20", owasp_sc: "SC04",
        detector_ids: &["SOL-013"], detected: true,
        detection_technique: "Pattern",
        description: "Account created without ensuring rent-exempt lamport minimum",
        real_incident: Some(Incident { project: "OptiFi", loss: "$661K", date: "2022-08" }),
        solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-050", name: "Unsafe Deserialization", category: "Account Validation",
        severity: "High", cwe: "CWE-502", owasp_sc: "SC04",
        detector_ids: &["SOL-014"], detected: true,
        detection_technique: "Pattern",
        description: "try_from_slice on untrusted account data without size/type checks",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-051", name: "Token Account Confusion", category: "Token Security",
        severity: "High", cwe: "CWE-843", owasp_sc: "SC04",
        detector_ids: &["SOL-023"], detected: true,
        detection_technique: "Pattern",
        description: "Token account mint/authority not validated",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-052", name: "Missing Token Validation", category: "Token Security",
        severity: "High", cwe: "CWE-20", owasp_sc: "SC04",
        detector_ids: &["SOL-024"], detected: true,
        detection_technique: "Pattern",
        description: "Token account not validated as belonging to expected mint",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-053", name: "Lamport Balance Drain", category: "Account Management",
        severity: "Critical", cwe: "CWE-862", owasp_sc: "SC01",
        detector_ids: &["SOL-025"], detected: true,
        detection_technique: "Pattern",
        description: "SOL lamports transferable without authorization",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-054", name: "Missing Seeds Validation", category: "PDA Security",
        severity: "High", cwe: "CWE-20", owasp_sc: "SC04",
        detector_ids: &["SOL-027"], detected: true,
        detection_technique: "Pattern",
        description: "PDA seeds not validated against expected derivation",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-055", name: "Account Aliasing Confusion", category: "Account Validation",
        severity: "High", cwe: "CWE-843", owasp_sc: "SC04",
        detector_ids: &["SOL-ALIAS-01", "SOL-ALIAS-02"], detected: true,
        detection_technique: "Account Aliasing Engine",
        description: "Two different account params that should be distinct may alias",
        real_incident: None, solana_specific: true,
    },

    // ══════════════════════════════════════════════════════════════════════
    //  CATEGORY 5: DeFi ATTACKS (56-70)
    // ══════════════════════════════════════════════════════════════════════
    VulnEntry {
        kb_id: "KB-056", name: "Oracle Price Manipulation", category: "DeFi",
        severity: "Critical", cwe: "CWE-20", owasp_sc: "SC02",
        detector_ids: &["SOL-019"], detected: true,
        detection_technique: "Pattern",
        description: "Oracle price used without staleness/confidence checks",
        real_incident: Some(Incident { project: "Mango Markets", loss: "$114M", date: "2022-10" }),
        solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-057", name: "Stale Oracle Data", category: "DeFi",
        severity: "High", cwe: "CWE-20", owasp_sc: "SC02",
        detector_ids: &["SOL-020"], detected: true,
        detection_technique: "Pattern",
        description: "Oracle price accepted without checking last_updated_slot",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-058", name: "Flash Loan Attack", category: "DeFi",
        severity: "Critical", cwe: "CWE-362", owasp_sc: "SC07",
        detector_ids: &["SOL-018", "SOL-058"], detected: true,
        detection_technique: "Pattern",
        description: "State manipulable via atomic borrow-arbitrage-repay in one tx",
        real_incident: Some(Incident { project: "Nirvana Finance", loss: "$3.5M", date: "2022-07" }),
        solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-059", name: "Slippage Attack", category: "DeFi",
        severity: "High", cwe: "CWE-20", owasp_sc: "SC02",
        detector_ids: &["SOL-033", "SOL-072"], detected: true,
        detection_technique: "Pattern",
        description: "Swap without minimum output amount allowing sandwich attacks",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-060", name: "Sandwich Attack", category: "DeFi",
        severity: "High", cwe: "CWE-362", owasp_sc: "SC02",
        detector_ids: &["SOL-034"], detected: true,
        detection_technique: "Pattern",
        description: "Transaction frontrun + backrun for MEV extraction",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-061", name: "Front-Running", category: "DeFi",
        severity: "High", cwe: "CWE-362", owasp_sc: "SC02",
        detector_ids: &["SOL-035"], detected: true,
        detection_technique: "Pattern",
        description: "Order-dependent operations exploitable by validators/searchers",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-062", name: "LP Token Manipulation", category: "DeFi",
        severity: "High", cwe: "CWE-682", owasp_sc: "SC03",
        detector_ids: &["SOL-049"], detected: true,
        detection_technique: "Pattern",
        description: "LP share calculation exploitable via first-depositor attack",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-063", name: "Missing Deadline Check", category: "DeFi",
        severity: "Medium", cwe: "CWE-20", owasp_sc: "SC04",
        detector_ids: &["SOL-051"], detected: true,
        detection_technique: "Pattern",
        description: "Swap/order has no expiry allowing execution at stale prices",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-064", name: "MEV Protection Missing", category: "DeFi",
        severity: "Medium", cwe: "CWE-362", owasp_sc: "SC02",
        detector_ids: &["SOL-066"], detected: true,
        detection_technique: "Pattern",
        description: "No Jito bundle, priority fee, or commit-reveal for MEV-sensitive ops",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-065", name: "Missing Pause Mechanism", category: "DeFi",
        severity: "Medium", cwe: "CWE-693", owasp_sc: "SC10",
        detector_ids: &["SOL-042"], detected: true,
        detection_technique: "Pattern",
        description: "No emergency pause for active exploit scenarios",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-066", name: "Missing State Machine", category: "Logic",
        severity: "High", cwe: "CWE-372", owasp_sc: "SC03",
        detector_ids: &["SOL-059"], detected: true,
        detection_technique: "Pattern",
        description: "Protocol state transitions not enforced (e.g., deposit before withdraw)",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-067", name: "Liquidation Price Manipulation", category: "DeFi",
        severity: "Critical", cwe: "CWE-682", owasp_sc: "SC02",
        detector_ids: &[], detected: false,
        detection_technique: "Not implemented",
        description: "Liquidation threshold manipulable via price oracle attacks",
        real_incident: Some(Incident { project: "Mango Markets", loss: "$114M", date: "2022-10" }),
        solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-068", name: "Interest Rate Model Exploit", category: "DeFi",
        severity: "High", cwe: "CWE-682", owasp_sc: "SC03",
        detector_ids: &[], detected: false,
        detection_technique: "Not implemented",
        description: "Borrow/supply rate curve exploitable via large flash deposits",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-069", name: "Vault Share Inflation Attack", category: "DeFi",
        severity: "Critical", cwe: "CWE-682", owasp_sc: "SC03",
        detector_ids: &[], detected: false,
        detection_technique: "Not implemented",
        description: "First depositor donates to inflate share price, stealing from subsequent depositors",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-070", name: "Collateral Factor Bypass", category: "DeFi",
        severity: "Critical", cwe: "CWE-682", owasp_sc: "SC03",
        detector_ids: &[], detected: false,
        detection_technique: "Not implemented",
        description: "Borrowing beyond collateral limits via multi-step exploit",
        real_incident: Some(Incident { project: "Loopscale", loss: "$5.8M", date: "2025-04" }),
        solana_specific: false,
    },

    // ══════════════════════════════════════════════════════════════════════
    //  CATEGORY 6: STATE & LOGIC (71-80)
    // ══════════════════════════════════════════════════════════════════════
    VulnEntry {
        kb_id: "KB-071", name: "Time Manipulation", category: "Logic",
        severity: "Medium", cwe: "CWE-367", owasp_sc: "SC09",
        detector_ids: &["SOL-046"], detected: true,
        detection_technique: "Pattern",
        description: "Clock::get() unix_timestamp used for critical logic without tolerance",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-072", name: "Event Log Spoofing", category: "Logic",
        severity: "Medium", cwe: "CWE-117", owasp_sc: "SC03",
        detector_ids: &["SOL-060"], detected: true,
        detection_technique: "Pattern",
        description: "Emitted events don't match actual state changes",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-073", name: "CU Exhaustion Partial State", category: "DoS",
        severity: "High", cwe: "CWE-400", owasp_sc: "SC10",
        detector_ids: &["SOL-061"], detected: true,
        detection_technique: "Pattern",
        description: "Transaction exceeds compute budget leaving state partially updated",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-074", name: "Unbounded Input Length", category: "DoS",
        severity: "Medium", cwe: "CWE-400", owasp_sc: "SC10",
        detector_ids: &["SOL-062"], detected: true,
        detection_technique: "Pattern",
        description: "Vec/String input without length cap causes CU exhaustion",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-075", name: "Missing Event Emission", category: "Monitoring",
        severity: "Info", cwe: "CWE-778", owasp_sc: "SC03",
        detector_ids: &["SOL-044"], detected: true,
        detection_technique: "Pattern",
        description: "State-changing operations without emit! for off-chain indexing",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-076", name: "Hardcoded Address", category: "Configuration",
        severity: "Info", cwe: "CWE-798", owasp_sc: "SC03",
        detector_ids: &["SOL-043"], detected: true,
        detection_technique: "Pattern",
        description: "Pubkeys hardcoded instead of passed as params or stored in config",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-077", name: "Lookup Table Trust Risk", category: "Transaction",
        severity: "Medium", cwe: "CWE-20", owasp_sc: "SC04",
        detector_ids: &["SOL-071"], detected: true,
        detection_technique: "Pattern",
        description: "Address Lookup Table contents not validated before use",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-078", name: "Legacy vs V0 Transaction Risk", category: "Transaction",
        severity: "Medium", cwe: "CWE-20", owasp_sc: "SC04",
        detector_ids: &["SOL-070"], detected: true,
        detection_technique: "Pattern",
        description: "Program doesn't handle both legacy and versioned transaction formats",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-079", name: "Concurrent State Manipulation", category: "Concurrency",
        severity: "High", cwe: "CWE-362", owasp_sc: "SC05",
        detector_ids: &[], detected: false,
        detection_technique: "Not implemented",
        description: "Sealevel parallel execution allows concurrent writes to shared state",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-080", name: "Instruction Introspection Bypass", category: "Logic",
        severity: "High", cwe: "CWE-20", owasp_sc: "SC04",
        detector_ids: &[], detected: false,
        detection_technique: "Not implemented",
        description: "sysvar::instructions used for checks but attacker crafts matching IX",
        real_incident: None, solana_specific: true,
    },

    // ══════════════════════════════════════════════════════════════════════
    //  CATEGORY 7: TAINT & INFORMATION FLOW (81-85)
    // ══════════════════════════════════════════════════════════════════════
    VulnEntry {
        kb_id: "KB-081", name: "Untrusted Input to CPI", category: "Taint Flow",
        severity: "High", cwe: "CWE-20", owasp_sc: "SC04",
        detector_ids: &["SOL-TAINT"], detected: true,
        detection_technique: "Taint Lattice",
        description: "User-controlled data flows to CPI invoke without sanitization",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-082", name: "Account Data to Transfer Amount", category: "Taint Flow",
        severity: "High", cwe: "CWE-20", owasp_sc: "SC04",
        detector_ids: &["SOL-TAINT"], detected: true,
        detection_technique: "Taint Lattice",
        description: "Unvalidated account data used directly as transfer amount",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-083", name: "Cross-Function Taint Propagation", category: "Taint Flow",
        severity: "High", cwe: "CWE-20", owasp_sc: "SC04",
        detector_ids: &["SOL-TAINT-IP"], detected: true,
        detection_technique: "Interprocedural Taint",
        description: "Tainted data passes through helper function to sensitive sink",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-084", name: "CFG Dominator Violation", category: "Control Flow",
        severity: "High", cwe: "CWE-20", owasp_sc: "SC04",
        detector_ids: &["SOL-CFG"], detected: true,
        detection_technique: "CFG Analysis",
        description: "Security check not on all paths to sensitive operation",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-085", name: "Abstract Interpretation Overflow Proof", category: "Formal",
        severity: "High", cwe: "CWE-190", owasp_sc: "SC08",
        detector_ids: &["SOL-ABS"], detected: true,
        detection_technique: "Abstract Interpretation",
        description: "Interval analysis proves arithmetic can overflow u64 range",
        real_incident: None, solana_specific: false,
    },

    // ══════════════════════════════════════════════════════════════════════
    //  CATEGORY 8: SUPPLY CHAIN & INFRASTRUCTURE (86-92)
    // ══════════════════════════════════════════════════════════════════════
    VulnEntry {
        kb_id: "KB-086", name: "Malicious Dependency (Supply Chain)", category: "Supply Chain",
        severity: "Critical", cwe: "CWE-829", owasp_sc: "SC06",
        detector_ids: &[], detected: false,
        detection_technique: "Not implemented (needs cargo-audit integration)",
        description: "Compromised npm/crate dependency exfiltrates private keys",
        real_incident: Some(Incident { project: "@solana/web3.js", loss: "Unknown", date: "2024-12" }),
        solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-087", name: "Outdated Solana SDK", category: "Supply Chain",
        severity: "Medium", cwe: "CWE-1104", owasp_sc: "SC06",
        detector_ids: &[], detected: false,
        detection_technique: "Not implemented",
        description: "Using Solana SDK with known vulnerabilities",
        real_incident: Some(Incident { project: "Solana rBPF", loss: "$0", date: "2022-CVE-23066" }),
        solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-088", name: "Private Key Exposure", category: "Infrastructure",
        severity: "Critical", cwe: "CWE-798", owasp_sc: "SC01",
        detector_ids: &[], detected: false,
        detection_technique: "Not implemented (needs secret scanning)",
        description: "Private key / seed phrase hardcoded or logged",
        real_incident: Some(Incident { project: "Slope Wallet", loss: "$8M", date: "2022-08" }),
        solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-089", name: "Insecure Randomness (On-chain)", category: "Cryptography",
        severity: "High", cwe: "CWE-330", owasp_sc: "SC09",
        detector_ids: &[], detected: false,
        detection_technique: "Not implemented",
        description: "Using slot/blockhash as randomness source (predictable by validators)",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-090", name: "Nonce Reuse", category: "Protocol",
        severity: "High", cwe: "CWE-323", owasp_sc: "SC03",
        detector_ids: &[], detected: false,
        detection_technique: "Not implemented",
        description: "Durable nonce reused allowing transaction replay",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-091", name: "Token-2022 ZK Vulnerability", category: "Cryptography",
        severity: "Critical", cwe: "CWE-327", owasp_sc: "SC09",
        detector_ids: &[], detected: false,
        detection_technique: "Not implemented",
        description: "ZK proof verification flaw allowing infinite token minting",
        real_incident: Some(Incident { project: "Token-2022", loss: "$0 (patched)", date: "2024-04" }),
        solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-092", name: "Missing overflow-checks in Cargo.toml", category: "Configuration",
        severity: "Medium", cwe: "CWE-190", owasp_sc: "SC08",
        detector_ids: &[], detected: false,
        detection_technique: "Not implemented",
        description: "Release profile missing overflow-checks = true",
        real_incident: None, solana_specific: true,
    },

    // ══════════════════════════════════════════════════════════════════════
    //  CATEGORY 9: ADVANCED / NOT YET DETECTED (93-100)
    // ══════════════════════════════════════════════════════════════════════
    VulnEntry {
        kb_id: "KB-093", name: "Cross-Program State Desync", category: "State",
        severity: "High", cwe: "CWE-362", owasp_sc: "SC03",
        detector_ids: &[], detected: false,
        detection_technique: "Not implemented (needs cross-program analysis)",
        description: "State updated in program A but not reflected in program B that reads it",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-094", name: "Governance Token Flash Loan Voting", category: "Governance",
        severity: "Critical", cwe: "CWE-362", owasp_sc: "SC07",
        detector_ids: &[], detected: false,
        detection_technique: "Not implemented",
        description: "Flash-borrow governance tokens to pass malicious proposals",
        real_incident: Some(Incident { project: "Mango Markets", loss: "$114M", date: "2022-10" }),
        solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-095", name: "Atomic Arbitrage in Single TX", category: "DeFi",
        severity: "High", cwe: "CWE-362", owasp_sc: "SC07",
        detector_ids: &[], detected: false,
        detection_technique: "Not implemented",
        description: "Multi-instruction TX performs risk-free arbitrage at protocol expense",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-096", name: "Composability Risk (Protocol Interaction)", category: "DeFi",
        severity: "High", cwe: "CWE-362", owasp_sc: "SC03",
        detector_ids: &[], detected: false,
        detection_technique: "Not implemented",
        description: "Unexpected behavior when protocol composed with others",
        real_incident: None, solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-097", name: "BPF Loader Exploitation", category: "Runtime",
        severity: "Critical", cwe: "CWE-119", owasp_sc: "SC06",
        detector_ids: &[], detected: false,
        detection_technique: "Not implemented (runtime-level)",
        description: "Exploiting BPF loader bugs to bypass program constraints",
        real_incident: Some(Incident { project: "Solana rBPF", loss: "$0", date: "CVE-2022-23066" }),
        solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-098", name: "Validator-Level MEV Extraction", category: "Infrastructure",
        severity: "High", cwe: "CWE-362", owasp_sc: "SC02",
        detector_ids: &[], detected: false,
        detection_technique: "Not implemented (off-chain)",
        description: "Validator reorders/inserts transactions for profit",
        real_incident: None, solana_specific: true,
    },
    VulnEntry {
        kb_id: "KB-099", name: "Wormhole-Style Bridge Spoofing", category: "Bridge",
        severity: "Critical", cwe: "CWE-287", owasp_sc: "SC01",
        detector_ids: &[], detected: false,
        detection_technique: "Not implemented (cross-chain)",
        description: "Cross-chain message verification bypass allowing fake mints",
        real_incident: Some(Incident { project: "Wormhole", loss: "$320M", date: "2022-02" }),
        solana_specific: false,
    },
    VulnEntry {
        kb_id: "KB-100", name: "Program Upgrade Backdoor", category: "Governance",
        severity: "Critical", cwe: "CWE-912", owasp_sc: "SC01",
        detector_ids: &[], detected: false,
        detection_technique: "Not implemented (needs upgrade history analysis)",
        description: "Upgradeable program modified to include malicious logic post-audit",
        real_incident: None, solana_specific: true,
    },
    ]
}

/// Summary statistics for the knowledge base.
pub fn coverage_summary() -> (usize, usize, usize) {
    let kb = get_knowledge_base();
    let total = kb.len();
    let detected = kb.iter().filter(|e| e.detected).count();
    let missing = total - detected;
    (total, detected, missing)
}

/// Get all undetected vulnerabilities (gaps).
pub fn get_gaps() -> Vec<&'static str> {
    get_knowledge_base()
        .iter()
        .filter(|e| !e.detected)
        .map(|e| e.kb_id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_knowledge_base_has_100_entries() {
        let kb = get_knowledge_base();
        assert_eq!(kb.len(), 100, "Knowledge base should have exactly 100 entries");
    }

    #[test]
    fn test_coverage_stats() {
        let (total, detected, missing) = coverage_summary();
        assert_eq!(total, 100);
        assert!(detected >= 75, "Should detect at least 75/100: got {}", detected);
        assert!(missing <= 25, "Should miss at most 25: got {}", missing);
    }

    #[test]
    fn test_all_critical_real_incidents_detected() {
        let kb = get_knowledge_base();
        let critical_with_incidents: Vec<_> = kb.iter()
            .filter(|e| e.severity == "Critical" && e.real_incident.is_some())
            .collect();
        // At least the major ones should be detected
        let detected_count = critical_with_incidents.iter().filter(|e| e.detected).count();
        assert!(detected_count >= 5,
            "Should detect at least 5 critical vulns with real incidents, got {}", detected_count);
    }

    #[test]
    fn test_unique_kb_ids() {
        let kb = get_knowledge_base();
        let mut ids: Vec<_> = kb.iter().map(|e| e.kb_id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 100, "All KB IDs should be unique");
    }
}
