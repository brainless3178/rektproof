//! # Account Aliasing & Confusion Analysis
//!
//! Detects **account confusion** and **aliasing** attacks specific to Solana
//! programs. These are among the most common real-world Solana exploits.
//!
//! ## Mathematical Foundation
//!
//! **Must-Not-Alias Analysis**: For each pair of account parameters (a, b),
//! prove that `a.key() ≠ b.key()` holds for all valid inputs. If not provable,
//! an attacker can pass the same account twice, corrupting state.
//!
//! Formally, let `A = {a₁, a₂, ..., aₙ}` be the set of account parameters.
//! For each pair `(aᵢ, aⱼ)` where `i ≠ j`:
//!
//! ```text
//! Does there exist a constraint C such that C ⊨ key(aᵢ) ≠ key(aⱼ)?
//! ```
//!
//! If no such constraint exists, the pair is **vulnerable to aliasing**.
//!
//! ## What This Finds
//!
//! 1. **Account Substitution** — Same account passed as two different parameters
//!    (e.g., source and destination in a transfer are the same account)
//! 2. **Missing Discriminator Checks** — Account data interpreted as wrong type
//! 3. **Token Account Confusion** — Different token mint accounts are not verified
//! 4. **Authority Spoofing** — Authority account not verified against expected key
//! 5. **Program ID Substitution** — Wrong program passed to CPI
//!
//! ## Real-World Incidents
//!
//! - **Wormhole Bridge ($320M)**: Missing signer verification + account substitution
//! - **Cashio ($52M)**: Token mint confusion - unchecked collateral token mint
//! - **Crema Finance ($8.8M)**: Account aliasing in liquidity operations

use crate::VulnerabilityFinding;
use quote::ToTokens;
use syn::{Item, ItemStruct, Field};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Account Parameter Model
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Represents an account parameter in an instruction.
#[derive(Debug, Clone)]
pub struct AccountParam {
    pub name: String,
    pub account_type: AccountType,
    pub constraints: Vec<AccountConstraint>,
    pub line: usize,
    pub is_mutable: bool,
    pub is_signer: bool,
}

/// Classification of account types
#[derive(Debug, Clone, PartialEq)]
pub enum AccountType {
    /// Anchor `Account<'info, T>` — typed, has discriminator
    TypedAccount(String),
    /// `AccountInfo<'info>` — raw, no type safety
    RawAccountInfo,
    /// `Signer<'info>` — verified signer
    Signer,
    /// `Program<'info, T>` — verified program identity
    Program(String),
    /// `SystemAccount<'info>` — system-owned
    SystemAccount,
    /// `UncheckedAccount<'info>` — explicitly unchecked
    UncheckedAccount,
    /// `TokenAccount` or `token::TokenAccount`
    TokenAccount,
    /// `Mint` — token mint account
    Mint,
    /// Unknown type
    Unknown(String),
}

/// Constraints applied to an account
#[derive(Debug, Clone)]
pub struct AccountConstraint {
    pub kind: ConstraintKind,
    pub raw: String,
}

/// Types of account constraints in Anchor
#[derive(Debug, Clone, PartialEq)]
pub enum ConstraintKind {
    /// `has_one = authority` — verifies field matches
    HasOne(String),
    /// `seeds = [...]` — PDA derivation
    Seeds,
    /// `constraint = ...` — arbitrary constraint
    CustomConstraint,
    /// `address = ...` — fixed address check
    Address,
    /// `owner = ...` — program owner check
    Owner,
    /// `token::mint = ...` — token mint check
    TokenMint(String),
    /// `token::authority = ...` — token authority check
    TokenAuthority(String),
    /// `init` — account initialization
    Init,
    /// `close = ...` — close destination
    Close,
    /// `mut` — mutable
    Mutable,
    /// `signer` — signer verification
    SignerConstraint,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Alias Analysis
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Result of alias analysis
#[derive(Debug)]
pub struct AliasAnalysisResult {
    pub struct_name: String,
    pub accounts: Vec<AccountParam>,
    pub aliasing_pairs: Vec<AliasingPair>,
    pub findings: Vec<VulnerabilityFinding>,
}

/// A pair of accounts that may alias
#[derive(Debug, Clone)]
pub struct AliasingPair {
    pub account_a: String,
    pub account_b: String,
    pub reason: String,
    pub severity: u8,
}

/// Run account aliasing analysis on source code
pub fn analyze_account_aliasing(source: &str, filename: &str) -> Vec<AliasAnalysisResult> {
    let lines: Vec<&str> = source.lines().collect();
    let ast = match syn::parse_file(source) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    let mut results = Vec::new();

    for item in &ast.items {
        // Find account structs (Anchor #[derive(Accounts)])
        if let Item::Struct(s) = item {
            if is_accounts_struct(s) {
                let result = analyze_accounts_struct(s, &lines, filename);
                results.push(result);
            }
        }
    }

    results
}

/// Check if a struct is an Anchor accounts struct
fn is_accounts_struct(s: &ItemStruct) -> bool {
    s.attrs.iter().any(|attr| {
        let attr_str = attr.to_token_stream().to_string();
        attr_str.contains("Accounts") || attr_str.contains("account")
    })
}

/// Analyze an accounts struct for aliasing vulnerabilities
fn analyze_accounts_struct(
    s: &ItemStruct,
    lines: &[&str],
    filename: &str,
) -> AliasAnalysisResult {
    let struct_name = s.ident.to_string();
    let mut accounts = Vec::new();
    let mut findings = Vec::new();

    // Parse each field into an AccountParam
    let fields: Vec<&Field> = match &s.fields {
        syn::Fields::Named(n) => n.named.iter().collect(),
        _ => vec![],
    };

    for field in &fields {
        let param = parse_account_field(field);
        accounts.push(param);
    }

    // ── Check 1: Must-Not-Alias Analysis ──────────────────────────────

    let aliasing_pairs = check_aliasing(&accounts);

    for pair in &aliasing_pairs {
        let severity = if pair.severity >= 4 { "CRITICAL" } else { "HIGH" };
        findings.push(VulnerabilityFinding {
            category: "Account Safety".into(),
            vuln_type: "Potential Account Aliasing".into(),
            severity: pair.severity,
            severity_label: severity.into(),
            id: "SOL-ALIAS-01".into(),
            cwe: Some("CWE-706".into()),
            location: filename.to_string(),
            function_name: struct_name.clone(),
            line_number: accounts.iter()
                .find(|a| a.name == pair.account_a)
                .map_or(0, |a| a.line),
            vulnerable_code: format!(
                "Both `{}` and `{}` can be the same account",
                pair.account_a, pair.account_b,
            ),
            description: format!(
                "Must-Not-Alias analysis in `{}`: accounts `{}` and `{}` \
                 have no constraint preventing them from being the same account. \
                 {}",
                struct_name, pair.account_a, pair.account_b, pair.reason,
            ),
            attack_scenario: format!(
                "An attacker passes the same account as both `{}` and `{}`. \
                 If the instruction reads from one and writes to the other, \
                 it may compute incorrect results (e.g., self-transfer \
                 doubles the balance).",
                pair.account_a, pair.account_b,
            ),
            real_world_incident: Some(crate::Incident {
                project: "Crema Finance".into(),
                loss: "$8.8M".into(),
                date: "2022-07-02".into(),
            }),
            secure_fix: format!(
                "Add a constraint: `#[account(constraint = {}.key() != {}.key())]` \
                 or use Anchor's `#[account(has_one = ...)]` to link accounts.",
                pair.account_a, pair.account_b,
            ),
            confidence: 68,
            prevention: "Verify all account pairs that should be distinct.".into(),
        });
    }

    // ── Check 2: Raw AccountInfo Usage ────────────────────────────────
    // Only flag raw AccountInfo fields that have NO constraints and NO
    // safety comments.  Fields with has_one, address, owner, seeds, or
    // CHECK comments are intentionally raw — the developer validated
    // manually or via data constraints.

    for account in &accounts {
        if account.account_type == AccountType::RawAccountInfo {
            // Skip if the field has meaningful constraints
            let has_meaningful_constraint = account.constraints.iter().any(|c| {
                matches!(
                    c.kind,
                    ConstraintKind::HasOne(_)
                        | ConstraintKind::Seeds
                        | ConstraintKind::Address
                        | ConstraintKind::Owner
                        | ConstraintKind::CustomConstraint
                        | ConstraintKind::Close
                )
            });
            if has_meaningful_constraint {
                continue;
            }

            // Skip if preceded by a `/// CHECK:` safety comment
            let has_check_comment = if account.line > 0 && account.line <= lines.len() {
                (1..=3).any(|offset| {
                    let check_line = account.line.saturating_sub(offset);
                    check_line > 0 && check_line <= lines.len()
                        && lines[check_line - 1].contains("CHECK")
                })
            } else {
                false
            };
            if has_check_comment {
                continue;
            }

            // Skip if the field is the target of another account's has_one
            // (e.g., `has_one = authority` means authority is a data field,
            // not a permissioning account — the caller's ownership is proven
            // by the data match, not by signing).
            let is_has_one_target = accounts.iter().any(|other| {
                other.name != account.name
                    && other.constraints.iter().any(|c| {
                        matches!(&c.kind, ConstraintKind::HasOne(target) if target == &account.name)
                    })
            });
            if is_has_one_target {
                continue;
            }

            findings.push(VulnerabilityFinding {
                category: "Account Safety".into(),
                vuln_type: "Raw AccountInfo Without Type Safety".into(),
                severity: 4,
                severity_label: "HIGH".into(),
                id: "SOL-ALIAS-02".into(),
                cwe: Some("CWE-704".into()),
                location: filename.to_string(),
                function_name: struct_name.clone(),
                line_number: account.line,
                vulnerable_code: format!(
                    "pub {}: AccountInfo<'info>", account.name,
                ),
                description: format!(
                    "Account `{}` in `{}` uses raw `AccountInfo` which provides \
                     no type safety or discriminator checking. The account data \
                     can contain anything — including data from a completely \
                     different program.",
                    account.name, struct_name,
                ),
                attack_scenario: format!(
                    "Attacker creates an account with crafted data that mimics \
                     the expected layout. Without discriminator checking, the \
                     program interprets this data as valid, leading to \
                     unauthorized operations.",
                ),
                real_world_incident: Some(crate::Incident {
                    project: "Wormhole Bridge".into(),
                    loss: "$320M".into(),
                    date: "2022-02-02".into(),
                }),
                secure_fix: format!(
                    "Replace `AccountInfo` with a typed Anchor account: \
                     `Account<'info, YourType>` which automatically validates \
                     the discriminator and owner.",
                ),
                confidence: 72,
                prevention: "Always use typed accounts with discriminator validation.".into(),
            });
        }
    }

    // ── Check 3: UncheckedAccount Usage ───────────────────────────────

    for account in &accounts {
        if account.account_type == AccountType::UncheckedAccount {
            // Check if there's a CHECK comment (Anchor requirement)
            let has_check_comment = if account.line > 0 && account.line <= lines.len() {
                // Look at preceding lines for /// CHECK:
                (1..=3).any(|offset| {
                    let check_line = account.line.saturating_sub(offset);
                    check_line > 0 && check_line <= lines.len()
                        && lines[check_line - 1].contains("CHECK")
                })
            } else {
                false
            };

            if !has_check_comment {
                findings.push(VulnerabilityFinding {
                    category: "Account Safety".into(),
                    vuln_type: "UncheckedAccount Without CHECK Comment".into(),
                    severity: 4,
                    severity_label: "HIGH".into(),
                    id: "SOL-ALIAS-03".into(),
                    cwe: Some("CWE-345".into()),
                    location: filename.to_string(),
                    function_name: struct_name.clone(),
                    line_number: account.line,
                    vulnerable_code: format!(
                        "pub {}: UncheckedAccount<'info>", account.name,
                    ),
                    description: format!(
                        "Account `{}` is an `UncheckedAccount` without a `/// CHECK:` \
                         comment explaining why it's safe. This is a security risk \
                         and will cause Anchor build to fail in production.",
                        account.name,
                    ),
                    attack_scenario: "Without validation, any account can be passed \
                         for this parameter. An attacker can substitute a malicious \
                         account.".into(),
                    real_world_incident: None,
                    secure_fix: "Either add `/// CHECK: reason` or replace with a \
                         typed account.".into(),
                    confidence: 80,
                    prevention: "Validate or type-check all accounts.".into(),
                });
            }
        }
    }

    // ── Check 4: Token Account Mint Verification ─────────────────────

    let token_accounts: Vec<_> = accounts.iter()
        .filter(|a| a.account_type == AccountType::TokenAccount)
        .collect();

    for ta in &token_accounts {
        let has_mint_check = ta.constraints.iter().any(|c| {
            matches!(c.kind, ConstraintKind::TokenMint(_))
        });

        if !has_mint_check {
            findings.push(VulnerabilityFinding {
                category: "Account Safety".into(),
                vuln_type: "Token Account Without Mint Verification".into(),
                severity: 5,
                severity_label: "CRITICAL".into(),
                id: "SOL-ALIAS-04".into(),
                cwe: Some("CWE-345".into()),
                location: filename.to_string(),
                function_name: struct_name.clone(),
                line_number: ta.line,
                vulnerable_code: format!(
                    "pub {}: Account<'info, TokenAccount>", ta.name,
                ),
                description: format!(
                    "Token account `{}` in `{}` has no `token::mint` constraint. \
                     An attacker can pass a token account with a different mint, \
                     enabling cross-token confusion attacks.",
                    ta.name, struct_name,
                ),
                attack_scenario: "Attacker creates a token account with a worthless \
                     custom mint and passes it as the expected token account. The \
                     program processes it as if it were the real token, allowing \
                     the attacker to trade worthless tokens for real ones.".into(),
                real_world_incident: Some(crate::Incident {
                    project: "Cashio".into(),
                    loss: "$52M".into(),
                    date: "2022-03-23".into(),
                }),
                secure_fix: format!(
                    "Add `#[account(token::mint = expected_mint)]` constraint to `{}`.",
                    ta.name,
                ),
                confidence: 75,
                prevention: "Always verify token account mints match expected values.".into(),
            });
        }
    }

    // ── Check 5: Missing Signer on Authority Accounts ────────────────
    //
    // An authority-named field ("authority", "admin", "owner") is only a
    // REAL vulnerability if it's the account that GRANTS permission.
    //
    // FALSE POSITIVE conditions (skip the finding):
    //  a) The struct already has a SEPARATE Signer<'info> field — the
    //     authority field is a data-matching target, not the permissioner.
    //  b) Another account in the struct has `has_one = <this_field>` —
    //     meaning it's validated via data constraint, not signing.
    //  c) The field has an `address = ...` constraint (checked by key).
    //  d) The field has a `close = ...` usage (receives lamports, not
    //     a permissioning role).
    //  e) The field has a CHECK comment above it.

    // Pre-compute: does this struct have any other Signer account?
    let struct_has_signer = accounts.iter().any(|a| {
        a.account_type == AccountType::Signer || a.is_signer
    });

    for account in &accounts {
        let name_lower = account.name.to_lowercase();
        if (name_lower.contains("authority") || name_lower.contains("admin")
            || name_lower.contains("owner"))
            && !account.is_signer
            && account.account_type != AccountType::Signer
        {
            // (a) If the struct has a separate Signer AND this field is
            //     referenced by `has_one` from another account, it's a
            //     data field, not a permissioning account.
            let is_has_one_target = accounts.iter().any(|other| {
                other.name != account.name
                    && other.constraints.iter().any(|c| {
                        matches!(&c.kind, ConstraintKind::HasOne(target) if target == &account.name)
                    })
            });
            if struct_has_signer && is_has_one_target {
                continue;
            }

            // (b) Even without companion Signer, if the field itself is
            //     ONLY used as `close = authority` target (lamport
            //     refund destination), it's not permissioning.
            let is_close_target = accounts.iter().any(|other| {
                other.constraints.iter().any(|c| {
                    matches!(&c.kind, ConstraintKind::Close)
                        && c.raw.contains(&account.name)
                })
            });
            // If it's ONLY a close target and has_one target, skip.
            if is_has_one_target && is_close_target {
                continue;
            }

            // (c) Field has address constraint — keyed, not a signer issue
            let has_address = account.constraints.iter().any(|c| {
                matches!(c.kind, ConstraintKind::Address)
            });
            if has_address {
                continue;
            }

            // (d) Field has a CHECK comment
            let has_check_comment = if account.line > 0 && account.line <= lines.len() {
                (1..=3).any(|offset| {
                    let check_line = account.line.saturating_sub(offset);
                    check_line > 0 && check_line <= lines.len()
                        && lines[check_line - 1].contains("CHECK")
                })
            } else {
                false
            };
            if has_check_comment && (struct_has_signer || is_has_one_target) {
                continue;
            }

            // (e) Field has custom constraint validating it
            let has_custom_constraint = account.constraints.iter().any(|c| {
                matches!(c.kind, ConstraintKind::CustomConstraint)
            });
            if has_custom_constraint {
                continue;
            }

            findings.push(VulnerabilityFinding {
                category: "Authorization".into(),
                vuln_type: "Authority Account Without Signer Check".into(),
                severity: 5,
                severity_label: "CRITICAL".into(),
                id: "SOL-ALIAS-05".into(),
                cwe: Some("CWE-862".into()),
                location: filename.to_string(),
                function_name: struct_name.clone(),
                line_number: account.line,
                vulnerable_code: format!(
                    "pub {}: {}", account.name,
                    format_account_type(&account.account_type),
                ),
                description: format!(
                    "Account `{}` in `{}` has an authority-like name but is not \
                     marked as a signer and no companion signer validates it. \
                     An attacker can pass any account as the authority without \
                     proving ownership.",
                    account.name, struct_name,
                ),
                attack_scenario: "Attacker reads the authority pubkey from the program's \
                     state, then passes that pubkey as the authority account without \
                     signing the transaction with the corresponding private key.".into(),
                real_world_incident: Some(crate::Incident {
                    project: "Wormhole Bridge".into(),
                    loss: "$320M".into(),
                    date: "2022-02-02".into(),
                }),
                secure_fix: "Add `Signer<'info>` type or `#[account(signer)]` constraint.".into(),
                confidence: 78,
                prevention: "Always require signer verification for authority accounts.".into(),
            });
        }
    }

    AliasAnalysisResult {
        struct_name,
        accounts,
        aliasing_pairs,
        findings,
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Must-Not-Alias Check
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Check all pairs of accounts for potential aliasing.
///
/// Two accounts can alias if:
/// 1. They have the same type
/// 2. Neither has a `seeds` constraint (PDA ≠ PDA unless same seeds)
/// 3. No `has_one` or `constraint` links them
/// 4. At least one is mutable (read-only aliasing is less dangerous)
fn check_aliasing(accounts: &[AccountParam]) -> Vec<AliasingPair> {
    let mut pairs = Vec::new();

    for i in 0..accounts.len() {
        for j in (i + 1)..accounts.len() {
            let a = &accounts[i];
            let b = &accounts[j];

            // Skip if different types (can't alias across types)
            if !types_compatible(&a.account_type, &b.account_type) {
                continue;
            }

            // Skip if both have PDA seeds (different PDAs can't alias)
            let a_has_seeds = a.constraints.iter().any(|c| c.kind == ConstraintKind::Seeds);
            let b_has_seeds = b.constraints.iter().any(|c| c.kind == ConstraintKind::Seeds);
            if a_has_seeds && b_has_seeds {
                continue;
            }

            // Skip if there's a has_one linking them
            let linked = a.constraints.iter().any(|c| {
                matches!(&c.kind, ConstraintKind::HasOne(target) if target == &b.name)
            }) || b.constraints.iter().any(|c| {
                matches!(&c.kind, ConstraintKind::HasOne(target) if target == &a.name)
            });
            if linked {
                continue;
            }

            // Skip if neither is mutable (read-only aliasing is less dangerous)
            if !a.is_mutable && !b.is_mutable {
                continue;
            }

            // Check for explicit inequality constraint
            let has_inequality = a.constraints.iter().any(|c| {
                matches!(&c.kind, ConstraintKind::CustomConstraint)
                    && c.raw.contains(&b.name) && c.raw.contains("!=")
            }) || b.constraints.iter().any(|c| {
                matches!(&c.kind, ConstraintKind::CustomConstraint)
                    && c.raw.contains(&a.name) && c.raw.contains("!=")
            });
            if has_inequality {
                continue;
            }

            // This pair can potentially alias
            let severity = if a.is_mutable && b.is_mutable { 5 } else { 4 };
            let reason = if a.is_mutable && b.is_mutable {
                "Both accounts are mutable with the same type and no \
                 constraint preventing aliasing. Self-referential operations \
                 (e.g., transferring from an account to itself) can corrupt state."
            } else {
                "Accounts have compatible types with no aliasing constraint. \
                 While only one is mutable, reading stale data from an aliased \
                 account can still cause logic errors."
            };

            pairs.push(AliasingPair {
                account_a: a.name.clone(),
                account_b: b.name.clone(),
                reason: reason.into(),
                severity,
            });
        }
    }

    pairs
}

/// Check if two account types are compatible (could alias)
fn types_compatible(a: &AccountType, b: &AccountType) -> bool {
    match (a, b) {
        (AccountType::TypedAccount(ta), AccountType::TypedAccount(tb)) => ta == tb,
        (AccountType::RawAccountInfo, _) | (_, AccountType::RawAccountInfo) => true,
        (AccountType::UncheckedAccount, _) | (_, AccountType::UncheckedAccount) => true,
        (AccountType::TokenAccount, AccountType::TokenAccount) => true,
        (AccountType::Mint, AccountType::Mint) => true,
        _ => false,
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Parsing Helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Parse an account field into an AccountParam
fn parse_account_field(field: &Field) -> AccountParam {
    let name = field.ident.as_ref()
        .map(|i| i.to_string())
        .unwrap_or_default();

    let type_str = field.ty.to_token_stream().to_string().replace(' ', "");
    let line = token_line(field);

    let account_type = classify_account_type(&type_str);
    let constraints = parse_constraints(&field.attrs);
    let is_mutable = constraints.iter().any(|c| c.kind == ConstraintKind::Mutable);
    let is_signer = constraints.iter().any(|c| c.kind == ConstraintKind::SignerConstraint)
        || matches!(account_type, AccountType::Signer);

    AccountParam {
        name,
        account_type,
        constraints,
        line,
        is_mutable,
        is_signer,
    }
}

/// Classify the Anchor account type from a type string
fn classify_account_type(type_str: &str) -> AccountType {
    if type_str.contains("Signer") {
        AccountType::Signer
    } else if type_str.contains("Program<") {
        let inner = extract_generic_param(type_str);
        AccountType::Program(inner)
    } else if type_str.contains("SystemAccount") {
        AccountType::SystemAccount
    } else if type_str.contains("UncheckedAccount") {
        AccountType::UncheckedAccount
    } else if type_str.contains("AccountInfo") {
        AccountType::RawAccountInfo
    } else if type_str.contains("TokenAccount") {
        AccountType::TokenAccount
    } else if type_str.contains("Mint") && !type_str.contains("Account<") {
        AccountType::Mint
    } else if type_str.contains("Account<") {
        let inner = extract_generic_param(type_str);
        if inner.contains("TokenAccount") {
            AccountType::TokenAccount
        } else if inner.contains("Mint") {
            AccountType::Mint
        } else {
            AccountType::TypedAccount(inner)
        }
    } else {
        AccountType::Unknown(type_str.to_string())
    }
}

/// Extract the generic parameter from `Type<'info, Param>`
fn extract_generic_param(type_str: &str) -> String {
    if let Some(start) = type_str.find(',') {
        let rest = &type_str[start + 1..];
        if let Some(end) = rest.rfind('>') {
            return rest[..end].trim().to_string();
        }
    }
    type_str.to_string()
}

/// Parse Anchor attribute constraints from field attributes
fn parse_constraints(attrs: &[syn::Attribute]) -> Vec<AccountConstraint> {
    let mut constraints = Vec::new();

    for attr in attrs {
        let attr_str = attr.to_token_stream().to_string();

        if attr_str.contains("mut") {
            constraints.push(AccountConstraint {
                kind: ConstraintKind::Mutable,
                raw: "mut".into(),
            });
        }
        if attr_str.contains("signer") {
            constraints.push(AccountConstraint {
                kind: ConstraintKind::SignerConstraint,
                raw: "signer".into(),
            });
        }
        if attr_str.contains("init") {
            constraints.push(AccountConstraint {
                kind: ConstraintKind::Init,
                raw: "init".into(),
            });
        }
        if attr_str.contains("seeds") {
            constraints.push(AccountConstraint {
                kind: ConstraintKind::Seeds,
                raw: attr_str.clone(),
            });
        }
        if attr_str.contains("has_one") {
            // Extract the target
            if let Some(pos) = attr_str.find("has_one") {
                let rest = &attr_str[pos + 8..];
                let target = rest.trim_start_matches(|c: char| !c.is_alphanumeric())
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .next()
                    .unwrap_or("")
                    .to_string();
                constraints.push(AccountConstraint {
                    kind: ConstraintKind::HasOne(target),
                    raw: attr_str.clone(),
                });
            }
        }
        if attr_str.contains("constraint") {
            constraints.push(AccountConstraint {
                kind: ConstraintKind::CustomConstraint,
                raw: attr_str.clone(),
            });
        }
        if attr_str.contains("address") {
            constraints.push(AccountConstraint {
                kind: ConstraintKind::Address,
                raw: attr_str.clone(),
            });
        }
        if attr_str.contains("owner") {
            constraints.push(AccountConstraint {
                kind: ConstraintKind::Owner,
                raw: attr_str.clone(),
            });
        }
        if attr_str.contains("token :: mint") || attr_str.contains("token::mint") {
            let target = extract_constraint_value(&attr_str, "mint");
            constraints.push(AccountConstraint {
                kind: ConstraintKind::TokenMint(target),
                raw: attr_str.clone(),
            });
        }
        if attr_str.contains("token :: authority") || attr_str.contains("token::authority") {
            let target = extract_constraint_value(&attr_str, "authority");
            constraints.push(AccountConstraint {
                kind: ConstraintKind::TokenAuthority(target),
                raw: attr_str.clone(),
            });
        }
        if attr_str.contains("close") {
            constraints.push(AccountConstraint {
                kind: ConstraintKind::Close,
                raw: attr_str.clone(),
            });
        }
    }

    constraints
}

/// Extract the value from a constraint like `token::mint = expected_mint`
fn extract_constraint_value(attr_str: &str, key: &str) -> String {
    if let Some(pos) = attr_str.find(key) {
        let rest = &attr_str[pos + key.len()..];
        if let Some(eq_pos) = rest.find('=') {
            let value = rest[eq_pos + 1..].trim()
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .next()
                .unwrap_or("")
                .to_string();
            return value;
        }
    }
    String::new()
}

fn format_account_type(at: &AccountType) -> String {
    match at {
        AccountType::TypedAccount(t) => format!("Account<'info, {}>", t),
        AccountType::RawAccountInfo => "AccountInfo<'info>".to_string(),
        AccountType::Signer => "Signer<'info>".to_string(),
        AccountType::Program(p) => format!("Program<'info, {}>", p),
        AccountType::SystemAccount => "SystemAccount<'info>".to_string(),
        AccountType::UncheckedAccount => "UncheckedAccount<'info>".to_string(),
        AccountType::TokenAccount => "Account<'info, TokenAccount>".to_string(),
        AccountType::Mint => "Account<'info, Mint>".to_string(),
        AccountType::Unknown(s) => s.clone(),
    }
}

fn token_line<T: ToTokens>(t: &T) -> usize {
    t.to_token_stream()
        .into_iter()
        .next()
        .map(|tt| tt.span().start().line)
        .unwrap_or(0)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_account_types() {
        assert_eq!(classify_account_type("Signer<'info>"), AccountType::Signer);
        assert_eq!(classify_account_type("AccountInfo<'info>"), AccountType::RawAccountInfo);
        assert_eq!(classify_account_type("UncheckedAccount<'info>"), AccountType::UncheckedAccount);
        assert_eq!(classify_account_type("SystemAccount<'info>"), AccountType::SystemAccount);
        assert!(matches!(classify_account_type("Account<'info,TokenAccount>"), AccountType::TokenAccount));
        assert!(matches!(classify_account_type("Program<'info,System>"), AccountType::Program(_)));
    }

    #[test]
    fn test_type_compatibility() {
        // Same typed accounts can alias
        assert!(types_compatible(
            &AccountType::TypedAccount("Vault".into()),
            &AccountType::TypedAccount("Vault".into()),
        ));

        // Different typed accounts cannot alias
        assert!(!types_compatible(
            &AccountType::TypedAccount("Vault".into()),
            &AccountType::TypedAccount("Pool".into()),
        ));

        // Raw AccountInfo can alias with anything
        assert!(types_compatible(
            &AccountType::RawAccountInfo,
            &AccountType::TokenAccount,
        ));

        // UncheckedAccount can alias with anything
        assert!(types_compatible(
            &AccountType::UncheckedAccount,
            &AccountType::TypedAccount("Vault".into()),
        ));
    }

    #[test]
    fn test_aliasing_detection() {
        let accounts = vec![
            AccountParam {
                name: "source".into(),
                account_type: AccountType::TokenAccount,
                constraints: vec![AccountConstraint {
                    kind: ConstraintKind::Mutable,
                    raw: "mut".into(),
                }],
                line: 5,
                is_mutable: true,
                is_signer: false,
            },
            AccountParam {
                name: "destination".into(),
                account_type: AccountType::TokenAccount,
                constraints: vec![AccountConstraint {
                    kind: ConstraintKind::Mutable,
                    raw: "mut".into(),
                }],
                line: 7,
                is_mutable: true,
                is_signer: false,
            },
        ];

        let pairs = check_aliasing(&accounts);
        assert!(!pairs.is_empty(), "Should detect potential aliasing between \
            source and destination token accounts");
        assert_eq!(pairs[0].severity, 5);
    }

    #[test]
    fn test_no_aliasing_with_seeds() {
        let accounts = vec![
            AccountParam {
                name: "vault_a".into(),
                account_type: AccountType::TypedAccount("Vault".into()),
                constraints: vec![
                    AccountConstraint { kind: ConstraintKind::Seeds, raw: "seeds".into() },
                    AccountConstraint { kind: ConstraintKind::Mutable, raw: "mut".into() },
                ],
                line: 5,
                is_mutable: true,
                is_signer: false,
            },
            AccountParam {
                name: "vault_b".into(),
                account_type: AccountType::TypedAccount("Vault".into()),
                constraints: vec![
                    AccountConstraint { kind: ConstraintKind::Seeds, raw: "seeds".into() },
                    AccountConstraint { kind: ConstraintKind::Mutable, raw: "mut".into() },
                ],
                line: 7,
                is_mutable: true,
                is_signer: false,
            },
        ];

        let pairs = check_aliasing(&accounts);
        assert!(pairs.is_empty(), "PDA accounts with seeds should not alias");
    }

    #[test]
    fn test_authority_without_signer() {
        let code = r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(mut)]
                pub vault: AccountInfo<'info>,
                pub authority: AccountInfo<'info>,
            }
        "#;

        let results = analyze_account_aliasing(code, "test.rs");
        assert!(!results.is_empty());
        let result = &results[0];

        // Should detect authority without signer
        let auth_findings: Vec<_> = result.findings.iter()
            .filter(|f| f.id == "SOL-ALIAS-05")
            .collect();
        assert!(!auth_findings.is_empty(),
            "Should detect authority account without signer check");
    }
}
