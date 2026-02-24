//! Typosquat Detection Engine
//!
//! Uses Levenshtein distance to detect packages whose names are suspiciously
//! similar to legitimate Solana ecosystem packages.

use serde::{Deserialize, Serialize};
use strsim::normalized_levenshtein;

/// Result of a typosquat check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TyposquatWarning {
    /// The suspicious package name that was found.
    pub suspicious_name: String,
    /// The legitimate package it likely impersonates.
    pub likely_target: String,
    /// String similarity score (0.0 = totally different, 1.0 = identical).
    pub similarity: f64,
    /// Ecosystem (npm or cargo).
    pub ecosystem: String,
}

/// Canonical list of legitimate Solana ecosystem npm packages.
const LEGITIMATE_NPM: &[&str] = &[
    "@solana/web3.js",
    "@solana/spl-token",
    "@solana/spl-account-compression",
    "@solana/spl-memo",
    "@solana/spl-name-service",
    "@solana/spl-stake-pool",
    "@solana/spl-token-lending",
    "@solana/spl-governance",
    "@solana/wallet-adapter-base",
    "@solana/wallet-adapter-react",
    "@solana/wallet-adapter-wallets",
    "@coral-xyz/anchor",
    "@coral-xyz/borsh",
    "@metaplex-foundation/mpl-token-metadata",
    "@metaplex-foundation/umi",
    "@metaplex-foundation/mpl-bubblegum",
    "@solana/pay",
    "@solana/buffer-layout",
    "@solana/spl-token-registry",
    "@project-serum/anchor",
    "@project-serum/serum",
    "@solflare-wallet/sdk",
    "@phantom/wallet-sdk",
    "@raydium-io/raydium-sdk",
    "@orca-so/whirlpools-sdk",
    "@jup-ag/core",
    "@jup-ag/api",
    "@marinade.finance/marinade-ts-sdk",
    "@switchboard-xyz/solana.js",
    "@pyth-network/client",
    "borsh",
    "bn.js",
    "bs58",
    "tweetnacl",
    "buffer-layout",
    "solana-bankrun",
];

/// Canonical list of legitimate Solana ecosystem Cargo crates.
const LEGITIMATE_CARGO: &[&str] = &[
    "solana-sdk",
    "solana-program",
    "solana-client",
    "solana-cli",
    "solana-transaction-status",
    "solana-account-decoder",
    "solana-rpc",
    "solana-program-test",
    "solana-banks-client",
    "solana-clap-utils",
    "solana-logger",
    "solana-measure",
    "solana-metrics",
    "anchor-lang",
    "anchor-spl",
    "anchor-client",
    "anchor-syn",
    "spl-token",
    "spl-token-2022",
    "spl-associated-token-account",
    "spl-memo",
    "spl-name-service",
    "spl-stake-pool",
    "spl-governance",
    "mpl-token-metadata",
    "mpl-bubblegum",
    "pyth-sdk-solana",
    "switchboard-solana",
    "clockwork-sdk",
    "borsh",
    "bs58",
];

/// Check a package name for typosquatting against known legitimate packages.
///
/// Returns `Some(TyposquatWarning)` if the name is suspiciously similar
/// (similarity > 0.75) to a legitimate package but not an exact match.
pub fn check_typosquat_npm(name: &str) -> Option<TyposquatWarning> {
    check_typosquat(name, LEGITIMATE_NPM, "npm")
}

/// Check a Cargo crate name for typosquatting.
pub fn check_typosquat_cargo(name: &str) -> Option<TyposquatWarning> {
    check_typosquat(name, LEGITIMATE_CARGO, "cargo")
}

fn check_typosquat(name: &str, legitimate: &[&str], ecosystem: &str) -> Option<TyposquatWarning> {
    let name_lower = name.to_lowercase();

    // Common typosquat patterns — check structurally first
    let structural_patterns: Vec<String> = vec![
        name_lower.replace('-', "_"),   // hyphen→underscore swap
        name_lower.replace('_', "-"),   // underscore→hyphen swap
        name_lower.replace("@", ""),    // dropped scope
    ];

    let mut best_match: Option<(&str, f64)> = None;

    for legit in legitimate {
        let legit_lower = legit.to_lowercase();

        // Exact match ⇒ not a typosquat, it IS the real package
        if name_lower == legit_lower {
            return None;
        }

        // Structural pattern match (e.g., anchor_lang vs anchor-lang)
        for pattern in &structural_patterns {
            if *pattern == legit_lower {
                return Some(TyposquatWarning {
                    suspicious_name: name.to_string(),
                    likely_target: legit.to_string(),
                    similarity: 0.95,
                    ecosystem: ecosystem.to_string(),
                });
            }
        }

        // Normalized Levenshtein similarity (1.0 = identical, 0.0 = nothing alike)
        let sim = normalized_levenshtein(&name_lower, &legit_lower);

        // Only flag if > 0.75 similar (high similarity, not exact match)
        if sim > 0.75 {
            match best_match {
                Some((_, best_sim)) if sim > best_sim => {
                    best_match = Some((legit, sim));
                }
                None => {
                    best_match = Some((legit, sim));
                }
                _ => {}
            }
        }
    }

    best_match.map(|(target, similarity)| TyposquatWarning {
        suspicious_name: name.to_string(),
        likely_target: target.to_string(),
        similarity,
        ecosystem: ecosystem.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match_not_typosquat() {
        assert!(check_typosquat_npm("@solana/web3.js").is_none());
        assert!(check_typosquat_cargo("solana-sdk").is_none());
    }

    #[test]
    fn test_underscore_hyphen_swap() {
        let result = check_typosquat_cargo("anchor_lang");
        assert!(result.is_some());
        let w = result.unwrap();
        assert_eq!(w.likely_target, "anchor-lang");
        assert!(w.similarity > 0.90);
    }

    #[test]
    fn test_similar_name_flagged() {
        let result = check_typosquat_npm("@solana/web3js");
        assert!(result.is_some());
    }

    #[test]
    fn test_unrelated_name_not_flagged() {
        assert!(check_typosquat_npm("lodash").is_none());
        assert!(check_typosquat_cargo("serde").is_none());
    }
}
