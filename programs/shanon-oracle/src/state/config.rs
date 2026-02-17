use anchor_lang::prelude::*;

/// Seed prefix for the global oracle configuration PDA.
pub const CONFIG_SEED: &[u8] = b"shanon_config";

/// Maximum number of guardians allowed (for bounded account sizing).
pub const MAX_GUARDIANS: usize = 10;

/// The global configuration for the Shanon Security Oracle.
///
/// This account stores the governance authority (the multisig or DAO that
/// controls the oracle), the list of guardian signers required for critical
/// operations, and protocol-level parameters.
///
/// PDA: ["shanon_config"]
#[account]
#[derive(Debug)]
pub struct OracleConfig {
    /// The upgrade/governance authority. This should be a multisig or
    /// governance program — never a single EOA in production.
    pub authority: Pubkey,

    /// Guardian committee for high-risk operations. Adding/removing analysts
    /// requires `min_guardian_signatures` out of this set.
    pub guardians: Vec<Pubkey>,

    /// Minimum number of guardian signatures required for protected operations.
    /// Must satisfy: 1 <= min_guardian_signatures <= guardians.len()
    pub min_guardian_signatures: u8,

    /// Number of analysts currently registered.
    pub analyst_count: u32,

    /// Number of programs currently scored.
    pub scored_program_count: u64,

    /// Whether the oracle is paused (emergency stop).
    pub paused: bool,

    /// Protocol version, incremented on schema changes.
    pub version: u8,

    /// Bump seed for this PDA.
    pub bump: u8,

    /// Pending authority for two-step authority transfer.
    /// Set by `propose_authority_transfer`, consumed by `accept_authority_transfer`.
    pub pending_authority: Option<Pubkey>,

    /// Reserved space for future upgrades without reallocation.
    /// Originally 128 bytes; 33 bytes carved out for pending_authority.
    pub _reserved: [u8; 95],
}

impl OracleConfig {
    /// Fixed account size. We use a fixed Vec capacity for guardians.
    /// 8 (discriminator) + 32 (authority) + 4 + 32*MAX_GUARDIANS (guardians vec)
    /// + 1 + 4 + 8 + 1 + 1 + 1 + 128 = 8 + 32 + 324 + 144 = 508
    pub const LEN: usize = 8  // anchor discriminator
        + 32                   // authority
        + 4 + (32 * MAX_GUARDIANS) // guardians (vec length prefix + data)
        + 1                    // min_guardian_signatures
        + 4                    // analyst_count
        + 8                    // scored_program_count
        + 1                    // paused
        + 1                    // version
        + 1                    // bump
        + 1 + 32               // pending_authority (Option<Pubkey>: 1 tag + 32 data)
        + 95;                  // reserved

    pub const CURRENT_VERSION: u8 = 1;
}
