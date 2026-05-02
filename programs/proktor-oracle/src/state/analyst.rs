use anchor_lang::prelude::*;

/// Seed prefix for analyst registry PDAs.
pub const ANALYST_SEED: &[u8] = b"analyst";

/// Represents an authorized security analyst who can submit risk assessments.
///
/// Each analyst is a PDA derived from their wallet pubkey, ensuring uniqueness.
/// Analysts accumulate reputation based on their assessment history.
///
/// PDA: ["analyst", analyst_wallet.key()]
#[account]
#[derive(Debug)]
pub struct AnalystAccount {
    /// The wallet pubkey of this analyst (also used for PDA derivation).
    pub wallet: Pubkey,

    /// Human-readable name or organization (max 64 bytes for on-chain storage).
    pub name: [u8; 64],

    /// Number of characters actually used in the name field.
    pub name_len: u8,

    /// Total number of assessments submitted by this analyst.
    pub assessments_submitted: u64,

    /// Number of assessments that were later confirmed by other analysts.
    pub assessments_confirmed: u64,

    /// Reputation score (0-10000, basis points). Starts at 5000.
    /// Increases when assessments are confirmed, decreases on disputes.
    pub reputation_bps: u16,

    /// Whether this analyst is currently active and can submit assessments.
    pub active: bool,

    /// Unix timestamp when this analyst was registered.
    pub registered_at: i64,

    /// Unix timestamp of the last assessment submitted.
    pub last_assessment_at: i64,

    /// The specific security domains this analyst is credentialed for.
    /// Bit flags: 0=DeFi, 1=Token, 2=NFT, 3=Governance, 4=Bridge, 5=Oracle
    pub domain_flags: u8,

    /// Bump seed for this PDA.
    pub bump: u8,

    /// Reserved space for future upgrades.
    pub _reserved: [u8; 64],
}

impl AnalystAccount {
    pub const LEN: usize = 8   // discriminator
        + 32                    // wallet
        + 64                    // name
        + 1                     // name_len
        + 8                     // assessments_submitted
        + 8                     // assessments_confirmed
        + 2                     // reputation_bps
        + 1                     // active
        + 8                     // registered_at
        + 8                     // last_assessment_at
        + 1                     // domain_flags
        + 1                     // bump
        + 64;                   // reserved

    pub const INITIAL_REPUTATION: u16 = 5000;

    /// Domain flag constants.
    pub const DOMAIN_DEFI: u8 = 1 << 0;
    pub const DOMAIN_TOKEN: u8 = 1 << 1;
    pub const DOMAIN_NFT: u8 = 1 << 2;
    pub const DOMAIN_GOVERNANCE: u8 = 1 << 3;
    pub const DOMAIN_BRIDGE: u8 = 1 << 4;
    pub const DOMAIN_ORACLE: u8 = 1 << 5;

    pub fn get_name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    pub fn has_domain(&self, domain: u8) -> bool {
        self.domain_flags & domain != 0
    }
}
