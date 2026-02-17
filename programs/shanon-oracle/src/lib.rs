use anchor_lang::prelude::*;

pub mod errors;
pub mod instructions;
pub mod state;

use instructions::*;

declare_id!("Ea1qKkVjEEGa5mLAWdDryPB1nsGHyuxwB7oQFz8obbw4");

/// Shanon Security Oracle — On-chain risk scores for Solana programs.
///
/// This program provides a composable security intelligence layer for
/// the Solana ecosystem. Security analysts submit assessments with
/// granular flag-level data, and any Solana program can query risk
/// scores via CPI to make security-aware decisions.
///
/// Key properties:
/// - Multi-analyst consensus (no single analyst controls scores)
/// - Reputation-weighted confidence scores
/// - CPI-queryable by any Solana program
/// - Emergency pause capability
/// - Guardian-based governance (not single admin)
/// - Two-step authority transfer (proposal → acceptance)
/// - Duplicate confirmation prevention (receipt PDAs)
#[program]
pub mod shanon_oracle {
    use super::*;

    // ─── Initialization ─────────────────────────────────────────────

    /// Initialize the oracle configuration. One-time operation.
    pub fn initialize(
        ctx: Context<Initialize>,
        min_guardian_signatures: u8,
    ) -> Result<()> {
        instructions::initialize::initialize(ctx, min_guardian_signatures)
    }

    // ─── Analyst Management ─────────────────────────────────────────

    /// Register a new security analyst.
    pub fn register_analyst(
        ctx: Context<RegisterAnalyst>,
        name: Vec<u8>,
        domain_flags: u8,
    ) -> Result<()> {
        instructions::register_analyst::register_analyst(ctx, name, domain_flags)
    }

    // ─── Assessment Operations ──────────────────────────────────────

    /// Submit a new security assessment for a target program.
    pub fn submit_assessment(
        ctx: Context<SubmitAssessment>,
        target_program: Pubkey,
        flags: Vec<FlagInput>,
        report_ipfs_cid: Vec<u8>,
        target_program_version: u32,
    ) -> Result<()> {
        instructions::submit_assessment::submit_assessment(
            ctx,
            target_program,
            flags,
            report_ipfs_cid,
            target_program_version,
        )
    }

    /// Update an existing assessment with revised findings.
    pub fn update_assessment(
        ctx: Context<UpdateAssessment>,
        target_program: Pubkey,
        flags: Vec<FlagInput>,
        report_ipfs_cid: Vec<u8>,
        target_program_version: u32,
    ) -> Result<()> {
        instructions::update_assessment::update_assessment(
            ctx,
            target_program,
            flags,
            report_ipfs_cid,
            target_program_version,
        )
    }

    /// Confirm an existing assessment (second analyst review).
    /// Creates a confirmation receipt PDA to prevent duplicate confirmations.
    pub fn confirm_assessment(
        ctx: Context<ConfirmAssessment>,
        target_program: Pubkey,
    ) -> Result<()> {
        instructions::confirm_assessment::confirm_assessment(ctx, target_program)
    }

    // ─── Query Interface (CPI-callable) ─────────────────────────────

    /// Query a program's risk score. Returns data via set_return_data
    /// so CPI callers can deserialize the result.
    pub fn query_risk(
        ctx: Context<QueryRisk>,
        target_program: Pubkey,
    ) -> Result<()> {
        instructions::query_risk::query_risk(ctx, target_program)
    }

    // ─── Admin Operations ───────────────────────────────────────────

    /// Add a guardian to the governance committee.
    pub fn add_guardian(
        ctx: Context<AddGuardian>,
        new_guardian: Pubkey,
    ) -> Result<()> {
        instructions::admin::add_guardian(ctx, new_guardian)
    }

    /// Remove a guardian from the governance committee.
    pub fn remove_guardian(
        ctx: Context<RemoveGuardian>,
        guardian: Pubkey,
    ) -> Result<()> {
        instructions::admin::remove_guardian(ctx, guardian)
    }

    /// Pause or resume the oracle.
    pub fn set_paused(
        ctx: Context<SetPaused>,
        paused: bool,
    ) -> Result<()> {
        instructions::admin::set_paused(ctx, paused)
    }

    // ─── Two-Step Authority Transfer ────────────────────────────────

    /// Propose transferring authority to a new address.
    /// Does NOT immediately change authority — the new authority must
    /// call `accept_authority_transfer` to finalize.
    pub fn propose_authority_transfer(
        ctx: Context<ProposeAuthorityTransfer>,
        new_authority: Pubkey,
    ) -> Result<()> {
        instructions::admin::propose_authority_transfer(ctx, new_authority)
    }

    /// Accept a pending authority transfer. Only the proposed new authority
    /// can call this.
    pub fn accept_authority_transfer(
        ctx: Context<AcceptAuthorityTransfer>,
    ) -> Result<()> {
        instructions::admin::accept_authority_transfer(ctx)
    }

    /// Cancel a pending authority transfer. Only the current authority can cancel.
    pub fn cancel_authority_transfer(
        ctx: Context<CancelAuthorityTransfer>,
    ) -> Result<()> {
        instructions::admin::cancel_authority_transfer(ctx)
    }

    /// Deactivate an analyst (soft-delete, preserves history).
    pub fn deactivate_analyst(
        ctx: Context<DeactivateAnalyst>,
        analyst_wallet: Pubkey,
    ) -> Result<()> {
        instructions::admin::deactivate_analyst(ctx, analyst_wallet)
    }
}
