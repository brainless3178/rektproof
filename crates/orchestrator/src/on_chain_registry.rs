//! On-Chain Registry Client for Shanon Security Oracle
//!
//! Provides a client for interacting with the shanon-oracle Solana program.
//! Supports submitting assessments, confirming assessments, querying risk
//! scores, and reading on-chain data for the Shanon Security Oracle.
//!
//! Aligned with the oracle program's actual instruction set:
//!   - SubmitAssessment (analyst submits security flags for a program)
//!   - ConfirmAssessment (second analyst confirms an existing assessment)
//!   - QueryRisk (read risk score for a program via CPI or off-chain)
//!   - Admin operations (authority transfer, guardian management, pause)

use serde::{Deserialize, Serialize};
use solana_account_decoder::UiAccountEncoding;
use solana_client::{
    rpc_client::RpcClient,
    rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig},
    rpc_filter::{Memcmp, RpcFilterType},
};
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_program,
    transaction::Transaction,
};
use std::str::FromStr;
use tracing::info;

// ─── Seeds and Constants (must match shanon-oracle program) ─────────────────

const CONFIG_SEED: &[u8] = b"shanon_config";
const ANALYST_SEED: &[u8] = b"shanon_analyst";
const RISK_SCORE_SEED: &[u8] = b"risk_score";
const CONFIRMATION_RECEIPT_SEED: &[u8] = b"confirmation";

/// Registry configuration
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    pub rpc_url: String,
    pub registry_program_id: String,
    pub commitment: CommitmentConfig,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            rpc_url: std::env::var("SOLANA_RPC_URL")
                .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string()),
            registry_program_id: "Ea1qKkVjEEGa5mLAWdDryPB1nsGHyuxwB7oQFz8obbw4".to_string(),
            commitment: CommitmentConfig::confirmed(),
        }
    }
}

// ─── Data Types (aligned with shanon-oracle state) ──────────────────────────

/// Severity levels matching `shanon-oracle::state::FlagSeverity`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FlagSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl FlagSeverity {
    fn to_borsh_byte(&self) -> u8 {
        match self {
            FlagSeverity::Info => 0,
            FlagSeverity::Low => 1,
            FlagSeverity::Medium => 2,
            FlagSeverity::High => 3,
            FlagSeverity::Critical => 4,
        }
    }
}

/// Category matching `shanon-oracle::state::FlagCategory`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FlagCategory {
    AccessControl,
    Arithmetic,
    Reentrancy,
    TokenSafety,
    Economic,
    OracleManipulation,
    AccountValidation,
    Centralization,
    DataIntegrity,
    Logic,
}

impl FlagCategory {
    fn to_borsh_byte(&self) -> u8 {
        match self {
            FlagCategory::AccessControl => 0,
            FlagCategory::Arithmetic => 1,
            FlagCategory::Reentrancy => 2,
            FlagCategory::TokenSafety => 3,
            FlagCategory::Economic => 4,
            FlagCategory::OracleManipulation => 5,
            FlagCategory::AccountValidation => 6,
            FlagCategory::Centralization => 7,
            FlagCategory::DataIntegrity => 8,
            FlagCategory::Logic => 9,
        }
    }
}

/// A flag input for submitting assessments (matches `FlagInput` in the program).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentFlag {
    pub flag_id: Vec<u8>,
    pub severity: FlagSeverity,
    pub category: FlagCategory,
    pub description: Vec<u8>,
}

/// An on-chain risk score (parsed from `ProgramRiskScore` account data).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScoreEntry {
    pub target_program: String,
    pub overall_score: u8,
    pub confidence: u8,
    pub critical_count: u8,
    pub high_count: u8,
    pub medium_count: u8,
    pub low_count: u8,
    pub info_count: u8,
    pub flag_count: u8,
    pub analyst: String,
    pub assessed_at: i64,
    pub updated_at: i64,
    pub revision: u16,
    pub confirmations: u8,
    pub status: String,
    pub pda: String,
}

/// An on-chain analyst record (parsed from `AnalystAccount` data).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalystEntry {
    pub wallet: String,
    pub name: String,
    pub reputation_bps: u16,
    pub assessments_submitted: u32,
    pub assessments_confirmed: u32,
    pub active: bool,
    pub registered_at: i64,
    pub pda: String,
}

// ─── Main Client ────────────────────────────────────────────────────────────

/// Client for interacting with the Shanon Security Oracle on-chain program.
pub struct OnChainRegistry {
    client: RpcClient,
    config: RegistryConfig,
    payer: Option<Keypair>,
}

impl OnChainRegistry {
    /// Create a new registry client.
    pub fn new(config: RegistryConfig) -> Self {
        let client = RpcClient::new_with_commitment(config.rpc_url.clone(), config.commitment);
        Self {
            client,
            config,
            payer: None,
        }
    }

    /// Create with default devnet configuration.
    pub fn devnet() -> Self {
        Self::new(RegistryConfig::default())
    }

    /// Set the payer keypair for write transactions.
    pub fn with_payer(mut self, payer: Keypair) -> Self {
        self.payer = Some(payer);
        self
    }

    /// Get the oracle program ID.
    fn program_id(&self) -> Result<Pubkey, RegistryError> {
        Pubkey::from_str(&self.config.registry_program_id)
            .map_err(|e| RegistryError::InvalidPubkey(e.to_string()))
    }

    // ─── PDA Derivation ─────────────────────────────────────────────────────

    /// Derive the config PDA.
    fn config_pda(&self) -> Result<(Pubkey, u8), RegistryError> {
        let program_id = self.program_id()?;
        Ok(Pubkey::find_program_address(&[CONFIG_SEED], &program_id))
    }

    /// Derive an analyst account PDA.
    fn analyst_pda(&self, analyst_wallet: &Pubkey) -> Result<(Pubkey, u8), RegistryError> {
        let program_id = self.program_id()?;
        Ok(Pubkey::find_program_address(
            &[ANALYST_SEED, analyst_wallet.as_ref()],
            &program_id,
        ))
    }

    /// Derive a risk score PDA for a target program.
    fn risk_score_pda(&self, target_program: &Pubkey) -> Result<(Pubkey, u8), RegistryError> {
        let program_id = self.program_id()?;
        Ok(Pubkey::find_program_address(
            &[RISK_SCORE_SEED, target_program.as_ref()],
            &program_id,
        ))
    }

    /// Derive a confirmation receipt PDA.
    fn confirmation_receipt_pda(
        &self,
        target_program: &Pubkey,
        analyst_wallet: &Pubkey,
    ) -> Result<(Pubkey, u8), RegistryError> {
        let program_id = self.program_id()?;
        Ok(Pubkey::find_program_address(
            &[
                CONFIRMATION_RECEIPT_SEED,
                target_program.as_ref(),
                analyst_wallet.as_ref(),
            ],
            &program_id,
        ))
    }

    // ─── Write Operations ───────────────────────────────────────────────────

    /// Submit a security assessment for a target program.
    ///
    /// The payer must be a registered, active analyst.
    pub async fn submit_assessment(
        &self,
        target_program: &str,
        flags: Vec<AssessmentFlag>,
        report_ipfs_cid: Vec<u8>,
        target_program_version: u32,
    ) -> Result<String, RegistryError> {
        let payer = self.payer.as_ref().ok_or(RegistryError::NoPayer)?;
        let program_id = self.program_id()?;
        let target = Pubkey::from_str(target_program)
            .map_err(|e| RegistryError::InvalidPubkey(e.to_string()))?;

        let (config_pda, _) = self.config_pda()?;
        let (analyst_pda, _) = self.analyst_pda(&payer.pubkey())?;
        let (risk_score_pda, _) = self.risk_score_pda(&target)?;

        // Anchor discriminator: SHA-256("global:submit_assessment")[..8]
        let discriminator = anchor_instruction_discriminator("global:submit_assessment");

        // Build instruction data: discriminator + target_program + flags + ipfs_cid + version
        let mut data = discriminator.to_vec();
        data.extend_from_slice(target.as_ref()); // target_program: Pubkey
        serialize_flags(&flags, &mut data);
        serialize_vec_u8(&report_ipfs_cid, &mut data);
        data.extend_from_slice(&target_program_version.to_le_bytes());

        let accounts = vec![
            AccountMeta::new(payer.pubkey(), true),  // analyst_signer
            AccountMeta::new(analyst_pda, false),    // analyst_account
            AccountMeta::new_readonly(config_pda, false), // config
            AccountMeta::new(risk_score_pda, false), // risk_score
            AccountMeta::new_readonly(system_program::id(), false),
        ];

        let instruction = Instruction {
            program_id,
            accounts,
            data,
        };

        self.send_transaction(&[instruction], payer).await
    }

    /// Confirm an existing assessment for a target program.
    ///
    /// The payer must be a different registered analyst from the original submitter.
    pub async fn confirm_assessment(
        &self,
        target_program: &str,
    ) -> Result<String, RegistryError> {
        let payer = self.payer.as_ref().ok_or(RegistryError::NoPayer)?;
        let program_id = self.program_id()?;
        let target = Pubkey::from_str(target_program)
            .map_err(|e| RegistryError::InvalidPubkey(e.to_string()))?;

        let (config_pda, _) = self.config_pda()?;
        let (confirming_analyst_pda, _) = self.analyst_pda(&payer.pubkey())?;
        let (risk_score_pda, _) = self.risk_score_pda(&target)?;
        let (confirmation_receipt_pda, _) =
            self.confirmation_receipt_pda(&target, &payer.pubkey())?;

        // Read risk_score to find the original analyst
        let risk_score_data = self
            .client
            .get_account_data(&risk_score_pda)
            .map_err(|e| RegistryError::RpcError(e.to_string()))?;

        // Original analyst pubkey is at offset 8 (discriminator) + 32 (target_program) + 8 (scores)
        // Exact offset: after target_program(32) + overall_score(1) + confidence(1) + critical(1) +
        // high(1) + medium(1) + low(1) + info(1) + flag_count(1) + flags(variable) + analyst(32)
        // Simplified: we just need the original analyst wallet to derive their PDA
        let original_analyst = parse_analyst_from_risk_score(&risk_score_data)
            .ok_or(RegistryError::NotFound("Cannot parse original analyst from risk score".into()))?;

        let (original_analyst_pda, _) = self.analyst_pda(&original_analyst)?;

        let discriminator = anchor_instruction_discriminator("global:confirm_assessment");
        let mut data = discriminator.to_vec();
        data.extend_from_slice(target.as_ref()); // target_program: Pubkey

        let accounts = vec![
            AccountMeta::new(payer.pubkey(), true),          // confirming_analyst_signer
            AccountMeta::new(confirming_analyst_pda, false), // confirming_analyst_account
            AccountMeta::new(original_analyst_pda, false),   // original_analyst_account
            AccountMeta::new_readonly(config_pda, false),    // config
            AccountMeta::new(risk_score_pda, false),         // risk_score
            AccountMeta::new(confirmation_receipt_pda, false), // confirmation_receipt
            AccountMeta::new_readonly(system_program::id(), false),
        ];

        let instruction = Instruction {
            program_id,
            accounts,
            data,
        };

        self.send_transaction(&[instruction], payer).await
    }

    // ─── Read Operations ────────────────────────────────────────────────────

    /// Query on-chain risk scores for a specific program.
    pub async fn get_risk_score(
        &self,
        program_id_str: &str,
    ) -> Result<Option<RiskScoreEntry>, RegistryError> {
        let target = Pubkey::from_str(program_id_str)
            .map_err(|e| RegistryError::InvalidPubkey(e.to_string()))?;
        let (risk_score_pda, _) = self.risk_score_pda(&target)?;

        match self.client.get_account_data(&risk_score_pda) {
            Ok(data) => {
                let entry = parse_risk_score_account(&data, &risk_score_pda.to_string());
                Ok(entry)
            }
            Err(_) => Ok(None), // Account doesn't exist = program hasn't been assessed
        }
    }

    /// Get all risk score assessments stored on-chain.
    pub async fn get_all_assessments(&self) -> Result<Vec<RiskScoreEntry>, RegistryError> {
        let program_id = self.program_id()?;
        let discriminator = anchor_account_discriminator("ProgramRiskScore");

        let filters = vec![RpcFilterType::Memcmp(Memcmp::new_base58_encoded(
            0,
            &discriminator,
        ))];

        let config = RpcProgramAccountsConfig {
            filters: Some(filters),
            account_config: RpcAccountInfoConfig {
                encoding: Some(UiAccountEncoding::Base64),
                commitment: Some(self.config.commitment),
                ..Default::default()
            },
            with_context: Some(false),
        };

        let accounts = self
            .client
            .get_program_accounts_with_config(&program_id, config)
            .map_err(|e| RegistryError::RpcError(e.to_string()))?;

        info!(
            "Found {} ProgramRiskScore accounts on-chain",
            accounts.len()
        );

        let mut entries = Vec::new();
        for (pubkey, account) in accounts {
            if let Some(entry) = parse_risk_score_account(&account.data, &pubkey.to_string()) {
                entries.push(entry);
            }
        }

        entries.sort_by(|a, b| b.assessed_at.cmp(&a.assessed_at));
        Ok(entries)
    }

    /// Get all registered analysts.
    pub async fn get_analysts(&self) -> Result<Vec<AnalystEntry>, RegistryError> {
        let program_id = self.program_id()?;
        let discriminator = anchor_account_discriminator("AnalystAccount");

        let filters = vec![RpcFilterType::Memcmp(Memcmp::new_base58_encoded(
            0,
            &discriminator,
        ))];

        let config = RpcProgramAccountsConfig {
            filters: Some(filters),
            account_config: RpcAccountInfoConfig {
                encoding: Some(UiAccountEncoding::Base64),
                commitment: Some(self.config.commitment),
                ..Default::default()
            },
            with_context: Some(false),
        };

        let accounts = self
            .client
            .get_program_accounts_with_config(&program_id, config)
            .map_err(|e| RegistryError::RpcError(e.to_string()))?;

        info!("Found {} AnalystAccount records on-chain", accounts.len());

        let mut entries = Vec::new();
        for (pubkey, account) in accounts {
            if let Some(entry) = parse_analyst_account(&account.data, &pubkey.to_string()) {
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    /// Check if a program has any on-chain assessment.
    pub async fn has_assessment(&self, program_id: &str) -> Result<bool, RegistryError> {
        Ok(self.get_risk_score(program_id).await?.is_some())
    }

    /// Get the security score for a program (overall_score from the on-chain assessment).
    pub async fn get_security_score(
        &self,
        program_id: &str,
    ) -> Result<Option<u8>, RegistryError> {
        Ok(self
            .get_risk_score(program_id)
            .await?
            .map(|r| r.overall_score))
    }

    /// Verify that a transaction signature exists and was successful.
    pub async fn verify_transaction(
        &self,
        tx_signature: &str,
    ) -> Result<bool, RegistryError> {
        let sig = solana_sdk::signature::Signature::from_str(tx_signature)
            .map_err(|e| RegistryError::InvalidSignature(e.to_string()))?;

        match self.client.get_signature_status(&sig) {
            Ok(Some(status)) => Ok(status.is_ok()),
            Ok(None) => Ok(false),
            Err(e) => Err(RegistryError::RpcError(e.to_string())),
        }
    }

    // ─── Internal Helpers ───────────────────────────────────────────────────

    async fn send_transaction(
        &self,
        instructions: &[Instruction],
        payer: &Keypair,
    ) -> Result<String, RegistryError> {
        let recent_blockhash = self
            .client
            .get_latest_blockhash()
            .map_err(|e| RegistryError::RpcError(e.to_string()))?;

        let message = Message::new(instructions, Some(&payer.pubkey()));
        let mut transaction = Transaction::new_unsigned(message);
        transaction.sign(&[payer], recent_blockhash);

        match self.client.send_and_confirm_transaction(&transaction) {
            Ok(sig) => {
                info!("Transaction confirmed: {}", sig);
                Ok(sig.to_string())
            }
            Err(e) => Err(RegistryError::TransactionFailed(format!(
                "Transaction failed: {}",
                e
            ))),
        }
    }

    /// Helper to hash data (SHA-256).
    pub fn hash_data(&self, data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}

// ─── Serialization Helpers ──────────────────────────────────────────────────

fn serialize_flags(flags: &[AssessmentFlag], buf: &mut Vec<u8>) {
    // Borsh Vec: 4-byte length prefix + elements
    buf.extend_from_slice(&(flags.len() as u32).to_le_bytes());
    for flag in flags {
        // flag_id: Vec<u8>
        serialize_vec_u8(&flag.flag_id, buf);
        // severity: enum (1 byte)
        buf.push(flag.severity.to_borsh_byte());
        // category: enum (1 byte)
        buf.push(flag.category.to_borsh_byte());
        // description: Vec<u8>
        serialize_vec_u8(&flag.description, buf);
    }
}

fn serialize_vec_u8(data: &[u8], buf: &mut Vec<u8>) {
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
}

// ─── Account Parsing ────────────────────────────────────────────────────────

/// Compute the 8-byte Anchor account discriminator for a given type name.
/// Anchor uses SHA-256("account:<TypeName>")[..8].
fn anchor_account_discriminator(type_name: &str) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(format!("account:{}", type_name).as_bytes());
    let hash = hasher.finalize();
    let mut disc = [0u8; 8];
    disc.copy_from_slice(&hash[..8]);
    disc
}

/// Compute the 8-byte Anchor instruction discriminator.
/// Anchor uses SHA-256("<namespace>:<instruction_name>")[..8].
fn anchor_instruction_discriminator(full_name: &str) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(full_name.as_bytes());
    let hash = hasher.finalize();
    let mut disc = [0u8; 8];
    disc.copy_from_slice(&hash[..8]);
    disc
}

/// Parse the analyst pubkey from a ProgramRiskScore account.
/// The analyst field is after: discriminator(8) + target_program(32) + score fields(8) +
/// flags vec (variable). We use a fixed offset assuming the account is well-formed.
fn parse_analyst_from_risk_score(data: &[u8]) -> Option<Pubkey> {
    if data.len() < 8 + 32 + 8 {
        return None;
    }
    let mut offset = 8; // discriminator
    offset += 32; // target_program
    offset += 1;  // overall_score
    offset += 1;  // confidence
    offset += 1;  // critical_count
    offset += 1;  // high_count
    offset += 1;  // medium_count
    offset += 1;  // low_count
    offset += 1;  // info_count
    offset += 1;  // flag_count

    // flags Vec: 4-byte length + elements
    if offset + 4 > data.len() {
        return None;
    }
    let flag_count = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
    offset += 4;
    // Each SecurityFlag is: 8 + 1 + 1 + 64 + 1 + 1 = 76 bytes
    offset += flag_count * 76;

    // analyst: Pubkey (32 bytes)
    if offset + 32 > data.len() {
        return None;
    }
    Pubkey::try_from(&data[offset..offset + 32]).ok()
}

/// Parse a ProgramRiskScore account from raw data.
fn parse_risk_score_account(data: &[u8], pda: &str) -> Option<RiskScoreEntry> {
    if data.len() < 8 + 32 + 8 + 4 {
        return None;
    }
    let mut offset = 8; // discriminator

    // target_program (32)
    let target_program = Pubkey::try_from(&data[offset..offset + 32]).ok()?;
    offset += 32;

    let overall_score = data[offset]; offset += 1;
    let confidence = data[offset]; offset += 1;
    let critical_count = data[offset]; offset += 1;
    let high_count = data[offset]; offset += 1;
    let medium_count = data[offset]; offset += 1;
    let low_count = data[offset]; offset += 1;
    let info_count = data[offset]; offset += 1;
    let flag_count = data[offset]; offset += 1;

    // Skip flags vec
    if offset + 4 > data.len() { return None; }
    let vec_len = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
    offset += 4;
    offset += vec_len * 76; // SecurityFlag::LEN = 76

    // analyst (32)
    if offset + 32 > data.len() { return None; }
    let analyst = Pubkey::try_from(&data[offset..offset + 32]).ok()?;
    offset += 32;

    // assessed_at (i64)
    if offset + 8 > data.len() { return None; }
    let assessed_at = i64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
    offset += 8;

    // updated_at (i64)
    if offset + 8 > data.len() { return None; }
    let updated_at = i64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
    offset += 8;

    // revision (u16)
    if offset + 2 > data.len() { return None; }
    let revision = u16::from_le_bytes(data[offset..offset + 2].try_into().ok()?);
    offset += 2;

    // confirmations (u8)
    if offset >= data.len() { return None; }
    let confirmations = data[offset];
    offset += 1;

    // Skip report_ipfs_cid (36) + report_cid_len (1)
    offset += 36 + 1;

    // status (1 byte enum)
    let status = if offset < data.len() {
        match data[offset] {
            0 => "Pending",
            1 => "Confirmed",
            2 => "Disputed",
            3 => "Superseded",
            4 => "Withdrawn",
            _ => "Unknown",
        }.to_string()
    } else {
        "Unknown".to_string()
    };

    Some(RiskScoreEntry {
        target_program: target_program.to_string(),
        overall_score,
        confidence,
        critical_count,
        high_count,
        medium_count,
        low_count,
        info_count,
        flag_count,
        analyst: analyst.to_string(),
        assessed_at,
        updated_at,
        revision,
        confirmations,
        status,
        pda: pda.to_string(),
    })
}

/// Parse an AnalystAccount from raw data.
fn parse_analyst_account(data: &[u8], pda: &str) -> Option<AnalystEntry> {
    // Minimum: discriminator(8) + wallet(32) + name(64) + name_len(1) + counts + etc
    if data.len() < 8 + 32 + 64 + 1 + 4 + 4 + 2 + 1 + 8 + 8 + 1 {
        return None;
    }
    let mut offset = 8; // discriminator

    // wallet (32)
    let wallet = Pubkey::try_from(&data[offset..offset + 32]).ok()?;
    offset += 32;

    // name ([u8; 64])
    let name_bytes = &data[offset..offset + 64];
    offset += 64;

    // name_len (u8)
    let name_len = data[offset] as usize;
    offset += 1;
    let name = String::from_utf8_lossy(&name_bytes[..name_len.min(64)]).to_string();

    // assessments_submitted (u32)
    let assessments_submitted = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
    offset += 4;

    // assessments_confirmed (u32)
    let assessments_confirmed = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
    offset += 4;

    // reputation_bps (u16)
    let reputation_bps = u16::from_le_bytes(data[offset..offset + 2].try_into().ok()?);
    offset += 2;

    // active (bool)
    let active = data[offset] != 0;
    offset += 1;

    // registered_at (i64)
    let registered_at = i64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);

    Some(AnalystEntry {
        wallet: wallet.to_string(),
        name,
        reputation_bps,
        assessments_submitted,
        assessments_confirmed,
        active,
        registered_at,
        pda: pda.to_string(),
    })
}

// ─── Error Type ─────────────────────────────────────────────────────────────

/// Registry errors.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("No payer keypair set")]
    NoPayer,
    #[error("Invalid pubkey: {0}")]
    InvalidPubkey(String),
    #[error("RPC error: {0}")]
    RpcError(String),
    #[error("Transaction failed: {0}")]
    TransactionFailed(String),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Not found: {0}")]
    NotFound(String),
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = OnChainRegistry::devnet();
        assert!(registry.payer.is_none());
    }

    #[test]
    fn test_config_defaults() {
        let config = RegistryConfig::default();
        assert!(config.rpc_url.contains("solana"));
        assert_eq!(
            config.registry_program_id,
            "Ea1qKkVjEEGa5mLAWdDryPB1nsGHyuxwB7oQFz8obbw4"
        );
    }

    #[test]
    fn test_anchor_account_discriminator() {
        let disc = anchor_account_discriminator("ProgramRiskScore");
        assert_eq!(disc.len(), 8);
        // Deterministic
        assert_eq!(disc, anchor_account_discriminator("ProgramRiskScore"));
        // Different types produce different discriminators
        assert_ne!(disc, anchor_account_discriminator("AnalystAccount"));
    }

    #[test]
    fn test_anchor_instruction_discriminator() {
        let disc = anchor_instruction_discriminator("global:submit_assessment");
        assert_eq!(disc.len(), 8);
        assert_ne!(
            disc,
            anchor_instruction_discriminator("global:confirm_assessment")
        );
    }

    #[test]
    fn test_pda_derivation() {
        let registry = OnChainRegistry::devnet();
        let (config_pda, _bump) = registry.config_pda().unwrap();
        assert_ne!(config_pda, Pubkey::default());

        let wallet = Pubkey::new_unique();
        let (analyst_pda, _) = registry.analyst_pda(&wallet).unwrap();
        assert_ne!(analyst_pda, Pubkey::default());

        let target = Pubkey::new_unique();
        let (risk_pda, _) = registry.risk_score_pda(&target).unwrap();
        assert_ne!(risk_pda, Pubkey::default());
    }

    #[test]
    fn test_flag_severity_to_borsh() {
        assert_eq!(FlagSeverity::Info.to_borsh_byte(), 0);
        assert_eq!(FlagSeverity::Low.to_borsh_byte(), 1);
        assert_eq!(FlagSeverity::Medium.to_borsh_byte(), 2);
        assert_eq!(FlagSeverity::High.to_borsh_byte(), 3);
        assert_eq!(FlagSeverity::Critical.to_borsh_byte(), 4);
    }

    #[test]
    fn test_parse_risk_score_too_short() {
        assert!(parse_risk_score_account(&[0u8; 40], "pda").is_none());
    }

    #[test]
    fn test_parse_analyst_too_short() {
        assert!(parse_analyst_account(&[0u8; 40], "pda").is_none());
    }
}
