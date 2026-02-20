//! Transaction Forge - Exploit Transaction Generation
//!
//! Converts symbolic exploit proofs into real, executable Solana transactions.

use serde::{Deserialize, Serialize};
use solana_sdk::{instruction::AccountMeta, transaction::Transaction};

pub mod builder;
pub mod error;
pub mod executor;
pub mod proof_generator;

pub use builder::TransactionBuilder;
pub use error::ForgeError;
pub use executor::ExploitExecutor;
pub use proof_generator::ExploitProofConverter;

/// A generated exploit transaction
#[derive(Debug, Clone)]
pub struct ExploitTransaction {
    pub transaction: Transaction,
    pub description: String,
    pub target_instruction: String,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

/// Types of vulnerabilities for transaction forging
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VulnerabilityType {
    MissingOwnerCheck,
    IntegerOverflow,
    ArbitraryCPI,
    Reentrancy,
    OracleManipulation,
    AccountConfusion,
    UninitializedData,
    MissingSignerCheck,
}

/// Configuration for transaction generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgeConfig {
    pub rpc_url: String,
    pub commitment: String,
    pub payer_keypair_path: String,
    pub compute_budget: u32,
    pub simulate_only: bool,
    pub max_retries: usize,
}

impl Default for ForgeConfig {
    fn default() -> Self {
        Self {
            rpc_url: "https://api.devnet.solana.com".to_string(),
            commitment: "confirmed".to_string(),
            payer_keypair_path: "~/.config/solana/id.json".to_string(),
            compute_budget: 200_000,
            simulate_only: true,
            max_retries: 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::{pubkey::Pubkey, signature::{Keypair, Signer}};

    #[test]
    fn test_default_config() {
        let config = ForgeConfig::default();
        assert!(config.simulate_only, "default should be simulate_only");
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.compute_budget, 200_000);
        assert!(config.rpc_url.contains("devnet"));
    }

    #[test]
    fn test_vulnerability_type_variants() {
        let types = vec![
            VulnerabilityType::MissingOwnerCheck,
            VulnerabilityType::IntegerOverflow,
            VulnerabilityType::ArbitraryCPI,
            VulnerabilityType::Reentrancy,
            VulnerabilityType::OracleManipulation,
            VulnerabilityType::AccountConfusion,
            VulnerabilityType::UninitializedData,
            VulnerabilityType::MissingSignerCheck,
        ];
        assert_eq!(types.len(), 8, "should have 8 vulnerability types");
        // Ensure PartialEq works
        assert_eq!(VulnerabilityType::Reentrancy, VulnerabilityType::Reentrancy);
        assert_ne!(VulnerabilityType::Reentrancy, VulnerabilityType::ArbitraryCPI);
    }

    #[test]
    fn test_builder_creates_instruction() {
        let program_id = Pubkey::new_unique();
        let mut builder = TransactionBuilder::new(program_id);
        let acct = Pubkey::new_unique();
        builder.add_account(acct, true, true);
        builder.set_data(vec![1, 2, 3, 4, 5, 6, 7, 8]);

        let ix = builder.build_instruction();
        assert_eq!(ix.program_id, program_id);
        assert_eq!(ix.accounts.len(), 1);
        assert!(ix.accounts[0].is_signer);
        assert!(ix.accounts[0].is_writable);
        assert_eq!(ix.data, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_builder_creates_signed_transaction() {
        let program_id = Pubkey::new_unique();
        let payer = Keypair::new();
        let mut builder = TransactionBuilder::new(program_id);
        builder.add_account(payer.pubkey(), true, true);
        builder.set_data(vec![0xAA; 8]);

        let blockhash = solana_sdk::hash::Hash::default();
        let exploit_tx = builder
            .build_exploit_transaction(&payer, blockhash)
            .expect("should build successfully");

        assert_eq!(exploit_tx.data, vec![0xAA; 8]);
        assert_eq!(exploit_tx.accounts.len(), 1);
        assert!(!exploit_tx.description.is_empty());
    }

    #[test]
    fn test_proof_converter_creates_builder() {
        let converter = ExploitProofConverter;
        let result = converter.convert_to_builder(
            "11111111111111111111111111111111",
            &[0u8; 16],
            vec![("11111111111111111111111111111111".to_string(), true, true)],
        );
        assert!(result.is_ok(), "converter should produce a valid builder");
    }
}

