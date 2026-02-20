//! Exploit Transaction Builder
//!
//! Build instruction and transactions from exploit parameters.

use crate::{ExploitTransaction, ForgeError};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

pub struct TransactionBuilder {
    program_id: Pubkey,
    accounts: Vec<AccountMeta>,
    data: Vec<u8>,
}

impl TransactionBuilder {
    pub fn new(program_id: Pubkey) -> Self {
        Self {
            program_id,
            accounts: Vec::new(),
            data: Vec::new(),
        }
    }

    pub fn add_account(&mut self, pubkey: Pubkey, is_signer: bool, is_writable: bool) -> &mut Self {
        self.accounts.push(AccountMeta {
            pubkey,
            is_signer,
            is_writable,
        });
        self
    }

    pub fn set_data(&mut self, data: Vec<u8>) -> &mut Self {
        self.data = data;
        self
    }

    pub fn build_instruction(&self) -> Instruction {
        Instruction {
            program_id: self.program_id,
            accounts: self.accounts.clone(),
            data: self.data.clone(),
        }
    }

    pub fn build_exploit_transaction(
        &self,
        payer: &Keypair,
        recent_blockhash: solana_sdk::hash::Hash,
    ) -> Result<ExploitTransaction, ForgeError> {
        let ix = self.build_instruction();
        let transaction = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[payer],
            recent_blockhash,
        );

        Ok(ExploitTransaction {
            transaction,
            description: "Generated exploit transaction".to_string(),
            target_instruction: "unknown".to_string(),
            accounts: self.accounts.clone(),
            data: self.data.clone(),
        })
    }

    /// Build exploit instruction data tailored to the vulnerability type.
    ///
    /// Each variant encodes a minimal payload designed to trigger the specific
    /// vulnerability class during on-chain simulation.
    pub fn build_exploit_data(vuln_type: &crate::VulnerabilityType) -> Vec<u8> {
        match vuln_type {
            crate::VulnerabilityType::IntegerOverflow => {
                // u64::MAX to trigger wrapping arithmetic
                u64::MAX.to_le_bytes().to_vec()
            }
            crate::VulnerabilityType::MissingOwnerCheck => {
                // Instruction data requesting a transfer with forged owner bytes
                let mut data = vec![0x01]; // transfer discriminator
                data.extend_from_slice(&1_000_000_000u64.to_le_bytes());
                data
            }
            crate::VulnerabilityType::MissingSignerCheck => {
                // Standard invoke without signer flag
                vec![0x02, 0x00] // action byte + no-signer marker
            }
            crate::VulnerabilityType::ArbitraryCPI => {
                // CPI invoke with attacker-controlled program ID bytes
                let mut data = vec![0x03]; // CPI discriminator
                data.extend_from_slice(&Pubkey::new_unique().to_bytes());
                data
            }
            crate::VulnerabilityType::Reentrancy => {
                // Re-entrant callback payload
                vec![0x04, 0x01] // action + re-entry flag
            }
            crate::VulnerabilityType::OracleManipulation => {
                // Crafted oracle price (u64::MAX / 2 to cause price deviation)
                let mut data = vec![0x05];
                data.extend_from_slice(&(u64::MAX / 2).to_le_bytes());
                data
            }
            crate::VulnerabilityType::AccountConfusion => {
                // Swap account indices to confuse program logic
                vec![0x06, 0x01, 0x00] // action + swapped indices
            }
            crate::VulnerabilityType::UninitializedData => {
                // Zero-filled data to exploit uninitialized reads
                vec![0x00; 32]
            }
        }
    }
}
