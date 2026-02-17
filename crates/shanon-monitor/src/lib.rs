//! # Shanon Monitor — Upgrade Authority Watcher
//!
//! Monitors Solana programs for upgrade authority changes and sends alerts
//! via webhooks (Discord, Slack, Telegram) when critical events are detected.
//!
//! ## Features
//! - Poll program accounts for authority state changes
//! - Detect authority transfers, revocations, and first-time upgrades
//! - Track historical authority changes with timestamps
//! - Deliver alerts via configurable webhooks

pub mod authority_watcher;
pub mod alerts;
pub mod indexer;
