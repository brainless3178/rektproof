//! CLI command implementations.
//!
//! Each command is implemented in its own sub-module for maintainability.
//! This replaces the previous monolithic `main.rs` approach.

pub mod helpers;
pub mod scan;
pub mod formal;
pub mod fuzz;
pub mod economic;

// Re-export command functions for use in main.rs
pub use helpers::*;
pub use scan::cmd_scan_repo;
pub use formal::cmd_verify_formal;
pub use fuzz::cmd_fuzz;
pub use economic::cmd_economic_verify;
