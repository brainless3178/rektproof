//! Attack flow sequences for ''
//! Multi-instruction patterns that model real-world attack scenarios.

use trident_fuzz::prelude::*;

/// Attack Flow: Init → Close → Re-Init (Re-initialization Attack)
/// Initializes, closes, and re-initializes to steal lamports.
pub fn attack_reinit_drain(trident: &mut TridentSVM, accounts: &mut FuzzAccounts) {
    let mut init = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = CreateUserAccountTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut close = HandleWithdrawTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = CreateUserAccountTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

}

