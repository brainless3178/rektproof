//! Attack flow sequences for ''
//! Multi-instruction patterns that model real-world attack scenarios.

use trident_fuzz::prelude::*;

/// Attack Flow: Double-Spend Attempt
/// Tries to execute the same transfer twice in rapid succession.
pub fn attack_double_spend(trident: &mut TridentSVM, accounts: &mut FuzzAccounts) {
    let mut tx1 = TransferAuthorityTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = TransferAuthorityTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = CloseEmptyTreeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = CloseEmptyTreeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = SetupGroupTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = SetupGroupTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = MakeWithdrawTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = MakeWithdrawTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = SwapBaseInputTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = SwapBaseInputTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = InitializeWithPermissionTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = InitializeWithPermissionTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = SwapBaseOutputTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = SwapBaseOutputTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = CollectCreatorFeeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = CollectCreatorFeeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = DepositTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = DepositTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = WithdrawTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = WithdrawTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = CollectProtocolFeeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = CollectProtocolFeeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = CollectFundFeeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = CollectFundFeeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = SwapBaseInputTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = SwapBaseInputTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = TransferLockedPositionTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = TransferLockedPositionTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = SetupMintTeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = SetupMintTeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = SetupAtaWithAmountTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = SetupAtaWithAmountTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = SpendingLimitUseTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = SpendingLimitUseTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = TransferMintAuthorityTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = TransferMintAuthorityTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = TransferDepositTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = TransferDepositTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = TransferPoolsTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = TransferPoolsTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = TransferPerpPositionTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = TransferPerpPositionTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = TransferIsolatedPerpPositionDepositTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = TransferIsolatedPerpPositionDepositTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = LiquidateSpotTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = LiquidateSpotTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = LiquidateBorrowForPerpPnlTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = LiquidateBorrowForPerpPnlTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = LiquidatePerpPnlForDepositTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = LiquidatePerpPnlForDepositTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = TransferProtocolIfSharesToRevenuePoolTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = TransferProtocolIfSharesToRevenuePoolTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = UpdatePerpMarketLpPoolFeeTransferScalarTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = UpdatePerpMarketLpPoolFeeTransferScalarTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = CalculateSettlementAmountTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = CalculateSettlementAmountTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = ValidateSettlementAmountTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = ValidateSettlementAmountTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = CalculateLpToPerpSettlementTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = CalculateLpToPerpSettlementTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = CalculatePerpToLpSettlementTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = CalculatePerpToLpSettlementTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleInitializeSpotMarketTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleInitializeSpotMarketTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleInitializePerpMarketTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleInitializePerpMarketTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleSettleExpiredMarketPoolsToRevenuePoolTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleSettleExpiredMarketPoolsToRevenuePoolTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleDepositIntoPerpMarketFeePoolTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleDepositIntoPerpMarketFeePoolTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleDepositIntoSpotMarketVaultTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleDepositIntoSpotMarketVaultTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleInitializeProtocolIfSharesTransferConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleInitializeProtocolIfSharesTransferConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleUpdateProtocolIfSharesTransferConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleUpdateProtocolIfSharesTransferConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleAdminDepositTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleAdminDepositTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleLpPoolRemoveLiquidityTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleLpPoolRemoveLiquidityTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleWithdrawFromProgramVaultTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleWithdrawFromProgramVaultTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleAddInsuranceFundStakeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleAddInsuranceFundStakeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleRemoveInsuranceFundStakeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleRemoveInsuranceFundStakeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleTransferProtocolIfSharesTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleTransferProtocolIfSharesTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleBeginInsuranceFundSwapTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleBeginInsuranceFundSwapTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleEndInsuranceFundSwapTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleEndInsuranceFundSwapTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleTransferProtocolIfSharesToRevenuePoolTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleTransferProtocolIfSharesToRevenuePoolTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleDepositIntoInsuranceFundStakeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleDepositIntoInsuranceFundStakeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleInitializeUserTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleInitializeUserTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleDepositTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleDepositTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleWithdrawTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleWithdrawTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleTransferDepositTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleTransferDepositTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleTransferPoolsTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleTransferPoolsTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleTransferPerpPositionTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleTransferPerpPositionTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleDepositIntoIsolatedPerpPositionTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleDepositIntoIsolatedPerpPositionTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleTransferIsolatedPerpPositionDepositTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleTransferIsolatedPerpPositionDepositTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleWithdrawFromIsolatedPerpPositionTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleWithdrawFromIsolatedPerpPositionTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleReclaimRentTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleReclaimRentTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleDepositIntoSpotMarketRevenuePoolTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleDepositIntoSpotMarketRevenuePoolTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleBeginSwapTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleBeginSwapTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleEndSwapTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleEndSwapTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleUpdatePerpMarketLpPoolFeeTransferScalarTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleUpdatePerpMarketLpPoolFeeTransferScalarTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleSettlePnlTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleSettlePnlTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleSettleMultiplePnlsTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleSettleMultiplePnlsTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleLiquidateSpotTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleLiquidateSpotTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleLiquidateSpotWithSwapBeginTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleLiquidateSpotWithSwapBeginTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleLiquidateSpotWithSwapEndTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleLiquidateSpotWithSwapEndTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleLiquidateBorrowForPerpPnlTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleLiquidateBorrowForPerpPnlTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleLiquidatePerpPnlForDepositTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleLiquidatePerpPnlForDepositTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleResolvePerpPnlDeficitTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleResolvePerpPnlDeficitTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleResolvePerpBankruptcyTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleResolvePerpBankruptcyTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleResolveSpotBankruptcyTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleResolveSpotBankruptcyTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleSettleRevenueToInsuranceFundTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleSettleRevenueToInsuranceFundTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleSettlePerpToLpPoolTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleSettlePerpToLpPoolTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = DepositTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = DepositTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = AddLiquidityTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = AddLiquidityTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = IsProvenSafeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = IsProvenSafeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandlerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = ConsumeVaaTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = ConsumeVaaTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = CreateAccountTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = CreateAccountTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = TransferFeesTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = TransferFeesTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = PostMessageInternalTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = PostMessageInternalTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = AttestTokenTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = AttestTokenTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = CompleteNativeWithPayloadTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = CompleteNativeWithPayloadTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = CompleteNativeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = CompleteNativeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = TransferNativeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = TransferNativeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = VerifyAndExecuteNativeTransfersTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = VerifyAndExecuteNativeTransfersTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = TransferWrappedTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = TransferWrappedTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = VerifyAndExecuteWrappedTransfersTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = VerifyAndExecuteWrappedTransfersTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = TransferNativeWithPayloadTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = TransferNativeWithPayloadTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = TransferWrappedWithPayloadTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = TransferWrappedWithPayloadTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = CompleteNativeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = CompleteNativeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = TransferNativeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = TransferNativeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = TransferWrappedTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = TransferWrappedTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = MigrateTokensTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = MigrateTokensTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = RemoveLiquidityTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = RemoveLiquidityTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = ClaimSharesTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = ClaimSharesTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = AddLiquidityTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = AddLiquidityTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = TransferAuthorityTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = TransferAuthorityTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = CloseEmptyTreeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = CloseEmptyTreeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = SetupGroupTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = SetupGroupTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = MakeWithdrawTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = MakeWithdrawTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleTokenWithdrawTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleTokenWithdrawTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = TransferTokensTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = TransferTokensTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = DelegateTransferTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = DelegateTransferTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = ProposeAuthorityTransferTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = ProposeAuthorityTransferTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = AcceptAuthorityTransferTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = AcceptAuthorityTransferTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = CancelAuthorityTransferTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = CancelAuthorityTransferTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = ProposeAuthorityTransferTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = ProposeAuthorityTransferTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = AcceptAuthorityTransferTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = AcceptAuthorityTransferTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = CancelAuthorityTransferTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = CancelAuthorityTransferTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

}

/// Attack Flow: Init → Close → Re-Init (Re-initialization Attack)
/// Initializes, closes, and re-initializes to steal lamports.
pub fn attack_reinit_drain(trident: &mut TridentSVM, accounts: &mut FuzzAccounts) {
    let mut init = InitEmptyMerkleTreeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitPreparedTreeWithRootTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = CreateAmmConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = CreatePermissionPdaTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeWithPermissionTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeWithPermissionTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = CreatePermissionPdaTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = CreateAmmConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializePoolTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeTickArrayTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeDynamicTickArrayTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeFeeTierTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeRewardTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializePositionBundleTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializePositionBundleWithMetadataTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeAdaptiveFeeTierTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = SetInitializePoolAuthorityTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializePoolWithAdaptiveFeeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializePoolV2Transaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeRewardV2Transaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeConfigExtensionTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeTokenBadgeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitTickArraysForRangeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = ProgramConfigInitTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = MultisigCreateTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = MultisigCreateV2Transaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = ConfigTransactionCreateTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = VaultTransactionCreateTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = TransactionBufferCreateTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = VaultTransactionCreateFromBufferTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = BatchCreateTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = ProposalCreateTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = CreateMultisigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeUserTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeUserStatsTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeSignedMsgUserOrdersTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeSignedMsgWsDelegatesTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeFuelOverflowTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeReferrerNameTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeInsuranceFundStakeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeSpotMarketTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = DeleteInitializedSpotMarketTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeSerumFulfillmentConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeOpenbookV2FulfillmentConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializePhoenixFulfillmentConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializePerpMarketTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeAmmCacheTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = UpdateInitialAmmCacheInfoTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializePredictionMarketTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = DeleteInitializedPerpMarketTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = UpdateSpotMarketScaleInitialAssetWeightStartTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = UpdateInitialPctToLiquidateTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = UpdateStateMaxInitializeUserFeeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializePrelaunchOracleTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializePythPullOracleTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializePythLazerOracleTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeHighLeverageModeConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeProtectedMakerModeConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeIfRebalanceConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeRevenueShareTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeRevenueShareEscrowTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeLpPoolTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeConstituentTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitializeSpotMarketTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitializeSerumFulfillmentConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitializeOpenbookV2FulfillmentConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitializePhoenixFulfillmentConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitializePerpMarketTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitializeAmmCacheTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitializePredictionMarketTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleDeleteInitializedPerpMarketTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleDeleteInitializedSpotMarketTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitUserFuelTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleUpdateSpotMarketScaleInitialAssetWeightStartTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleUpdateInitialPctToLiquidateTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleUpdateStateMaxInitializeUserFeeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitializeProtocolIfSharesTransferConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitializePrelaunchOracleTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitializePythPullOracleTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitializePythLazerOracleTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitializeHighLeverageModeConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitializeProtectedMakerModeConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitializeIfRebalanceConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitializeInsuranceFundStakeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitializeUserTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitializeUserStatsTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitializeReferrerNameTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitializeSignedMsgUserOrdersTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitializeSignedMsgWsDelegatesTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitializeFuelOverflowTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitializeRevenueShareTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitializeRevenueShareEscrowTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitializeLpPoolTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleInitializeConstituentTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = HandleUpdateInitialAmmCacheInfoTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = CreateMarketTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = CreateOpenOrdersIndexerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = CreateOpenOrdersAccountTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = CreateAccountTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = CreateWrappedTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = CreateWrappedAccountTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = CreateWrappedTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = CreateAccountsTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = CreatePoolTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitEmptyMerkleTreeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitPreparedTreeWithRootTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = CreateUserAccountTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut close = CloseEmptyTreeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = MakeWithdrawTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = ClosePermissionPdaTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = WithdrawTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = WithdrawTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = ClosePermissionPdaTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = ClosePositionTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = CloseBundledPositionTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = ClosePositionWithTokenExtensionsTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = TransactionBufferCloseTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = ConfigTransactionAccountsCloseTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = VaultTransactionAccountsCloseTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = VaultBatchTransactionAccountCloseTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = BatchAccountsCloseTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = WithdrawTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = WithdrawFromIsolatedPerpPositionTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = PauseSpotMarketDepositWithdrawTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = UpdateWithdrawGuardThresholdTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = WithdrawFromProgramVaultTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = HandleUpdateWithdrawGuardThresholdTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = HandleWithdrawFromProgramVaultTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = HandleWithdrawTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = HandleWithdrawFromIsolatedPerpPositionTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = HandlePauseSpotMarketDepositWithdrawTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = WithdrawStakeAccountTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = WithdrawAuthorFeeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = CloseSignaturesTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = CloseEmptyTreeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = MakeWithdrawTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = HandleTokenWithdrawTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = WithdrawOneTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = WithdrawTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = EmergencyWithdrawTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = HandleWithdrawTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitEmptyMerkleTreeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitPreparedTreeWithRootTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = CreateAmmConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = CreatePermissionPdaTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeWithPermissionTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeWithPermissionTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = CreatePermissionPdaTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = CreateAmmConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializePoolTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeTickArrayTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeDynamicTickArrayTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeFeeTierTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeRewardTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializePositionBundleTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializePositionBundleWithMetadataTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeAdaptiveFeeTierTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = SetInitializePoolAuthorityTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializePoolWithAdaptiveFeeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializePoolV2Transaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeRewardV2Transaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeConfigExtensionTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeTokenBadgeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitTickArraysForRangeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = ProgramConfigInitTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = MultisigCreateTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = MultisigCreateV2Transaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = ConfigTransactionCreateTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = VaultTransactionCreateTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = TransactionBufferCreateTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = VaultTransactionCreateFromBufferTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = BatchCreateTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = ProposalCreateTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = CreateMultisigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeUserTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeUserStatsTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeSignedMsgUserOrdersTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeSignedMsgWsDelegatesTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeFuelOverflowTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeReferrerNameTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeInsuranceFundStakeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeSpotMarketTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = DeleteInitializedSpotMarketTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeSerumFulfillmentConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeOpenbookV2FulfillmentConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializePhoenixFulfillmentConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializePerpMarketTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeAmmCacheTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = UpdateInitialAmmCacheInfoTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializePredictionMarketTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = DeleteInitializedPerpMarketTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = UpdateSpotMarketScaleInitialAssetWeightStartTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = UpdateInitialPctToLiquidateTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = UpdateStateMaxInitializeUserFeeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializePrelaunchOracleTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializePythPullOracleTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializePythLazerOracleTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeHighLeverageModeConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeProtectedMakerModeConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeIfRebalanceConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeRevenueShareTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeRevenueShareEscrowTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeLpPoolTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeConstituentTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitializeSpotMarketTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitializeSerumFulfillmentConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitializeOpenbookV2FulfillmentConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitializePhoenixFulfillmentConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitializePerpMarketTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitializeAmmCacheTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitializePredictionMarketTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleDeleteInitializedPerpMarketTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleDeleteInitializedSpotMarketTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitUserFuelTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleUpdateSpotMarketScaleInitialAssetWeightStartTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleUpdateInitialPctToLiquidateTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleUpdateStateMaxInitializeUserFeeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitializeProtocolIfSharesTransferConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitializePrelaunchOracleTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitializePythPullOracleTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitializePythLazerOracleTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitializeHighLeverageModeConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitializeProtectedMakerModeConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitializeIfRebalanceConfigTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitializeInsuranceFundStakeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitializeUserTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitializeUserStatsTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitializeReferrerNameTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitializeSignedMsgUserOrdersTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitializeSignedMsgWsDelegatesTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitializeFuelOverflowTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitializeRevenueShareTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitializeRevenueShareEscrowTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitializeLpPoolTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleInitializeConstituentTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = HandleUpdateInitialAmmCacheInfoTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = CreateMarketTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = CreateOpenOrdersIndexerTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = CreateOpenOrdersAccountTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = CreateAccountTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = CreateWrappedTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = CreateWrappedAccountTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = CreateWrappedTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = CreateAccountsTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = CreatePoolTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitEmptyMerkleTreeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitPreparedTreeWithRootTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = CreateUserAccountTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

}

/// Attack Flow: Privilege Escalation
/// Attempts to call admin functions with non-admin accounts.
pub fn attack_privilege_escalation(trident: &mut TridentSVM, accounts: &mut FuzzAccounts) {
    // Call 'setup_group' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetupGroupTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_setup_group"));
    assert!(result.is_err(), "Admin function 'setup_group' accepted non-admin signer!");

    // Call 'update_amm_config' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateAmmConfigTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_amm_config"));
    assert!(result.is_err(), "Admin function 'update_amm_config' accepted non-admin signer!");

    // Call 'update_pool_status' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePoolStatusTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_pool_status"));
    assert!(result.is_err(), "Admin function 'update_pool_status' accepted non-admin signer!");

    // Call 'update_pool_status' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePoolStatusTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_pool_status"));
    assert!(result.is_err(), "Admin function 'update_pool_status' accepted non-admin signer!");

    // Call 'update_amm_config' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateAmmConfigTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_amm_config"));
    assert!(result.is_err(), "Admin function 'update_amm_config' accepted non-admin signer!");

    // Call 'set_reward_emissions' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetRewardEmissionsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_reward_emissions"));
    assert!(result.is_err(), "Admin function 'set_reward_emissions' accepted non-admin signer!");

    // Call 'update_fees_and_rewards' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateFeesAndRewardsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_fees_and_rewards"));
    assert!(result.is_err(), "Admin function 'update_fees_and_rewards' accepted non-admin signer!");

    // Call 'set_default_fee_rate' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetDefaultFeeRateTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_default_fee_rate"));
    assert!(result.is_err(), "Admin function 'set_default_fee_rate' accepted non-admin signer!");

    // Call 'set_default_protocol_fee_rate' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetDefaultProtocolFeeRateTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_default_protocol_fee_rate"));
    assert!(result.is_err(), "Admin function 'set_default_protocol_fee_rate' accepted non-admin signer!");

    // Call 'set_fee_rate' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetFeeRateTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_fee_rate"));
    assert!(result.is_err(), "Admin function 'set_fee_rate' accepted non-admin signer!");

    // Call 'set_protocol_fee_rate' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetProtocolFeeRateTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_protocol_fee_rate"));
    assert!(result.is_err(), "Admin function 'set_protocol_fee_rate' accepted non-admin signer!");

    // Call 'set_fee_authority' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetFeeAuthorityTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_fee_authority"));
    assert!(result.is_err(), "Admin function 'set_fee_authority' accepted non-admin signer!");

    // Call 'set_collect_protocol_fees_authority' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetCollectProtocolFeesAuthorityTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_collect_protocol_fees_authority"));
    assert!(result.is_err(), "Admin function 'set_collect_protocol_fees_authority' accepted non-admin signer!");

    // Call 'set_reward_authority' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetRewardAuthorityTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_reward_authority"));
    assert!(result.is_err(), "Admin function 'set_reward_authority' accepted non-admin signer!");

    // Call 'set_reward_authority_by_super_authority' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetRewardAuthorityBySuperAuthorityTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_reward_authority_by_super_authority"));
    assert!(result.is_err(), "Admin function 'set_reward_authority_by_super_authority' accepted non-admin signer!");

    // Call 'set_reward_emissions_super_authority' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetRewardEmissionsSuperAuthorityTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_reward_emissions_super_authority"));
    assert!(result.is_err(), "Admin function 'set_reward_emissions_super_authority' accepted non-admin signer!");

    // Call 'reset_position_range' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = ResetPositionRangeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_reset_position_range"));
    assert!(result.is_err(), "Admin function 'reset_position_range' accepted non-admin signer!");

    // Call 'set_default_base_fee_rate' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetDefaultBaseFeeRateTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_default_base_fee_rate"));
    assert!(result.is_err(), "Admin function 'set_default_base_fee_rate' accepted non-admin signer!");

    // Call 'set_delegated_fee_authority' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetDelegatedFeeAuthorityTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_delegated_fee_authority"));
    assert!(result.is_err(), "Admin function 'set_delegated_fee_authority' accepted non-admin signer!");

    // Call 'set_initialize_pool_authority' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetInitializePoolAuthorityTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_initialize_pool_authority"));
    assert!(result.is_err(), "Admin function 'set_initialize_pool_authority' accepted non-admin signer!");

    // Call 'set_preset_adaptive_fee_constants' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetPresetAdaptiveFeeConstantsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_preset_adaptive_fee_constants"));
    assert!(result.is_err(), "Admin function 'set_preset_adaptive_fee_constants' accepted non-admin signer!");

    // Call 'set_fee_rate_by_delegated_fee_authority' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetFeeRateByDelegatedFeeAuthorityTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_fee_rate_by_delegated_fee_authority"));
    assert!(result.is_err(), "Admin function 'set_fee_rate_by_delegated_fee_authority' accepted non-admin signer!");

    // Call 'set_adaptive_fee_constants' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetAdaptiveFeeConstantsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_adaptive_fee_constants"));
    assert!(result.is_err(), "Admin function 'set_adaptive_fee_constants' accepted non-admin signer!");

    // Call 'set_config_feature_flag' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetConfigFeatureFlagTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_config_feature_flag"));
    assert!(result.is_err(), "Admin function 'set_config_feature_flag' accepted non-admin signer!");

    // Call 'set_reward_emissions_v2' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetRewardEmissionsV2Transaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_reward_emissions_v2"));
    assert!(result.is_err(), "Admin function 'set_reward_emissions_v2' accepted non-admin signer!");

    // Call 'set_config_extension_authority' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetConfigExtensionAuthorityTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_config_extension_authority"));
    assert!(result.is_err(), "Admin function 'set_config_extension_authority' accepted non-admin signer!");

    // Call 'set_token_badge_authority' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetTokenBadgeAuthorityTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_token_badge_authority"));
    assert!(result.is_err(), "Admin function 'set_token_badge_authority' accepted non-admin signer!");

    // Call 'set_token_badge_attribute' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetTokenBadgeAttributeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_token_badge_attribute"));
    assert!(result.is_err(), "Admin function 'set_token_badge_attribute' accepted non-admin signer!");

    // Call 'setup_all_mints' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetupAllMintsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_setup_all_mints"));
    assert!(result.is_err(), "Admin function 'setup_all_mints' accepted non-admin signer!");

    // Call 'setup_all_atas' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetupAllAtasTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_setup_all_atas"));
    assert!(result.is_err(), "Admin function 'setup_all_atas' accepted non-admin signer!");

    // Call 'setup_whirlpool' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetupWhirlpoolTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_setup_whirlpool"));
    assert!(result.is_err(), "Admin function 'setup_whirlpool' accepted non-admin signer!");

    // Call 'setup_position' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetupPositionTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_setup_position"));
    assert!(result.is_err(), "Admin function 'setup_position' accepted non-admin signer!");

    // Call 'setup_te_position' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetupTePositionTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_setup_te_position"));
    assert!(result.is_err(), "Admin function 'setup_te_position' accepted non-admin signer!");

    // Call 'setup_position_bundle' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetupPositionBundleTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_setup_position_bundle"));
    assert!(result.is_err(), "Admin function 'setup_position_bundle' accepted non-admin signer!");

    // Call 'setup_mint_te' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetupMintTeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_setup_mint_te"));
    assert!(result.is_err(), "Admin function 'setup_mint_te' accepted non-admin signer!");

    // Call 'setup_mint_te_fee' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetupMintTeFeeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_setup_mint_te_fee"));
    assert!(result.is_err(), "Admin function 'setup_mint_te_fee' accepted non-admin signer!");

    // Call 'setup_mint_te_sua' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetupMintTeSuaTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_setup_mint_te_sua"));
    assert!(result.is_err(), "Admin function 'setup_mint_te_sua' accepted non-admin signer!");

    // Call 'setup_ata_te' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetupAtaTeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_setup_ata_te"));
    assert!(result.is_err(), "Admin function 'setup_ata_te' accepted non-admin signer!");

    // Call 'setup_ata' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetupAtaTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_setup_ata"));
    assert!(result.is_err(), "Admin function 'setup_ata' accepted non-admin signer!");

    // Call 'setup_ata_with_amount' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetupAtaWithAmountTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_setup_ata_with_amount"));
    assert!(result.is_err(), "Admin function 'setup_ata_with_amount' accepted non-admin signer!");

    // Call 'setup_mint' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetupMintTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_setup_mint"));
    assert!(result.is_err(), "Admin function 'setup_mint' accepted non-admin signer!");

    // Call 'setup_mint_with_decimals' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetupMintWithDecimalsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_setup_mint_with_decimals"));
    assert!(result.is_err(), "Admin function 'setup_mint_with_decimals' accepted non-admin signer!");

    // Call 'setup_all_mints' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetupAllMintsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_setup_all_mints"));
    assert!(result.is_err(), "Admin function 'setup_all_mints' accepted non-admin signer!");

    // Call 'setup_all_atas' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetupAllAtasTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_setup_all_atas"));
    assert!(result.is_err(), "Admin function 'setup_all_atas' accepted non-admin signer!");

    // Call 'setup_all_mints' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetupAllMintsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_setup_all_mints"));
    assert!(result.is_err(), "Admin function 'setup_all_mints' accepted non-admin signer!");

    // Call 'setup_all_atas' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetupAllAtasTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_setup_all_atas"));
    assert!(result.is_err(), "Admin function 'setup_all_atas' accepted non-admin signer!");

    // Call 'setup_all_mints' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetupAllMintsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_setup_all_mints"));
    assert!(result.is_err(), "Admin function 'setup_all_mints' accepted non-admin signer!");

    // Call 'setup_all_atas' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetupAllAtasTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_setup_all_atas"));
    assert!(result.is_err(), "Admin function 'setup_all_atas' accepted non-admin signer!");

    // Call 'program_config_set_authority' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = ProgramConfigSetAuthorityTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_program_config_set_authority"));
    assert!(result.is_err(), "Admin function 'program_config_set_authority' accepted non-admin signer!");

    // Call 'program_config_set_multisig_creation_fee' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = ProgramConfigSetMultisigCreationFeeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_program_config_set_multisig_creation_fee"));
    assert!(result.is_err(), "Admin function 'program_config_set_multisig_creation_fee' accepted non-admin signer!");

    // Call 'program_config_set_treasury' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = ProgramConfigSetTreasuryTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_program_config_set_treasury"));
    assert!(result.is_err(), "Admin function 'program_config_set_treasury' accepted non-admin signer!");

    // Call 'multisig_set_time_lock' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = MultisigSetTimeLockTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_multisig_set_time_lock"));
    assert!(result.is_err(), "Admin function 'multisig_set_time_lock' accepted non-admin signer!");

    // Call 'multisig_set_config_authority' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = MultisigSetConfigAuthorityTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_multisig_set_config_authority"));
    assert!(result.is_err(), "Admin function 'multisig_set_config_authority' accepted non-admin signer!");

    // Call 'multisig_set_rent_collector' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = MultisigSetRentCollectorTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_multisig_set_rent_collector"));
    assert!(result.is_err(), "Admin function 'multisig_set_rent_collector' accepted non-admin signer!");

    // Call 'set_price' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetPriceTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_price"));
    assert!(result.is_err(), "Admin function 'set_price' accepted non-admin signer!");

    // Call 'set_price_info' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetPriceInfoTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_price_info"));
    assert!(result.is_err(), "Admin function 'set_price_info' accepted non-admin signer!");

    // Call 'set_twap' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetTwapTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_twap"));
    assert!(result.is_err(), "Admin function 'set_twap' accepted non-admin signer!");

    // Call 'reset_fuel_season' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = ResetFuelSeasonTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_reset_fuel_season"));
    assert!(result.is_err(), "Admin function 'reset_fuel_season' accepted non-admin signer!");

    // Call 'update_user_name' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateUserNameTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_user_name"));
    assert!(result.is_err(), "Admin function 'update_user_name' accepted non-admin signer!");

    // Call 'update_user_custom_margin_ratio' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateUserCustomMarginRatioTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_user_custom_margin_ratio"));
    assert!(result.is_err(), "Admin function 'update_user_custom_margin_ratio' accepted non-admin signer!");

    // Call 'update_user_perp_position_custom_margin_ratio' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateUserPerpPositionCustomMarginRatioTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_user_perp_position_custom_margin_ratio"));
    assert!(result.is_err(), "Admin function 'update_user_perp_position_custom_margin_ratio' accepted non-admin signer!");

    // Call 'update_user_margin_trading_enabled' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateUserMarginTradingEnabledTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_user_margin_trading_enabled"));
    assert!(result.is_err(), "Admin function 'update_user_margin_trading_enabled' accepted non-admin signer!");

    // Call 'update_user_pool_id' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateUserPoolIdTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_user_pool_id"));
    assert!(result.is_err(), "Admin function 'update_user_pool_id' accepted non-admin signer!");

    // Call 'update_user_delegate' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateUserDelegateTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_user_delegate"));
    assert!(result.is_err(), "Admin function 'update_user_delegate' accepted non-admin signer!");

    // Call 'update_user_reduce_only' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateUserReduceOnlyTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_user_reduce_only"));
    assert!(result.is_err(), "Admin function 'update_user_reduce_only' accepted non-admin signer!");

    // Call 'update_user_protected_maker_orders' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateUserProtectedMakerOrdersTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_user_protected_maker_orders"));
    assert!(result.is_err(), "Admin function 'update_user_protected_maker_orders' accepted non-admin signer!");

    // Call 'update_user_idle' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateUserIdleTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_user_idle"));
    assert!(result.is_err(), "Admin function 'update_user_idle' accepted non-admin signer!");

    // Call 'update_user_stats_referrer_status' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateUserStatsReferrerStatusTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_user_stats_referrer_status"));
    assert!(result.is_err(), "Admin function 'update_user_stats_referrer_status' accepted non-admin signer!");

    // Call 'admin_update_user_stats_paused_operations' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = AdminUpdateUserStatsPausedOperationsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_admin_update_user_stats_paused_operations"));
    assert!(result.is_err(), "Admin function 'admin_update_user_stats_paused_operations' accepted non-admin signer!");

    // Call 'settle_pnl' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SettlePnlTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_settle_pnl"));
    assert!(result.is_err(), "Admin function 'settle_pnl' accepted non-admin signer!");

    // Call 'settle_multiple_pnls' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SettleMultiplePnlsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_settle_multiple_pnls"));
    assert!(result.is_err(), "Admin function 'settle_multiple_pnls' accepted non-admin signer!");

    // Call 'settle_funding_payment' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SettleFundingPaymentTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_settle_funding_payment"));
    assert!(result.is_err(), "Admin function 'settle_funding_payment' accepted non-admin signer!");

    // Call 'settle_expired_market' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SettleExpiredMarketTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_settle_expired_market"));
    assert!(result.is_err(), "Admin function 'settle_expired_market' accepted non-admin signer!");

    // Call 'set_user_status_to_being_liquidated' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetUserStatusToBeingLiquidatedTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_user_status_to_being_liquidated"));
    assert!(result.is_err(), "Admin function 'set_user_status_to_being_liquidated' accepted non-admin signer!");

    // Call 'settle_revenue_to_insurance_fund' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SettleRevenueToInsuranceFundTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_settle_revenue_to_insurance_fund"));
    assert!(result.is_err(), "Admin function 'settle_revenue_to_insurance_fund' accepted non-admin signer!");

    // Call 'update_funding_rate' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateFundingRateTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_funding_rate"));
    assert!(result.is_err(), "Admin function 'update_funding_rate' accepted non-admin signer!");

    // Call 'update_prelaunch_oracle' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePrelaunchOracleTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_prelaunch_oracle"));
    assert!(result.is_err(), "Admin function 'update_prelaunch_oracle' accepted non-admin signer!");

    // Call 'update_perp_bid_ask_twap' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpBidAskTwapTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_bid_ask_twap"));
    assert!(result.is_err(), "Admin function 'update_perp_bid_ask_twap' accepted non-admin signer!");

    // Call 'update_spot_market_cumulative_interest' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateSpotMarketCumulativeInterestTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_spot_market_cumulative_interest"));
    assert!(result.is_err(), "Admin function 'update_spot_market_cumulative_interest' accepted non-admin signer!");

    // Call 'update_amms' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateAmmsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_amms"));
    assert!(result.is_err(), "Admin function 'update_amms' accepted non-admin signer!");

    // Call 'update_spot_market_expiry' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateSpotMarketExpiryTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_spot_market_expiry"));
    assert!(result.is_err(), "Admin function 'update_spot_market_expiry' accepted non-admin signer!");

    // Call 'update_user_quote_asset_insurance_stake' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateUserQuoteAssetInsuranceStakeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_user_quote_asset_insurance_stake"));
    assert!(result.is_err(), "Admin function 'update_user_quote_asset_insurance_stake' accepted non-admin signer!");

    // Call 'update_user_gov_token_insurance_stake' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateUserGovTokenInsuranceStakeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_user_gov_token_insurance_stake"));
    assert!(result.is_err(), "Admin function 'update_user_gov_token_insurance_stake' accepted non-admin signer!");

    // Call 'update_delegate_user_gov_token_insurance_stake' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateDelegateUserGovTokenInsuranceStakeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_delegate_user_gov_token_insurance_stake"));
    assert!(result.is_err(), "Admin function 'update_delegate_user_gov_token_insurance_stake' accepted non-admin signer!");

    // Call 'update_pyth_pull_oracle' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePythPullOracleTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_pyth_pull_oracle"));
    assert!(result.is_err(), "Admin function 'update_pyth_pull_oracle' accepted non-admin signer!");

    // Call 'post_pyth_pull_oracle_update_atomic' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = PostPythPullOracleUpdateAtomicTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_post_pyth_pull_oracle_update_atomic"));
    assert!(result.is_err(), "Admin function 'post_pyth_pull_oracle_update_atomic' accepted non-admin signer!");

    // Call 'post_multi_pyth_pull_oracle_updates_atomic' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = PostMultiPythPullOracleUpdatesAtomicTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_post_multi_pyth_pull_oracle_updates_atomic"));
    assert!(result.is_err(), "Admin function 'post_multi_pyth_pull_oracle_updates_atomic' accepted non-admin signer!");

    // Call 'update_serum_fulfillment_config_status' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateSerumFulfillmentConfigStatusTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_serum_fulfillment_config_status"));
    assert!(result.is_err(), "Admin function 'update_serum_fulfillment_config_status' accepted non-admin signer!");

    // Call 'update_initial_amm_cache_info' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateInitialAmmCacheInfoTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_initial_amm_cache_info"));
    assert!(result.is_err(), "Admin function 'update_initial_amm_cache_info' accepted non-admin signer!");

    // Call 'update_perp_market_amm_summary_stats' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketAmmSummaryStatsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_amm_summary_stats"));
    assert!(result.is_err(), "Admin function 'update_perp_market_amm_summary_stats' accepted non-admin signer!");

    // Call 'update_perp_market_expiry' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketExpiryTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_expiry"));
    assert!(result.is_err(), "Admin function 'update_perp_market_expiry' accepted non-admin signer!");

    // Call 'update_perp_market_lp_pool_paused_operations' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketLpPoolPausedOperationsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_lp_pool_paused_operations"));
    assert!(result.is_err(), "Admin function 'update_perp_market_lp_pool_paused_operations' accepted non-admin signer!");

    // Call 'update_perp_market_lp_pool_status' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketLpPoolStatusTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_lp_pool_status"));
    assert!(result.is_err(), "Admin function 'update_perp_market_lp_pool_status' accepted non-admin signer!");

    // Call 'update_perp_market_lp_pool_fee_transfer_scalar' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketLpPoolFeeTransferScalarTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_lp_pool_fee_transfer_scalar"));
    assert!(result.is_err(), "Admin function 'update_perp_market_lp_pool_fee_transfer_scalar' accepted non-admin signer!");

    // Call 'settle_expired_market_pools_to_revenue_pool' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SettleExpiredMarketPoolsToRevenuePoolTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_settle_expired_market_pools_to_revenue_pool"));
    assert!(result.is_err(), "Admin function 'settle_expired_market_pools_to_revenue_pool' accepted non-admin signer!");

    // Call 'update_perp_market_pnl_pool' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketPnlPoolTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_pnl_pool"));
    assert!(result.is_err(), "Admin function 'update_perp_market_pnl_pool' accepted non-admin signer!");

    // Call 'update_perp_market_amm_oracle_twap' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketAmmOracleTwapTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_amm_oracle_twap"));
    assert!(result.is_err(), "Admin function 'update_perp_market_amm_oracle_twap' accepted non-admin signer!");

    // Call 'reset_perp_market_amm_oracle_twap' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = ResetPerpMarketAmmOracleTwapTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_reset_perp_market_amm_oracle_twap"));
    assert!(result.is_err(), "Admin function 'reset_perp_market_amm_oracle_twap' accepted non-admin signer!");

    // Call 'update_k' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateKTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_k"));
    assert!(result.is_err(), "Admin function 'update_k' accepted non-admin signer!");

    // Call 'update_perp_market_margin_ratio' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketMarginRatioTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_margin_ratio"));
    assert!(result.is_err(), "Admin function 'update_perp_market_margin_ratio' accepted non-admin signer!");

    // Call 'update_perp_market_high_leverage_margin_ratio' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketHighLeverageMarginRatioTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_high_leverage_margin_ratio"));
    assert!(result.is_err(), "Admin function 'update_perp_market_high_leverage_margin_ratio' accepted non-admin signer!");

    // Call 'update_perp_market_funding_period' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketFundingPeriodTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_funding_period"));
    assert!(result.is_err(), "Admin function 'update_perp_market_funding_period' accepted non-admin signer!");

    // Call 'update_perp_market_max_imbalances' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketMaxImbalancesTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_max_imbalances"));
    assert!(result.is_err(), "Admin function 'update_perp_market_max_imbalances' accepted non-admin signer!");

    // Call 'update_perp_market_liquidation_fee' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketLiquidationFeeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_liquidation_fee"));
    assert!(result.is_err(), "Admin function 'update_perp_market_liquidation_fee' accepted non-admin signer!");

    // Call 'update_perp_market_lp_pool_id' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketLpPoolIdTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_lp_pool_id"));
    assert!(result.is_err(), "Admin function 'update_perp_market_lp_pool_id' accepted non-admin signer!");

    // Call 'update_insurance_fund_unstaking_period' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateInsuranceFundUnstakingPeriodTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_insurance_fund_unstaking_period"));
    assert!(result.is_err(), "Admin function 'update_insurance_fund_unstaking_period' accepted non-admin signer!");

    // Call 'update_spot_market_pool_id' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateSpotMarketPoolIdTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_spot_market_pool_id"));
    assert!(result.is_err(), "Admin function 'update_spot_market_pool_id' accepted non-admin signer!");

    // Call 'update_spot_market_liquidation_fee' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateSpotMarketLiquidationFeeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_spot_market_liquidation_fee"));
    assert!(result.is_err(), "Admin function 'update_spot_market_liquidation_fee' accepted non-admin signer!");

    // Call 'update_withdraw_guard_threshold' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateWithdrawGuardThresholdTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_withdraw_guard_threshold"));
    assert!(result.is_err(), "Admin function 'update_withdraw_guard_threshold' accepted non-admin signer!");

    // Call 'update_spot_market_if_factor' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateSpotMarketIfFactorTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_spot_market_if_factor"));
    assert!(result.is_err(), "Admin function 'update_spot_market_if_factor' accepted non-admin signer!");

    // Call 'update_spot_market_revenue_settle_period' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateSpotMarketRevenueSettlePeriodTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_spot_market_revenue_settle_period"));
    assert!(result.is_err(), "Admin function 'update_spot_market_revenue_settle_period' accepted non-admin signer!");

    // Call 'update_spot_market_status' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateSpotMarketStatusTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_spot_market_status"));
    assert!(result.is_err(), "Admin function 'update_spot_market_status' accepted non-admin signer!");

    // Call 'update_spot_market_paused_operations' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateSpotMarketPausedOperationsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_spot_market_paused_operations"));
    assert!(result.is_err(), "Admin function 'update_spot_market_paused_operations' accepted non-admin signer!");

    // Call 'update_spot_market_asset_tier' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateSpotMarketAssetTierTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_spot_market_asset_tier"));
    assert!(result.is_err(), "Admin function 'update_spot_market_asset_tier' accepted non-admin signer!");

    // Call 'update_spot_market_margin_weights' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateSpotMarketMarginWeightsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_spot_market_margin_weights"));
    assert!(result.is_err(), "Admin function 'update_spot_market_margin_weights' accepted non-admin signer!");

    // Call 'update_spot_market_borrow_rate' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateSpotMarketBorrowRateTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_spot_market_borrow_rate"));
    assert!(result.is_err(), "Admin function 'update_spot_market_borrow_rate' accepted non-admin signer!");

    // Call 'update_spot_market_max_token_deposits' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateSpotMarketMaxTokenDepositsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_spot_market_max_token_deposits"));
    assert!(result.is_err(), "Admin function 'update_spot_market_max_token_deposits' accepted non-admin signer!");

    // Call 'update_spot_market_max_token_borrows' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateSpotMarketMaxTokenBorrowsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_spot_market_max_token_borrows"));
    assert!(result.is_err(), "Admin function 'update_spot_market_max_token_borrows' accepted non-admin signer!");

    // Call 'update_spot_market_scale_initial_asset_weight_start' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateSpotMarketScaleInitialAssetWeightStartTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_spot_market_scale_initial_asset_weight_start"));
    assert!(result.is_err(), "Admin function 'update_spot_market_scale_initial_asset_weight_start' accepted non-admin signer!");

    // Call 'update_spot_market_oracle' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateSpotMarketOracleTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_spot_market_oracle"));
    assert!(result.is_err(), "Admin function 'update_spot_market_oracle' accepted non-admin signer!");

    // Call 'update_spot_market_step_size_and_tick_size' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateSpotMarketStepSizeAndTickSizeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_spot_market_step_size_and_tick_size"));
    assert!(result.is_err(), "Admin function 'update_spot_market_step_size_and_tick_size' accepted non-admin signer!");

    // Call 'update_spot_market_min_order_size' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateSpotMarketMinOrderSizeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_spot_market_min_order_size"));
    assert!(result.is_err(), "Admin function 'update_spot_market_min_order_size' accepted non-admin signer!");

    // Call 'update_spot_market_orders_enabled' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateSpotMarketOrdersEnabledTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_spot_market_orders_enabled"));
    assert!(result.is_err(), "Admin function 'update_spot_market_orders_enabled' accepted non-admin signer!");

    // Call 'update_spot_market_if_paused_operations' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateSpotMarketIfPausedOperationsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_spot_market_if_paused_operations"));
    assert!(result.is_err(), "Admin function 'update_spot_market_if_paused_operations' accepted non-admin signer!");

    // Call 'update_spot_market_name' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateSpotMarketNameTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_spot_market_name"));
    assert!(result.is_err(), "Admin function 'update_spot_market_name' accepted non-admin signer!");

    // Call 'update_perp_market_status' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketStatusTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_status"));
    assert!(result.is_err(), "Admin function 'update_perp_market_status' accepted non-admin signer!");

    // Call 'update_perp_market_paused_operations' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketPausedOperationsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_paused_operations"));
    assert!(result.is_err(), "Admin function 'update_perp_market_paused_operations' accepted non-admin signer!");

    // Call 'update_perp_market_contract_tier' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketContractTierTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_contract_tier"));
    assert!(result.is_err(), "Admin function 'update_perp_market_contract_tier' accepted non-admin signer!");

    // Call 'update_perp_market_imf_factor' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketImfFactorTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_imf_factor"));
    assert!(result.is_err(), "Admin function 'update_perp_market_imf_factor' accepted non-admin signer!");

    // Call 'update_perp_market_unrealized_asset_weight' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketUnrealizedAssetWeightTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_unrealized_asset_weight"));
    assert!(result.is_err(), "Admin function 'update_perp_market_unrealized_asset_weight' accepted non-admin signer!");

    // Call 'update_perp_market_concentration_coef' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketConcentrationCoefTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_concentration_coef"));
    assert!(result.is_err(), "Admin function 'update_perp_market_concentration_coef' accepted non-admin signer!");

    // Call 'update_perp_market_curve_update_intensity' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketCurveUpdateIntensityTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_curve_update_intensity"));
    assert!(result.is_err(), "Admin function 'update_perp_market_curve_update_intensity' accepted non-admin signer!");

    // Call 'update_perp_market_reference_price_offset_deadband_pct' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketReferencePriceOffsetDeadbandPctTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_reference_price_offset_deadband_pct"));
    assert!(result.is_err(), "Admin function 'update_perp_market_reference_price_offset_deadband_pct' accepted non-admin signer!");

    // Call 'update_perp_fee_structure' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpFeeStructureTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_fee_structure"));
    assert!(result.is_err(), "Admin function 'update_perp_fee_structure' accepted non-admin signer!");

    // Call 'update_spot_fee_structure' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateSpotFeeStructureTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_spot_fee_structure"));
    assert!(result.is_err(), "Admin function 'update_spot_fee_structure' accepted non-admin signer!");

    // Call 'update_initial_pct_to_liquidate' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateInitialPctToLiquidateTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_initial_pct_to_liquidate"));
    assert!(result.is_err(), "Admin function 'update_initial_pct_to_liquidate' accepted non-admin signer!");

    // Call 'update_liquidation_duration' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateLiquidationDurationTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_liquidation_duration"));
    assert!(result.is_err(), "Admin function 'update_liquidation_duration' accepted non-admin signer!");

    // Call 'update_liquidation_margin_buffer_ratio' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateLiquidationMarginBufferRatioTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_liquidation_margin_buffer_ratio"));
    assert!(result.is_err(), "Admin function 'update_liquidation_margin_buffer_ratio' accepted non-admin signer!");

    // Call 'update_oracle_guard_rails' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateOracleGuardRailsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_oracle_guard_rails"));
    assert!(result.is_err(), "Admin function 'update_oracle_guard_rails' accepted non-admin signer!");

    // Call 'update_state_settlement_duration' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateStateSettlementDurationTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_state_settlement_duration"));
    assert!(result.is_err(), "Admin function 'update_state_settlement_duration' accepted non-admin signer!");

    // Call 'update_state_max_number_of_sub_accounts' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateStateMaxNumberOfSubAccountsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_state_max_number_of_sub_accounts"));
    assert!(result.is_err(), "Admin function 'update_state_max_number_of_sub_accounts' accepted non-admin signer!");

    // Call 'update_state_max_initialize_user_fee' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateStateMaxInitializeUserFeeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_state_max_initialize_user_fee"));
    assert!(result.is_err(), "Admin function 'update_state_max_initialize_user_fee' accepted non-admin signer!");

    // Call 'update_perp_market_oracle' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketOracleTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_oracle"));
    assert!(result.is_err(), "Admin function 'update_perp_market_oracle' accepted non-admin signer!");

    // Call 'update_perp_market_base_spread' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketBaseSpreadTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_base_spread"));
    assert!(result.is_err(), "Admin function 'update_perp_market_base_spread' accepted non-admin signer!");

    // Call 'update_amm_jit_intensity' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateAmmJitIntensityTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_amm_jit_intensity"));
    assert!(result.is_err(), "Admin function 'update_amm_jit_intensity' accepted non-admin signer!");

    // Call 'update_perp_market_max_spread' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketMaxSpreadTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_max_spread"));
    assert!(result.is_err(), "Admin function 'update_perp_market_max_spread' accepted non-admin signer!");

    // Call 'update_perp_market_step_size_and_tick_size' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketStepSizeAndTickSizeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_step_size_and_tick_size"));
    assert!(result.is_err(), "Admin function 'update_perp_market_step_size_and_tick_size' accepted non-admin signer!");

    // Call 'update_perp_market_name' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketNameTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_name"));
    assert!(result.is_err(), "Admin function 'update_perp_market_name' accepted non-admin signer!");

    // Call 'update_perp_market_min_order_size' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketMinOrderSizeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_min_order_size"));
    assert!(result.is_err(), "Admin function 'update_perp_market_min_order_size' accepted non-admin signer!");

    // Call 'update_perp_market_max_slippage_ratio' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketMaxSlippageRatioTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_max_slippage_ratio"));
    assert!(result.is_err(), "Admin function 'update_perp_market_max_slippage_ratio' accepted non-admin signer!");

    // Call 'update_perp_market_max_fill_reserve_fraction' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketMaxFillReserveFractionTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_max_fill_reserve_fraction"));
    assert!(result.is_err(), "Admin function 'update_perp_market_max_fill_reserve_fraction' accepted non-admin signer!");

    // Call 'update_perp_market_max_open_interest' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketMaxOpenInterestTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_max_open_interest"));
    assert!(result.is_err(), "Admin function 'update_perp_market_max_open_interest' accepted non-admin signer!");

    // Call 'update_perp_market_number_of_users' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketNumberOfUsersTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_number_of_users"));
    assert!(result.is_err(), "Admin function 'update_perp_market_number_of_users' accepted non-admin signer!");

    // Call 'update_perp_market_fee_adjustment' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketFeeAdjustmentTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_fee_adjustment"));
    assert!(result.is_err(), "Admin function 'update_perp_market_fee_adjustment' accepted non-admin signer!");

    // Call 'update_spot_market_fee_adjustment' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateSpotMarketFeeAdjustmentTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_spot_market_fee_adjustment"));
    assert!(result.is_err(), "Admin function 'update_spot_market_fee_adjustment' accepted non-admin signer!");

    // Call 'update_perp_market_protected_maker_params' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketProtectedMakerParamsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_protected_maker_params"));
    assert!(result.is_err(), "Admin function 'update_perp_market_protected_maker_params' accepted non-admin signer!");

    // Call 'update_perp_market_oracle_low_risk_slot_delay_override' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketOracleLowRiskSlotDelayOverrideTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_oracle_low_risk_slot_delay_override"));
    assert!(result.is_err(), "Admin function 'update_perp_market_oracle_low_risk_slot_delay_override' accepted non-admin signer!");

    // Call 'update_perp_market_amm_spread_adjustment' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketAmmSpreadAdjustmentTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_amm_spread_adjustment"));
    assert!(result.is_err(), "Admin function 'update_perp_market_amm_spread_adjustment' accepted non-admin signer!");

    // Call 'update_perp_market_oracle_slot_delay_override' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpMarketOracleSlotDelayOverrideTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_market_oracle_slot_delay_override"));
    assert!(result.is_err(), "Admin function 'update_perp_market_oracle_slot_delay_override' accepted non-admin signer!");

    // Call 'update_admin' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateAdminTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_admin"));
    assert!(result.is_err(), "Admin function 'update_admin' accepted non-admin signer!");

    // Call 'update_discount_mint' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateDiscountMintTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_discount_mint"));
    assert!(result.is_err(), "Admin function 'update_discount_mint' accepted non-admin signer!");

    // Call 'update_exchange_status' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateExchangeStatusTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_exchange_status"));
    assert!(result.is_err(), "Admin function 'update_exchange_status' accepted non-admin signer!");

    // Call 'update_perp_auction_duration' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePerpAuctionDurationTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_perp_auction_duration"));
    assert!(result.is_err(), "Admin function 'update_perp_auction_duration' accepted non-admin signer!");

    // Call 'update_spot_auction_duration' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateSpotAuctionDurationTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_spot_auction_duration"));
    assert!(result.is_err(), "Admin function 'update_spot_auction_duration' accepted non-admin signer!");

    // Call 'update_prelaunch_oracle_params' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePrelaunchOracleParamsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_prelaunch_oracle_params"));
    assert!(result.is_err(), "Admin function 'update_prelaunch_oracle_params' accepted non-admin signer!");

    // Call 'post_pyth_lazer_oracle_update' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = PostPythLazerOracleUpdateTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_post_pyth_lazer_oracle_update"));
    assert!(result.is_err(), "Admin function 'post_pyth_lazer_oracle_update' accepted non-admin signer!");

    // Call 'update_high_leverage_mode_config' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateHighLeverageModeConfigTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_high_leverage_mode_config"));
    assert!(result.is_err(), "Admin function 'update_high_leverage_mode_config' accepted non-admin signer!");

    // Call 'update_protected_maker_mode_config' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateProtectedMakerModeConfigTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_protected_maker_mode_config"));
    assert!(result.is_err(), "Admin function 'update_protected_maker_mode_config' accepted non-admin signer!");

    // Call 'admin_deposit' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = AdminDepositTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_admin_deposit"));
    assert!(result.is_err(), "Admin function 'admin_deposit' accepted non-admin signer!");

    // Call 'update_if_rebalance_config' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateIfRebalanceConfigTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_if_rebalance_config"));
    assert!(result.is_err(), "Admin function 'update_if_rebalance_config' accepted non-admin signer!");

    // Call 'update_feature_bit_flags_mm_oracle' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateFeatureBitFlagsMmOracleTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_feature_bit_flags_mm_oracle"));
    assert!(result.is_err(), "Admin function 'update_feature_bit_flags_mm_oracle' accepted non-admin signer!");

    // Call 'update_feature_bit_flags_median_trigger_price' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateFeatureBitFlagsMedianTriggerPriceTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_feature_bit_flags_median_trigger_price"));
    assert!(result.is_err(), "Admin function 'update_feature_bit_flags_median_trigger_price' accepted non-admin signer!");

    // Call 'update_feature_bit_flags_builder_codes' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateFeatureBitFlagsBuilderCodesTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_feature_bit_flags_builder_codes"));
    assert!(result.is_err(), "Admin function 'update_feature_bit_flags_builder_codes' accepted non-admin signer!");

    // Call 'update_feature_bit_flags_settle_lp_pool' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateFeatureBitFlagsSettleLpPoolTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_feature_bit_flags_settle_lp_pool"));
    assert!(result.is_err(), "Admin function 'update_feature_bit_flags_settle_lp_pool' accepted non-admin signer!");

    // Call 'update_feature_bit_flags_swap_lp_pool' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateFeatureBitFlagsSwapLpPoolTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_feature_bit_flags_swap_lp_pool"));
    assert!(result.is_err(), "Admin function 'update_feature_bit_flags_swap_lp_pool' accepted non-admin signer!");

    // Call 'update_feature_bit_flags_mint_redeem_lp_pool' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateFeatureBitFlagsMintRedeemLpPoolTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_feature_bit_flags_mint_redeem_lp_pool"));
    assert!(result.is_err(), "Admin function 'update_feature_bit_flags_mint_redeem_lp_pool' accepted non-admin signer!");

    // Call 'update_constituent_status' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateConstituentStatusTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_constituent_status"));
    assert!(result.is_err(), "Admin function 'update_constituent_status' accepted non-admin signer!");

    // Call 'update_constituent_paused_operations' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateConstituentPausedOperationsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_constituent_paused_operations"));
    assert!(result.is_err(), "Admin function 'update_constituent_paused_operations' accepted non-admin signer!");

    // Call 'update_constituent_params' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateConstituentParamsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_constituent_params"));
    assert!(result.is_err(), "Admin function 'update_constituent_params' accepted non-admin signer!");

    // Call 'update_lp_pool_params' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateLpPoolParamsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_lp_pool_params"));
    assert!(result.is_err(), "Admin function 'update_lp_pool_params' accepted non-admin signer!");

    // Call 'update_amm_constituent_mapping_data' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateAmmConstituentMappingDataTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_amm_constituent_mapping_data"));
    assert!(result.is_err(), "Admin function 'update_amm_constituent_mapping_data' accepted non-admin signer!");

    // Call 'update_constituent_correlation_data' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateConstituentCorrelationDataTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_constituent_correlation_data"));
    assert!(result.is_err(), "Admin function 'update_constituent_correlation_data' accepted non-admin signer!");

    // Call 'update_lp_constituent_target_base' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateLpConstituentTargetBaseTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_lp_constituent_target_base"));
    assert!(result.is_err(), "Admin function 'update_lp_constituent_target_base' accepted non-admin signer!");

    // Call 'update_lp_pool_aum' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateLpPoolAumTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_lp_pool_aum"));
    assert!(result.is_err(), "Admin function 'update_lp_pool_aum' accepted non-admin signer!");

    // Call 'update_amm_cache' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateAmmCacheTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_amm_cache"));
    assert!(result.is_err(), "Admin function 'update_amm_cache' accepted non-admin signer!");

    // Call 'update_constituent_oracle_info' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateConstituentOracleInfoTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_constituent_oracle_info"));
    assert!(result.is_err(), "Admin function 'update_constituent_oracle_info' accepted non-admin signer!");

    // Call 'settle_perp_to_lp_pool' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SettlePerpToLpPoolTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_settle_perp_to_lp_pool"));
    assert!(result.is_err(), "Admin function 'settle_perp_to_lp_pool' accepted non-admin signer!");

    // Call 'calculate_settlement_amount' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = CalculateSettlementAmountTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_calculate_settlement_amount"));
    assert!(result.is_err(), "Admin function 'calculate_settlement_amount' accepted non-admin signer!");

    // Call 'validate_settlement_amount' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = ValidateSettlementAmountTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_validate_settlement_amount"));
    assert!(result.is_err(), "Admin function 'validate_settlement_amount' accepted non-admin signer!");

    // Call 'calculate_lp_to_perp_settlement' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = CalculateLpToPerpSettlementTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_calculate_lp_to_perp_settlement"));
    assert!(result.is_err(), "Admin function 'calculate_lp_to_perp_settlement' accepted non-admin signer!");

    // Call 'calculate_perp_to_lp_settlement' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = CalculatePerpToLpSettlementTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_calculate_perp_to_lp_settlement"));
    assert!(result.is_err(), "Admin function 'calculate_perp_to_lp_settlement' accepted non-admin signer!");

    // Call 'handle_update_pyth_pull_oracle' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePythPullOracleTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_pyth_pull_oracle"));
    assert!(result.is_err(), "Admin function 'handle_update_pyth_pull_oracle' accepted non-admin signer!");

    // Call 'handle_post_pyth_pull_oracle_update_atomic' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandlePostPythPullOracleUpdateAtomicTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_post_pyth_pull_oracle_update_atomic"));
    assert!(result.is_err(), "Admin function 'handle_post_pyth_pull_oracle_update_atomic' accepted non-admin signer!");

    // Call 'handle_post_multi_pyth_pull_oracle_updates_atomic' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandlePostMultiPythPullOracleUpdatesAtomicTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_post_multi_pyth_pull_oracle_updates_atomic"));
    assert!(result.is_err(), "Admin function 'handle_post_multi_pyth_pull_oracle_updates_atomic' accepted non-admin signer!");

    // Call 'handle_update_spot_market_pool_id' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateSpotMarketPoolIdTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_spot_market_pool_id"));
    assert!(result.is_err(), "Admin function 'handle_update_spot_market_pool_id' accepted non-admin signer!");

    // Call 'handle_update_serum_fulfillment_config_status' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateSerumFulfillmentConfigStatusTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_serum_fulfillment_config_status"));
    assert!(result.is_err(), "Admin function 'handle_update_serum_fulfillment_config_status' accepted non-admin signer!");

    // Call 'handle_update_serum_vault' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateSerumVaultTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_serum_vault"));
    assert!(result.is_err(), "Admin function 'handle_update_serum_vault' accepted non-admin signer!");

    // Call 'handle_update_openbook_v2_fulfillment_config_status' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateOpenbookV2FulfillmentConfigStatusTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_openbook_v2_fulfillment_config_status"));
    assert!(result.is_err(), "Admin function 'handle_update_openbook_v2_fulfillment_config_status' accepted non-admin signer!");

    // Call 'handle_update_phoenix_fulfillment_config_status' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePhoenixFulfillmentConfigStatusTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_phoenix_fulfillment_config_status"));
    assert!(result.is_err(), "Admin function 'handle_update_phoenix_fulfillment_config_status' accepted non-admin signer!");

    // Call 'handle_update_spot_market_oracle' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateSpotMarketOracleTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_spot_market_oracle"));
    assert!(result.is_err(), "Admin function 'handle_update_spot_market_oracle' accepted non-admin signer!");

    // Call 'handle_update_spot_market_expiry' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateSpotMarketExpiryTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_spot_market_expiry"));
    assert!(result.is_err(), "Admin function 'handle_update_spot_market_expiry' accepted non-admin signer!");

    // Call 'handle_update_perp_market_expiry' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketExpiryTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_expiry"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_expiry' accepted non-admin signer!");

    // Call 'handle_update_perp_market_amm_summary_stats' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketAmmSummaryStatsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_amm_summary_stats"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_amm_summary_stats' accepted non-admin signer!");

    // Call 'handle_settle_expired_market_pools_to_revenue_pool' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleSettleExpiredMarketPoolsToRevenuePoolTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_settle_expired_market_pools_to_revenue_pool"));
    assert!(result.is_err(), "Admin function 'handle_settle_expired_market_pools_to_revenue_pool' accepted non-admin signer!");

    // Call 'handle_update_perp_market_pnl_pool' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketPnlPoolTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_pnl_pool"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_pnl_pool' accepted non-admin signer!");

    // Call 'handle_update_amm_oracle_twap' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateAmmOracleTwapTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_amm_oracle_twap"));
    assert!(result.is_err(), "Admin function 'handle_update_amm_oracle_twap' accepted non-admin signer!");

    // Call 'handle_update_k' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateKTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_k"));
    assert!(result.is_err(), "Admin function 'handle_update_k' accepted non-admin signer!");

    // Call 'handle_reset_amm_oracle_twap' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleResetAmmOracleTwapTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_reset_amm_oracle_twap"));
    assert!(result.is_err(), "Admin function 'handle_reset_amm_oracle_twap' accepted non-admin signer!");

    // Call 'handle_update_perp_market_margin_ratio' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketMarginRatioTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_margin_ratio"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_margin_ratio' accepted non-admin signer!");

    // Call 'handle_update_perp_market_high_leverage_margin_ratio' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketHighLeverageMarginRatioTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_high_leverage_margin_ratio"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_high_leverage_margin_ratio' accepted non-admin signer!");

    // Call 'handle_update_perp_market_funding_period' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketFundingPeriodTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_funding_period"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_funding_period' accepted non-admin signer!");

    // Call 'handle_update_perp_market_max_imbalances' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketMaxImbalancesTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_max_imbalances"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_max_imbalances' accepted non-admin signer!");

    // Call 'handle_update_perp_market_name' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketNameTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_name"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_name' accepted non-admin signer!");

    // Call 'handle_update_spot_market_name' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateSpotMarketNameTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_spot_market_name"));
    assert!(result.is_err(), "Admin function 'handle_update_spot_market_name' accepted non-admin signer!");

    // Call 'handle_update_perp_liquidation_fee' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpLiquidationFeeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_liquidation_fee"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_liquidation_fee' accepted non-admin signer!");

    // Call 'handle_update_perp_lp_pool_id' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpLpPoolIdTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_lp_pool_id"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_lp_pool_id' accepted non-admin signer!");

    // Call 'handle_update_insurance_fund_unstaking_period' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateInsuranceFundUnstakingPeriodTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_insurance_fund_unstaking_period"));
    assert!(result.is_err(), "Admin function 'handle_update_insurance_fund_unstaking_period' accepted non-admin signer!");

    // Call 'handle_update_spot_market_liquidation_fee' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateSpotMarketLiquidationFeeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_spot_market_liquidation_fee"));
    assert!(result.is_err(), "Admin function 'handle_update_spot_market_liquidation_fee' accepted non-admin signer!");

    // Call 'handle_update_withdraw_guard_threshold' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateWithdrawGuardThresholdTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_withdraw_guard_threshold"));
    assert!(result.is_err(), "Admin function 'handle_update_withdraw_guard_threshold' accepted non-admin signer!");

    // Call 'handle_update_spot_market_if_factor' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateSpotMarketIfFactorTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_spot_market_if_factor"));
    assert!(result.is_err(), "Admin function 'handle_update_spot_market_if_factor' accepted non-admin signer!");

    // Call 'handle_update_spot_market_revenue_settle_period' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateSpotMarketRevenueSettlePeriodTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_spot_market_revenue_settle_period"));
    assert!(result.is_err(), "Admin function 'handle_update_spot_market_revenue_settle_period' accepted non-admin signer!");

    // Call 'handle_update_spot_market_status' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateSpotMarketStatusTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_spot_market_status"));
    assert!(result.is_err(), "Admin function 'handle_update_spot_market_status' accepted non-admin signer!");

    // Call 'handle_update_spot_market_paused_operations' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateSpotMarketPausedOperationsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_spot_market_paused_operations"));
    assert!(result.is_err(), "Admin function 'handle_update_spot_market_paused_operations' accepted non-admin signer!");

    // Call 'handle_update_spot_market_asset_tier' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateSpotMarketAssetTierTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_spot_market_asset_tier"));
    assert!(result.is_err(), "Admin function 'handle_update_spot_market_asset_tier' accepted non-admin signer!");

    // Call 'handle_update_spot_market_margin_weights' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateSpotMarketMarginWeightsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_spot_market_margin_weights"));
    assert!(result.is_err(), "Admin function 'handle_update_spot_market_margin_weights' accepted non-admin signer!");

    // Call 'handle_update_spot_market_borrow_rate' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateSpotMarketBorrowRateTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_spot_market_borrow_rate"));
    assert!(result.is_err(), "Admin function 'handle_update_spot_market_borrow_rate' accepted non-admin signer!");

    // Call 'handle_update_spot_market_max_token_deposits' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateSpotMarketMaxTokenDepositsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_spot_market_max_token_deposits"));
    assert!(result.is_err(), "Admin function 'handle_update_spot_market_max_token_deposits' accepted non-admin signer!");

    // Call 'handle_update_spot_market_max_token_borrows' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateSpotMarketMaxTokenBorrowsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_spot_market_max_token_borrows"));
    assert!(result.is_err(), "Admin function 'handle_update_spot_market_max_token_borrows' accepted non-admin signer!");

    // Call 'handle_update_spot_market_scale_initial_asset_weight_start' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateSpotMarketScaleInitialAssetWeightStartTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_spot_market_scale_initial_asset_weight_start"));
    assert!(result.is_err(), "Admin function 'handle_update_spot_market_scale_initial_asset_weight_start' accepted non-admin signer!");

    // Call 'handle_update_spot_market_orders_enabled' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateSpotMarketOrdersEnabledTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_spot_market_orders_enabled"));
    assert!(result.is_err(), "Admin function 'handle_update_spot_market_orders_enabled' accepted non-admin signer!");

    // Call 'handle_update_spot_market_if_paused_operations' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateSpotMarketIfPausedOperationsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_spot_market_if_paused_operations"));
    assert!(result.is_err(), "Admin function 'handle_update_spot_market_if_paused_operations' accepted non-admin signer!");

    // Call 'handle_update_perp_market_status' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketStatusTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_status"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_status' accepted non-admin signer!");

    // Call 'handle_update_perp_market_paused_operations' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketPausedOperationsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_paused_operations"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_paused_operations' accepted non-admin signer!");

    // Call 'handle_update_perp_market_contract_tier' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketContractTierTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_contract_tier"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_contract_tier' accepted non-admin signer!");

    // Call 'handle_update_perp_market_imf_factor' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketImfFactorTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_imf_factor"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_imf_factor' accepted non-admin signer!");

    // Call 'handle_update_perp_market_unrealized_asset_weight' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketUnrealizedAssetWeightTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_unrealized_asset_weight"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_unrealized_asset_weight' accepted non-admin signer!");

    // Call 'handle_update_perp_market_concentration_coef' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketConcentrationCoefTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_concentration_coef"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_concentration_coef' accepted non-admin signer!");

    // Call 'handle_update_perp_market_curve_update_intensity' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketCurveUpdateIntensityTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_curve_update_intensity"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_curve_update_intensity' accepted non-admin signer!");

    // Call 'handle_update_perp_market_reference_price_offset_deadband_pct' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketReferencePriceOffsetDeadbandPctTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_reference_price_offset_deadband_pct"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_reference_price_offset_deadband_pct' accepted non-admin signer!");

    // Call 'handle_update_perp_fee_structure' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpFeeStructureTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_fee_structure"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_fee_structure' accepted non-admin signer!");

    // Call 'handle_update_spot_fee_structure' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateSpotFeeStructureTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_spot_fee_structure"));
    assert!(result.is_err(), "Admin function 'handle_update_spot_fee_structure' accepted non-admin signer!");

    // Call 'handle_update_initial_pct_to_liquidate' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateInitialPctToLiquidateTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_initial_pct_to_liquidate"));
    assert!(result.is_err(), "Admin function 'handle_update_initial_pct_to_liquidate' accepted non-admin signer!");

    // Call 'handle_update_liquidation_duration' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateLiquidationDurationTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_liquidation_duration"));
    assert!(result.is_err(), "Admin function 'handle_update_liquidation_duration' accepted non-admin signer!");

    // Call 'handle_update_liquidation_margin_buffer_ratio' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateLiquidationMarginBufferRatioTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_liquidation_margin_buffer_ratio"));
    assert!(result.is_err(), "Admin function 'handle_update_liquidation_margin_buffer_ratio' accepted non-admin signer!");

    // Call 'handle_update_oracle_guard_rails' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateOracleGuardRailsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_oracle_guard_rails"));
    assert!(result.is_err(), "Admin function 'handle_update_oracle_guard_rails' accepted non-admin signer!");

    // Call 'handle_update_state_settlement_duration' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateStateSettlementDurationTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_state_settlement_duration"));
    assert!(result.is_err(), "Admin function 'handle_update_state_settlement_duration' accepted non-admin signer!");

    // Call 'handle_update_state_max_number_of_sub_accounts' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateStateMaxNumberOfSubAccountsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_state_max_number_of_sub_accounts"));
    assert!(result.is_err(), "Admin function 'handle_update_state_max_number_of_sub_accounts' accepted non-admin signer!");

    // Call 'handle_update_state_max_initialize_user_fee' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateStateMaxInitializeUserFeeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_state_max_initialize_user_fee"));
    assert!(result.is_err(), "Admin function 'handle_update_state_max_initialize_user_fee' accepted non-admin signer!");

    // Call 'handle_update_perp_market_oracle' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketOracleTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_oracle"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_oracle' accepted non-admin signer!");

    // Call 'handle_update_perp_market_base_spread' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketBaseSpreadTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_base_spread"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_base_spread' accepted non-admin signer!");

    // Call 'handle_update_amm_jit_intensity' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateAmmJitIntensityTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_amm_jit_intensity"));
    assert!(result.is_err(), "Admin function 'handle_update_amm_jit_intensity' accepted non-admin signer!");

    // Call 'handle_update_perp_market_max_spread' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketMaxSpreadTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_max_spread"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_max_spread' accepted non-admin signer!");

    // Call 'handle_update_perp_market_step_size_and_tick_size' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketStepSizeAndTickSizeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_step_size_and_tick_size"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_step_size_and_tick_size' accepted non-admin signer!");

    // Call 'handle_update_perp_market_min_order_size' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketMinOrderSizeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_min_order_size"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_min_order_size' accepted non-admin signer!");

    // Call 'handle_update_spot_market_step_size_and_tick_size' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateSpotMarketStepSizeAndTickSizeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_spot_market_step_size_and_tick_size"));
    assert!(result.is_err(), "Admin function 'handle_update_spot_market_step_size_and_tick_size' accepted non-admin signer!");

    // Call 'handle_update_spot_market_min_order_size' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateSpotMarketMinOrderSizeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_spot_market_min_order_size"));
    assert!(result.is_err(), "Admin function 'handle_update_spot_market_min_order_size' accepted non-admin signer!");

    // Call 'handle_update_perp_market_max_slippage_ratio' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketMaxSlippageRatioTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_max_slippage_ratio"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_max_slippage_ratio' accepted non-admin signer!");

    // Call 'handle_update_perp_market_max_fill_reserve_fraction' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketMaxFillReserveFractionTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_max_fill_reserve_fraction"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_max_fill_reserve_fraction' accepted non-admin signer!");

    // Call 'handle_update_perp_market_max_open_interest' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketMaxOpenInterestTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_max_open_interest"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_max_open_interest' accepted non-admin signer!");

    // Call 'handle_update_perp_market_fee_adjustment' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketFeeAdjustmentTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_fee_adjustment"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_fee_adjustment' accepted non-admin signer!");

    // Call 'handle_update_perp_market_number_of_users' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketNumberOfUsersTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_number_of_users"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_number_of_users' accepted non-admin signer!");

    // Call 'handle_update_perp_market_fuel' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketFuelTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_fuel"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_fuel' accepted non-admin signer!");

    // Call 'handle_update_perp_market_protected_maker_params' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketProtectedMakerParamsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_protected_maker_params"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_protected_maker_params' accepted non-admin signer!");

    // Call 'handle_update_perp_market_lp_pool_paused_operations' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketLpPoolPausedOperationsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_lp_pool_paused_operations"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_lp_pool_paused_operations' accepted non-admin signer!");

    // Call 'handle_update_perp_market_oracle_low_risk_slot_delay_override' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketOracleLowRiskSlotDelayOverrideTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_oracle_low_risk_slot_delay_override"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_oracle_low_risk_slot_delay_override' accepted non-admin signer!");

    // Call 'handle_update_perp_market_amm_spread_adjustment' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketAmmSpreadAdjustmentTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_amm_spread_adjustment"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_amm_spread_adjustment' accepted non-admin signer!");

    // Call 'handle_update_perp_market_oracle_slot_delay_override' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketOracleSlotDelayOverrideTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_oracle_slot_delay_override"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_oracle_slot_delay_override' accepted non-admin signer!");

    // Call 'handle_update_spot_market_fee_adjustment' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateSpotMarketFeeAdjustmentTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_spot_market_fee_adjustment"));
    assert!(result.is_err(), "Admin function 'handle_update_spot_market_fee_adjustment' accepted non-admin signer!");

    // Call 'handle_update_spot_market_fuel' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateSpotMarketFuelTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_spot_market_fuel"));
    assert!(result.is_err(), "Admin function 'handle_update_spot_market_fuel' accepted non-admin signer!");

    // Call 'handle_update_admin' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateAdminTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_admin"));
    assert!(result.is_err(), "Admin function 'handle_update_admin' accepted non-admin signer!");

    // Call 'handle_update_whitelist_mint' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateWhitelistMintTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_whitelist_mint"));
    assert!(result.is_err(), "Admin function 'handle_update_whitelist_mint' accepted non-admin signer!");

    // Call 'handle_update_discount_mint' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateDiscountMintTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_discount_mint"));
    assert!(result.is_err(), "Admin function 'handle_update_discount_mint' accepted non-admin signer!");

    // Call 'handle_update_exchange_status' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateExchangeStatusTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_exchange_status"));
    assert!(result.is_err(), "Admin function 'handle_update_exchange_status' accepted non-admin signer!");

    // Call 'handle_update_perp_auction_duration' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpAuctionDurationTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_auction_duration"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_auction_duration' accepted non-admin signer!");

    // Call 'handle_update_spot_auction_duration' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateSpotAuctionDurationTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_spot_auction_duration"));
    assert!(result.is_err(), "Admin function 'handle_update_spot_auction_duration' accepted non-admin signer!");

    // Call 'handle_admin_update_user_stats_paused_operations' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleAdminUpdateUserStatsPausedOperationsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_admin_update_user_stats_paused_operations"));
    assert!(result.is_err(), "Admin function 'handle_admin_update_user_stats_paused_operations' accepted non-admin signer!");

    // Call 'handle_update_protocol_if_shares_transfer_config' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateProtocolIfSharesTransferConfigTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_protocol_if_shares_transfer_config"));
    assert!(result.is_err(), "Admin function 'handle_update_protocol_if_shares_transfer_config' accepted non-admin signer!");

    // Call 'handle_update_prelaunch_oracle_params' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePrelaunchOracleParamsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_prelaunch_oracle_params"));
    assert!(result.is_err(), "Admin function 'handle_update_prelaunch_oracle_params' accepted non-admin signer!");

    // Call 'handle_settle_expired_market' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleSettleExpiredMarketTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_settle_expired_market"));
    assert!(result.is_err(), "Admin function 'handle_settle_expired_market' accepted non-admin signer!");

    // Call 'handle_update_high_leverage_mode_config' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateHighLeverageModeConfigTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_high_leverage_mode_config"));
    assert!(result.is_err(), "Admin function 'handle_update_high_leverage_mode_config' accepted non-admin signer!");

    // Call 'handle_update_protected_maker_mode_config' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateProtectedMakerModeConfigTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_protected_maker_mode_config"));
    assert!(result.is_err(), "Admin function 'handle_update_protected_maker_mode_config' accepted non-admin signer!");

    // Call 'handle_admin_deposit' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleAdminDepositTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_admin_deposit"));
    assert!(result.is_err(), "Admin function 'handle_admin_deposit' accepted non-admin signer!");

    // Call 'handle_update_if_rebalance_config' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateIfRebalanceConfigTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_if_rebalance_config"));
    assert!(result.is_err(), "Admin function 'handle_update_if_rebalance_config' accepted non-admin signer!");

    // Call 'handle_update_feature_bit_flags_mm_oracle' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateFeatureBitFlagsMmOracleTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_feature_bit_flags_mm_oracle"));
    assert!(result.is_err(), "Admin function 'handle_update_feature_bit_flags_mm_oracle' accepted non-admin signer!");

    // Call 'handle_update_feature_bit_flags_median_trigger_price' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateFeatureBitFlagsMedianTriggerPriceTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_feature_bit_flags_median_trigger_price"));
    assert!(result.is_err(), "Admin function 'handle_update_feature_bit_flags_median_trigger_price' accepted non-admin signer!");

    // Call 'handle_update_delegate_user_gov_token_insurance_stake' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateDelegateUserGovTokenInsuranceStakeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_delegate_user_gov_token_insurance_stake"));
    assert!(result.is_err(), "Admin function 'handle_update_delegate_user_gov_token_insurance_stake' accepted non-admin signer!");

    // Call 'handle_update_feature_bit_flags_builder_codes' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateFeatureBitFlagsBuilderCodesTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_feature_bit_flags_builder_codes"));
    assert!(result.is_err(), "Admin function 'handle_update_feature_bit_flags_builder_codes' accepted non-admin signer!");

    // Call 'handle_update_feature_bit_flags_builder_referral' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateFeatureBitFlagsBuilderReferralTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_feature_bit_flags_builder_referral"));
    assert!(result.is_err(), "Admin function 'handle_update_feature_bit_flags_builder_referral' accepted non-admin signer!");

    // Call 'handle_update_feature_bit_flags_settle_lp_pool' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateFeatureBitFlagsSettleLpPoolTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_feature_bit_flags_settle_lp_pool"));
    assert!(result.is_err(), "Admin function 'handle_update_feature_bit_flags_settle_lp_pool' accepted non-admin signer!");

    // Call 'handle_update_feature_bit_flags_swap_lp_pool' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateFeatureBitFlagsSwapLpPoolTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_feature_bit_flags_swap_lp_pool"));
    assert!(result.is_err(), "Admin function 'handle_update_feature_bit_flags_swap_lp_pool' accepted non-admin signer!");

    // Call 'handle_update_feature_bit_flags_mint_redeem_lp_pool' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateFeatureBitFlagsMintRedeemLpPoolTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_feature_bit_flags_mint_redeem_lp_pool"));
    assert!(result.is_err(), "Admin function 'handle_update_feature_bit_flags_mint_redeem_lp_pool' accepted non-admin signer!");

    // Call 'handle_update_pyth_lazer_oracle' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePythLazerOracleTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_pyth_lazer_oracle"));
    assert!(result.is_err(), "Admin function 'handle_update_pyth_lazer_oracle' accepted non-admin signer!");

    // Call 'handle_update_constituent_target_base' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateConstituentTargetBaseTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_constituent_target_base"));
    assert!(result.is_err(), "Admin function 'handle_update_constituent_target_base' accepted non-admin signer!");

    // Call 'handle_update_lp_pool_aum' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateLpPoolAumTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_lp_pool_aum"));
    assert!(result.is_err(), "Admin function 'handle_update_lp_pool_aum' accepted non-admin signer!");

    // Call 'handle_update_constituent_oracle_info' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateConstituentOracleInfoTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_constituent_oracle_info"));
    assert!(result.is_err(), "Admin function 'handle_update_constituent_oracle_info' accepted non-admin signer!");

    // Call 'handle_reset_fuel_season' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleResetFuelSeasonTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_reset_fuel_season"));
    assert!(result.is_err(), "Admin function 'handle_reset_fuel_season' accepted non-admin signer!");

    // Call 'handle_update_user_name' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateUserNameTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_user_name"));
    assert!(result.is_err(), "Admin function 'handle_update_user_name' accepted non-admin signer!");

    // Call 'handle_update_user_custom_margin_ratio' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateUserCustomMarginRatioTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_user_custom_margin_ratio"));
    assert!(result.is_err(), "Admin function 'handle_update_user_custom_margin_ratio' accepted non-admin signer!");

    // Call 'handle_update_user_perp_position_custom_margin_ratio' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateUserPerpPositionCustomMarginRatioTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_user_perp_position_custom_margin_ratio"));
    assert!(result.is_err(), "Admin function 'handle_update_user_perp_position_custom_margin_ratio' accepted non-admin signer!");

    // Call 'handle_update_user_margin_trading_enabled' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateUserMarginTradingEnabledTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_user_margin_trading_enabled"));
    assert!(result.is_err(), "Admin function 'handle_update_user_margin_trading_enabled' accepted non-admin signer!");

    // Call 'handle_update_user_pool_id' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateUserPoolIdTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_user_pool_id"));
    assert!(result.is_err(), "Admin function 'handle_update_user_pool_id' accepted non-admin signer!");

    // Call 'handle_update_user_delegate' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateUserDelegateTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_user_delegate"));
    assert!(result.is_err(), "Admin function 'handle_update_user_delegate' accepted non-admin signer!");

    // Call 'handle_update_user_reduce_only' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateUserReduceOnlyTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_user_reduce_only"));
    assert!(result.is_err(), "Admin function 'handle_update_user_reduce_only' accepted non-admin signer!");

    // Call 'handle_update_user_advanced_lp' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateUserAdvancedLpTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_user_advanced_lp"));
    assert!(result.is_err(), "Admin function 'handle_update_user_advanced_lp' accepted non-admin signer!");

    // Call 'handle_update_user_protected_maker_orders' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateUserProtectedMakerOrdersTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_user_protected_maker_orders"));
    assert!(result.is_err(), "Admin function 'handle_update_user_protected_maker_orders' accepted non-admin signer!");

    // Call 'handle_update_constituent_status' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateConstituentStatusTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_constituent_status"));
    assert!(result.is_err(), "Admin function 'handle_update_constituent_status' accepted non-admin signer!");

    // Call 'handle_update_constituent_paused_operations' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateConstituentPausedOperationsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_constituent_paused_operations"));
    assert!(result.is_err(), "Admin function 'handle_update_constituent_paused_operations' accepted non-admin signer!");

    // Call 'handle_update_perp_market_lp_pool_fee_transfer_scalar' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketLpPoolFeeTransferScalarTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_lp_pool_fee_transfer_scalar"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_lp_pool_fee_transfer_scalar' accepted non-admin signer!");

    // Call 'handle_update_constituent_params' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateConstituentParamsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_constituent_params"));
    assert!(result.is_err(), "Admin function 'handle_update_constituent_params' accepted non-admin signer!");

    // Call 'handle_update_lp_pool_params' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateLpPoolParamsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_lp_pool_params"));
    assert!(result.is_err(), "Admin function 'handle_update_lp_pool_params' accepted non-admin signer!");

    // Call 'handle_update_amm_constituent_mapping_data' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateAmmConstituentMappingDataTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_amm_constituent_mapping_data"));
    assert!(result.is_err(), "Admin function 'handle_update_amm_constituent_mapping_data' accepted non-admin signer!");

    // Call 'handle_update_constituent_correlation_data' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateConstituentCorrelationDataTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_constituent_correlation_data"));
    assert!(result.is_err(), "Admin function 'handle_update_constituent_correlation_data' accepted non-admin signer!");

    // Call 'handle_update_perp_market_lp_pool_status' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpMarketLpPoolStatusTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_market_lp_pool_status"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_market_lp_pool_status' accepted non-admin signer!");

    // Call 'handle_update_initial_amm_cache_info' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateInitialAmmCacheInfoTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_initial_amm_cache_info"));
    assert!(result.is_err(), "Admin function 'handle_update_initial_amm_cache_info' accepted non-admin signer!");

    // Call 'handle_update_user_idle' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateUserIdleTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_user_idle"));
    assert!(result.is_err(), "Admin function 'handle_update_user_idle' accepted non-admin signer!");

    // Call 'handle_update_user_fuel_bonus' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateUserFuelBonusTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_user_fuel_bonus"));
    assert!(result.is_err(), "Admin function 'handle_update_user_fuel_bonus' accepted non-admin signer!");

    // Call 'handle_update_user_stats_referrer_info' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateUserStatsReferrerInfoTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_user_stats_referrer_info"));
    assert!(result.is_err(), "Admin function 'handle_update_user_stats_referrer_info' accepted non-admin signer!");

    // Call 'handle_update_user_open_orders_count' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateUserOpenOrdersCountTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_user_open_orders_count"));
    assert!(result.is_err(), "Admin function 'handle_update_user_open_orders_count' accepted non-admin signer!");

    // Call 'handle_settle_pnl' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleSettlePnlTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_settle_pnl"));
    assert!(result.is_err(), "Admin function 'handle_settle_pnl' accepted non-admin signer!");

    // Call 'handle_settle_multiple_pnls' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleSettleMultiplePnlsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_settle_multiple_pnls"));
    assert!(result.is_err(), "Admin function 'handle_settle_multiple_pnls' accepted non-admin signer!");

    // Call 'handle_settle_funding_payment' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleSettleFundingPaymentTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_settle_funding_payment"));
    assert!(result.is_err(), "Admin function 'handle_settle_funding_payment' accepted non-admin signer!");

    // Call 'handle_set_user_status_to_being_liquidated' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleSetUserStatusToBeingLiquidatedTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_set_user_status_to_being_liquidated"));
    assert!(result.is_err(), "Admin function 'handle_set_user_status_to_being_liquidated' accepted non-admin signer!");

    // Call 'handle_update_funding_rate' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateFundingRateTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_funding_rate"));
    assert!(result.is_err(), "Admin function 'handle_update_funding_rate' accepted non-admin signer!");

    // Call 'handle_update_prelaunch_oracle' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePrelaunchOracleTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_prelaunch_oracle"));
    assert!(result.is_err(), "Admin function 'handle_update_prelaunch_oracle' accepted non-admin signer!");

    // Call 'handle_update_perp_bid_ask_twap' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdatePerpBidAskTwapTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_perp_bid_ask_twap"));
    assert!(result.is_err(), "Admin function 'handle_update_perp_bid_ask_twap' accepted non-admin signer!");

    // Call 'handle_settle_revenue_to_insurance_fund' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleSettleRevenueToInsuranceFundTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_settle_revenue_to_insurance_fund"));
    assert!(result.is_err(), "Admin function 'handle_settle_revenue_to_insurance_fund' accepted non-admin signer!");

    // Call 'handle_update_spot_market_cumulative_interest' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateSpotMarketCumulativeInterestTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_spot_market_cumulative_interest"));
    assert!(result.is_err(), "Admin function 'handle_update_spot_market_cumulative_interest' accepted non-admin signer!");

    // Call 'handle_update_amms' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateAmmsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_amms"));
    assert!(result.is_err(), "Admin function 'handle_update_amms' accepted non-admin signer!");

    // Call 'handle_update_user_quote_asset_insurance_stake' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateUserQuoteAssetInsuranceStakeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_user_quote_asset_insurance_stake"));
    assert!(result.is_err(), "Admin function 'handle_update_user_quote_asset_insurance_stake' accepted non-admin signer!");

    // Call 'handle_update_user_gov_token_insurance_stake' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateUserGovTokenInsuranceStakeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_user_gov_token_insurance_stake"));
    assert!(result.is_err(), "Admin function 'handle_update_user_gov_token_insurance_stake' accepted non-admin signer!");

    // Call 'handle_settle_perp_to_lp_pool' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleSettlePerpToLpPoolTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_settle_perp_to_lp_pool"));
    assert!(result.is_err(), "Admin function 'handle_settle_perp_to_lp_pool' accepted non-admin signer!");

    // Call 'handle_update_amm_cache' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = HandleUpdateAmmCacheTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_handle_update_amm_cache"));
    assert!(result.is_err(), "Admin function 'handle_update_amm_cache' accepted non-admin signer!");

    // Call 'set_validator_score' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetValidatorScoreTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_validator_score"));
    assert!(result.is_err(), "Admin function 'set_validator_score' accepted non-admin signer!");

    // Call 'update_active' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateActiveTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_active"));
    assert!(result.is_err(), "Admin function 'update_active' accepted non-admin signer!");

    // Call 'update_deactivated' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateDeactivatedTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_deactivated"));
    assert!(result.is_err(), "Admin function 'update_deactivated' accepted non-admin signer!");

    // Call 'set_collateral_hard_cap' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetCollateralHardCapTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_collateral_hard_cap"));
    assert!(result.is_err(), "Admin function 'set_collateral_hard_cap' accepted non-admin signer!");

    // Call 'set_curator' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetCuratorTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_curator"));
    assert!(result.is_err(), "Admin function 'set_curator' accepted non-admin signer!");

    // Call 'set_bankman' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetBankmanTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_bankman"));
    assert!(result.is_err(), "Admin function 'set_bankman' accepted non-admin signer!");

    // Call 'upgrade_guardian_set' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpgradeGuardianSetTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_upgrade_guardian_set"));
    assert!(result.is_err(), "Admin function 'upgrade_guardian_set' accepted non-admin signer!");

    // Call 'set_fees' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetFeesTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_fees"));
    assert!(result.is_err(), "Admin function 'set_fees' accepted non-admin signer!");

    // Call 'update_accounts' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateAccountsTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_accounts"));
    assert!(result.is_err(), "Admin function 'update_accounts' accepted non-admin signer!");

    // Call 'setup_group' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetupGroupTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_setup_group"));
    assert!(result.is_err(), "Admin function 'setup_group' accepted non-admin signer!");

    // Call 'apply_new_admin' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = ApplyNewAdminTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_apply_new_admin"));
    assert!(result.is_err(), "Admin function 'apply_new_admin' accepted non-admin signer!");

    // Call 'commit_new_admin' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = CommitNewAdminTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_commit_new_admin"));
    assert!(result.is_err(), "Admin function 'commit_new_admin' accepted non-admin signer!");

    // Call 'set_fee_account' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetFeeAccountTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_fee_account"));
    assert!(result.is_err(), "Admin function 'set_fee_account' accepted non-admin signer!");

    // Call 'set_new_fees' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetNewFeesTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_new_fees"));
    assert!(result.is_err(), "Admin function 'set_new_fees' accepted non-admin signer!");

    // Call 'update_assessment' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateAssessmentTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_assessment"));
    assert!(result.is_err(), "Admin function 'update_assessment' accepted non-admin signer!");

    // Call 'set_paused' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetPausedTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_paused"));
    assert!(result.is_err(), "Admin function 'set_paused' accepted non-admin signer!");

    // Call 'set_paused' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetPausedTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_paused"));
    assert!(result.is_err(), "Admin function 'set_paused' accepted non-admin signer!");

    // Call 'update_assessment' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateAssessmentTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_assessment"));
    assert!(result.is_err(), "Admin function 'update_assessment' accepted non-admin signer!");

    // Call 'update_reward_rate' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateRewardRateTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_reward_rate"));
    assert!(result.is_err(), "Admin function 'update_reward_rate' accepted non-admin signer!");

}

