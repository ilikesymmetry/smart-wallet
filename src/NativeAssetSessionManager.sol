// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {UserOperation, UserOperationLib} from "account-abstraction/interfaces/UserOperation.sol";

import {SessionManager} from "./SessionManager.sol";

/// @title NativeAssetSessionManager
///
/// @notice EIP-1271-compatible session key implementation that limits native asset spend.
///
/// @author Coinbase (https://github.com/coinbase/smart-wallet)
contract NativeAssetSessionManager is SessionManager {
    /// @notice Represents a call to make.
    struct Call {
        /// @dev The address to call.
        address target;
        /// @dev The value to send when making the call.
        uint256 value;
        /// @dev The data of the call.
        bytes data;
    }

    /// @notice UserOperation does not match provided hash.
    error InvalidUserOperation();

    /// @notice Function selector for userOp callData not supported
    error UnsupportedFunctionSelector();

    /// @notice Total value sent in userOp exceeds session's spending limit
    error SpendingLimitExceeded();

    /// @notice Validates a session via EIP-1271.
    ///
    /// @dev assumes called by CoinbaseSmartWallet where this contract is an owner.
    ///
    /// @param hash Arbitrary data to sign over.
    /// @param authData Combination of an approved Session and a signature from the session's signer for `hash`.
    function isValidSignature(bytes32 hash, bytes calldata authData) external view override returns (bytes4 result) {
        // assume session, signature, userOp encoded together
        (Session memory session, bytes memory signature, UserOperation userOp) = abi.decode(authData, (Session, bytes, UserOperation));

        // validate core session logic
        _validateSessionSignature(session, hash, signature);

        // validate native asset spending limits

        // check userOp matches hash
        if (UserOperationLib.hash(userOp) != hash) revert InvalidUserOperation();
        // check function is executeCalls (0x34fcd5be)
        if (userOp.callData[0:5] != 0x34fcd5be) revert InvalidFunctionSelector();
        (Calls[] memory calls) = abi.decode(userOp.callData[5:], (Call[]));
        uint256 totalValue = 0;
        for (uint256 i; i < calls.length; i++) {
            totalValue += calls[i].value;
        }
        // check totalValue under spendingLimit
        uint256 spendingLimit = abi.decode(sesssion.scopes, (uint256));
        if (totalValue > spendingLimit) revert SpendingLimitExceeded();

        return 0x1626ba7e;
    }
}