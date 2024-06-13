// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {UserOperation, UserOperationLib} from "account-abstraction/interfaces/UserOperation.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";

import {SessionManager} from "./SessionManager.sol";

/// @title OffchainAssetationSessionManager
///
/// @notice EIP-1271-compatible session key implementation that trusts an attestor for permissions defined offchain
///
/// @author Coinbase (https://github.com/coinbase/smart-wallet)
contract NativeAssetSessionManager is SessionManager {
    /// @notice Validates a session via EIP-1271.
    ///
    /// @dev assumes called by CoinbaseSmartWallet where this contract is an owner.
    ///
    /// @param hash Arbitrary data to sign over.
    /// @param authData Combination of an approved Session and a signature from the session's signer for `hash`.
    function isValidSignature(bytes32 hash, bytes calldata authData) external view override returns (bytes4 result) {
        // assume session, signature, attestation encoded together
        (Session memory session, bytes memory signature, bytes memory attestation) = abi.decode(authData, (Session, bytes, bytes));

        // validate core session logic
        _validateSessionSignature(session, hash, signature);

        // validate attestation
        address attestor = abi.decode(sesssion.scopes, (address));
        // check attestation
        SignatureCheckerLib.isValidSignatureNow(attestor, hash, attestation);

        return 0x1626ba7e;
    }
}