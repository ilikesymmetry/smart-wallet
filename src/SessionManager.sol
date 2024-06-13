// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {IERC1271} from "openzeppelin-contracts/interfaces/IERC1271.sol";

import {SignatureChecker} from "./utils/SignatureChecker.sol";

/// @title SessionManager
///
/// @notice EIP-1271-compatible session key implementation that supports arbitrary scopes and EOA+passkey signers.
///
/// @dev Without the full UserOp and control of the execution flow, this contract only validates session validity.
///      Account implementations MUST validate scopes within their execution flow outside of validateUserOp.
///
/// @author Coinbase (https://github.com/coinbase/smart-wallet)
abstract contract SessionManager {
    /// @notice A time-bound provision of scoped account control to another signer.
    struct Session {
        address account;
        bytes approval;
        bytes signer;
        bytes scopes; // TODO: account needs to check this with UserOp and diff before/after execution
        uint40 expiresAt;
        // TODO: consider EIP-712 format instead
        uint256 chainId; // 0 represents chain-agnostic i.e. this session applies on any network
        address verifyingContract; // prevent replay on other potential SessionManager implementations
    }

    /// @notice Session account does not match currently authentication sender.
    error InvalidSessionAccount();

    /// @notice Session chain is not agnositc and not this chain.
    error InvalidSessionChain();

    /// @notice Session verifying contract is not this SessionManager.
    error InvalidSessionVerifyingContract();

    /// @notice Session is revoked.
    error SessionRevoked();
    
    /// @notice Session has expired.
    error SessionExpired();
    
    /// @notice SessionApproval is invalid
    error InvalidSessionApproval();

    /// @notice Signature from session signer does not match hash.
    error InvalidSignature();

    /// @notice Session was revoked prematurely by account.
    ///
    /// @param account The smart contract account the session controlled.
    /// @param sessionId The unique hash representing the session.
    event SessionRevoked(address indexed account, bytes32 indexed sessionId);
    
    /// @dev keying storage by account enables us to pass 4337 storage access limitations
    mapping(address account => mapping(bytes32 sessionId => bool revoked)) internal _revokedSessions;

    /// @notice Validates a session via EIP-1271.
    ///
    /// @dev assumes called by CoinbaseSmartWallet where this contract is an owner.
    ///
    /// @param hash Arbitrary data to sign over.
    /// @param authData Combination of an approved Session and a signature from the session's signer for `hash`.
    function isValidSignature(bytes32 hash, bytes calldata authData) external view virtual returns (bytes4 result) {
        // assume session and signature encoded together
        (Session memory session, bytes memory signature) = abi.decode(authData, (Session, bytes));
        
        _validateSessionSignature(session, hash, signature);

        return 0x1626ba7e;
    }

    function _validateSessionSignature(Session memory session, bytes32 hash, bytes memory signature) internal view {
        bytes32 sessionId = keccak256(abi.encode(session));

        // check sender is session account
        if (msg.sender != session.account) revert InvalidSessionAccount();
        // check chainId is agnostic or this chain
        if (session.chainId != 0 && session.chainId != block.chainid) revert InvalidSessionChain();
        // check verifyingContract is SessionManager
        if (session.verifyingContract != address(this)) revert InvalidSessionVerifyingContract();
        // check session not expired
        if (session.expiresAt < block.timestamp) revert SessionExpired();
        // check session not revoked
        if (_revokedSessions[session.account][sessionId]) revert SessionRevoked();
        // check session account approval
        if (!ERC1271(session.account).isValidSignature(sessionId, approval)) revert InvalidSessionApproval();
        // check session signer's signature on hash
        if (!SignatureChecker.isValidSignatureNow(hash, signature, session.signer)) revert InvalidSignature();
    }

    /// @notice Revoke a session to prematurely expire it.
    ///
    /// @dev Without a scope to mitigate, sessions can revoke other sessions.
    ///
    /// @param session The session to revoke
    function revokeSession(Session calldata session) external {
        bytes32 sessionId = keccak256(abi.encode(session));
        if (_revokedSessions[msg.sender][sessionId]) {
            revert SessionRevoked();
        }
        _revokedSessions[msg.sender][sessionId] = true;

        emit SessionRevoked(msg.sender, sessionId);
    }
}