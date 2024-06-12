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
contract SessionManager {
    /// @notice A time-bound provision of scoped account control to another signer.
    struct Session {
        uint256 chainId; // 0 represents chain-agnostic i.e. this session applies on any network
        bytes signer;
        bytes scopes; // TODO: account needs to check this with UserOp and diff before/after execution
        uint40 expiresAt;
        bytes approval;
    }

    /// @notice Session is revoked.
    error SessionRevoked();
    
    /// @notice Session has expired.
    error SessionExpired();
    
    /// @notice SessionApproval is invalid
    error SessionApprovalInvalid();

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
    function isValidSignature(bytes32 hash, bytes calldata authData) external view returns (bytes4 result) {
        // assume called by 4337 account
        address account = msg.sender;
        // assume session and signature encoded together
        (Session memory session, bytes memory signature) = abi.decode(authData, (Session, bytes));

        bytes32 sessionId = keccak256(abi.encode(session));
        // check session not expired
        if (session.expiresAt < block.timestamp) revert SessionExpired();
        // check session not revoked
        if (_revokedSessions[account][sessionId]) revert SessionRevoked();
        // check session account approval
        if (!ERC1271(account).isValidSignature(sessionId, approval)) revert SessionApprovalInvalid();
        // check session signer's signature on hash
        if (!SignatureChecker.isValidSignatureNow(hash, signature, session.signer)) revert InvalidSignature();

        return 0x1626ba7e;
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