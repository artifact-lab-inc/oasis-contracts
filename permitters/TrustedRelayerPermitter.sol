// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IIdentityRegistry, IdentityId, Permitter} from "./helper/Permitter.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract TrustedRelayerPermitter is Permitter, Ownable {
    event TrustedRelayerStatusUpdated(address trustedRelayer, bool status);
    event SecretMigration(string message);

    error InputLengthMismatch();
    mapping(address => bool) public isTrustedRelayer;

    constructor(
        address registry,
        address initialTrustedRelayer
    ) Permitter(registry) Ownable(msg.sender) {
        isTrustedRelayer[initialTrustedRelayer] = true;
    }

    modifier isValidRelayer() {
        if (!isTrustedRelayer[msg.sender]) revert Unauthorized();
        _;
    }

    function manageTrustedRelayer(
        address trustedRelayer,
        bool status
    ) external onlyOwner {
        isTrustedRelayer[trustedRelayer] = status;
        emit TrustedRelayerStatusUpdated(trustedRelayer, status);
    }

    function migrateSecret(
        bytes32[] calldata assignees,
        IdentityId[] calldata uIds,
        bytes32[] calldata idSecrets
    ) external override isValidRelayer {
        if (
            assignees.length != uIds.length ||
            assignees.length != idSecrets.length
        ) revert InputLengthMismatch();
        for (uint256 i; i < assignees.length; i++) {
            try
                IIdentityRegistry(_getIdentityRegistry()).manualMigration(
                    assignees[i],
                    uIds[i],
                    idSecrets[i]
                )
            {
                emit SecretMigration("Success");
            } catch Error(string memory reason) {
                // catch failing revert() and require()
                emit SecretMigration(reason);
            }
        }
    }

    function _acquireIdentity(
        IdentityId identity,
        address requester,
        uint64 duration,
        bytes calldata context,
        bytes calldata
    ) internal virtual override isValidRelayer returns (uint64 expiry) {
        uint64 lifetime = _getPermitLifetime(
            identity,
            requester,
            duration,
            context
        );
        return uint64(block.timestamp + lifetime);
    }

    function _releaseIdentity(
        IdentityId,
        address,
        bytes calldata,
        bytes calldata
    ) internal virtual override isValidRelayer {}

    function _getPermitLifetime(
        IdentityId,
        address requester,
        uint64 requestedDuration,
        bytes calldata context
    ) internal view virtual returns (uint64) {
        (requester, context);
        return requestedDuration;
    }
}
