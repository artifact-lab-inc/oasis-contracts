// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AttributePermitter} from "./helper/AttributePermitter.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract TrustedRelayerAttributePermitter is AttributePermitter, Ownable {
    event TrustedRelayerStatusUpdated(address trustedRelayer, bool status);

    error InputLengthMismatch();
    mapping(address => bool) public isTrustedRelayer;

    constructor(
        address registry,
        address initialTrustedRelayer
    ) AttributePermitter(registry) Ownable(msg.sender) {
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

    function _acquireAttribute(
        bytes32 attributeHash,
        address requester,
        uint64 duration,
        bytes calldata context,
        bytes calldata
    ) internal virtual override isValidRelayer returns (uint64 expiry) {
        uint64 lifetime = _getPermitLifetime(
            attributeHash,
            requester,
            duration,
            context
        );
        return uint64(block.timestamp + lifetime);
    }

    function _releaseAttribute(
        bytes32,
        address,
        bytes calldata,
        bytes calldata
    ) internal virtual override isValidRelayer {}

    function _getPermitLifetime(
        bytes32,
        address requester,
        uint64 requestedDuration,
        bytes calldata context
    ) internal view virtual returns (uint64) {
        (requester, context);
        return requestedDuration;
    }
}
