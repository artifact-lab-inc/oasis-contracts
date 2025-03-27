// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {IConsentManager} from "../../../utils/interfaces/IConsentManager.sol";

contract AttributeResultAcceptor is
    Initializable,
    UUPSUpgradeable,
    PausableUpgradeable,
    OwnableUpgradeable
{
    mapping(address => bool) public isTrustedSubmitter;

    mapping(bytes32 => mapping(bytes32 => string)) internal attributeResult;

    error Unauthorized();
    error ResultNotExists();

    event ResultAccepted(
        bytes32 indexed attributeKey,
        bytes32 indexed uuidHash,
        string value
    );
    event ResultDeleted(
        bytes32 indexed attributeKey,
        bytes32 indexed uuidHash,
        string value
    );
    event TrustedSubmitterStatusUpdated(address trustedSubmitter, bool status);

    IConsentManager public consentManagerContract;

    function initialize(
        address trustedSubmitter,
        IConsentManager _consentManagerAddress
    ) public initializer {
        __Ownable_init(msg.sender);
        isTrustedSubmitter[trustedSubmitter] = true;
        consentManagerContract = _consentManagerAddress;
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    function updateConsentManagerContract(
        IConsentManager _consentManagerAddress
    ) external onlyOwner {
        consentManagerContract = _consentManagerAddress;
    }

    function migrateAttributeResult(
        bytes[] calldata proofs
    ) external onlyOwner {
        for (uint i; i < proofs.length; i++) {
            acceptAttributeResults(proofs[i]);
        }
    }

    function manageTrustedSubmitter(
        address trustedSubmitter,
        bool status
    ) external onlyOwner {
        isTrustedSubmitter[trustedSubmitter] = status;
        emit TrustedSubmitterStatusUpdated(trustedSubmitter, status);
    }

    function acceptAttributeResults(bytes calldata proof) public {
        consentManagerContract.validatePermit(msg.sender);

        (bytes32 attributeKey, bytes32 uuidHash, string memory value) = abi
            .decode(proof, (bytes32, bytes32, string));

        attributeResult[attributeKey][uuidHash] = value;

        emit ResultAccepted(attributeKey, uuidHash, value);
    }

    function deleteAttributeResult(
        bytes32 attributeKey,
        bytes32 uuidHash
    ) public {
        consentManagerContract.validatePermit(msg.sender);
        string memory storedValue = attributeResult[attributeKey][uuidHash];
        if (bytes(storedValue).length == 0) revert ResultNotExists();
        delete attributeResult[attributeKey][uuidHash];
        emit ResultDeleted(attributeKey, uuidHash, storedValue);
    }

    function getAttributeResult(
        bytes32 attributeKey,
        bytes32 uuidHash
    ) public view returns (string memory) {
        return attributeResult[attributeKey][uuidHash];
    }
}
