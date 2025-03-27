// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {BaseNitroEnclavePermitter, IIdentityRegistry, IdentityId, NE} from "./helper/NitroEnclavePermitter.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Multicall} from "../../utils/Multicall.sol";

contract TrustedRelayerNitroEnclavePermitter is
    BaseNitroEnclavePermitter,
    Ownable,
    Multicall
{
    event SecretMigration(string message);

    event AcquireConsentInitiated(
        IdentityId identity,
        bytes32 messageHash,
        bytes l2Signature
    );

    event ValidatorCheckInitiated(bytes32 messageHash, bytes l2Signature);

    event UpdatedRelayerStatus(address relayer, bool isTrusted);

    error InputLengthMismatch();

    struct PCRInfo {
        uint16 pcrMask;
        bytes32 pcrHash;
    }

    PCRInfo public pcrInfo;

    mapping(address => bool) public relayerStatus;

    constructor(
        address upstream,
        uint16 _pcrMask,
        bytes32 _pcrHash,
        address relayer
    ) BaseNitroEnclavePermitter(upstream) Ownable(msg.sender) {
        pcrInfo.pcrMask = _pcrMask;
        pcrInfo.pcrHash = _pcrHash;
        relayerStatus[relayer] = true;
    }

    modifier isTrustedRelayer() {
        if (!relayerStatus[msg.sender]) revert Unauthorized();
        _;
    }

    function updateRelayerStatus(
        address relayer,
        bool status
    ) external onlyOwner {
        relayerStatus[relayer] = status;
        emit UpdatedRelayerStatus(relayer, status);
    }

    function migrateSecret(
        bytes32[] calldata assignees,
        IdentityId[] calldata uIds,
        bytes32[] calldata idSecrets
    ) external override isTrustedRelayer {
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

    function updatePCRInfo(
        uint16 _pcrMask,
        bytes32 _pcrHash
    ) external onlyOwner {
        pcrInfo.pcrMask = _pcrMask;
        pcrInfo.pcrHash = _pcrHash;
    }

    function acquireConsent(
        IdentityId identity,
        bytes32 hashedData,
        bytes memory l2Signature,
        bytes calldata context,
        bytes calldata authorization
    ) external isTrustedRelayer {
        _processAttestation(
            identity,
            msg.sender,
            context,
            authorization,
            false
        );
        emit AcquireConsentInitiated(identity, hashedData, l2Signature);
    }

    function validatorCheck(
        bytes32 hashedData,
        bytes memory l2Signature,
        bytes calldata context,
        bytes calldata authorization
    ) external isTrustedRelayer {
        _processAttestation(
            IdentityId.wrap(0),
            msg.sender,
            context,
            authorization,
            false
        );
        emit ValidatorCheckInitiated(hashedData, l2Signature);
    }

    function _beforeAcquireIdentity(
        IdentityId,
        address,
        uint64,
        bytes calldata,
        bytes calldata
    ) internal view override isTrustedRelayer {}

    function _beforeReleaseIdentity(
        IdentityId,
        address,
        bytes calldata,
        bytes calldata
    ) internal view override isTrustedRelayer {}

    function _getPCR()
        internal
        view
        virtual
        override
        returns (NE.PcrSelector memory)
    {
        return NE.PcrSelector({mask: pcrInfo.pcrMask, hash: pcrInfo.pcrHash});
    }
}
