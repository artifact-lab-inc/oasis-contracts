// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {UUIDRegistry} from "./helper/UUIDRegistry.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/**
 * @title AttributeSegmentLinker
 * @dev A contract that manages the provisioning and retrieval of secret keys for identities.
 */
contract AttributeSegmentLinker is UUIDRegistry, EIP712 {
    /// @dev The requested key has already been provisioned.
    error KeyAlreadyProvisioned(); // 6PXuXA==

    error SignatureExpired(uint256 expiredAt);

    error UnauthorizedPermit(uint256 index);

    // Add a new event to emit when an attribute is stored
    event AttributeStored(bytes32 attributeHash);

    event SegmentStored(bytes32 uuid);

    /**
     * @dev Structure representing a signed key request.
     * @param req The key request details.
     * @param sig The signature of the key request.
     */
    struct SignedKeyRequest {
        KeyRequest req;
        bytes sig;
    }

    /**
     * @dev Structure representing a key request.
     * @param attributeHash The hash of attribute name or segment bytes32.
     * @param requester The address of the requester.
     * @param expiry The expiration timestamp of the request.
     */
    struct KeyRequest {
        bytes32 attributeHash;
        address requester;
        uint256 expiry;
    }
    mapping(bytes32 => mapping(bytes32 => bytes32)) internal segmentMapping;

    mapping(bytes32 => bytes32) internal attributeMapping;

    modifier segmentMappingACL(bytes32 uuid) {
        if (
            msg.sender != owner() &&
            keccak256(abi.encodePacked(msg.sender)) !=
            uuidRegistration[uuid].vendorHash
        ) revert Unauthorized();
        _;
    }

    /**
     * @dev Initializes the AttributeSegmentLinker contract.
     */
    constructor()
        UUIDRegistry(msg.sender)
        EIP712("AttributeSegmentLinker", "1")
    {}

    /**
     * @dev Modifier to restrict access to only permitted callers based on a signed key request.
     * @param signedKeyReq The signed key request.
     */
    function onlyPermitted(
        SignedKeyRequest calldata signedKeyReq
    ) internal view returns (bool status) {
        KeyRequest calldata req = signedKeyReq.req;
        bytes32 typeHash = keccak256(
            "KeyRequest(bytes32 key,address requester,uint256 expiry)"
        );
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(typeHash, req)));
        address signer = ECDSA.recover(digest, signedKeyReq.sig);
        if (req.expiry < block.timestamp) revert SignatureExpired(req.expiry);
        else {
            Permit memory permit = readPermit(req.requester, req.attributeHash);
            if (signer != req.requester || permit.expiry <= block.timestamp)
                status = false;
            status = true;
        }
    }

    // Add a new function setAttribute to update a global attribute mapping
    function setAttribute(
        string[] calldata inputs,
        bytes calldata pers
    ) external onlyRegistrant {
        for (uint256 i = 0; i < inputs.length; i++) {
            bytes32 attributeHash = keccak256(abi.encodePacked(inputs[i]));
            if (attributeMapping[attributeHash] != bytes32(0))
                revert KeyAlreadyProvisioned();
            attributeMapping[attributeHash] = _generateKey(pers);
            emit AttributeStored(attributeHash);
        }
    }

    function storeSegments(
        bytes32 uuid,
        string calldata name,
        uint256 jobId,
        bytes calldata pers
    ) external onlyRegistrant {
        bytes32 segmentHash = keccak256(abi.encodePacked(name, jobId));
        if (segmentMapping[uuid][segmentHash] != bytes32(0))
            revert KeyAlreadyProvisioned();
        segmentMapping[uuid][segmentHash] = _generateKey(pers);
        emit SegmentStored(uuid);
    }

    function getSegmentKey(
        bytes32 uuid,
        string calldata name,
        uint256 jobId
    ) external view segmentMappingACL(uuid) returns (bytes32) {
        bytes32 segmentHash = keccak256(abi.encodePacked(name, jobId));
        return segmentMapping[uuid][segmentHash];
    }

    /**
     * @dev Retrieves the attribute's keys for the specified attribute Hash based on a signed key request.
     * @param signedKeyReqs The signed key request.
     * @return keys attribute secret keys.
     */
    function getAttributeKeys(
        SignedKeyRequest[] calldata signedKeyReqs
    ) external view returns (bytes32[] memory keys) {
        keys = new bytes32[](signedKeyReqs.length);
        for (uint256 i = 0; i < signedKeyReqs.length; i++) {
            bool res = onlyPermitted(signedKeyReqs[i]);
            if (res)
                keys[i] = attributeMapping[signedKeyReqs[i].req.attributeHash];
            else revert UnauthorizedPermit(i);
        }
    }

    /**
     * @dev Generates a random secret key using the provided pers.
     * @param pers Additional personalization dataused for key generation.
     * @return The generated key.
     */
    function _generateKey(bytes calldata pers) internal view returns (bytes32) {
        return bytes32(_randomBytes(32, pers));
    }
}
