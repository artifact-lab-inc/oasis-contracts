// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {IdentityId, IdentityRegistry} from "./helper/IdentityRegistry.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/**
 * @title OmniKeyStore
 * @dev A contract that manages the provisioning and retrieval of secret keys for identities.
 */
contract OmniKeyStore is IdentityRegistry, EIP712 {
    type Key is bytes32;

    /// @dev The requested key has not been provisioned.
    error KeyNotProvisioned(); // cUmqUg==
    /// @dev The requested key has already been provisioned.
    error KeyAlreadyProvisioned(); // 6PXuXA==

    error SignatureExpired(uint256 expiredAt);

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
     * @param identity The identity ID.
     * @param requester The address of the requester.
     * @param expiry The expiration timestamp of the request.
     */
    struct KeyRequest {
        IdentityId identity;
        address requester;
        uint256 expiry;
    }

    mapping(IdentityId => Key) internal primaryKeys;
    mapping(IdentityId => Key) internal secondaryKeys;

    OmniKeyStore immutable oldContract;

    /**
     * @dev Initializes the OmniKeyStore contract.
     */
    constructor(
        address _oldContractAddress
    ) IdentityRegistry(msg.sender) EIP712("OmniKeyStore", "1") {
        oldContract = OmniKeyStore(_oldContractAddress);
        _pause();
    }

    function togglePause() external onlyOwner {
        paused() ? _unpause() : _pause();
    }

    function manualMigration(
        bytes32 assigneeHash,
        IdentityId iDs,
        bytes32 secrets
    ) external override onlyPermitter whenPaused {
        if (IdentityId.unwrap(fetchIdentity[assigneeHash]) != 0)
            revert PreExists();

        if (idRegistration[iDs].registered) revert IdAlreadyAssigned();

        fetchIdentity[assigneeHash] = iDs;
        idRegistration[iDs] = Registration({
            registered: true,
            assigneeHash: assigneeHash
        });

        primaryKeys[iDs] = Key.wrap(secrets);
        emit IdentityCreated(iDs, assigneeHash);
    }

    function autoMigration(
        bytes32 _assigneeHash,
        SignedKeyRequest calldata signedKeyReq
    ) external onlyOwner whenPaused {
        // Migrate permitted accounts
        IdentityId id = oldContract.fetchIdentity(_assigneeHash);

        primaryKeys[id] = oldContract.getKey(signedKeyReq);

        idRegistration[id] = Registration({
            registered: true,
            assigneeHash: _assigneeHash
        });

        for (
            uint256 i = 0;
            i < oldContract.getPermittedAccountsLength(id);
            i++
        ) {
            address permittedAcc = oldContract.getPermittedAccountAtIndex(
                id,
                i
            );
            permits[permittedAcc][id] = oldContract.readPermit(
                permittedAcc,
                id
            );
            EnumerableSet.add(permittedAccounts[id], permittedAcc);
        }
    }

    /**
     * @dev Modifier to restrict access to only permitted callers based on a signed key request.
     * @param signedKeyReq The signed key request.
     */
    modifier onlyPermitted(SignedKeyRequest calldata signedKeyReq) {
        KeyRequest calldata req = signedKeyReq.req;
        bytes32 typeHash = keccak256(
            "KeyRequest(uint256 identity,address requester,uint256 expiry)"
        );
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(typeHash, req)));
        address signer = ECDSA.recover(digest, signedKeyReq.sig);
        if (req.expiry < block.timestamp) revert SignatureExpired(req.expiry);
        if (
            keccak256(abi.encodePacked(signer)) ==
            idRegistration[req.identity].assigneeHash
        ) _;
        else {
            Permit memory permit = readPermit(req.requester, req.identity);
            if (signer != req.requester || permit.expiry <= block.timestamp)
                revert Unauthorized();
            _;
        }
    }

    /**
     * @dev Retrieves the primary key for the specified identity based on a signed key request.
     * @param signedKeyReq The signed key request.
     * @return The primary key.
     */
    function getKey(
        SignedKeyRequest calldata signedKeyReq
    ) external view onlyPermitted(signedKeyReq) returns (Key) {
        return primaryKeys[signedKeyReq.req.identity];
    }

    /**
     * @dev Retrieves the secondary(backup) key for the specified identity based on a signed key request.
     * @param signedKeyReq The signed key request.
     * @return The secondary key.
     */
    function getSecondaryKey(
        SignedKeyRequest calldata signedKeyReq
    ) external view onlyPermitted(signedKeyReq) returns (Key) {
        Key key = secondaryKeys[signedKeyReq.req.identity];
        if (Key.unwrap(key) == 0) revert KeyNotProvisioned();
        return key;
    }

    /**
     * @dev Provisions a secondary key for the specified identity.
     * @param identityId The identity ID.
     * @param pers Additional personalization dataused for key generation.
     */
    function provisionSecondaryKey(
        IdentityId identityId,
        bytes calldata pers
    ) external onlyRegistrant {
        Key key = secondaryKeys[identityId];
        if (Key.unwrap(key) != 0) revert KeyAlreadyProvisioned();
        secondaryKeys[identityId] = _generateKey(pers);
    }

    /**
     * @dev Rotates(swap primary and secondary) the keys for the specified identity.
     * @param identityId The identity ID.
     */
    function rotateKeys(IdentityId identityId) external onlyRegistrant {
        primaryKeys[identityId] = secondaryKeys[identityId];
        secondaryKeys[identityId] = Key.wrap(0);
    }

    /**
     * @dev Callback function triggered when an identity is created.
     * @param id The identity ID.
     * @param pers Additional personalization dataused for key generation.
     */
    function _whenIdentityCreated(
        IdentityId id,
        bytes calldata pers
    ) internal override {
        primaryKeys[id] = _generateKey(pers);
    }

    /**
     * @dev Callback function triggered when an identity is destroyed.
     * @param id The identity ID.
     */
    function _whenIdentityDestroyed(IdentityId id) internal override {
        primaryKeys[id] = Key.wrap(0);
        secondaryKeys[id] = Key.wrap(0);
    }

    /**
     * @dev Generates a random secret key using the provided pers.
     * @param pers Additional personalization dataused for key generation.
     * @return The generated key.
     */
    function _generateKey(bytes calldata pers) internal view returns (Key) {
        return Key.wrap(bytes32(_randomBytes(32, pers)));
    }
}
