// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {IAttributePermitter} from "../../permitters/helper/IAttributePermitter.sol";

interface IUUIDRegistry is IERC165 {
    error Unauthorized();

    // The provided contract address does not support the correct interface.
    error InterfaceUnsupported(); // bbaa55aa u6pVqg==

    struct Permit {
        uint64 expiry;
    }

    event UUIDCreated(bytes32 indexed uuid, bytes32 vendorHash);
    event UUIDDestroyed(bytes32 indexed uuid);
    event AttributeGranted(bytes32 indexed uuid, address indexed to);
    event AttributeRevoked(bytes32 indexed uuid, address indexed from);
    event RegistrantStatusUpdated(address indexed registrant, bool status);
    event PermitterStatusUpdated(
        IAttributePermitter indexed permitter,
        bool status
    );

    // Creates a new identity controlled by a valid registrant.
    /// @param vendorHash An identifier to which the generated identity will be assigned to.
    /// @param pers [optional] Extra entropy used to generate the identity.
    function createUUID(bytes32 vendorHash, bytes calldata pers) external;

    // Destroys an existing identity.
    function destroyUUID(bytes32 uuid) external;

    // Sets the status of a permitter.
    function setPermitter(address permitter, bool status) external;

    // Sets the status of a registrant.
    function setRegistrant(address registrant, bool status) external;

    /// Grants an attribute's permit to an account. Must be called by the permitter.
    /// @param attributeKey The attributeKey to grant.
    /// @param to The address of the permit's recipient.
    /// @param expiry The Unix timestamp at which the permit expires.
    function grantAttribute(
        bytes32 attributeKey,
        address to,
        uint64 expiry
    ) external;

    // Called by the attribute's permitter to revoke the identity from the recipient.
    function revokeAttribute(bytes32 attributeKey, address from) external;

    /// Returns the permit to the attribute held by the provided account, if any.
    function readPermit(
        address holder,
        bytes32 attributeKey
    ) external view returns (Permit memory);

    // Checks if an address is a valid registrant.
    function isValidRegistrant(address _addr) external view returns (bool);
}
