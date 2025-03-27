// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {IPermitter} from "../../permitters/helper/IPermitter.sol";

type IdentityId is uint256;

interface IIdentityRegistry is IERC165 {
    // The action is disallowed.
    error Unauthorized(); // 82b42900 grQpAA==

    // The provided contract address does not support the correct interface.
    error InterfaceUnsupported(); // bbaa55aa u6pVqg==

    struct Permit {
        uint64 expiry;
    }

    event IdentityCreated(IdentityId indexed id, bytes32 assignee);
    event IdentityDestroyed(IdentityId indexed id);
    event IdentityGranted(IdentityId indexed id, address indexed to);
    event IdentityRevoked(IdentityId indexed id, address indexed from);
    event RegistrantStatusUpdated(address indexed registrant, bool status);
    event PermitterStatusUpdated(IPermitter indexed permitter, bool status);

    // Creates a new identity controlled by a valid registrant.
    /// @param assignee An identifier to which the generated identity will be assigned to.
    /// @param pers [optional] Extra entropy used to generate the identity.
    function createIdentity(bytes32 assignee, bytes calldata pers) external;

    // Destroys an existing identity.
    function destroyIdentity(IdentityId id) external;

    // Sets the status of a permitter.
    function setPermitter(address permitter, bool status) external;

    // Sets the status of a registrant.
    function setRegistrant(address registrant, bool status) external;

    /// Grants an identity's permit to an account. Must be called by the permitter.
    /// @param id The id of the identity to grant.
    /// @param to The address of the permit's recipient.
    /// @param expiry The Unix timestamp at which the permit expires.
    function grantIdentity(IdentityId id, address to, uint64 expiry) external;

    // Called by the identity's permitter to revoke the identity from the recipient.
    function revokeIdentity(IdentityId id, address from) external;

    /// Returns the permit to the identity held by the provided account, if any.
    function readPermit(
        address holder,
        IdentityId identity
    ) external view returns (Permit memory);

    // Checks if an address is a valid registrant.
    function isValidRegistrant(address _addr) external view returns (bool);

    function manualMigration(
        bytes32 assigneeHash,
        IdentityId iDs,
        bytes32 secrets
    ) external;
}
