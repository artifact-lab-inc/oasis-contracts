// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Sapphire} from "@oasisprotocol/sapphire-contracts/contracts/Sapphire.sol";
import {ERC165, IERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IdentityId, IIdentityRegistry, IPermitter} from "./IIdentityRegistry.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title IdentityRegistry
 * @dev A contract that manages the creation, destruction, and permissioning of identities.
 */
abstract contract IdentityRegistry is
    IIdentityRegistry,
    Ownable,
    ERC165,
    Pausable
{
    error PreExists();
    error IdAlreadyAssigned();

    using EnumerableSet for EnumerableSet.AddressSet;

    // representing the registration status of an identity
    struct Registration {
        bool registered; // Indicates whether the identity is registered
        bytes32 assigneeHash; // Hash of the assignee address
    }

    // Mapping to store the permitter status
    mapping(IPermitter => bool) public isPermitter;

    // Mapping to store the registrant status
    mapping(address => bool) internal registrantStatus;

    // Mapping to store the registration details of an identity
    mapping(IdentityId => Registration) public idRegistration;

    mapping(bytes32 => IdentityId) public fetchIdentity;

    // Mapping to store all the permitted accounts to acquire that identity
    mapping(IdentityId => EnumerableSet.AddressSet) internal permittedAccounts;

    // Mapping to store the permit expiry for a specific account and identity
    mapping(address => mapping(IdentityId => Permit)) internal permits;

    // Modifier to restrict access to only permitted callers
    modifier onlyPermitter() {
        if (!isPermitter[_requireIsPermitter(msg.sender)])
            revert Unauthorized();
        _;
    }

    // Modifier to restrict access to only registered callers(identity registrants)
    modifier onlyRegistrant() {
        if (!isValidRegistrant(msg.sender)) revert Unauthorized();
        _;
    }

    constructor(address _initialOwner) Ownable(_initialOwner) {}

    function manualMigration(
        bytes32 assigneeHash,
        IdentityId iDs,
        bytes32 secrets
    ) external virtual onlyPermitter whenPaused {}

    function getPermittedAccountsLength(
        IdentityId identityId
    ) public view returns (uint256) {
        return permittedAccounts[identityId].length();
    }

    function getPermittedAccountAtIndex(
        IdentityId identityId,
        uint256 index
    ) public view returns (address) {
        return permittedAccounts[identityId].at(index);
    }

    /**
     * @notice Creates a new identity and assigns it to an assignee.
     * @param assignee An identifier to which the generated identity will be assigned to.
     * @param pers Additional personalization dataused for randomness.
     */
    function createIdentity(
        bytes32 assignee,
        bytes calldata pers
    ) external override onlyRegistrant whenNotPaused {
        if (IdentityId.unwrap(fetchIdentity[assignee]) != 0) revert PreExists();

        IdentityId _id = IdentityId.wrap(
            uint256(bytes32(_randomBytes(32, pers)))
        );
        if (idRegistration[_id].registered) revert IdAlreadyAssigned();

        fetchIdentity[assignee] = _id;
        idRegistration[_id] = Registration({
            registered: true,
            assigneeHash: assignee
        });

        _whenIdentityCreated(_id, pers);
        emit IdentityCreated(_id, assignee);
    }

    /**
     * @notice Destroys an existing identity.
     * @param id The identity to be destroyed.
     */
    function destroyIdentity(IdentityId id) external override onlyRegistrant {
        fetchIdentity[idRegistration[id].assigneeHash] = IdentityId.wrap(0);
        delete idRegistration[id];

        EnumerableSet.AddressSet storage permitted = permittedAccounts[id];
        for (uint256 i; i < permitted.length(); i++) {
            address account = permitted.at(i);
            delete permits[account][id];
            permitted.remove(account);
        }
        _whenIdentityDestroyed(id);
        emit IdentityDestroyed(id);
    }

    /**
     * @notice Sets the status of a permitter whether to whitelist or blacklist
     * @param permitter The address of the permitter.
     * @param status The new status of the permitter.
     */
    function setPermitter(
        address permitter,
        bool status
    ) external override onlyOwner {
        IPermitter _permitter = _requireIsPermitter(permitter);
        isPermitter[_permitter] = status;
        emit PermitterStatusUpdated(_permitter, status);
    }

    /**
     * @notice Sets the status of a registrant whether to whitelist or blacklist
     * @param registrant The address of the registrant.
     * @param status The new status of the registrant.
     */
    function setRegistrant(
        address registrant,
        bool status
    ) external override onlyOwner {
        registrantStatus[registrant] = status;
        emit RegistrantStatusUpdated(registrant, status);
    }

    /**
     * @notice Checks if an address is a valid registrant
     * @param _addr The address to check.
     * @return A boolean indicating whether the address is a valid registrant.
     */
    function isValidRegistrant(
        address _addr
    ) public view override returns (bool) {
        return registrantStatus[_addr];
    }

    /**
     * @notice Grants the identity to the recipient.
     * @param id The ID of the identity.
     * @param to The address of the recipient.
     * @param expiry The expiry timestamp for the permit.
     */
    function grantIdentity(
        IdentityId id,
        address to,
        uint64 expiry
    ) external override onlyPermitter {
        permits[to][id] = Permit({expiry: expiry});
        permittedAccounts[id].add(to);
        emit IdentityGranted(id, to);
    }

    /**
     * @notice Revokes the identity from the existing holder.
     * @param id The ID of the identity.
     * @param from The address of the holder.
     */
    function revokeIdentity(
        IdentityId id,
        address from
    ) external override onlyPermitter {
        delete permits[from][id];
        permittedAccounts[id].remove(from);
        emit IdentityRevoked(id, from);
    }

    /**
     * @notice Retrieves the permit associated with the holder and identity.
     * @param holder The address of the holder.
     * @param id The ID of the identity.
     * @return The permit associated with the holder and identity.
     */
    function readPermit(
        address holder,
        IdentityId id
    ) public view override returns (Permit memory) {
        return permits[holder][id];
    }

    /**
     * @notice Checks if the contract supports a given interface.
     * @param interfaceId The interface identifier.
     * @return A boolean indicating whether the contract supports the given interface.
     */
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ERC165, IERC165) returns (bool) {
        return
            interfaceId == type(IIdentityRegistry).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    function _requireIsPermitter(
        address permitter
    ) internal view returns (IPermitter) {
        if (
            !ERC165Checker.supportsInterface(
                permitter,
                type(IPermitter).interfaceId
            )
        ) {
            revert InterfaceUnsupported();
        }
        return IPermitter(permitter);
    }

    function _whenIdentityCreated(
        IdentityId id,
        bytes calldata pers
    ) internal virtual {}

    function _whenIdentityDestroyed(IdentityId id) internal virtual {}

    /**
     * @notice Generates pseudorandom bytes, When run on Sapphire, the random bytes are private and cryptographically secure.
     * @param count The number of bytes to generate.
     * @param pers Additional personalization dataused for randomness.
     * @return A byte array containing the pseudorandom bytes.
     */
    function _randomBytes(
        uint256 count,
        bytes calldata pers
    ) internal view returns (bytes memory) {
        if (
            block.chainid == 0x5aff ||
            block.chainid == 0x5afe ||
            block.chainid == 0x5afd
        ) {
            return Sapphire.randomBytes(count, pers);
        }
        uint256 words = (count + 31) >> 5;
        bytes memory out = new bytes(words << 5);
        bytes32 seed;
        if (block.chainid == 1337 || block.chainid == 31337) {
            seed = keccak256(abi.encodePacked(msg.sender, count, pers));
        } else {
            seed = keccak256(
                abi.encodePacked(
                    msg.sender,
                    blockhash(block.number),
                    block.timestamp,
                    block.prevrandao,
                    block.coinbase,
                    count,
                    pers
                )
            );
        }
        for (uint256 i = 0; i < words; i++) {
            unchecked {
                seed = keccak256(
                    abi.encodePacked(seed, i, blockhash(block.number - i - 1))
                );
            }
            assembly ("memory-safe") {
                mstore(add(out, add(32, mul(32, i))), seed)
            }
        }
        assembly ("memory-safe") {
            mstore(out, count)
        }
        return out;
    }
}
