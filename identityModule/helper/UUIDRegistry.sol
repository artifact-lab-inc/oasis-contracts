// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Sapphire} from "@oasisprotocol/sapphire-contracts/contracts/Sapphire.sol";
import {ERC165, IERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IUUIDRegistry, IAttributePermitter} from "./IUUIDRegistry.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title UUIDRegistry
 */
abstract contract UUIDRegistry is IUUIDRegistry, Ownable, ERC165, Pausable {
    error PreExists();
    error UUIDAlreadyAssigned();
    error UUIDNotExists();

    using EnumerableSet for EnumerableSet.AddressSet;

    // representing the registration status of an uuid
    struct Registration {
        bool registered; // Indicates whether the uuid is registered
        bytes32 vendorHash; // Hash of the assignee address
    }

    // Mapping to store the permitter status
    mapping(IAttributePermitter => bool) public isPermitter;

    // Mapping to store the registrant status
    mapping(address => bool) internal registrantStatus;

    // Mapping to store the registration details of an uuid
    mapping(bytes32 => Registration) public uuidRegistration;

    mapping(bytes32 => bytes32) public fetchUUID;

    // Mapping to store all the permitted accounts to acquire that uuid
    mapping(bytes32 => EnumerableSet.AddressSet) internal permittedAccounts;

    // Mapping to store the permit expiry for a specific account and uuid
    mapping(address => mapping(bytes32 => Permit)) internal permits;

    // Modifier to restrict access to only permitted callers
    modifier onlyPermitter() {
        if (!isPermitter[_requireIsPermitter(msg.sender)])
            revert Unauthorized();
        _;
    }

    // Modifier to restrict access to only registered callers(uuid registrants)
    modifier onlyRegistrant() {
        if (!isValidRegistrant(msg.sender)) revert Unauthorized();
        _;
    }

    constructor(address _initialOwner) Ownable(_initialOwner) {}

    /**
     * @notice Sets the status of a permitter whether to whitelist or blacklist
     * @param permitter The address of the permitter.
     * @param status The new status of the permitter.
     */
    function setPermitter(
        address permitter,
        bool status
    ) external override onlyOwner {
        IAttributePermitter _permitter = _requireIsPermitter(permitter);
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
     * @notice Creates a new uuid and assigns it to an assignee.
     * @param assignee An identifier to which the generated uuid will be assigned to.
     * @param pers Additional personalization data used for randomness.
     */
    function createUUID(
        bytes32 assignee,
        bytes calldata pers
    ) external override onlyRegistrant {
        if (fetchUUID[assignee] != 0) revert PreExists();

        bytes32 uuid = bytes32(_randomBytes(32, pers));
        if (uuidRegistration[uuid].registered) revert UUIDAlreadyAssigned();

        fetchUUID[assignee] = uuid;
        uuidRegistration[uuid] = Registration({
            registered: true,
            vendorHash: assignee
        });

        _whenUUIDCreated(uuid, pers);
        emit UUIDCreated(uuid, assignee);
    }

    /**
     * @notice Destroys an existing uuid.
     * @param uuid The uuid to be destroyed.
     */
    function destroyUUID(bytes32 uuid) external override onlyRegistrant {
        if (!uuidRegistration[uuid].registered) revert UUIDNotExists();
        fetchUUID[uuidRegistration[uuid].vendorHash] = bytes32(0);
        delete uuidRegistration[uuid];

        _whenUUIDDestroyed(uuid);
        emit UUIDDestroyed(uuid);
    }

    /**
     * @notice Grants the attributeKeys to the recipient.
     * @param attributeKeys keys of attribute mapping
     * @param to The address of the recipient.
     * @param expiry The expiry timestamp for the permit.
     */
    function grantAttribute(
        bytes32 attributeKeys,
        address to,
        uint64 expiry
    ) external override onlyPermitter {
        permits[to][attributeKeys] = Permit({expiry: expiry});
        permittedAccounts[attributeKeys].add(to);
        emit AttributeGranted(attributeKeys, to);
    }

    /**
     * @notice Revokes the attributeKeys from the existing holder.
     * @param attributeKeys  keys of attribute mapping
     * @param from The address of the holder.
     */
    function revokeAttribute(
        bytes32 attributeKeys,
        address from
    ) external override onlyPermitter {
        delete permits[from][attributeKeys];
        permittedAccounts[attributeKeys].remove(from);
        emit AttributeRevoked(attributeKeys, from);
    }

    /**
     * @notice Retrieves the permit associated with the holder and attributeKeys.
     * @param holder The address of the holder.
     * @param attributeKeys  keys of attribute mapping
     * @return The permit associated with the holder and attributeKeys.
     */
    function readPermit(
        address holder,
        bytes32 attributeKeys
    ) public view override returns (Permit memory) {
        return permits[holder][attributeKeys];
    }

    function getPermittedAccountsLength(
        bytes32 attributeKeys
    ) public view returns (uint256) {
        return permittedAccounts[attributeKeys].length();
    }

    function getPermittedAccountAtIndex(
        bytes32 attributeKeys,
        uint256 index
    ) public view returns (address) {
        return permittedAccounts[attributeKeys].at(index);
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
            interfaceId == type(IUUIDRegistry).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    function _requireIsPermitter(
        address permitter
    ) internal view returns (IAttributePermitter) {
        if (
            !ERC165Checker.supportsInterface(
                permitter,
                type(IAttributePermitter).interfaceId
            )
        ) {
            revert InterfaceUnsupported();
        }
        return IAttributePermitter(permitter);
    }

    function _whenUUIDCreated(
        bytes32 uuid,
        bytes calldata pers
    ) internal virtual {}

    function _whenUUIDDestroyed(bytes32 uuid) internal virtual {}

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
        // Source: Escrin (https://github.com/escrin/escrin/blob/e774a504ef730a0bbf15007b4c3d5b7c62bcde73/evm/contracts/identity/v1/IdentityRegistry.sol#L138)
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
