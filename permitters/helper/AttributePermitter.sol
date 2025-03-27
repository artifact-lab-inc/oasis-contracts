// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC165, IERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";

import {IUUIDRegistry} from "../../identityModule/helper/IUUIDRegistry.sol";
import {IAttributePermitter} from "./IAttributePermitter.sol";

abstract contract AttributePermitter is IAttributePermitter, ERC165 {
    /// The provided contract address does not support the correct interface.
    error InterfaceUnsupported(); // bbaa55aa u6pVqg==

    /// The action is disallowed.
    error Unauthorized(); // 82b42900 grQpAA==
    /// The requested duration of the permit was too long.
    error DurationTooLong(); // lSn1Bg==

    enum UpstreamKind {
        Unknown,
        Registry,
        AttributePermitter
    }

    bytes32 private immutable upstreamAndKind;

    constructor(address upstreamRegistryOrPermitter) {
        if (!ERC165Checker.supportsERC165(upstreamRegistryOrPermitter)) {
            revert InterfaceUnsupported();
        }
        UpstreamKind upstreamKind;
        if (
            ERC165Checker.supportsERC165InterfaceUnchecked(
                upstreamRegistryOrPermitter,
                type(IUUIDRegistry).interfaceId
            )
        ) {
            upstreamKind = UpstreamKind.Registry;
        } else {
            revert InterfaceUnsupported();
        }
        upstreamAndKind = bytes32(
            uint256(bytes32(bytes20(upstreamRegistryOrPermitter))) |
                uint8(upstreamKind)
        );
    }

    function acquireAttribute(
        bytes32[] calldata attributeHashes,
        address requester,
        uint64 duration,
        bytes calldata context,
        bytes calldata authorization
    ) external virtual override returns (uint64 expiry) {
        for (uint256 i; i < attributeHashes.length; i++) {
            bytes32 attributeHash = attributeHashes[i];
            _beforeAcquireAttribute({
                attributeHash: attributeHash,
                requester: requester,
                duration: duration,
                context: context,
                authorization: authorization
            });
            expiry = _acquireAttribute({
                attributeHash: attributeHash,
                requester: requester,
                duration: duration,
                context: context,
                authorization: authorization
            });
            (UpstreamKind upstreamKind, address up) = _upstream();
            if (upstreamKind == UpstreamKind.Registry) {
                IUUIDRegistry(up).grantAttribute(
                    attributeHash,
                    requester,
                    expiry
                );
            } else {
                revert InterfaceUnsupported();
            }
            _afterAcquireAttribute(attributeHash, requester, context);
        }
    }

    function releaseAttribute(
        bytes32[] calldata attributeHashes,
        address requester,
        bytes calldata context,
        bytes calldata authorization
    ) external virtual override {
        for (uint256 i; i < attributeHashes.length; i++) {
            bytes32 attributeHash = attributeHashes[i];
            _beforeReleaseAttribute({
                attributeHash: attributeHash,
                requester: requester,
                context: context,
                authorization: authorization
            });
            _releaseAttribute({
                attributeHash: attributeHash,
                requester: requester,
                context: context,
                authorization: authorization
            });
            (UpstreamKind upstreamKind, address up) = _upstream();
            if (upstreamKind == UpstreamKind.Registry) {
                IUUIDRegistry(up).revokeAttribute(attributeHash, requester);
            } else {
                revert InterfaceUnsupported();
            }
            _afterReleaseAttribute(attributeHash, requester, context);
        }
    }

    function upstream() external view virtual override returns (address) {
        (, address addr) = _upstream();
        return addr;
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ERC165, IERC165) returns (bool) {
        return
            interfaceId == type(IAttributePermitter).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    function _upstream() internal view returns (UpstreamKind, address) {
        bytes32 up = upstreamAndKind;
        address addr = address(bytes20(up));
        UpstreamKind kind = UpstreamKind(uint256(up) & 0xff);
        return (kind, addr);
    }

    function _getUUIDRegistry() internal view returns (IUUIDRegistry) {
        (UpstreamKind kind, address up) = _upstream();
        bool isRegistry = kind == UpstreamKind.Registry;
        while (!isRegistry) {
            up = IAttributePermitter(up).upstream();
            isRegistry = ERC165Checker.supportsInterface(
                up,
                type(IUUIDRegistry).interfaceId
            );
        }
        return IUUIDRegistry(up);
    }

    /// Authorizes the attributeHash acquisition request, returning the expiry if approved or reverting if denied.
    function _acquireAttribute(
        bytes32 attributeHash,
        address requester,
        uint64 duration,
        bytes calldata context,
        bytes calldata authorization
    ) internal virtual returns (uint64 expiry);

    /// Authorizes the attributeHash release request, reverting if denied.
    function _releaseAttribute(
        bytes32 attributeHash,
        address requester,
        bytes calldata context,
        bytes calldata authorization
    ) internal virtual;

    function _beforeAcquireAttribute(
        bytes32 attributeHash,
        address requester,
        uint64 duration,
        bytes calldata context,
        bytes calldata authorization
    ) internal virtual {}

    function _afterAcquireAttribute(
        bytes32 attributeHash,
        address requester,
        bytes calldata context
    ) internal virtual {}

    function _beforeReleaseAttribute(
        bytes32 attributeHash,
        address requester,
        bytes calldata context,
        bytes calldata authorization
    ) internal virtual {}

    function _afterReleaseAttribute(
        bytes32 attributeHash,
        address requester,
        bytes calldata context
    ) internal virtual {}
}
