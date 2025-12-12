// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "../openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import "./interfaces/ICreatorToken.sol";
import "./interfaces/ICreatorTokenLegacy.sol";
import "./interfaces/ITransferValidator.sol";
import "./interfaces/ITransferValidatorSetTokenType.sol";
import {Initializable} from "../openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "./interfaces/ILimitbreakAccountFreezer.sol";

/**
 * @title CreatorTokenValidator
 * @author Limit Break, Inc.
 * @notice CreatorTokenBaseV3 is an abstract contract that provides basic functionality for managing token
 * transfer policies through an implementation of ICreatorTokenTransferValidator/ICreatorTokenTransferValidatorV2/ICreatorTokenTransferValidatorV3.
 * This contract is intended to be used as a base for creator-specific token contracts, enabling customizable transfer
 * restrictions and security policies.
 * <h4>Benefits:</h4>
 * <ul>Provides a flexible and modular way to implement custom token transfer restrictions and security policies.</ul>
 * <ul>Allows creators to enforce policies such as account and codehash blacklists, whitelists, and graylists.</ul>
 * <ul>Can be easily integrated into other token contracts as a base contract.</ul>
 *
 * <h4>Intended Usage:</h4>
 * <ul>Use as a base contract for creator token implementations that require advanced transfer restrictions and
 *   security policies.</ul>
 * <ul>Set and update the ICreatorTokenTransferValidator implementation contract to enforce desired policies for the
 *   creator token.</ul>
 *
 * <h4>Compatibility:</h4>
 * <ul>Backward and Forward Compatible - V1/V2/V3 Creator Token Base will work with V1/V2/V3 Transfer Validators.</ul>
 */
abstract contract CreatorTokenValidator is
    Initializable,
    Ownable2StepUpgradeable,
    ICreatorToken
{
    /// @dev Thrown when setting a transfer validator address that has no deployed code.
    error CreatorTokenBase__InvalidTransferValidatorContract();

    /// @dev The default transfer validator that will be used if no transfer validator has been set by the creator.
    address public constant DEFAULT_TRANSFER_VALIDATOR =
        address(0x721C0078c2328597Ca70F5451ffF5A7B38D4E947);
    uint256 constant TOKEN_TYPE_ERC721 = 721;

    /// @dev Used to determine if the default transfer validator is applied.
    /// @dev Set to true when the creator sets a transfer validator address.
    bool private isValidatorInitialized;
    /// @dev Address of the transfer validator to apply to transactions.
    address private transferValidator;

    event TokenTypeRegistrationFailed(
        address indexed validator,
        address indexed collection,
        bytes reason
    );

    function __CreatorTokenValidator_init() internal onlyInitializing {
        _emitDefaultTransferValidator();
        _registerTokenType(DEFAULT_TRANSFER_VALIDATOR);
    }

    /**
     * @notice Sets the transfer validator for the token contract.
     *
     * @dev    Throws when provided validator contract is not the zero address and does not have code.
     * @dev    Throws when the caller is not the contract owner.
     *
     * @dev    <h4>Postconditions:</h4>
     *         1. The transferValidator address is updated.
     *         2. The `TransferValidatorUpdated` event is emitted.
     *
     * @param transferValidator_ The address of the transfer validator contract.
     */
    function setTransferValidator(address transferValidator_) public onlyOwner {
        bool isValidTransferValidator = transferValidator_.code.length > 0;

        if (transferValidator_ != address(0) && !isValidTransferValidator) {
            revert CreatorTokenBase__InvalidTransferValidatorContract();
        }

        emit TransferValidatorUpdated(
            address(getTransferValidator()),
            transferValidator_
        );

        isValidatorInitialized = true;
        transferValidator = transferValidator_;

        _registerTokenType(transferValidator_);
    }

    /**
     * @notice Returns the transfer validator contract address for this token contract.
     */
    function getTransferValidator()
        public
        view
        override
        returns (address validator)
    {
        validator = transferValidator;

        if (validator == address(0)) {
            if (!isValidatorInitialized) {
                validator = DEFAULT_TRANSFER_VALIDATOR;
            }
        }
    }

    /**
     * @dev Pre-validates a token transfer, reverting if the transfer is not allowed by this token's security policy.
     *      Inheriting contracts are responsible for overriding the _beforeTokenTransfer function, or its equivalent
     *      and calling _validateBeforeTransfer so that checks can be properly applied during token transfers.
     *
     * @dev Be aware that if the msg.sender is the transfer validator, the transfer is automatically permitted, as the
     *      transfer validator is expected to pre-validate the transfer.
     *
     * @dev Throws when the transfer doesn't comply with the collection's transfer policy, if the transferValidator is
     *      set to a non-zero address.
     *
     * @param caller  The address of the caller.
     * @param from    The address of the sender.
     * @param to      The address of the receiver.
     * @param tokenId The token id being transferred.
     */
    function _preValidateTransfer(
        address caller,
        address from,
        address to,
        uint256 tokenId
    ) internal virtual {
        address validator = getTransferValidator();

        if (validator != address(0)) {
            if (msg.sender == validator) {
                return;
            }

            ITransferValidator(validator).validateTransfer(
                caller,
                from,
                to,
                tokenId
            );
        }
    }

    function _tokenType() internal pure virtual returns (uint16) {
        return uint16(TOKEN_TYPE_ERC721);
    }

    /// @dev Registers this collection’s token type with a validator contract (if provided).
    ///      - Checks that `validator` address is non-zero.
    ///      - Uses `extcodesize` via inline assembly to check that `validator` is indeed a deployed contract.
    ///      - If so, calls `setTokenTypeOfCollection` on the validator, passing this contract address and the token-type.
    ///      - If the call fails (reverts or returns error), emits `TokenTypeRegistrationFailed`.
    function _registerTokenType(address validator) internal {
        if (validator != address(0)) {
            uint256 validatorCodeSize;

            assembly {
                // Inline assembly used to retrieve the size of the code at `validator`.
                // A non-zero size indicates the address hosts a contract (deployed code).
                validatorCodeSize := extcodesize(validator)
            }
            if (validatorCodeSize > 0) {
                try
                    ITransferValidatorSetTokenType(validator)
                        .setTokenTypeOfCollection(address(this), _tokenType())
                {} catch (bytes memory reason) {
                    emit TokenTypeRegistrationFailed(
                        validator,
                        address(this),
                        reason
                    );
                }
            }
        }
    }

    /**
     * @dev  Used during contract deployment for constructable and cloneable creator tokens
     * @dev  to emit the `TransferValidatorUpdated` event signaling the validator for the contract
     * @dev  is the default transfer validator.
     */
    function _emitDefaultTransferValidator() internal {
        emit TransferValidatorUpdated(address(0), DEFAULT_TRANSFER_VALIDATOR);
    }

    /**
     * @notice Returns the function selector for the transfer validator's validation function to be called
     * @notice for transaction simulation.
     */
    function getTransferValidationFunction()
        external
        pure
        returns (bytes4 functionSignature, bool isViewFunction)
    {
        functionSignature = bytes4(
            keccak256("validateTransfer(address,address,address,uint256)")
        );
        isViewFunction = true;
    }

    /// @dev Ties the open-zeppelin _beforeTokenTransfer hook to more granular transfer validation logic
    function _beforeTokenTransfer(
        address caller,
        address from,
        address to,
        uint256 firstTokenId
    ) internal virtual {
        _preValidateTransfer(caller, from, to, firstTokenId);
    }

    /// @notice Freezes the specified accounts for a given NFT collection.
    /// @dev Calls the Limitbreak transfer validator to apply the freeze.
    /// @param collection The address of the NFT collection.
    /// @param accounts The list of accounts to freeze.
    function _freeze(
        address collection,
        address[] calldata accounts
    ) internal virtual {
        ILimitbreakAccountFreezer(getTransferValidator())
            .freezeAccountsForCollection(collection, accounts);
    }

    /// @notice Unfreezes the specified accounts for a given NFT collection.
    /// @dev Calls the Limitbreak transfer validator to remove the freeze.
    /// @param collection The address of the NFT collection.
    /// @param accounts The list of accounts to unfreeze.
    function _unfreeze(
        address collection,
        address[] calldata accounts
    ) internal virtual {
        ILimitbreakAccountFreezer(getTransferValidator())
            .unfreezeAccountsForCollection(collection, accounts);
    }

}
