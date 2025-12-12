// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ERC721Upgradeable, IERC721} from "./openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import {ERC721BurnableUpgradeable} from "./openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721BurnableUpgradeable.sol";
import {ERC721EnumerableUpgradeable} from "./openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721EnumerableUpgradeable.sol";
import {ERC721PausableUpgradeable} from "./openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721PausableUpgradeable.sol";
import {ERC721URIStorageUpgradeable} from "./openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721URIStorageUpgradeable.sol";
import {Initializable} from "./openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {Ownable2StepUpgradeable} from "./openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {ERC2981Upgradeable} from "./openzeppelin/contracts-upgradeable/token/common/ERC2981Upgradeable.sol";
import {AccessControlUpgradeable} from "./openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {SmartValidator} from "./smartlocks/SmartValidator.sol";
import {CreatorTokenValidator} from "./limitbreak/CreatorTokenValidator.sol";
import {MessageHashUtils} from "./openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "./openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ReentrancyGuardUpgradeable} from "./openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

/**
 * @title Panini Blockchain - An upgradeable ERC721 contract with extended features like pausing, burning, royalties, role-based access, and signature-based minting/unlocking
 * @notice This contract allows controlled minting, locking, and unlocking of NFTs using off-chain signatures with replay protection
 * @dev Inherits from multiple OpenZeppelin upgradeable extensions and includes custom signature validation
 */
contract PaniniBlockchain is
    Initializable,
    ERC721Upgradeable,
    ERC721EnumerableUpgradeable,
    ERC721URIStorageUpgradeable,
    ERC721PausableUpgradeable,
    Ownable2StepUpgradeable,
    ERC721BurnableUpgradeable,
    ERC2981Upgradeable,
    AccessControlUpgradeable,
    SmartValidator,
    CreatorTokenValidator,
    ReentrancyGuardUpgradeable
{
    using ECDSA for bytes32;
    /** @notice Role identifier for operators allowed to mint and manage NFTs */
    bytes32 public constant PANINI_NFT_OPERATOR =
        keccak256("PANINI_NFT_OPERATOR");
    bytes32 public constant PANINI_NFT_MANAGER =
        keccak256("PANINI_NFT_MANAGER");
    /** @notice Tracks used nonces to prevent signature replay attacks */
    mapping(uint256 => bool) internal usedNonces;
    /** @notice Tracks token IDs that have been burned to prevent reuse */
    mapping(uint256 => bool) public burnedTokenIds;

    /** @notice Toggle to control whether token Minting is enabled */
    bool public isMintingEnabled;

    /** @notice Toggle to control whether token burning is enabled */
    bool public isBurnEnabled;
    /** @notice A lightweight struct used in view-only methods to return token ownership */
    struct TokenOwner {
        uint256 tokenId;
        address owner;
    }
    /**
     * @notice Emitted when tokens are minted or unlocked via signature-based request
     * @param requestNonce The nonce used to prevent replay
     * @param owner The owner who received the tokens
     * @param tokenIds The list of token IDs affected
     */
    event NFTBatchMintedOrUnlocked(
        uint256 indexed requestNonce,
        address indexed owner,
        uint256[] tokenIds
    );

    /**
     * @notice Emitted when tokens are locked for bridging via signature-based request
     * @param requestNonce The nonce used to prevent replay
     * @param owner The owner who locked the tokens
     * @param tokenIds The list of token IDs locked
     */
    event NFTBatchLocked(
        uint256 indexed requestNonce,
        address indexed owner,
        uint256[] tokenIds
    );

    // @notice Emitted when the minting functionality flag is updated.
    event MintStatusUpdated(
        address indexed owner,
        bool oldStatus,
        bool newStatus
    );

    // @notice Emitted when the burning functionality flag is updated.
    event BurnStatusUpdated(
        address indexed admin,
        bool oldStatus,
        bool newStatus
    );

    /**
     * @notice Initializes the NFT contract with royalty and access control
     * @param initialOwner Address to be assigned as the initial contract owner
     * @param nftManager Address to be granted NFT manager role
     * @param receiver Address to receive royalty fees
     * @param feeNumerator Royalty fee (basis points format, e.g., 500 = 5%)
     */
    function initialize(
        address initialOwner,
        address nftManager,
        address receiver,
        uint96 feeNumerator
    ) public initializer {
        __Context_init();
        __ERC165_init();
        __ERC721_init("Panini Blockchain", "PaniniBC");
        __ERC721Enumerable_init();
        __ERC721URIStorage_init();
        __ERC721Pausable_init();
        __Ownable_init(initialOwner);
        __Ownable2Step_init();
        __ERC721Burnable_init();
        __ERC2981_init(receiver, feeNumerator);
        __SmartValidator_init();
        __CreatorTokenValidator_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, initialOwner);
        _grantRole(PANINI_NFT_MANAGER, initialOwner);
        _grantRole(PANINI_NFT_MANAGER, nftManager);
    }

    /** @notice Pauses all token transfers */
    function pause() public onlyRole(PANINI_NFT_MANAGER) {
        _pause();
    }

    /** @notice Unpauses all token transfers */
    function unpause() public onlyRole(PANINI_NFT_MANAGER) {
        _unpause();
    }

    /**
     * @notice Mints a new NFT
     * @param to The address that will own the minted token
     * @param tokenId The ID of the token to be minted
     * @param uri Metadata URI associated with the token
     * @dev Can only be called by PANINI_NFT_OPERATOR
     *
     * NOTE: Sending tokens to contract addresses triggers `onERC721Received`,
     * allowing the receiver contract to run arbitrary code.
     * Risks:
     * - Potential reentrancy or malicious behavior during the callback.
     * Mitigations:
     * - Perform all state updates before the external call.
     * - Use `nonReentrant` when appropriate.
     */
    function safeMint(
        address to,
        uint256 tokenId,
        string memory uri
    ) public onlyRole(PANINI_NFT_OPERATOR) nonReentrant {
        require(isMintingEnabled, "Minting NFT is not enabled");
        require(to != address(0), "Invalid recipient");
        require(
            !burnedTokenIds[tokenId],
            "Token ID was burned and cannot be reused"
        );
        _safeMint(to, tokenId);
        _setTokenURI(tokenId, uri);
    }

    /**
     * @notice Updates the token ownership and validates transfer using panini rules.
     * @inheritdoc ERC721Upgradeable
     */
    function _update(
        address to,
        uint256 tokenId,
        address auth
    )
        internal
        override(
            ERC721Upgradeable,
            ERC721EnumerableUpgradeable,
            ERC721PausableUpgradeable
        )
        returns (address)
    {
        // limit break beforeTokenTransfer hook
        _beforeTokenTransfer(auth, _ownerOf(tokenId), to, tokenId);

        // panini validateTransfer hook
        _validateTransfer(auth, _ownerOf(tokenId), to);

        return super._update(to, tokenId, auth);
    }

    /**
     * @notice Increases the token balance of an account.
     * @inheritdoc ERC721Upgradeable
     */
    function _increaseBalance(
        address account,
        uint128 value
    ) internal override(ERC721Upgradeable, ERC721EnumerableUpgradeable) {
        super._increaseBalance(account, value);
    }

    /**
     * @notice Returns the URI for a given token ID.
     * @param tokenId The ID of the token.
     * @return The URI string for the specified token.
     */
    function tokenURI(
        uint256 tokenId
    )
        public
        view
        override(ERC721Upgradeable, ERC721URIStorageUpgradeable)
        returns (string memory)
    {
        return super.tokenURI(tokenId);
    }

    /**
     * @notice Checks which interfaces the contract supports.
     * @param interfaceId The interface identifier.
     * @return True if the interface is supported.
     * @inheritdoc ERC721Upgradeable
     */
    function supportsInterface(
        bytes4 interfaceId
    )
        public
        view
        override(
            ERC721Upgradeable,
            ERC721EnumerableUpgradeable,
            ERC721URIStorageUpgradeable,
            ERC2981Upgradeable,
            AccessControlUpgradeable
        )
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    /**
     * @notice Batch mints multiple NFTs to a single address.
     * @param to Recipient address.
     * @param tokenIds Array of token IDs to mint.
     * @param uris Array of metadata URIs for each token.
     * @dev Only callable by the PANINI_NFT_OPERATOR.
     */
    function batchMint(
        address to,
        uint256[] memory tokenIds,
        string[] memory uris
    ) external onlyRole(PANINI_NFT_OPERATOR) {
        require(isMintingEnabled, "Minting NFT is not enabled");
        require(to != address(0), "Invalid recipient");
        require(
            tokenIds.length == uris.length && tokenIds.length <= 25,
            "Invalid input: length mismatch or too many tokens (max 25)"
        );

        for (uint256 i = 0; i < tokenIds.length; i++) {
            require(!_exists(tokenIds[i]), "Token ID already exists");
            require(
                !burnedTokenIds[tokenIds[i]],
                "Token ID was burned and cannot be reused"
            );
            _safeMint(to, tokenIds[i]);
            _setTokenURI(tokenIds[i], uris[i]);
        }
    }

    /**
     * @notice Validates the operator before setting approval for all.
     * @inheritdoc ERC721Upgradeable
     */
    function setApprovalForAll(
        address operator,
        bool approved
    ) public override(ERC721Upgradeable, IERC721) {
        _validateApproval(operator);
        super.setApprovalForAll(operator, approved);
    }

    /**
     * @notice Validates the operator before setting approval for a specific token.
     * @inheritdoc ERC721Upgradeable
     */
    function approve(
        address operator,
        uint256 tokenId
    ) public override(ERC721Upgradeable, IERC721) {
        require(operator != address(0), "Invalid recipient");
        _validateApproval(operator);
        super.approve(operator, tokenId);
    }

    /**
     * @notice Checks if the operator is approved for all tokens owned by the owner.
     * @dev Adds an extra validation for operator before delegating to super implementation.
     * @inheritdoc ERC721Upgradeable
     */
    function isApprovedForAll(
        address owner,
        address operator
    ) public view override(ERC721Upgradeable, IERC721) returns (bool) {
        require(owner != address(0), "Invalid recipient");
        require(operator != address(0), "Invalid recipient");
        // Non-reverting read: treat non-whitelisted operators as not approved
        if (paniniLock && !hasRole(WHITELISTED_MARKETPLACE, operator)) {
            return false;
        }
        return super.isApprovedForAll(owner, operator);
    }

    /**
     * @notice Burns the specified NFT.
     * @param tokenId Token ID to burn.
     * @dev Only the token owner can burn their NFT, and only when burning is enabled.
     */
    function burn(uint256 tokenId) public virtual override {
        require(isBurnEnabled, "Burning NFT is not enabled");
        require(_ownerOf(tokenId) == _msgSender(), "Only token owner can burn");
        super._burn(tokenId);
        burnedTokenIds[tokenId] = true;
        _resetTokenRoyalty(tokenId);
    }

    /**
     * @notice Batch mints or unlocks NFTs using a valid signature.
     * @param tokenIds The token IDs to mint/unlock.
     * @param tokenURIs Metadata URIs of the tokens.
     * @param requestNonce A unique nonce for the request.
     * @param expiredAt Expiry timestamp of the signature.
     * @param signature Signature authorizing the request.
     * @dev Prevents replay attacks using requestNonce.
     * @dev Uses `block.timestamp` to validate signature expiry (`expiredAt > block.timestamp`).
     *
     * Emits - NFTBatchMintedOrUnlocked - including request nonce, msg.sender, tokenIds.
     */
    function batchMintOrUnlock(
        uint256[] calldata tokenIds,
        string[] calldata tokenURIs,
        uint256 requestNonce,
        uint256 expiredAt,
        bytes calldata signature
    ) external nonReentrant {
        require(
            tokenIds.length == tokenURIs.length,
            "Input array lengths mismatch"
        );
        require(
            tokenIds.length <= 25,
            "Input array length can't be greater than 25"
        );
        require(expiredAt > block.timestamp, "Signature expired");
        require(!usedNonces[requestNonce], "Nonce already used");

        bytes memory message = abi.encode(
            address(this),
            block.chainid,
            "PANINI_BRIDGE_MINT_UNLOCK_V1",
            _msgSender(),
            tokenIds,
            tokenURIs,
            requestNonce,
            expiredAt
        );
        require(_verifySignature(message, signature), "Invalid signature");
        usedNonces[requestNonce] = true;

        for (uint256 i = 0; i < tokenIds.length; i++) {
            require(
                !burnedTokenIds[tokenIds[i]],
                "Token ID was burned and cannot be reused"
            );

            if (!_exists(tokenIds[i])) {
                _safeMint(_msgSender(), tokenIds[i]);
                _setTokenURI(tokenIds[i], tokenURIs[i]);
            } else {
                require(
                    _ownerOf(tokenIds[i]) == address(this),
                    "Escrow Contract does not own token to unlock"
                );
                _safeTransfer(address(this), _msgSender(), tokenIds[i]);
            }
        }

        emit NFTBatchMintedOrUnlocked(requestNonce, _msgSender(), tokenIds);
    }

    /**
     * @notice Locks NFTs to bridge them to another network.
     * @param tokenIds The token IDs to lock.
     * @param requestNonce A unique nonce for the request.
     * @param expiredAt Expiry timestamp of the signature.
     * @param signature Signature authorizing the request.
     * @dev Prevents replay attacks using requestNonce.
     * @dev Uses `block.timestamp` to validate signature expiry (`expiredAt > block.timestamp`).
     * @dev Assigns ownership to this contract to act as an escrow.
     *
     * Emits - NFTBatchLocked - including request nonce, msg.sender, tokenIds
     */
    function batchLockNFT(
        uint256[] calldata tokenIds,
        uint256 requestNonce,
        uint256 expiredAt,
        bytes calldata signature
    ) external nonReentrant {
        require(
            tokenIds.length <= 25,
            "Input array length can't be greater than 25"
        );
        require(expiredAt > block.timestamp, "Signature expired");
        require(!usedNonces[requestNonce], "Nonce already used");

        bytes memory message = abi.encode(
            address(this),
            block.chainid,
            "PANINI_BRIDGE_LOCK_V1",
            _msgSender(),
            tokenIds,
            requestNonce,
            expiredAt
        );
        require(_verifySignature(message, signature), "Invalid signature");
        usedNonces[requestNonce] = true;

        for (uint256 i = 0; i < tokenIds.length; i++) {
            _bridgeLockTransfer(_msgSender(), address(this), tokenIds[i]);
        }
        emit NFTBatchLocked(requestNonce, _msgSender(), tokenIds);
    }

    /**
     * @notice Verifies that a given signature is valid and signed by an operator.
     * @param message The encoded message to verify.
     * @param signature Signature bytes to verify.
     * @return True if the signature is valid, otherwise false.
     */
    function _verifySignature(
        bytes memory message,
        bytes memory signature
    ) internal view returns (bool) {
        bytes32 messageHash = keccak256(message);
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(messageHash);
        address signer = ECDSA.recover(digest, signature);
        return hasRole(PANINI_NFT_OPERATOR, signer);
    }

    /**
     * @notice Checks whether a nonce has already been used.
     * @param _requestNonce The nonce to check.
     * @return True if nonce was already used, otherwise false.
     */
    function isNonceUsed(uint256 _requestNonce) public view returns (bool) {
        return usedNonces[_requestNonce];
    }

    /**
     * @notice Force-updates the token URI for a specific token.
     * @param tokenId The token ID to update.
     * @param _tokenURI The new token URI.
     * Emits - MetadataUpdate - includes tokenId.
     * @dev Can only be called by PANINI_NFT_MANAGER. Intended for rare metadata corrections.
     */
    function updateTokenURI(
        uint256 tokenId,
        string memory _tokenURI
    ) public virtual onlyRole(PANINI_NFT_MANAGER) {
        require(_exists(tokenId), "Token ID does not exists");
        _setTokenURI(tokenId, _tokenURI);
        emit MetadataUpdate(tokenId);
    }

    /**
     * @notice Sets the default royalty information for all tokens.
     * @dev Only the contract owner can call this function.
     *      The receiver address cannot be the zero address.
     *      The fee numerator should follow the fee denominator (default 10000 for basis points).
     * @param receiver The address that will receive royalty payments.
     * @param feeNumerator The royalty fee in basis points (parts per 10,000).
     */
    function setDefaultRoyalty(
        address receiver,
        uint96 feeNumerator
    ) public virtual onlyOwner {
        require(receiver != address(0), "Invalid receiver: zero address");
        _setDefaultRoyalty(receiver, feeNumerator);
    }

    /**
     * @notice Enables or disables minting functionality.
     * @param _status True to enable mint, false to disable.
     * @dev Can only be called by onlyOwner.
     * Emits - MintStatusUpdated event - msg.sender, oldstatus, newstatus
     */
    function updateMintStatus(bool _status) public onlyOwner {
        bool oldStatus = isMintingEnabled;
        isMintingEnabled = _status;
        emit MintStatusUpdated(_msgSender(), oldStatus, isMintingEnabled);
    }

    /**
     * @notice Enables or disables burning functionality.
     * @param _status True to enable burn, false to disable.
     * @dev Can only be called by onlyOwner.
     * Emits - BurnStatusUpdated event - msg.sender, oldstatus, newstatus
     */
    function updateBurnStatus(bool _status) public onlyOwner {
        bool oldStatus = isBurnEnabled;
        isBurnEnabled = _status;
        emit BurnStatusUpdated(_msgSender(), oldStatus, isBurnEnabled);
    }

    /**
     * @notice Returns the owners of multiple token IDs.
     * @param tokenIds Array of token IDs to query.
     * @return result Array of TokenOwner structs with token ID and owner address.
     */
    function ownersOf(
        uint256[] calldata tokenIds
    ) external view returns (TokenOwner[] memory) {
        require(
            tokenIds.length <= 25,
            "Input array length can't be greater than 25"
        );
        TokenOwner[] memory result = new TokenOwner[](tokenIds.length);
        for (uint256 i = 0; i < tokenIds.length; i++) {
            result[i] = TokenOwner(tokenIds[i], super._ownerOf(tokenIds[i]));
        }
        return result;
    }

    /**
     * @notice Returns the processing status of a given request nonce and can be called by anyone.
     * @param requestNonce The unique nonce identifier to query.
     * @return  string representing the status of the nonce:
     * - `"PROCESSED"` if the nonce has already been used.
     * - `"UNPROCESSED"` if the nonce has not yet been used.
     */
    function getRequestNonceStatus(
        uint256 requestNonce
    ) public view returns (string memory) {
        return usedNonces[requestNonce] ? "PROCESSED" : "UNPROCESSED";
    }

    /// @notice Freezes the given accounts for this NFT collection.
    /// @param accounts The addresses to freeze.
    function freezeAccounts(
        address[] calldata accounts
    ) external onlyRole(PANINI_NFT_MANAGER) {
        _freeze(address(this), accounts);
    }

    /// @notice Unfreezes the given accounts for this NFT collection.
    /// @param accounts The addresses to unfreeze.
    function unfreezeAccounts(
        address[] calldata accounts
    ) external onlyRole(PANINI_NFT_MANAGER) {
        _unfreeze(address(this), accounts);
    }
}
