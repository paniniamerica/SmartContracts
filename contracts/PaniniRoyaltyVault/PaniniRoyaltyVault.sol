// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {OwnableUpgradeable} from "./openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "./openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "./openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {IERC20} from "./openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "./openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IUniswapV3Router3} from "./uniswap/IUniswapV3Router3.sol";
import {AccessControlUpgradeable} from "./openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "./openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

/**
 * @title Panini Royalty Vault
 * @notice Handles ETH and ERC20 fund management, including withdrawals and uses the
 * Uniswap V3 Router for ETH, ERC20 token swaps.
 * @dev Upgradeable contract with access control, pausing, and whitelist mechanisms.
 * External Dependency:
 * - Swap logic relies on the Uniswap router (a third-party DeFi protocol).
 *
 * Risks:
 * - Router issues, liquidity problems, or price manipulation can affect swaps.
 * - External protocol failures may cause reverts or poor execution.
 *
 * Mitigations:
 * - Uses caller-provided `amountOutMin` to protect against slippage.
 * - Router address is fixed and trusted.
 * - Reentrancy protection is applied on swap functions.
 */

contract PaniniRoyaltyVault is
    Initializable,
    OwnableUpgradeable,
    PausableUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable
{
    using SafeERC20 for IERC20;

    /// @notice Addresses allowed to manage the vault (withdraw, approve, swap)
    bytes32 public constant VAULT_PAUSER = keccak256("VAULT_PAUSER");
    bytes32 public constant VAULT_MANAGER = keccak256("VAULT_MANAGER");
    bytes32 public constant WHITELISTED_RECEIVER =
        keccak256("WHITELISTED_RECEIVER");

    /// @notice Address of the Uniswap V3 router used for swaps
    IUniswapV3Router3 public uniswapRouter;

    /// @notice Emitted when ETH is withdrawn from the contract
    event Withdrawn(address indexed recipient, uint256 amount);

    /// @notice Emitted when ERC20 tokens are withdrawn from the contract
    event WithdrawnERC20(
        address indexed recipient,
        uint256 amount,
        address indexed token
    );

    /// @notice Emitted when ETH is swapped for an ERC20 token
    event EthSwappedForToken(
        address indexed recipient,
        uint256 ethAmountIn,
        uint256 tokenAmountOut,
        address indexed tokenOutAddress
    );

    /// @notice Emitted when an ERC20 token is swapped for another ERC20 token
    event TokenSwappedForToken(
        address indexed tokenInAddress,
        uint256 tokenAmountIn,
        address indexed tokenOutAddress,
        uint256 tokenAmountOut,
        address indexed recipient
    );
    event UniswapRouterUpdated(
        address indexed admin,
        address indexed oldRouter,
        address indexed newRouter
    );

    /**
     * @notice Disables initializers to protect logic contract.
     */
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the contract with initial configurations.
     * @param _owner Address that will become the owner.
     * @param _pauser Address to be granted pauser role
     * @param _whitelistedAccount Address to be whitelisted as receiver
     * @param _uniswapRouter Address of the Uniswap V3 router.
     */
    function initialize(
        address _owner,
        address _pauser,
        address _whitelistedAccount,
        address _uniswapRouter
    ) public initializer {
        require(_uniswapRouter != address(0), "Invalid router address");
        require(_pauser != address(0), "Invalid router address");
        require(_owner != address(0), "Invalid owner address");
        require(_whitelistedAccount != address(0), "Invalid whitelist address");

        __Context_init();
        __Ownable_init(_owner);
        __Pausable_init();
        __ERC165_init();
        __AccessControl_init();
        __ReentrancyGuard_init();

        uniswapRouter = IUniswapV3Router3(_uniswapRouter);

        _grantRole(DEFAULT_ADMIN_ROLE, _owner);
        _grantRole(VAULT_PAUSER, _owner);
        _grantRole(VAULT_PAUSER, _pauser);
        _grantRole(WHITELISTED_RECEIVER, _whitelistedAccount);
        _grantRole(WHITELISTED_RECEIVER, address(this));
    }

    /**
     * @notice Accepts ETH deposits into the vault.
     */
    receive() external payable {
        require(msg.value > 0, "Must send some ETH");
    }

    /**
     * @notice Pauses the contract (disables swap and withdraw functions).
     */
    function pause() external onlyRole(VAULT_PAUSER) {
        _pause();
    }

    /**
     * @notice Unpauses the contract (enables swap and withdraw functions).
     */
    function unpause() external onlyRole(VAULT_PAUSER) {
        _unpause();
    }

    /**
     * @notice Returns the contract's ETH balance.
     * @return balance The current ETH balance of the contract.
     */
    function getEthBalance() public view returns (uint256 balance) {
        return address(this).balance;
    }

    /**
     * @notice Returns the contract's balance for a given ERC20 token.
     * @param token Address of the token.
     * @return balance The amount of the specified token held by the contract.
     */
    function getTokenBalance(
        address token
    ) public view returns (uint256 balance) {
        require(address(token) != address(0), "Invalid Token address");
        return IERC20(token).balanceOf(address(this));
    }

    // -------- Withdrawals --------

    /**
     * @notice Withdraws ETH from the vault to a whitelisted receiver.
     * @param amount Amount of ETH to withdraw.
     * @param receiver Address to receive the ETH.
     * Emits:
     * - {Withdrawn} indicating the recipient, eth withdrawn.
     */
    function withdrawETH(
        uint256 amount,
        address receiver
    ) external whenNotPaused onlyRole(VAULT_MANAGER) nonReentrant {
        require(amount <= getEthBalance(), "Insufficient ETH balance");
        require(
            receiver != address(0) && hasRole(WHITELISTED_RECEIVER, receiver),
            "Invalid receiver"
        );
        payable(receiver).transfer(amount);
        emit Withdrawn(receiver, amount);
    }

    /**
     * @notice Withdraws ERC20 tokens from the vault to a whitelisted receiver.
     * @param token Address of the ERC20 token.
     * @param receiver Address to receive the tokens.
     * @param amount Amount of tokens to withdraw.
     *
     * Emits:
     * - {WithdrawnERC20} indicating the recipient, token amount withdrawn, token address.
     */
    function withdrawERC20(
        address token,
        address receiver,
        uint256 amount
    ) external whenNotPaused onlyRole(VAULT_MANAGER) nonReentrant {
        require(amount <= getTokenBalance(token), "Insufficient token balance");
        require(token != address(0), "Invalid token address");
        require(
            receiver != address(0) && hasRole(WHITELISTED_RECEIVER, receiver),
            "Invalid receiver"
        );
        IERC20(token).safeTransfer(receiver, amount);
        emit WithdrawnERC20(receiver, amount, token);
    }

    // -------- Approvals & Swaps --------


    /**
     * @notice Swaps ETH for a ERC20 token via Uniswap V3 router.
     * @dev Validates inputs, enforces access control, and calls
     *      `uniswapRouter.exactInputSingle{value: amountIn}(params)` using `block.timestamp`
     *      as the deadline.
     *
     * @dev External Dependency — Uniswap V3 Router:
     * - Relies on Uniswap V3; router issues may affect swap execution.
     *
     * Risks:
     * - Low liquidity, price impact, MEV, or token callback behavior may cause reverts.
     *
     * Mitigations:
     * - Caller provides `amountOutMinimum` to prevent excessive slippage.
     * - Reentrancy guard applied; token/pool parameters validated before swapping.
     * @dev Reverts if the router call fails, thereby reverting the entire transaction.
     * @param amountIn The amount of ETH to send for the swap.
     * @param outToken The address of the ERC20 token to receive.
     * @param amountOutMin The minimum token amount acceptable from the swap.
     * @param feeTier The Uniswap V3 fee tier to use (e.g., 500, 3000, 10000).
     * @param sqrtPriceLimitX96 The limit for the price (pass 0 for default unrestricted).
     * @param recipient The address to receive the output token (must be whitelisted).
     * @return amountOut Amount of `outToken` received.
     *
     * Emits:
     * - {EthSwappedForToken} indicating the recipient, ETH spent, tokens received, and token address.
     */
    function swapEthForToken(
        uint256 amountIn,
        address outToken,
        uint256 amountOutMin,
        uint24 feeTier,
        uint96 sqrtPriceLimitX96,
        address recipient
    )
        external
        whenNotPaused
        onlyRole(VAULT_MANAGER)
        nonReentrant
        returns (uint256 amountOut)
    {
        require(amountIn > 0, "Must send ETH to swap");
        require(outToken != address(0), "Invalid Out token address");
        require(
            recipient != address(0) && hasRole(WHITELISTED_RECEIVER, recipient),
            "Invalid receiver"
        );
        require(amountOutMin > 0, "Invalid minimum output amount");

        // uniswap v3 swap interaction
        IUniswapV3Router3.ExactInputSingleParams memory params = IUniswapV3Router3
            .ExactInputSingleParams({
                tokenIn: uniswapRouter.WETH9(),
                tokenOut: outToken,
                fee: feeTier,
                recipient: recipient,
                deadline: block.timestamp + 120, // 2-minute (TTL)
                amountIn: amountIn,
                amountOutMinimum: amountOutMin,
                sqrtPriceLimitX96: sqrtPriceLimitX96 // 0 as default
            });
        // send ETH along with the swap
        amountOut = uniswapRouter.exactInputSingle{value: amountIn}(params);

        emit EthSwappedForToken(recipient, amountIn, amountOut, outToken);
    }

    /**
     * @notice Swaps ERC20 for a ERC20 token via Uniswap V3 router.
     * @dev Validates inputs, enforces access control, and calls Approves Uniswap router, then calls
     *      `uniswapRouter.exactInputSingle{value: amountIn}(params)` using `block.timestamp`
     *      as the deadline.
     * @dev External Dependency — Uniswap V3 Router:
     * - Relies on Uniswap V3; router issues may affect swap execution.
     * Risks:
     * - Low liquidity, price impact, MEV, or token callback behavior may cause reverts.
     * Mitigations:
     * - Caller provides `amountOutMinimum` to prevent excessive slippage.
     * - Reentrancy guard applied; token/pool parameters validated before swapping.
     * @param inToken Input token address.
     * @param amountIn Input token amount.
     * @param outToken Output token address.
     * @param amountOutMin Minimum acceptable output token amount.
     * @param feeTier feeTier range.
     * @param sqrtPriceLimitX96 Price limit.
     * @param recipient Whitelisted receiver of output tokens.
     *
     * @return amountOut Amount of `outToken` received.
     * Emits:
     * - {TokenSwappedForToken} indicating the inToken, tokens spent,tokens received,outToken, recipient.
     */
    function swapTokenForToken(
        address inToken,
        uint256 amountIn,
        address outToken,
        uint256 amountOutMin,
        uint24 feeTier,
        uint96 sqrtPriceLimitX96,
        address recipient
    )
        external
        whenNotPaused
        onlyRole(VAULT_MANAGER)
        nonReentrant
        returns (uint256 amountOut)
    {
        require(amountIn > 0, "Must send amountIn to swap");
        require(inToken != address(0), "Invalid inToken Address");
        require(outToken != address(0), "Invalid outToken Address");
        require(
            recipient != address(0) && hasRole(WHITELISTED_RECEIVER, recipient),
            "Invalid recipient"
        );
        require(amountOutMin > 0, "Invalid minimum output amount");

        // erc20 approval to uniswapRouter
        IERC20(inToken).approve(address(uniswapRouter), amountIn);
        // uniswap v3 swap interaction
        IUniswapV3Router3.ExactInputSingleParams memory params = IUniswapV3Router3
            .ExactInputSingleParams({
                tokenIn: inToken,
                tokenOut: outToken,
                fee: feeTier,
                recipient: recipient,
                deadline: block.timestamp + 120, // 2-minute (TTL)
                amountIn: amountIn,
                amountOutMinimum: amountOutMin,
                sqrtPriceLimitX96: sqrtPriceLimitX96 // 0 as default
            });

        // ERC20 swap, no ETH needed
        amountOut = uniswapRouter.exactInputSingle{value: 0}(params);
        emit TokenSwappedForToken(
            inToken,
            amountIn,
            outToken,
            amountOut,
            recipient
        );
    }

    /**
     * @notice Updates the Uniswap V3 router address used by the contract.
     * @param newRouter The address of the new Uniswap V3 router contract.
     *
     * Requirements:
     * - `newRouter` cannot be the zero address, must be valid uniswap v3 address.
     * - Caller must have the `DEFAULT_ADMIN_ROLE`.
     *
     * Emits - UniswapRouterUpdated - msgSender, oldRouterAddress, newRouterAddress
     */
    function updateUniswapRouter(
        address newRouter
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newRouter != address(0), "Invalid router address");
        require(
            address(newRouter).code.length > 0,
            "Invalid router: no contract code"
        );
        address old = address(uniswapRouter);
        uniswapRouter = IUniswapV3Router3(newRouter);
        emit UniswapRouterUpdated(_msgSender(), old, newRouter);
    }
}
