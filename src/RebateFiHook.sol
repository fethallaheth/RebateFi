// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Hooks} from "v4-core/libraries/Hooks.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {SwapParams} from "v4-core/types/PoolOperation.sol";
import {BalanceDelta} from "v4-core/types/BalanceDelta.sol";
import {BaseHook} from "v4-periphery/src/utils/BaseHook.sol";
import {PoolId, PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {LPFeeLibrary} from "v4-core/libraries/LPFeeLibrary.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Currency, CurrencyLibrary} from "v4-core/types/Currency.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "v4-core/types/BeforeSwapDelta.sol";


/// @title ReFiSwapRebateHook - The ReFi Swap Rebate Hook
/// @author ChoasSR (https://x.com/0xlinguin)
contract ReFiSwapRebateHook is BaseHook, Ownable {
    using CurrencyLibrary for Currency;
    using PoolIdLibrary for PoolKey;
    using LPFeeLibrary for uint24;
    
    
    /* ™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™ */
    /*                      CONSTANTS                      */
    /* ™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™ */
    
    address public immutable ReFi;

    /* ™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™ */
    /*                   STATE VARIABLES                   */
    /* ™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™ */
    
    uint24 public  buyFee = 0;   
    uint24 public  sellFee = 3000;    
    uint256 public buyDonationBps = 10; 
    uint256 public totalDonations; 
    mapping(address => uint256) public userBuyCount;
    mapping(address => uint256) public userSellCount;
    
    /* ™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™ */
    /*                    CUSTOM EVENTS                    */
    /* ™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™ */

    event ReFiBought(address indexed buyer, uint256 amount);
    event ReFiSold(address indexed seller, uint256 amount, uint256 fee);
     event TokensWithdrawn(address indexed token, address indexed to, uint256 amount);

    /* ™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™ */
    /*                    CUSTOM ERRORS                    */
    /* ™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™ */
   
    error ReFiNotInPool();
    error MustUseDynamicFee();
    error InsufficientDonationBalance();

    /* ™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™ */
    /*                     CONSTRUCTOR                     */
    /* ™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™ */
    /// @notice Initializes the contract with required addresses and permissions
    /// @param _poolManager Uniswap V4 position manager address 
    /// @param _ReFi The ReFi token address
    constructor(IPoolManager _poolManager, address _ReFi) BaseHook(_poolManager) Ownable(msg.sender) {
        ReFi = _ReFi;
    } 

    /* ™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™ */
    /*                    ADMIN FUNCTIONS                  */
    /* ™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™ */

        /**
     * @notice Fund the hook with ReFi tokens for donations
     * @param amount Amount of ReFi tokens to deposit
     */
      function fundDonations(uint256 amount) external {
        IERC20(ReFi).transferFrom(msg.sender, address(this), amount);
    }

      /**
     * @notice Withdraw tokens from hook (for rebalancing or emergency)
     * @param token Token address to withdraw
     * @param to Recipient address
     * @param amount Amount to withdraw
     */
    function withdrawTokens(address token, address to, uint256 amount) external onlyOwner {
        IERC20(token).transfer(to, amount);
        emit TokensWithdrawn(token, to, amount);
    }
    
    /**
     * @notice Change the Fees 
     * @param _isBuyFee Whether to change buy fee
     * @param _buyFee New buy fee 
     * @param _isSellFee Whether to change sell fee
     * @param _sellFee New sell fee
     * @param _isDonationBps Whether to change donation bps
     * @param _buyDonationBps New donation bps
     */
    function ChangeFee(
        bool _isBuyFee, 
        uint24 _buyFee, 
        bool _isSellFee,
        uint24 _sellFee,
        bool _isDonationBps, 
        uint256 _buyDonationBps
    ) external onlyOwner {
        if(_isBuyFee) buyFee = _buyFee;
        if(_isSellFee) sellFee = _sellFee;
        if(_isDonationBps) buyDonationBps = _buyDonationBps;
    }
    
    /* ™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™ */
    /*                  UNISWAP FUNCTIONS                  */
    /* ™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™ */

    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: true,
            afterInitialize: true,
            beforeAddLiquidity: false,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: true,
            afterSwap: false,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    /**
     * @notice Validate that ReFi token is in the pool before initialization
     */
    function _beforeInitialize(address, PoolKey calldata key, uint160) internal view override returns (bytes4) {
   
        if (Currency.unwrap(key.currency0) != ReFi && 
            Currency.unwrap(key.currency1) != ReFi) {
            revert ReFiNotInPool();
        }
        
        return BaseHook.beforeInitialize.selector;
    }

    /**
     * @notice Ensure dynamic fee is enabled after initialization
     */
    function _afterInitialize(address, PoolKey calldata key, uint160, int24) internal pure override returns (bytes4) {
        if (!key.fee.isDynamicFee()) {
            revert MustUseDynamicFee();
        }
        return BaseHook.afterInitialize.selector;
    }

   /**
     * @notice Set dynamic fee based on swap direction
     * - Buying ReFi: 0% fee to user, but hook donates 0.1% to LPs
     * - Selling ReFi: 0.3% fee
     */
    function _beforeSwap(
        address sender,
        PoolKey calldata key,
        SwapParams calldata params,
        bytes calldata
    ) internal override returns (bytes4, BeforeSwapDelta, uint24) {
        
        bool isReFiBuy = _isReFiBuy(key, params.zeroForOne);
        
        uint256 swapAmount = params.amountSpecified < 0 
            ? uint256(-params.amountSpecified) 
            : uint256(params.amountSpecified);

        uint24 fee;
        
        if (isReFiBuy) {
            fee = buyFee;
            
            // Calculate and execute ReFi donation to LPs (only on ReFi buys)
            uint256 donationAmount = (swapAmount * buyDonationBps) / 10000;
            
            if (donationAmount > 0) {
                uint256 hookReFiBalance = IERC20(ReFi).balanceOf(address(this));
                if (hookReFiBalance < donationAmount) {
                    revert InsufficientDonationBalance();
                }
                
                // Determine if ReFi is currency0 or currency1 for donation
                bool reFiIsCurrency0 = Currency.unwrap(key.currency0) == ReFi;
                uint256 amount0 = reFiIsCurrency0 ? donationAmount : 0;
                uint256 amount1 = reFiIsCurrency0 ? 0 : donationAmount;
                
                // Donate ReFi tokens to pool
                poolManager.donate(key, amount0, amount1, "");
                totalDonations += donationAmount;
                
            }

            userBuyCount[sender]++;
            emit ReFiBought(sender, swapAmount);
            
        } else {
            fee = sellFee; // 0.3% fee for selling ReFi
            userSellCount[sender]++;
            uint256 feeAmount = (swapAmount * sellFee) / 1000000;
            emit ReFiSold(sender, swapAmount , feeAmount);
        }
    
        // Return with dynamic fee override
        return (
            BaseHook.beforeSwap.selector,
            BeforeSwapDeltaLibrary.ZERO_DELTA,
            fee | LPFeeLibrary.OVERRIDE_FEE_FLAG
        );
    }


    /* ™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™ */
    /*                  INTERNAL FUNCTIONS                 */
    /* ™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™ */
    
    /**
     * @notice Determine if swap is buying ReFi token
     * @param key The pool key
     * @param zeroForOne Swap direction
     * @return true if buying ReFi, false if selling ReFi
     */

    function _isReFiBuy(PoolKey calldata key, bool zeroForOne) internal view returns (bool) {
        bool IsReFiCurrency0 = Currency.unwrap(key.currency0) == ReFi;

        // zeroForOne = true: selling currency0, buying currency1
        // zeroForOne = false: selling currency1, buying currency0
        // if refi is token0 then zeroForOne mean selling refi and get the token1 
        if (IsReFiCurrency0) {
            // ReFi is currency0, buying means zeroForOne = false
            return !zeroForOne;
        // if refi is token1 the zeroForOne mean getting refi and selling token0 
        } else {
            // ReFi is currency1, buying means zeroForOne = true
            return zeroForOne;
        }
    }

    
    /* ™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™ */
    /*                    VIEW FUNCTIONS                   */
    /* ™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™™ */

    /**
     * @notice Get user's swap statistics
     * @param user User address
     */
    function getUserStats(address user) external view returns (uint256 buys, uint256 sells) {
        return (userBuyCount[user], userSellCount[user]);
    }

    /**
     * @notice Check available ReFi balance for donations
     * @return Available ReFi token balance
     */
    function availableDonationBalance() external view returns (uint256) {
        return IERC20(ReFi).balanceOf(address(this));
    }

    /**
     * @notice Get current fee configuration
     * @return Current buy fee, sell fee, and donation bps
     */
    function getFeeConfig() external view returns (uint24, uint24, uint256) {
        return (buyFee, sellFee, buyDonationBps);
    }
}