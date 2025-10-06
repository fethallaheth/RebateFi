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
    
    
    /* ═══════════════════════════════════════════════════════════════ */
    /*                      CONSTANTS                                  */
    /* ═══════════════════════════════════════════════════════════════ */
    
    address public immutable ReFi;

    /* ═══════════════════════════════════════════════════════════════ */
    /*                   STATE VARIABLES                               */
    /* ═══════════════════════════════════════════════════════════════ */
    
    uint24 public  buyFee = 0;   
    uint24 public  sellFee = 3000;    
    
    /* ═══════════════════════════════════════════════════════════════ */
    /*                    CUSTOM EVENTS                                */
    /* ═══════════════════════════════════════════════════════════════ */

    event ReFiBought(address indexed buyer, uint256 amount);
    event ReFiSold(address indexed seller, uint256 amount, uint256 fee);
    event TokensWithdrawn(address indexed token, address indexed to, uint256 amount);

    /* ═══════════════════════════════════════════════════════════════ */
    /*                    CUSTOM ERRORS                                */
    /* ═══════════════════════════════════════════════════════════════ */
   
    error ReFiNotInPool();
    error MustUseDynamicFee();

    /* ═══════════════════════════════════════════════════════════════ */
    /*                     CONSTRUCTOR                                 */
    /* ═══════════════════════════════════════════════════════════════ */
    
    constructor(IPoolManager _poolManager, address _ReFi) BaseHook(_poolManager) Ownable(msg.sender) {
        ReFi = _ReFi;
    } 

    /* ═══════════════════════════════════════════════════════════════ */
    /*                    ADMIN FUNCTIONS                              */
    /* ═══════════════════════════════════════════════════════════════ */


    function withdrawTokens(address token, address to, uint256 amount) external onlyOwner {
        IERC20(token).transfer(to, amount);
        emit TokensWithdrawn(token, to, amount);
    }
    
    function ChangeFee(
        bool _isBuyFee, 
        uint24 _buyFee, 
        bool _isSellFee,
        uint24 _sellFee
    ) external onlyOwner {
        if(_isBuyFee) buyFee = _buyFee;
        if(_isSellFee) sellFee = _sellFee;
    }
    
    /* ═══════════════════════════════════════════════════════════════ */
    /*                  UNISWAP FUNCTIONS                              */
    /* ═══════════════════════════════════════════════════════════════ */

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

    function _beforeInitialize(address, PoolKey calldata key, uint160) internal view override returns (bytes4) {
        if (Currency.unwrap(key.currency0) != ReFi && 
            Currency.unwrap(key.currency1) != ReFi) {
            revert ReFiNotInPool();
        }
        
        return BaseHook.beforeInitialize.selector;
    }

    function _afterInitialize(address, PoolKey calldata key, uint160, int24) internal pure override returns (bytes4) {
        if (!key.fee.isDynamicFee()) {
            revert MustUseDynamicFee();
        }
        return BaseHook.afterInitialize.selector;
    }

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
            emit ReFiBought(sender, swapAmount);
            
        } else {
            fee = sellFee;
            uint256 feeAmount = (swapAmount * sellFee) / 1000000;
            emit ReFiSold(sender, swapAmount, feeAmount);
        }
    
        return (
            BaseHook.beforeSwap.selector,
            BeforeSwapDeltaLibrary.ZERO_DELTA,
            fee | LPFeeLibrary.OVERRIDE_FEE_FLAG
        );
    }

    /* ═══════════════════════════════════════════════════════════════ */
    /*                  INTERNAL FUNCTIONS                             */
    /* ═══════════════════════════════════════════════════════════════ */
    
    function _isReFiBuy(PoolKey calldata key, bool zeroForOne) internal view returns (bool) {
        bool IsReFiCurrency0 = Currency.unwrap(key.currency0) == ReFi;
        
        if (IsReFiCurrency0) {
            return !zeroForOne;
        } else {
            return zeroForOne;
        }
    }

    /* ═══════════════════════════════════════════════════════════════ */
    /*                    VIEW FUNCTIONS                               */
    /* ═══════════════════════════════════════════════════════════════ */


    function getFeeConfig() external view returns (uint24, uint24) {
        return (buyFee, sellFee);
    }
}