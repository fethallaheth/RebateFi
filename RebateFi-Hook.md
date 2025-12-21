# RebateFi Hook - Findings Report

# Table of contents
- ### [Contest Summary](#contest-summary)
- ### [Results Summary](#results-summary)
- ## High Risk Findings
    - [H-01. _beforeInitialize Always Reverts When ReFi is Token0 Due to Duplicate Currency Check](#H-01)
    - [H-02. Buy/Sell Logic Is Reversed in _isReFiBuy (Critical Economic Failure)](#H-02)
    - [H-03. No protocol revenue](#H-03)
- ## Medium Risk Findings
    - [M-01. Unchecked ERC20 Transfer in withdrawTokens](#M-01)
- ## Low Risk Findings
    - [L-01. Incorrect parameters in the event `TokensWithdrawn`](#L-01)
    - [L-02. Incorrect Fee Calculation in Events Reports 10x the Actual Fee](#L-02)
    - [L-03. Incorrect Sender Logged in Events During Native ETH Swaps](#L-03)


# <a id='contest-summary'></a>Contest Summary

### Sponsor: First Flight #53

### Dates: Nov 20th, 2025 - Nov 27th, 2025

[See more contest details here](https://codehawks.cyfrin.io/c/2025-11-rebatefi-hook)

# <a id='results-summary'></a>Results Summary

### Number of findings:
   - High: 3
   - Medium: 1
   - Low: 3


# High Risk Findings

## <a id='H-01'></a>H-01. _beforeInitialize Always Reverts When ReFi is Token0 Due to Duplicate Currency Check

_Submitted by [comfortnurse021](https://profiles.cyfrin.io/u/comfortnurse021), [arsenii9](https://profiles.cyfrin.io/u/arsenii9), [rf_](https://profiles.cyfrin.io/u/rf_), [adrianheldesai](https://profiles.cyfrin.io/u/adrianheldesai), [return](https://profiles.cyfrin.io/u/return), [ayushmanraj1123](https://profiles.cyfrin.io/u/ayushmanraj1123), [mostafapahlevani93](https://profiles.cyfrin.io/u/mostafapahlevani93), [sulfurpt](https://profiles.cyfrin.io/u/sulfurpt), [0xjoaovictor](https://profiles.cyfrin.io/u/0xjoaovictor), [s3mvl4d](https://profiles.cyfrin.io/u/s3mvl4d), [ciphermalware](https://profiles.cyfrin.io/u/ciphermalware), [ashutoshcshah](https://profiles.cyfrin.io/u/ashutoshcshah), [cryptomv3](https://profiles.cyfrin.io/u/cryptomv3), [ultron](https://profiles.cyfrin.io/u/ultron), [minos](https://profiles.cyfrin.io/u/minos), [efimxff](https://profiles.cyfrin.io/u/efimxff), [hunterspartan5](https://profiles.cyfrin.io/u/hunterspartan5), [seenu1947](https://profiles.cyfrin.io/u/seenu1947), [themo2](https://profiles.cyfrin.io/u/themo2), [howiecht](https://profiles.cyfrin.io/u/howiecht), [chain__warden](https://profiles.cyfrin.io/u/chain__warden), [muzammilmohammed678](https://profiles.cyfrin.io/u/muzammilmohammed678), [wojack0x0](https://profiles.cyfrin.io/u/wojack0x0), [themilenkov](https://profiles.cyfrin.io/u/themilenkov), [kakoozavian](https://profiles.cyfrin.io/u/kakoozavian), [x0jgsleepy](https://profiles.cyfrin.io/u/x0jgsleepy), [fourb](https://profiles.cyfrin.io/u/fourb), [tekalign3330](https://profiles.cyfrin.io/u/tekalign3330), [alexscherbatyuk](https://profiles.cyfrin.io/u/alexscherbatyuk), [samuelsmith442](https://profiles.cyfrin.io/u/samuelsmith442), [rusrio](https://profiles.cyfrin.io/u/rusrio), [iainlim](https://profiles.cyfrin.io/u/iainlim), [vyqno](https://profiles.cyfrin.io/u/vyqno), [nutledger](https://profiles.cyfrin.io/u/nutledger), [shashankwcw](https://profiles.cyfrin.io/u/shashankwcw), [valya](https://profiles.cyfrin.io/u/valya), [smartshielder](https://profiles.cyfrin.io/u/smartshielder), [objectplayer](https://profiles.cyfrin.io/u/objectplayer), [uandersonricardo](https://profiles.cyfrin.io/u/uandersonricardo), [aniruddhrao723](https://profiles.cyfrin.io/u/aniruddhrao723), [farnad](https://profiles.cyfrin.io/u/farnad), [cryptostellar5](https://profiles.cyfrin.io/u/cryptostellar5), [hawksvision](https://profiles.cyfrin.io/u/hawksvision), [lallanaad](https://profiles.cyfrin.io/u/lallanaad), [accessdenied](https://profiles.cyfrin.io/u/accessdenied), [jufel](https://profiles.cyfrin.io/u/jufel), [rohan_x2](https://profiles.cyfrin.io/u/rohan_x2). Selected submission by: [comfortnurse021](https://profiles.cyfrin.io/u/comfortnurse021)._      
            


The \_beforeInitialize hook is designed to enforce a security rule: only pools that contain the ReFi token as one of the two traded assets are allowed to use this hook. This prevents the hook from being accidentally (or maliciously) attached to unrelated pools.
The current implementation contains a critical logic error: it checks key.currency1 twice instead of checking both currency0 and currency1. As a result, the validation completely ignores whether the ReFi token is present as currency0. Whenever the ReFi token has the lower address (and is therefore sorted into currency0), the condition always evaluates to true and reverts, even though the pool is perfectly valifunction \_beforeInitialize(address, PoolKey calldata key, uint160) internal view override returns (bytes4) {
// @> BUG: currency1 is checked twice – currency0 is never examined
if (Currency.unwrap(key.currency1) != ReFi &&
Currency.unwrap(key.currency1) != ReFi) {
revert ReFiNotInPool();
}

```Solidity
function _beforeInitialize(address, PoolKey calldata key, uint160) internal view override returns (bytes4) {
    // @> BUG: currency1 is checked twice – currency0 is never examined
    if (Currency.unwrap(key.currency1) != ReFi &&
        Currency.unwrap(key.currency1) != ReFi) {
        revert ReFiNotInPool();
    }
   
    return BaseHook.beforeInitialize.selector;
}
https://github.com/CodeHawks-Contests/2025-11-rebatefi-hook/blob/add4b298d1246ad2f1df726216849c1c31f83065/src/RebateFiHook.sol#L122-124
```

}

## Risk

**Likelihood**:

Occurs on every pool initialization attempt

 

* Triggers whenever ReFi token address < paired token address

**Impact**:

##

&#x20;Hook deployment fails for half of all possible token orderings

 

* Users/owners cannot create valid ReFi pools with standard token ordering

```Solidity
 Example addresses
address constant ReFi = 0x0000000000000000000000000000000000000011; // lower address
address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2; // higher address

// PoolManager will sort tokens → currency0 = ReFi, currency1 = WETH
PoolKey memory key = PoolKey({
    currency0: Currency.wrap(ReFi),
    currency1: Currency.wrap(WETH),
    fee: uint24(0x800000), // dynamic fee placeholder
    tickSpacing: 60,
    hooks: IHooks(address(hook))
});

// Current buggy code evaluates:
// key.currency1 != ReFi → true (WETH != ReFi)
// key.currency1 != ReFi → true (again)
// → true && true → revert ReFiNotInPool()

// Even though ReFi IS in the pool → initialization permanently blocked
```

## Recommended Mitigation

```diff
- remove this function _beforeInitialize(address, PoolKey calldata key, uint160) internal view override returns (bytes4) {
-       if (Currency.unwrap(key.currency1) != ReFi &&
-           Currency.unwrap(key.currency1) != ReFi) {
+       // Ensure the ReFi token is one of the two currencies in the pool
+       if (Currency.unwrap(key.currency0) != ReFi &&
+           Currency.unwrap(key.currency1) != ReFi) {
            revert ReFiNotInPool();
        }
       
        return BaseHook.beforeInitialize.selector;
}ode
+ +       bool hasReFi = Currency.unwrap(key.currency0) == ReFi ||
+                      Currency.unwrap(key.currency1) == ReFi;
+       if (!hasReFi) revert ReFiNotInPool();
```

## <a id='H-02'></a>H-02. Buy/Sell Logic Is Reversed in _isReFiBuy (Critical Economic Failure)

_Submitted by [rf_](https://profiles.cyfrin.io/u/rf_), [mostafapahlevani93](https://profiles.cyfrin.io/u/mostafapahlevani93), [s3mvl4d](https://profiles.cyfrin.io/u/s3mvl4d), [snufflesrea](https://profiles.cyfrin.io/u/snufflesrea), [ciphermalware](https://profiles.cyfrin.io/u/ciphermalware), [365smile](https://profiles.cyfrin.io/u/365smile), [ashutoshcshah](https://profiles.cyfrin.io/u/ashutoshcshah), [eagerpanda582](https://profiles.cyfrin.io/u/eagerpanda582), [minos](https://profiles.cyfrin.io/u/minos), [howiecht](https://profiles.cyfrin.io/u/howiecht), [seenu1947](https://profiles.cyfrin.io/u/seenu1947), [efimxff](https://profiles.cyfrin.io/u/efimxff), [themo2](https://profiles.cyfrin.io/u/themo2), [chain__warden](https://profiles.cyfrin.io/u/chain__warden), [wojack0x0](https://profiles.cyfrin.io/u/wojack0x0), [topgee001](https://profiles.cyfrin.io/u/topgee001), [x0jgsleepy](https://profiles.cyfrin.io/u/x0jgsleepy), [themilenkov](https://profiles.cyfrin.io/u/themilenkov), [alexscherbatyuk](https://profiles.cyfrin.io/u/alexscherbatyuk), [iamgeorgi](https://profiles.cyfrin.io/u/iamgeorgi), [hunterspartan5](https://profiles.cyfrin.io/u/hunterspartan5), [valya](https://profiles.cyfrin.io/u/valya), [nutledger](https://profiles.cyfrin.io/u/nutledger), [0xki](https://profiles.cyfrin.io/u/0xki), [objectplayer](https://profiles.cyfrin.io/u/objectplayer), [tekalign3330](https://profiles.cyfrin.io/u/tekalign3330), [uandersonricardo](https://profiles.cyfrin.io/u/uandersonricardo), [bubblybee789](https://profiles.cyfrin.io/u/bubblybee789), [farnad](https://profiles.cyfrin.io/u/farnad), [prhymemanuel](https://profiles.cyfrin.io/u/prhymemanuel), [accessdenied](https://profiles.cyfrin.io/u/accessdenied), [jufel](https://profiles.cyfrin.io/u/jufel), [rozaliyacrypto](https://profiles.cyfrin.io/u/rozaliyacrypto). Selected submission by: [rf_](https://profiles.cyfrin.io/u/rf_)._      
            


# Root + Impact

## Description

Under expected behavior, the hook must apply:

* **Reduced fees on buys** of the ReFi token.

* **Higher fees on sells** of the ReFi token.

However, the `_isReFiBuy()` logic is implemented incorrectly.\
When ReFi is `currency1` (which is always the case due to a separate initialization bug), the function **classifies every buy as a sell** and every sell as a buy.

This fully **inverts the economic incentives** that the protocol intends to enforce.

The root cause is highlighted below:

```solidity
function _isReFiBuy(PoolKey calldata key, bool zeroForOne) internal view returns (bool) {
    bool IsReFiCurrency0 = Currency.unwrap(key.currency0) == ReFi;

    if (IsReFiCurrency0) {
        @> return zeroForOne;      // BUG: reversed meaning
    } else {
        @> return !zeroForOne;     // BUG: reversed meaning
    }
}
```

## Risk

**Likelihood:**

* ReFi is always `currency1` due to another bug in `_beforeInitialize()`, so this logic runs in the faulty branch 100% of the time.

* Every swap involving the ReFi token will be misclassified.

* No user can ever receive the intended fee structure.

**Impact:**

* **Buyers are charged premium sell fees**, making accumulation unattractive.

* **Sellers are charged reduced buy fees**, making dumping cheaper.

* The tokenomics of ReFi reverse entirely, harming liquidity, price stability, and protocol sustainability.

* Protocol revenue and incentives behave opposite to design, breaking the project’s core mechanism.

## Proof of Concept

The following PoC shows how swap direction is always interpreted incorrectly when ReFi is `currency1`.

### Explanation

* In Uniswap V4:

  * `zeroForOne = true` → swap token0 → token1

  * `zeroForOne = false` → swap token1 → token0

* If ReFi is `currency1`, then:

  * A **buy** means token0 → token1 → `zeroForOne = true`

  * A **sell** means token1 → token0 → `zeroForOne = false`

The hook mislabels these:

```solidity
// Setup for the PoC where ReFi = currency1
key.currency0 = address(USDC);
key.currency1 = address(ReFi);

// ---- USER BUYS ReFi ----
bool zeroForOne = true;                     // token0 -> token1
bool isBuy = _isReFiBuy(key, zeroForOne);

// Expected: true (buying ReFi)
// Actual: false (treated as SELL)


// ---- USER SELLS ReFi ----
zeroForOne = false;                         // token1 -> token0
isBuy = _isReFiBuy(key, zeroForOne);

// Expected: false (selling ReFi)
// Actual: true (treated as BUY)
```

This PoC shows that **every buy is treated as a sell** and **every sell is treated as a buy**.

## Recommended Mitigation

### Explanation

To determine if a user is buying ReFi, we must check:

* If ReFi is `currency0`, a buy is `token1 -> token0` → `zeroForOne = false`

* If ReFi is `currency1`, a buy is `token0 -> token1` → `zeroForOne = true`

The corrected logic directly reflects this.

```diff
 function _isReFiBuy(PoolKey calldata key, bool zeroForOne) internal view returns (bool) {
     bool isReFiToken0 = Currency.unwrap(key.currency0) == ReFi;

-    if (isReFiToken0) {
-        return zeroForOne;
-    } else {
-        return !zeroForOne;
-    }
+    // Buy ReFi if:
+    // - ReFi is token0 and user swaps token1 -> token0 (zeroForOne == false)
+    // - ReFi is token1 and user swaps token0 -> token1 (zeroForOne == true)
+    if (isReFiToken0) {
+        return !zeroForOne;
+    } else {
+        return zeroForOne;
+    }
 }
```

## <a id='H-03'></a>H-03. No protocol revenue

_Submitted by [ciphermalware](https://profiles.cyfrin.io/u/ciphermalware), [wojack0x0](https://profiles.cyfrin.io/u/wojack0x0), [x0jgsleepy](https://profiles.cyfrin.io/u/x0jgsleepy), [chain__warden](https://profiles.cyfrin.io/u/chain__warden), [shashankwcw](https://profiles.cyfrin.io/u/shashankwcw), [bubblybee789](https://profiles.cyfrin.io/u/bubblybee789). Selected submission by: [ciphermalware](https://profiles.cyfrin.io/u/ciphermalware)._      
            


# Root + Impact

## Description

* The protocol states that its purpose is to apply "premium fees for selling to discourage dumping and generate protocol revenue" that can be withdrawn by the owner via `withdrawTokens()`

* The hook never takes custody of any tokens because it always returns `BeforeSwapDeltaLibrary.ZERO_DELTA` and has all delta  hooks disabled

```Solidity
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
@>      beforeSwapReturnDelta: false,  // Hook cant take tokens via beforeSwap
@>      afterSwapReturnDelta: false,   // Hook cant take tokens via afterSwap
        afterAddLiquidityReturnDelta: false,
        afterRemoveLiquidityReturnDelta: false
    });
}

function _beforeSwap(
    address sender,
    PoolKey calldata key,
    SwapParams calldata params,
    bytes calldata
) internal override returns (bytes4, BeforeSwapDelta, uint24) {
    // ... fee determination logic ...
    
    return (
        BaseHook.beforeSwap.selector,
@>      BeforeSwapDeltaLibrary.ZERO_DELTA,  // Never takes tokens from swap
        fee | LPFeeLibrary.OVERRIDE_FEE_FLAG // Fee goes to LPs
    );
}
```

## Risk

**Likelihood**:

* Every swap sends 100% of fees to LP's

* The hook  balance remains permanently at zero

**Impact**:

* Protocol generates no revenue

* The owner cant extract any value from fee mechanism

## Proof of Concept

```Solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {Currency} from "v4-core/types/Currency.sol";
import {SwapParams} from "v4-core/types/PoolOperation.sol";
import {BeforeSwapDelta} from "v4-core/types/BeforeSwapDelta.sol";
import {ReFiSwapRebateHook} from "../src/RebateFiHook.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract NoRevenueTest is Test {
    ReFiSwapRebateHook hook;
    address refiToken;
    address otherToken;
    PoolKey poolKey;
    
    function setUp() public {
        refiToken = address(new MockERC20());
        otherToken = address(new MockERC20());
        
        IPoolManager poolManager = IPoolManager(address(0x789));
        hook = new ReFiSwapRebateHook(poolManager, refiToken);
        
        poolKey = PoolKey({
            currency0: Currency.wrap(otherToken),
            currency1: Currency.wrap(refiToken),
            fee: 0x800000,
            tickSpacing: 60,
            hooks: hook
        });
        
        // Fund tokens for test
        deal(refiToken, address(this), 1_000_000e18);
    }
    
    function testHookNeverCollectsFees() public {
        uint256 hookBalanceBefore = IERC20(refiToken).balanceOf(address(hook));
        
        // Execute a sell that should generate 3% fees
        SwapParams memory params = SwapParams({
            zeroForOne: false,
            amountSpecified: -100_000e18, // Sell 100k ReFi
            sqrtPriceLimitX96: 0
        });
        
        (bytes4 selector, BeforeSwapDelta delta, uint24 fee) = hook.beforeSwap(
            address(this),
            poolKey,
            params,
            ""
        );

        assertEq(BeforeSwapDelta.unwrap(delta), 0, "Hook should return ZERO_DELTA");

        uint256 hookBalanceAfter = IERC20(refiToken).balanceOf(address(hook));
        assertEq(hookBalanceAfter, hookBalanceBefore, "Hook balance should remain zero");
        assertEq(hookBalanceAfter, 0, "Hook collected no fees");
    }
    
    function testWithdrawTokensHasNothingToWithdraw() public {

        vm.expectRevert(); 
        hook.withdrawTokens(refiToken, address(this), 1e18);
    }
}

contract MockERC20 is IERC20 {
    mapping(address => uint256) public override balanceOf;
    
    function transfer(address to, uint256 amount) external override returns (bool) {
        require(balanceOf[msg.sender] >= amount);
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
    
    function totalSupply() external pure override returns (uint256) { return 0; }
    function allowance(address, address) external pure override returns (uint256) { return 0; }
    function approve(address, uint256) external pure override returns (bool) { return true; }
    function transferFrom(address, address, uint256) external pure override returns (bool) { return false; }
}
```

## Recommended Mitigation

```diff
function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
    return Hooks.Permissions({
        // ... other permissions ...
        beforeSwap: true,
+       beforeSwapReturnDelta: true,  // Enable delta returns
        // ... other permissions ...
    });
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
+   BeforeSwapDelta delta = BeforeSwapDeltaLibrary.ZERO_DELTA;
    
    if (isReFiBuy) {
        fee = buyFee;
        emit ReFiBought(sender, swapAmount);
    } else {
        fee = sellFee;
+       // Take protocol fee (e.g., 30% of the 3% sell fee = 0.9%)
+       uint256 protocolFee = (swapAmount * sellFee * 30) / 10000000;
+       // Specify delta to take protocolFee from the swap
+       delta = toBeforeSwapDelta(int128(int256(protocolFee)), 0);
        emit ReFiSold(sender, swapAmount, protocolFee);
    }
    
    return (
        BaseHook.beforeSwap.selector,
-       BeforeSwapDeltaLibrary.ZERO_DELTA,
+       delta,
        fee | LPFeeLibrary.OVERRIDE_FEE_FLAG
    );
}
```


# Medium Risk Findings

## <a id='M-01'></a>M-01. Unchecked ERC20 Transfer in withdrawTokens

_Submitted by [rf_](https://profiles.cyfrin.io/u/rf_), [adrianheldesai](https://profiles.cyfrin.io/u/adrianheldesai), [mostafapahlevani93](https://profiles.cyfrin.io/u/mostafapahlevani93), [s3mvl4d](https://profiles.cyfrin.io/u/s3mvl4d), [ashutoshcshah](https://profiles.cyfrin.io/u/ashutoshcshah), [themo2](https://profiles.cyfrin.io/u/themo2), [efimxff](https://profiles.cyfrin.io/u/efimxff), [seenu1947](https://profiles.cyfrin.io/u/seenu1947), [muzammilmohammed678](https://profiles.cyfrin.io/u/muzammilmohammed678), [wojack0x0](https://profiles.cyfrin.io/u/wojack0x0), [x0jgsleepy](https://profiles.cyfrin.io/u/x0jgsleepy), [ghufranhassan1](https://profiles.cyfrin.io/u/ghufranhassan1), [snufflesrea](https://profiles.cyfrin.io/u/snufflesrea), [alexscherbatyuk](https://profiles.cyfrin.io/u/alexscherbatyuk), [samuelsmith442](https://profiles.cyfrin.io/u/samuelsmith442), [valya](https://profiles.cyfrin.io/u/valya), [smartshielder](https://profiles.cyfrin.io/u/smartshielder), [objectplayer](https://profiles.cyfrin.io/u/objectplayer), [jufel](https://profiles.cyfrin.io/u/jufel), [accessdenied](https://profiles.cyfrin.io/u/accessdenied). Selected submission by: [wojack0x0](https://profiles.cyfrin.io/u/wojack0x0)._      
            


# Unchecked ERC20 Transfer in withdrawTokens

## Root + Impact

The `withdrawTokens` function uses `transfer()` without checking its return value. Some ERC20 tokens return `false` on failure instead of reverting, which means failed withdrawals will silently succeed, potentially locking funds permanently in the contract.

## Description

The `withdrawTokens` function allows the owner to withdraw any ERC20 tokens from the hook contract. However, it uses the unsafe `transfer()` method without checking the return value.

According to the ERC20 standard, `transfer()` should return a boolean indicating success or failure. While many tokens revert on failure, some tokens (especially older or non-standard implementations) return `false` instead of reverting. Examples include:

* USDT on mainnet (returns nothing)

* ZRX (returns false on failure)

* BNB (returns false on failure)

When such tokens are used, a failed transfer will not revert the transaction, causing the function to emit the `TokensWithdrawn` event even though no tokens were actually transferred.

```solidity
// RebateFiHook.sol, lines 73-76
function withdrawTokens(address token, address to, uint256 amount) external onlyOwner {
    IERC20(token).transfer(to, amount);  // @> BUG: Return value not checked
    emit TokensWithdrawn(to, token , amount);
}
```

## Risk

**Likelihood**: MEDIUM

* This vulnerability only affects tokens that return false instead of reverting (not all tokens)

* The protocol is designed to work with "standard ERC20 tokens" per README

* However, USDT is a very common token that could be accumulated via sell fees

* Owner might try to withdraw tokens that returned from an incomplete transfer

**Impact**: MEDIUM

* Failed tokens withdrawals will appear successful (event emitted)

* Tokens remain stuck in the contract

* Owner may think funds were recovered when they weren't

* Affects protocol revenue collection

* Violates INV-15: "After withdrawal, hook balance should decrease by exact withdrawal amount"

## Proof of Concept

The goal of this PoC is to demonstrate that using `IERC20.transfer` without checking its boolean return can cause silent failures. We simulate a token that returns `false` and show:

* The withdrawal call does not revert, and the event is emitted.

* Balances remain unchanged because the transfer failed.
  This proves the need to either use `SafeERC20.safeTransfer` or manually require a successful return value.

```solidity
// File: test/audit/Vulnerability03_UncheckedTransfer_PoC.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import {ReFiSwapRebateHook} from "../../src/RebateFiHook.sol";

import {Deployers} from "@uniswap/v4-core/test/utils/Deployers.sol";
import {MockERC20} from "solmate/src/test/utils/mocks/MockERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";

import {Hooks} from "v4-core/libraries/Hooks.sol";
import {HookMiner} from "v4-periphery/src/utils/HookMiner.sol";

// Mock token that returns false instead of reverting
contract BadERC20 {
    mapping(address => uint256) public balanceOf;
    
    function transfer(address, uint256) external pure returns (bool) {
        return false;  // Always returns false without reverting
    }
    
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }
}

contract Vulnerability03_UncheckedTransfer_PoC is Test, Deployers {
    
    MockERC20 reFiToken;
    BadERC20 badToken;
    ReFiSwapRebateHook public rebateHook;

    function setUp() public {
        // Deploy the Uniswap V4 PoolManager
        deployFreshManagerAndRouters();

        // Deploy tokens
        reFiToken = new MockERC20("ReFi Token", "ReFi", 18);
        badToken = new BadERC20();

        // Deploy hook
        bytes memory creationCode = type(ReFiSwapRebateHook).creationCode;
        bytes memory constructorArgs = abi.encode(manager, address(reFiToken));

        uint160 flags = uint160(
            Hooks.BEFORE_INITIALIZE_FLAG | 
            Hooks.AFTER_INITIALIZE_FLAG | 
            Hooks.BEFORE_SWAP_FLAG
        );

        (address hookAddress, bytes32 salt) = HookMiner.find(
            address(this),
            flags,
            creationCode,
            constructorArgs
        );

        rebateHook = new ReFiSwapRebateHook{salt: salt}(manager, address(reFiToken));
        require(address(rebateHook) == hookAddress, "Hook address mismatch");
    }

    /**
     * @notice This test demonstrates that failed transfers don't revert
     * @dev A token that returns false will cause silent failure
     */
    function test_UncheckedTransfer_SilentFailure() public {
        // Mint bad tokens to the hook
        uint256 amount = 100 ether;
        badToken.mint(address(rebateHook), amount);
        
        uint256 hookBalanceBefore = badToken.balanceOf(address(rebateHook));
        uint256 ownerBalanceBefore = badToken.balanceOf(address(this));
        
        console.log("\n=== Before Withdrawal ===");
        console.log("Hook balance:", hookBalanceBefore);
        console.log("Owner balance:", ownerBalanceBefore);
        
        // Try to withdraw - this will NOT revert even though transfer returns false!
        rebateHook.withdrawTokens(address(badToken), address(this), amount);
        
        uint256 hookBalanceAfter = badToken.balanceOf(address(rebateHook));
        uint256 ownerBalanceAfter = badToken.balanceOf(address(this));
        
        console.log("\n=== After Withdrawal ===");
        console.log("Hook balance:", hookBalanceAfter);
        console.log("Owner balance:", ownerBalanceAfter);
        console.log("\nIMPACT: Withdrawal appeared to succeed but tokens were not transferred!");
        
        // Withdrawal "succeeded" (no revert) but balances didn't change
        assertEq(hookBalanceAfter, hookBalanceBefore, "Hook balance unchanged");
        assertEq(ownerBalanceAfter, ownerBalanceBefore, "Owner balance unchanged");
        
        // Event was emitted even though transfer failed
        // This is extremely misleading for the owner
    }

    /**
     * @notice Compare with safe transfer patterns
     */
    function test_SafeTransferWouldCatch() public {
        uint256 amount = 100 ether;
        badToken.mint(address(rebateHook), amount);
        
        // Simulate what a safe transfer check would do
        bool success = IERC20(address(badToken)).transfer(address(this), amount);
        
        console.log("\n=== Safe Pattern Demonstration ===");
        console.log("Transfer return value:", success);
        console.log("With proper check, this would revert");
        
        assertFalse(success, "Transfer returns false");
        
        // A safe implementation would revert here:
        // require(success, "Transfer failed");
    }
}
```

**Test Results:**

```bash
forge test --via-ir -vv --match-path test/audit/Vulnerability03_UncheckedTransfer_PoC.t.sol

Ran 2 tests for test/audit/Vulnerability03_UncheckedTransfer_PoC.t.sol:Vulnerability03_UncheckedTransfer_PoC
[PASS] test_SafeTransferWouldCatch() (gas: 42451)
Logs:
  
=== Safe Pattern Demonstration ===
  Transfer return value: false
  With proper check, this would revert

[PASS] test_UncheckedTransfer_SilentFailure() (gas: 71072)
Logs:
  
=== Before Withdrawal ===
  Hook balance: 100000000000000000000
  Owner balance: 0
  
=== After Withdrawal ===
  Hook balance: 100000000000000000000
  Owner balance: 0
  
IMPACT: Withdrawal appeared to succeed but tokens were not transferred!

Suite result: ok. 2 passed; 0 failed; 0 skipped; finished in 1.66s (601.20µs CPU time)
```

Expected output showing the silent failure of token withdrawal.

## Recommended Mitigation

Use OpenZeppelin's `SafeERC20` library:

```diff
+ import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract ReFiSwapRebateHook is BaseHook, Ownable {
+   using SafeERC20 for IERC20;
    
    function withdrawTokens(address token, address to, uint256 amount) external onlyOwner {
-       IERC20(token).transfer(to, amount);
+       IERC20(token).safeTransfer(to, amount);
        emit TokensWithdrawn(to, token , amount);
    }
}
```

**Alternative manual fix:**

```diff
function withdrawTokens(address token, address to, uint256 amount) external onlyOwner {
-   IERC20(token).transfer(to, amount);
+   bool success = IERC20(token).transfer(to, amount);
+   require(success, "Transfer failed");
    emit TokensWithdrawn(to, token , amount);
}
```

Both solutions ensure that failed transfers cause the transaction to revert, preventing silent failures and protecting the withdrawal functionality.


# Low Risk Findings

## <a id='L-01'></a>L-01. Incorrect parameters in the event `TokensWithdrawn`

_Submitted by [comfortnurse021](https://profiles.cyfrin.io/u/comfortnurse021), [rf_](https://profiles.cyfrin.io/u/rf_), [mostafapahlevani93](https://profiles.cyfrin.io/u/mostafapahlevani93), [sulfurpt](https://profiles.cyfrin.io/u/sulfurpt), [cryptomv3](https://profiles.cyfrin.io/u/cryptomv3), [0xjoaovictor](https://profiles.cyfrin.io/u/0xjoaovictor), [s3mvl4d](https://profiles.cyfrin.io/u/s3mvl4d), [ciphermalware](https://profiles.cyfrin.io/u/ciphermalware), [ashutoshcshah](https://profiles.cyfrin.io/u/ashutoshcshah), [eagerpanda582](https://profiles.cyfrin.io/u/eagerpanda582), [iamgeorgi](https://profiles.cyfrin.io/u/iamgeorgi), [minos](https://profiles.cyfrin.io/u/minos), [themo2](https://profiles.cyfrin.io/u/themo2), [muzammilmohammed678](https://profiles.cyfrin.io/u/muzammilmohammed678), [wojack0x0](https://profiles.cyfrin.io/u/wojack0x0), [themilenkov](https://profiles.cyfrin.io/u/themilenkov), [howiecht](https://profiles.cyfrin.io/u/howiecht), [chain__warden](https://profiles.cyfrin.io/u/chain__warden), [alexscherbatyuk](https://profiles.cyfrin.io/u/alexscherbatyuk), [samuelsmith442](https://profiles.cyfrin.io/u/samuelsmith442), [hunterspartan5](https://profiles.cyfrin.io/u/hunterspartan5), [valya](https://profiles.cyfrin.io/u/valya), [farnad](https://profiles.cyfrin.io/u/farnad), [nutledger](https://profiles.cyfrin.io/u/nutledger), [shashankwcw](https://profiles.cyfrin.io/u/shashankwcw), [snufflesrea](https://profiles.cyfrin.io/u/snufflesrea), [smartshielder](https://profiles.cyfrin.io/u/smartshielder), [objectplayer](https://profiles.cyfrin.io/u/objectplayer), [lallanaad](https://profiles.cyfrin.io/u/lallanaad), [jufel](https://profiles.cyfrin.io/u/jufel). Selected submission by: [iamgeorgi](https://profiles.cyfrin.io/u/iamgeorgi)._      
            


# Incorrectly passed parameters result in emitting misleading or inaccurate event data 

## Description

* Normal **behavior - **In `RebateFiHook.sol`when the owner wants to withdraw tokens from the contract via the `withdrawTokens`   function an event should be emitted in that order :  address indexed token, address indexed to, uint256 amount.

* Issue - The order of the parameters is wrong and it can lead to inaccurate logs.

```Solidity
 function withdrawTokens(address token, address to, uint256 amount) external onlyOwner {
        IERC20(token).transfer(to, amount);
  @>    emit TokensWithdrawn(to, token , amount);
    }
```

## Risk

**Likelihood**:

* High likelihood because every time user wants to withdraw tokens this event is going to be emitted with the wrong parameters

**Impact**:

* Misleading information

* Inaccurate  data could cause serious issues if an off-chain monitoring system relies on these events at some point in the future. 

  <br />

## Proof of Concept

N/A

```Solidity
event TokensWithdrawn(address indexed token, address indexed to, uint256 amount);
```

## Recommended Mitigation

Update  `RebateFiHook.sol.` by using the correct order of the parameteres.

```diff
 function withdrawTokens(address token, address to, uint256 amount) external onlyOwner {
        IERC20(token).transfer(to, amount);
-       emit TokensWithdrawn(to, token , amount);
+       emit TokensWithdrawn(token,to,amount);
    }
```

## <a id='L-02'></a>L-02. Incorrect Fee Calculation in Events Reports 10x the Actual Fee

_Submitted by [rf_](https://profiles.cyfrin.io/u/rf_), [s3mvl4d](https://profiles.cyfrin.io/u/s3mvl4d), [ciphermalware](https://profiles.cyfrin.io/u/ciphermalware), [ashutoshcshah](https://profiles.cyfrin.io/u/ashutoshcshah), [minos](https://profiles.cyfrin.io/u/minos), [efimxff](https://profiles.cyfrin.io/u/efimxff), [howiecht](https://profiles.cyfrin.io/u/howiecht), [muzammilmohammed678](https://profiles.cyfrin.io/u/muzammilmohammed678), [0xjoaovictor](https://profiles.cyfrin.io/u/0xjoaovictor), [wojack0x0](https://profiles.cyfrin.io/u/wojack0x0), [themilenkov](https://profiles.cyfrin.io/u/themilenkov), [nutledger](https://profiles.cyfrin.io/u/nutledger), [valya](https://profiles.cyfrin.io/u/valya), [objectplayer](https://profiles.cyfrin.io/u/objectplayer), [uandersonricardo](https://profiles.cyfrin.io/u/uandersonricardo). Selected submission by: [wojack0x0](https://profiles.cyfrin.io/u/wojack0x0)._      
            


# Incorrect Fee Calculation in Events Reports 10x the Actual Fee

## Root + Impact

**Root Cause**: The event fee calculation uses a denominator of `100,000` (10^5) while Uniswap V4 fees are typically in pips (1/1,000,000 or 10^6).
**Impact**: The `ReFiSold` event reports a fee amount that is 10 times larger than the actual fee applied to the pool. This causes misleading off-chain data and accounting errors for indexers or users relying on events.

## Description

In `_beforeSwap`, the fee amount for the event is calculated as:

```solidity
            uint256 feeAmount = (swapAmount * sellFee) / 100000;
            emit ReFiSold(sender, swapAmount, feeAmount);
```

The `sellFee` is initialized to `3000`.

* In Uniswap V4, `3000` usually represents `0.3%` (3000 / 1,000,000).

* The event calculation uses `100,000` as denominator: `3000 / 100,000` = `0.03` = `3%`.

Thus, the event reports a 3% fee, while the pool applies a 0.3% fee.

## Risk

**Likelihood**: High (Always occurs for sells).
**Impact**: Low (Off-chain reporting issue, does not affect on-chain balances directly, but misleading).

## Proof of Concept

If `sellFee` is set to `100000` (10% in pips):

* Pool Fee: 10%.

* Event Fee: `(amount * 100000) / 100000` = `amount` (100%).

* The event reports 100% fee when it should be 10%.

## Recommended Mitigation

Use the correct denominator for pips (1,000,000).

```diff
-           uint256 feeAmount = (swapAmount * sellFee) / 100000;
+           uint256 feeAmount = (swapAmount * sellFee) / 1000000;
```

## <a id='L-03'></a>L-03. Incorrect Sender Logged in Events During Native ETH Swaps

_Submitted by [s3mvl4d](https://profiles.cyfrin.io/u/s3mvl4d), [ashutoshcshah](https://profiles.cyfrin.io/u/ashutoshcshah), [valya](https://profiles.cyfrin.io/u/valya). Selected submission by: [ashutoshcshah](https://profiles.cyfrin.io/u/ashutoshcshah)._      
            


## **Description**

 

In `_beforeSwap`, events use:

```Solidity
emit ReFiBought(sender, swapAmount);

```

However, **in Uniswap V4,** **`sender`** **is** ***not*** **the user**.

For swaps involving native ETH (or via router):

* `msg.sender` = router
* `sender` (param) = router
* actual user = `tx.origin` or `msg.sender` of router

**Result:**\
Events show the router as the entity that bought/sold ReFi, not the real user.

This breaks:

* analytics
* aggregators
* reward/points systems
* anti-bot/trading rules
* user-facing dashboards

### Example:

User swaps through `SwapRouter`, but every event shows:

```Solidity
sender = 0xUniswapV4Router

```

This is **incorrect** and hides real trading behavior.

***

## **Impact**

* **Completely incorrect user trading data**
* Misapplied rebates or rewards
* Trading volume appears massively skewed toward router
* Impossible to track real traders
* Attackers can exploit router abstraction to:
  * bypass anti-whale limits
  * avoid volume tracking
  * cheat volume-based rewards

This is a **serious problem for any protocol attaching economics or analytics to events**.

***

## **Proof of Concept**

```Solidity
function test_EventSenderIsRouter() public {
    // User initiates swap through swap router
    address user = makeAddr("user");
    vm.startPrank(user);

    // Expect event, but sender will be router, not user (bug)
    vm.expectEmit(true, true, true, true);
    emit ReFiSwapRebateHook.ReFiBought(address(router), amount);

    router.swap(...); // executed by user
}

```

Result:

* `sender` in event = router
* Correct should be = user

***

## **Recommended Mitigation**

Use the correct user address.\
When using a router-based pattern:

Replace:

```Solidity
emit ReFiBought(sender, swapAmount);

```

With:

```Solidity
emit ReFiBought(msg.sender, swapAmount);

```






    