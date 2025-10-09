# Protocol Name

RebateFi Hook

### Prize Pool TO BE FILLED OUT BY CYFRIN

- Total Pool -
- H/M -
- Low -

- Starts:
- Ends:

- nSLOC: ~150

[//]: # (contest-details-open)

## About the Project

RebateFi Hook is a Uniswap V4 hook implementation that enables asymmetric fee structures for designated ReFi (Rebate Finance) tokens. The protocol applies differential LP fee overrides based on swap direction, creating an innovative economic model that incentivizes token accumulation while managing sell pressure.

The hook intercepts swap operations and applies custom fee logic - zero(0%) or reduced fees for buying ReFi tokens to encourage accumulation, and standard (0.3%) or premium fees for selling to discourage dumping and generate protocol revenue. This creates a sustainable economic mechanism for regenerative finance projects.


[Documentation](https://github.com/fethallaheth/RebateFi/blob/main/README.md)

[GitHub](https://github.com/fethallaheth/RebateFi)

[Uniswap V4 Docs](https://docs.uniswap.org/contracts/v4/overview)

## Actors

```

There are 2 main actors in this protocol:

1. owner:
RESPONSIBILITIES:

- deploys hook contract with designated ReFi token address
- can modify buy and sell fee rates via ChangeFee() function
- can withdraw accumulated tokens from hook contract to specified addresses
- has full administrative control over fee configuration
- monitors protocol revenue and token accumulation


2. swapper:
RESPONSIBILITIES:

- can execute swaps through Uniswap V4 pools utilizing this hook
- can buy ReFi tokens with reduced or zero fees (depending on configuration)
- can sell ReFi tokens subject to configured sell fees
- must provide sufficient token approvals for swaps

LIMITATIONS:

- cannot bypass hook-enforced fees
- cannot modify fee structures
- subject to pool liquidity constraints
- must use pools that contain the designated ReFi token


```

[//]: # (contest-details-close)

[//]: # (scope-open)

## Scope (contracts)


```
All contracts in `src` are in scope.

```

## Compatibilities

```
Compatibilities:

  Blockchains:
      - Ethereum Mainnet
      - Arbitrum
      - Optimism
      - Base
      - Polygon
      - Any EVM-compatible chain with Uniswap V4
  Tokens:
      - Standard ERC20 tokens
```



[//]: # (getting-started-open)

## Setup

Build:

```
git clone https://github.com/fethallaheth/RebateFi.git
cd RebateFi

forge init

forge install 

forge build --via-ir

```

Tests:

```
forge test --via-ir

```


[//]: # (known-issues-open)

## Known Issues

Known Issues:

- Owner has unrestricted access to modify fees and withdraw tokens (consider multi-sig or timelock for production)

