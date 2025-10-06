# Protocol Name 

Raisebox faucet


### Prize Pool TO BE FILLED OUT BY CYFRIN

- Total Pool - 
- H/M -  
- Low - 

- Starts: 
- Ends: 

- nSLOC: 

[//]: # (contest-details-open)

## About the Project

This section should give auditors a feeling for what the protocol does, it's primary functions and the goals it hopes to achieve. Can include links to project websites or docs

```
About 

RaiseBox Faucet is a token drip faucet that drips 1000 test tokens to users every 3 days. It also drips 0.005 sepolia eth to first time users.

The faucet tokens will be useful for testing the testnet of a future protocol that would only allow interactions using this tokens.

[Documentation](www.GitHub.com/oxcoda/RaiseboxFaucet_ff/README.md)
[Website](https://sepolia.etherscan.io/address/0xb0ca2ae586b1ccf5ead5634ac14bdc50bbb5d138#readContract)
[Twitter](www.twitter.com/0xebby_)
[GitHub](www.gitHub.com/oxcoda)

```

## Actors

```

There are basically 3 actors in this protocol:

1. owner: 
RESPONSIBILITIES:

- deploys contract, 
- mint initial supply and any new token in future, 
- can burn tokens, 
- can adjust daily claim limit, 
- can refill sepolia eth balance

LIMITATIONS: 

- cannot claimfaucet tokens


2. claimer: 
RESPONSIBILITIES:

- can claim tokens by calling the claimFaucetTokens function of this contract.

LIMITATIONS: 

- Doesn't have any owner defined rights above.

3. Donators:
RESPONSIBILITIES:
- can donate sepolia eth directly to contract

```

[//]: # (contest-details-close)

[//]: # (scope-open)

## Scope (contracts)

SCOPE:

```
All Contracts in `src` and `tests` are in scope.

```
src/
├── RaiseBoxFaucet.sol
├── RaiseBoxFaucet.t.sol
├── DeployRaiseBoxFaucet.s.sol

├── interfaces
│   ├── IERC20.sol

└── utils(Open Zeppelin)
    ├── Ownable.sol
    ├── ERC20.sol



```

## Compatibilities

```
Compatibilities:

  Blockchains:
      - Ethereum/EVM
  Tokens:
      - SEP ETH
```

[//]: # (scope-close)


[//]: # (getting-started-open)

## Setup

Build:

```
git clone: repo

forge init

forge install OpenZeppelin/openzeppelin-contracts

forge install forge std

forge build

```

Tests:

```
Forge test

```

[//]: # (getting-started-close)

[//]: # (known-issues-open)

## Known Issues

`Known Issues:

No known issue.

`
[//]: # (known-issues-close)