#!/usr/bin/env python3
"""
CTF Benchmark — Validate SolidityGuard scanner against known-vulnerable contracts.

Supports multiple CTF sources:
  - DeFiVulnLabs (56 isolated vulnerability tests by SunWeb3Sec)
  - Paradigm CTF 2021/2022/2023 (competitive security challenges)

Usage:
    python3 ctf_benchmark.py                     # DeFiVulnLabs benchmark
    python3 ctf_benchmark.py --paradigm          # Paradigm CTF benchmark
    python3 ctf_benchmark.py --all               # All benchmarks
    python3 ctf_benchmark.py --dry-run           # Show mapping only
    python3 ctf_benchmark.py --repo-path /tmp/X  # Use existing clone
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# Add parent dir so we can import solidity_guard
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from solidity_guard import scan_patterns


# ─── DeFiVulnLabs → ETH pattern mapping ───────────────────────────────────

DEFI_VULN_LABS_MAP = {
    # Contract filename (in src/test/) → expected ETH pattern(s)
    # Filenames verified against actual repo: github.com/SunWeb3Sec/DeFiVulnLabs

    # ─── Reentrancy ───
    "Reentrancy.sol": {
        "eth_ids": ["ETH-001"],
        "category": "Reentrancy",
        "description": "Single-function reentrancy via external call before state update",
    },
    "ReadOnlyReentrancy.sol": {
        "eth_ids": ["ETH-004"],
        "category": "Reentrancy",
        "description": "Read-only reentrancy via view function during callback",
    },
    "ERC777-reentrancy.sol": {
        "eth_ids": ["ETH-044"],
        "category": "Reentrancy",
        "description": "ERC-777 reentrancy via token hooks",
    },

    # ─── Access Control ───
    "txorigin.sol": {
        "eth_ids": ["ETH-007"],
        "category": "Access Control",
        "description": "tx.origin used for authentication — phishing vulnerable",
    },
    "Selfdestruct.sol": {
        "eth_ids": ["ETH-008"],
        "category": "Access Control",
        "description": "Unprotected selfdestruct allows contract destruction",
    },
    "Selfdestruct2.sol": {
        "eth_ids": ["ETH-008"],
        "category": "Access Control",
        "description": "selfdestruct variant — force-send ETH",
    },
    "Visibility.sol": {
        "eth_ids": ["ETH-009"],
        "category": "Access Control",
        "description": "Default function visibility allows unintended access",
    },
    "Bypasscontract.sol": {
        "eth_ids": ["ETH-089"],
        "category": "Access Control",
        "description": "isContract check bypass via constructor",
    },
    "NFT-transfer.sol": {
        "eth_ids": ["ETH-006"],
        "category": "Access Control",
        "description": "Missing access control on NFT transfer",
    },
    "recoverERC20.sol": {
        "eth_ids": ["ETH-006"],
        "category": "Access Control",
        "description": "Missing access control on token recovery",
    },
    "Backdoor-assembly.sol": {
        "eth_ids": ["ETH-012"],
        "category": "Access Control",
        "description": "Hidden backdoor via inline assembly",
    },

    # ─── Arithmetic ───
    "Overflow.sol": {
        "eth_ids": ["ETH-013", "ETH-072"],
        "category": "Arithmetic",
        "description": "Integer overflow in older Solidity version",
    },
    "Overflow2.sol": {
        "eth_ids": ["ETH-013"],
        "category": "Arithmetic",
        "description": "Integer overflow variant — unchecked block",
    },
    "Divmultiply.sol": {
        "eth_ids": ["ETH-014"],
        "category": "Arithmetic",
        "description": "Division before multiplication precision loss",
    },
    "Precision-loss.sol": {
        "eth_ids": ["ETH-017"],
        "category": "Arithmetic",
        "description": "Precision loss in token calculations",
    },
    "Invariant.sol": {
        "eth_ids": ["ETH-013"],
        "category": "Arithmetic",
        "description": "Invariant violation via unchecked math",
    },
    "unsafe-downcast.sol": {
        "eth_ids": ["ETH-013"],
        "category": "Arithmetic",
        "description": "Unsafe integer downcast truncation",
    },

    # ─── External Calls ───
    "Delegatecall.sol": {
        "eth_ids": ["ETH-019"],
        "category": "External Calls",
        "description": "Delegatecall to untrusted callee — storage overwrite",
    },
    "Returnvalue.sol": {
        "eth_ids": ["ETH-041"],
        "category": "Token",
        "description": "Non-standard ERC-20 return value (USDT transfer without bool return)",
    },
    "UnsafeCall.sol": {
        "eth_ids": ["ETH-018"],
        "category": "External Calls",
        "description": "Unsafe low-level call usage",
    },
    "DOS.sol": {
        "eth_ids": ["ETH-021"],
        "category": "Gas & DoS",
        "description": "Denial of service via failed call in loop",
    },
    "payable-transfer.sol": {
        "eth_ids": ["ETH-021", "ETH-079"],
        "category": "Gas & DoS",
        "description": "DoS via .transfer() to contract without receive()",
    },

    # ─── Oracle & Price ───
    "Oracle-stale.sol": {
        "eth_ids": ["ETH-028"],
        "category": "Oracle",
        "description": "Stale oracle data — missing freshness check",
    },
    "Price_manipulation.sol": {
        "eth_ids": ["ETH-024"],
        "category": "Oracle",
        "description": "Price manipulation via balance-based oracle",
    },
    "Flashloan-flaw.sol": {
        "eth_ids": ["ETH-025"],
        "category": "Oracle",
        "description": "Flash loan attack vector",
    },

    # ─── Storage ───
    "Storage-collision.sol": {
        "eth_ids": ["ETH-030"],
        "category": "Storage",
        "description": "Storage collision in proxy pattern",
    },
    "Storage-collision-audio.sol": {
        "eth_ids": ["ETH-030"],
        "category": "Storage",
        "description": "Storage collision variant — audio example",
    },
    "DataLocation.sol": {
        "eth_ids": ["ETH-029"],
        "category": "Storage",
        "description": "Incorrect data location — storage vs memory confusion",
    },
    "Uninitialized_variables.sol": {
        "eth_ids": ["ETH-029"],
        "category": "Storage",
        "description": "Uninitialized storage variables",
    },
    "Privatedata.sol": {
        "eth_ids": ["ETH-078"],
        "category": "Storage",
        "description": "Private data stored on-chain is publicly readable",
    },

    # ─── Logic ───
    "Randomness.sol": {
        "eth_ids": ["ETH-037"],
        "category": "Logic",
        "description": "Weak randomness from block attributes",
    },
    "SignatureReplay.sol": {
        "eth_ids": ["ETH-039"],
        "category": "Logic",
        "description": "Signature replay — missing nonce or chain ID",
    },
    "SignatureReplayNBA.sol": {
        "eth_ids": ["ETH-039"],
        "category": "Logic",
        "description": "Signature replay variant (NBA)",
    },
    "ecrecover.sol": {
        "eth_ids": ["ETH-038"],
        "category": "Logic",
        "description": "ecrecover signature malleability",
    },

    # ─── Token ───
    "Returnfalse.sol": {
        "eth_ids": ["ETH-041"],
        "category": "Token",
        "description": "ERC-20 non-standard return values (returns false silently)",
    },
    "ApproveScam.sol": {
        "eth_ids": ["ETH-046"],
        "category": "Token",
        "description": "ERC-20 approval race condition / scam",
    },
    "fee-on-transfer.sol": {
        "eth_ids": ["ETH-042"],
        "category": "Token",
        "description": "Fee-on-transfer token incompatibility",
    },
    "SenseFinance_exp.sol": {
        "eth_ids": ["ETH-048"],
        "category": "Token",
        "description": "Token supply manipulation (Sense Finance exploit)",
    },
    "self-transfer.sol": {
        "eth_ids": ["ETH-098"],
        "category": "Token",
        "description": "Self-transfer balance check bypass",
    },
    "phantom-permit.sol": {
        "eth_ids": ["ETH-046"],
        "category": "Token",
        "description": "Phantom permit — non-standard permit compatibility",
    },

    # ─── DeFi ───
    "first-deposit.sol": {
        "eth_ids": ["ETH-057"],
        "category": "DeFi",
        "description": "Vault share inflation / first depositor attack",
    },
    "Slippage-deadline.sol": {
        "eth_ids": ["ETH-027", "ETH-060"],
        "category": "DeFi",
        "description": "Missing slippage protection and transaction deadline",
    },
    "Unprotected-callback.sol": {
        "eth_ids": ["ETH-064"],
        "category": "DeFi",
        "description": "Insecure callback handler without validation",
    },
    "UniswapV3ETHRefundExploit.sol": {
        "eth_ids": ["ETH-060"],
        "category": "DeFi",
        "description": "Uniswap V3 ETH refund exploit",
    },

    # ─── Miscellaneous ───
    "Hash-collisions.sol": {
        "eth_ids": ["ETH-073"],
        "category": "Miscellaneous",
        "description": "Hash collision with abi.encodePacked and dynamic types",
    },
    "Dirtybytes.sol": {
        "eth_ids": ["ETH-097"],
        "category": "Miscellaneous",
        "description": "Dirty bytes from legacy ABI encoder",
    },
    "Array-deletion.sol": {
        "eth_ids": ["ETH-075"],
        "category": "Miscellaneous",
        "description": "Incorrect array deletion leaving gaps",
    },
    "Struct-deletion.sol": {
        "eth_ids": ["ETH-075"],
        "category": "Miscellaneous",
        "description": "Incomplete struct deletion",
    },
    "empty-loop.sol": {
        "eth_ids": ["ETH-075"],
        "category": "Miscellaneous",
        "description": "Empty loop body with no effects",
    },
    "return-break.sol": {
        "eth_ids": ["ETH-075"],
        "category": "Miscellaneous",
        "description": "Incorrect return/break in loop",
    },
    "gas-price.sol": {
        "eth_ids": ["ETH-079"],
        "category": "Miscellaneous",
        "description": "Hardcoded gas amount / gas price dependency",
    },
    "NFTMint_exposedMetadata.sol": {
        "eth_ids": ["ETH-078"],
        "category": "Miscellaneous",
        "description": "Exposed metadata / private data on-chain",
    },

    # ─── Input Validation ───
    "Incorrect_sanity_checks.sol": {
        "eth_ids": ["ETH-098"],
        "category": "Input Validation",
        "description": "Incorrect sanity checks on input parameters",
    },
    "Immunefi_ch1.sol": {
        "eth_ids": ["ETH-098"],
        "category": "Input Validation",
        "description": "Immunefi challenge 1 — input validation bypass",
    },
    "Immunefi_ch2.sol": {
        "eth_ids": ["ETH-030"],
        "category": "Storage",
        "description": "Immunefi challenge 2 — storage collision",
    },

    # ─── Transient Storage ───
    "TransientStorageMisuse.t.sol": {
        "eth_ids": ["ETH-081"],
        "category": "Transient Storage",
        "description": "Transient storage misuse (EIP-1153 / SIR exploit pattern)",
    },
}

# Additional CTF sources for the matrix (not cloned, documentation-only)
ADDITIONAL_CTF_SOURCES = {
    "DeFiHackLabs": {
        "url": "https://github.com/SunWeb3Sec/DeFiHackLabs",
        "count": "700+",
        "description": "Real-world DeFi exploit reproductions in Foundry",
    },
    "Damn Vulnerable DeFi v4": {
        "url": "https://github.com/tinchoabbate/damn-vulnerable-defi",
        "count": "18",
        "description": "Progressive DeFi challenge suite",
    },
    "Ethernaut": {
        "url": "https://github.com/OpenZeppelin/ethernaut",
        "count": "32",
        "description": "OpenZeppelin wargame covering classic Solidity vulnerabilities",
    },
    "Mr Steal Yo Crypto": {
        "url": "https://github.com/0xToshii/mr-steal-yo-crypto-ctf-foundry",
        "count": "20",
        "description": "DeFi-focused CTF with Foundry framework",
    },
    "Secureum A-MAZE-X": {
        "url": "https://github.com/secureum/DeFi-Security-Summit-Stanford",
        "count": "12",
        "description": "Advanced DeFi security challenges from Secureum",
    },
    "QuillCTF": {
        "url": "https://academy.quillaudits.com/challenges",
        "count": "30+",
        "description": "QuillAudits CTF challenges for auditors",
    },
}


# ─── Paradigm CTF → ETH pattern mapping ───────────────────────────────────
# Maps challenge_name → { files: [relative paths], eth_ids, category, year, static }
# "static" indicates if it's detectable by static analysis alone

PARADIGM_CTF_REPOS = {
    2021: "https://github.com/paradigmxyz/paradigm-ctf-2021.git",
    2022: "https://github.com/paradigmxyz/paradigm-ctf-2022.git",
    2023: "https://github.com/paradigmxyz/paradigm-ctf-2023.git",
}

PARADIGM_CTF_MAP = {
    # ═══════════════════════════════════════════════════════════════
    #  PARADIGM CTF 2021
    # ═══════════════════════════════════════════════════════════════

    "2021/hello": {
        "files": ["hello/public/contracts/Hello.sol"],
        "eth_ids": [],  # No vulnerability — sanity check
        "category": "Sanity",
        "year": 2021,
        "static": True,
        "description": "Sanity check — just call solve()",
    },
    "2021/bouncer": {
        "files": ["bouncer/public/contracts/Bouncer.sol"],
        "eth_ids": ["ETH-098"],  # msg.value reuse in loop
        "category": "Input Validation",
        "year": 2021,
        "static": True,
        "description": "msg.value reuse across loop iterations in convertMany()",
    },
    "2021/broker": {
        "files": ["broker/public/contracts/Broker.sol"],
        "eth_ids": ["ETH-024"],  # Oracle manipulation via getReserves()
        "category": "Oracle",
        "year": 2021,
        "static": True,
        "description": "Oracle manipulation via Uniswap V2 getReserves() spot price",
    },
    "2021/bank": {
        "files": ["bank/public/contracts/Bank.sol"],
        "eth_ids": ["ETH-033", "ETH-013"],  # Array length manipulation + overflow
        "category": "Storage",
        "year": 2021,
        "static": True,
        "description": "Array length underflow (Solidity 0.4.24) → arbitrary storage write",
    },
    "2021/yield_aggregator": {
        "files": ["yield_aggregator/public/contracts/YieldAggregator.sol"],
        "eth_ids": ["ETH-065"],  # User-supplied protocol address
        "category": "DeFi",
        "year": 2021,
        "static": True,
        "description": "User-controlled protocol address enables malicious external calls",
    },
    "2021/farmer": {
        "files": ["farmer/public/contracts/Farmer.sol"],
        "eth_ids": ["ETH-027"],  # Zero slippage in swap
        "category": "DeFi",
        "year": 2021,
        "static": True,
        "description": "swapExactTokensForTokens with amountOutMin=0 (sandwich attack)",
    },
    "2021/vault": {
        "files": ["vault/public/contracts/Vault.sol"],
        "eth_ids": ["ETH-019"],  # Delegatecall to untrusted callee
        "category": "External Calls",
        "year": 2021,
        "static": True,
        "description": "delegatecall to user-supplied target in emergencyCall()",
    },
    "2021/lockbox": {
        "files": ["lockbox/public/contracts/Lockbox.sol"],
        "eth_ids": ["ETH-038"],  # ecrecover + signature patterns (overflow is pre-0.8.0 implicit)
        "category": "Logic",
        "year": 2021,
        "static": True,
        "description": "ecrecover + integer overflow (Solidity 0.4.24 implicit overflow)",
    },
    "2021/babysandbox": {
        "files": ["babysandbox/public/contracts/BabySandbox.sol"],
        "eth_ids": ["ETH-019"],  # delegatecall to user-supplied code
        "category": "External Calls",
        "year": 2021,
        "static": True,
        "description": "Sandbox bypass — delegatecall to user code (staticcall→call pattern)",
    },
    "2021/market": {
        "files": ["market/public/contracts/EternalStorage.sol"],
        "eth_ids": ["ETH-033"],  # Assembly sstore with user-controlled slot
        "category": "Storage",
        "year": 2021,
        "static": True,
        "description": "Arbitrary sstore with user-controlled tokenId overlapping owner slot",
    },
    "2021/upgrade": {
        "files": ["upgrade/public/contracts/FiatTokenV3.sol"],
        "eth_ids": [],  # Logic bug: _transfer(from, msg.sender) without approval — requires semantic analysis
        "category": "Logic",
        "year": 2021,
        "static": False,
        "description": "Unauthorized token transfer via reclaim() — semantic logic bug",
    },
    "2021/secure": {
        "files": ["secure/public/contracts/Wallet.sol"],
        "eth_ids": [],  # Unused parameter logic bug — requires semantic analysis
        "category": "Logic",
        "year": 2021,
        "static": False,
        "description": "addOperator writes _operators[owner] not _operators[operator] — unused param",
    },
    "2021/swap": {
        "files": ["swap/public/contracts/Swap.sol"],
        "eth_ids": ["ETH-013"],  # Overflow in 10**decimals (Solidity 0.4.24)
        "category": "Arithmetic",
        "year": 2021,
        "static": True,
        "description": "Integer overflow in 10**decimals exponentiation (Solidity 0.4.24)",
    },

    # ── 2021 challenges requiring dynamic analysis (bytecode RE) ──
    "2021/babyrev": {
        "files": ["babyrev/public/contracts/Setup.sol"],
        "eth_ids": [],  # Bytecode RE — not statically detectable
        "category": "Reversing",
        "year": 2021,
        "static": False,
        "description": "EVM bytecode reversing challenge",
    },
    "2021/rever": {
        "files": ["rever/public/contracts/Setup.sol"],
        "eth_ids": [],  # Bytecode RE
        "category": "Reversing",
        "year": 2021,
        "static": False,
        "description": "EVM bytecode reversing challenge",
    },
    "2021/jop": {
        "files": ["jop/public/contracts/Setup.sol"],
        "eth_ids": [],  # JOP gadget chain
        "category": "Reversing",
        "year": 2021,
        "static": False,
        "description": "Jump-oriented programming gadget chain",
    },

    # ═══════════════════════════════════════════════════════════════
    #  PARADIGM CTF 2022
    # ═══════════════════════════════════════════════════════════════

    "2022/random": {
        "files": ["random/public/contracts/Random.sol"],
        "eth_ids": ["ETH-037"],  # Weak randomness (hardcoded constant)
        "category": "Logic",
        "year": 2022,
        "static": True,
        "description": "Hardcoded 'random' return value (trivial)",
    },
    "2022/rescue": {
        "files": ["rescue/public/contracts/MasterChefHelper.sol"],
        "eth_ids": ["ETH-027", "ETH-047"],  # Zero slippage + infinite approval
        "category": "DeFi",
        "year": 2022,
        "static": True,
        "description": "swapExactTokensForTokens with 0 min + infinite approval",
    },
    "2022/merkledrop": {
        "files": ["merkledrop/public/contracts/MerkleDistributor.sol",
                  "merkledrop/public/contracts/MerkleProof.sol"],
        "eth_ids": ["ETH-073"],  # abi.encodePacked collision in Merkle tree
        "category": "Miscellaneous",
        "year": 2022,
        "static": True,
        "description": "abi.encodePacked hash collision in Merkle proof verification",
    },
    "2022/hint-finance": {
        "files": ["hint-finance/public/contracts/HintFinanceVault.sol"],
        "eth_ids": ["ETH-025"],  # Flash loan function + share manipulation
        "category": "DeFi",
        "year": 2022,
        "static": True,
        "description": "Flash loan + ERC-777 reentrancy + vault share manipulation",
    },
    "2022/just-in-time": {
        "files": ["just-in-time/public/contracts/JIT.sol"],
        "eth_ids": ["ETH-019"],  # Delegatecall to dynamically created contract
        "category": "External Calls",
        "year": 2022,
        "static": True,
        "description": "create() then delegatecall() to user-compiled bytecode",
    },
    "2022/lockbox2": {
        "files": ["lockbox2/public/contracts/Lockbox2.sol"],
        "eth_ids": ["ETH-019", "ETH-007"],  # Delegatecall + tx.origin
        "category": "External Calls",
        "year": 2022,
        "static": True,
        "description": "Self-delegatecall with msg.data + tx.origin check + arbitrary mstore",
    },
    "2022/vanity": {
        "files": ["vanity/public/contracts/Challenge.sol",
                  "vanity/public/contracts/SignatureChecker.sol"],
        "eth_ids": ["ETH-073"],  # abi.encodePacked in signature checker + CREATE2 exploit
        "category": "Logic",
        "year": 2022,
        "static": True,
        "description": "ERC-1271 signature bypass via CREATE2 (abi.encodePacked in checker)",
    },

    # ── 2022 challenges requiring dynamic analysis ──
    "2022/sourcecode": {
        "files": ["sourcecode/public/contracts/Challenge.sol"],
        "eth_ids": [],  # Quine / bytecode puzzle
        "category": "Reversing",
        "year": 2022,
        "static": False,
        "description": "Bytecode quine challenge",
    },
    "2022/fun-reversing-challenge": {
        "files": ["fun-reversing-challenge/public/contracts/Challenge.sol"],
        "eth_ids": [],  # Bytecode RE
        "category": "Reversing",
        "year": 2022,
        "static": False,
        "description": "EVM bytecode reversing",
    },
    "2022/electric-sheep": {
        "files": ["electric-sheep/public/contracts/Setup.sol"],
        "eth_ids": [],  # L2/network level
        "category": "Reversing",
        "year": 2022,
        "static": False,
        "description": "Network-level challenge",
    },
    "2022/stealing-sats": {
        "files": ["stealing-sats/public/contracts/Setup.sol"],
        "eth_ids": [],  # Cross-chain BTC bridge
        "category": "Reversing",
        "year": 2022,
        "static": False,
        "description": "Cross-chain Bitcoin bridge challenge",
    },
    "2022/trapdooor": {
        "files": ["trapdooor/public/deploy/Script.sol"],
        "eth_ids": [],  # Crypto puzzle
        "category": "Reversing",
        "year": 2022,
        "static": False,
        "description": "Cryptographic trapdoor challenge",
    },
    "2022/trapdoooor": {
        "files": ["trapdoooor/public/deploy/Script.sol"],
        "eth_ids": [],  # Crypto puzzle
        "category": "Reversing",
        "year": 2022,
        "static": False,
        "description": "Cryptographic trapdoor challenge (variant)",
    },

    # ═══════════════════════════════════════════════════════════════
    #  PARADIGM CTF 2023
    # ═══════════════════════════════════════════════════════════════

    "2023/one-hundred-percent": {
        "files": ["one-hundred-percent/challenge/project/src/Split.sol",
                  "one-hundred-percent/challenge/project/src/SplitWallet.sol"],
        "eth_ids": ["ETH-073"],  # abi.encodePacked collision
        "category": "Miscellaneous",
        "year": 2023,
        "static": True,
        "description": "abi.encodePacked hash collision with dynamic arrays",
    },
    "2023/dragon-tyrant": {
        "files": ["dragon-tyrant/challenge/project/src/Factory.sol",
                  "dragon-tyrant/challenge/project/src/NFT.sol",
                  "dragon-tyrant/challenge/project/src/Randomness.sol"],
        "eth_ids": ["ETH-006"],  # onlyOwner centralization + extcodehash bypass
        "category": "Access Control",
        "year": 2023,
        "static": True,
        "description": "extcodehash for auth (bypassable via CREATE2) + centralized operator",
    },
    "2023/enterprise-blockchain": {
        "files": ["enterprise-blockchain/challenge/project/src/bridge/Bridge.sol",
                  "enterprise-blockchain/challenge/project/src/multisig/MultiSig.sol"],
        "eth_ids": ["ETH-007"],  # tx.origin in receive()
        "category": "Access Control",
        "year": 2023,
        "static": True,
        "description": "Bridge with tx.origin check + centralized relayer",
    },
    "2023/dai-plus-plus": {
        "files": ["dai-plus-plus/challenge/project/src/AccountManager.sol",
                  "dai-plus-plus/challenge/project/src/Account.sol"],
        "eth_ids": [],  # Overflow in imported library (ClonesWithImmutableArgs) — not in local source
        "category": "Arithmetic",
        "year": 2023,
        "static": False,
        "description": "ClonesWithImmutableArgs data length overflow (in imported library)",
    },
    "2023/suspicious-charity": {
        "files": ["suspicious-charity/challenge/project/src/Router.sol",
                  "suspicious-charity/challenge/project/src/FlagCharity.sol",
                  "suspicious-charity/challenge/project/src/Pair.sol",
                  "suspicious-charity/challenge/project/src/PairFactory.sol"],
        "eth_ids": ["ETH-024"],  # AMM price manipulation via getReserves
        "category": "Oracle",
        "year": 2023,
        "static": True,
        "description": "AMM pair price manipulation via custom token/pair factory",
    },
    "2023/token-locker": {
        "files": ["token-locker/challenge/project/src/UNCX_ProofOfReservesV2_UniV3.sol"],
        "eth_ids": ["ETH-064"],  # Insecure callback handler
        "category": "DeFi",
        "year": 2023,
        "static": True,
        "description": "NFT callback exploitation in token locker contract",
    },

    # ── 2023 fork-based challenges (thin wrapper, vulnerability on mainnet) ──
    "2023/hello-world": {
        "files": ["hello-world/challenge/project/src/Challenge.sol"],
        "eth_ids": [],  # Balance used with > not ==; exploit is selfdestruct from attacker contract
        "category": "Logic",
        "year": 2023,
        "static": False,
        "description": "Force ETH to Beacon Deposit Contract via selfdestruct (exploit-side)",
    },
    "2023/dodont": {
        "files": ["dodont/challenge/project/src/Challenge.sol"],
        "eth_ids": ["ETH-034"],  # Strict balance equality
        "category": "Logic",
        "year": 2023,
        "static": True,
        "description": "DODO DVM re-initialization (balance == 0 win condition)",
    },
    "2023/grains-of-sand": {
        "files": ["grains-of-sand/challenge/project/src/Challenge.sol"],
        "eth_ids": [],  # Fork-based, fee-on-transfer but code is on-chain only
        "category": "Token",
        "year": 2023,
        "static": False,
        "description": "Fee-on-transfer token exploitation (fork-based, no local source)",
    },
    "2023/skill-based-game": {
        "files": ["skill-based-game/challenge/project/src/Challenge.sol"],
        "eth_ids": ["ETH-034"],  # Strict balance equality check
        "category": "Logic",
        "year": 2023,
        "static": True,
        "description": "Predictable randomness in Blackjack (balance == 0 win)",
    },
    "2023/free-real-estate": {
        "files": ["free-real-estate/challenge/project/src/Challenge.sol",
                  "free-real-estate/challenge/project/src/InuToken.sol"],
        "eth_ids": [],  # Fork-based Merkle distributor
        "category": "Miscellaneous",
        "year": 2023,
        "static": False,
        "description": "Merkle distributor airdrop claim (fork-based)",
    },
    "2023/hopping-into-place": {
        "files": ["hopping-into-place/challenge/project/src/Challenge.sol"],
        "eth_ids": [],  # Fork-based governance/bridge
        "category": "DeFi",
        "year": 2023,
        "static": False,
        "description": "Governance bridge drain (fork-based, no local source)",
    },

    # ── 2023 non-Solidity/dynamic challenges ──
    "2023/black-sheep": {
        "files": ["black-sheep/challenge/project/src/Challenge.sol"],
        "eth_ids": [],  # Huff bytecode (not Solidity)
        "category": "Reversing",
        "year": 2023,
        "static": False,
        "description": "Huff contract ECDSA bypass (not Solidity)",
    },
    "2023/cosmic-radiation": {
        "files": ["cosmic-radiation/challenge/project/src/Challenge.sol"],
        "eth_ids": [],  # Bit-flip oracle puzzle
        "category": "Reversing",
        "year": 2023,
        "static": False,
        "description": "Cosmic ray bit-flip oracle challenge",
    },
    "2023/dropper": {
        "files": ["dropper/challenge/project/src/Challenge.sol"],
        "eth_ids": [],  # Puzzle challenge
        "category": "Reversing",
        "year": 2023,
        "static": False,
        "description": "Puzzle / simulation challenge",
    },
}


@dataclass
class BenchmarkResult:
    contract: str
    expected_ids: list
    detected_ids: list
    true_positives: list = field(default_factory=list)
    false_negatives: list = field(default_factory=list)
    extra_detections: list = field(default_factory=list)

    @property
    def detected(self) -> bool:
        return len(self.true_positives) > 0

    def compute(self):
        self.true_positives = [eid for eid in self.expected_ids if eid in self.detected_ids]
        self.false_negatives = [eid for eid in self.expected_ids if eid not in self.detected_ids]
        self.extra_detections = [did for did in self.detected_ids if did not in self.expected_ids]


def clone_repo(dest: str, url: str = "https://github.com/SunWeb3Sec/DeFiVulnLabs.git") -> bool:
    """Clone a git repository."""
    print(f"Cloning {url} into {dest}...")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, dest],
            capture_output=True, text=True, timeout=120, check=True
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"[ERROR] Failed to clone: {e}")
        return False


def find_contract(repo_path: str, filename: str) -> str | None:
    """Find a contract file in the repo (searches src/test/ and src/)."""
    for subdir in ["src/test", "src", "contracts", "."]:
        candidate = Path(repo_path) / subdir / filename
        if candidate.exists():
            return str(candidate)
    # Fallback: recursive search
    matches = list(Path(repo_path).rglob(filename))
    return str(matches[0]) if matches else None


def run_benchmark(repo_path: str) -> list[BenchmarkResult]:
    """Run scan_patterns against each mapped DeFiVulnLabs contract."""
    results = []

    for contract_file, mapping in sorted(DEFI_VULN_LABS_MAP.items()):
        contract_path = find_contract(repo_path, contract_file)
        if not contract_path:
            print(f"  [SKIP] {contract_file} — not found in repo")
            results.append(BenchmarkResult(
                contract=contract_file,
                expected_ids=mapping["eth_ids"],
                detected_ids=[],
            ))
            results[-1].compute()
            continue

        # Run our scanner on the contract's directory
        # Create a temp dir with just this file to avoid cross-contamination
        with tempfile.TemporaryDirectory() as tmpdir:
            # Copy just this contract
            import shutil
            shutil.copy2(contract_path, os.path.join(tmpdir, contract_file))

            findings = scan_patterns(tmpdir)
            detected_ids = list(set(f.id for f in findings))

            result = BenchmarkResult(
                contract=contract_file,
                expected_ids=mapping["eth_ids"],
                detected_ids=detected_ids,
            )
            result.compute()
            results.append(result)

            status = "PASS" if result.detected else "MISS"
            print(f"  [{status}] {contract_file}: expected {mapping['eth_ids']}, "
                  f"detected {detected_ids}")

    return results


def ensure_paradigm_repos() -> dict:
    """Ensure Paradigm CTF repos are cloned, return {year: path}."""
    paths = {}
    for year, url in PARADIGM_CTF_REPOS.items():
        dest = os.path.join(tempfile.gettempdir(), f"paradigm-ctf-{year}")
        if os.path.isdir(dest):
            print(f"Using existing clone at {dest}")
        else:
            if not clone_repo(dest, url):
                continue
        paths[year] = dest
    return paths


def run_paradigm_benchmark(repo_paths: dict) -> list[BenchmarkResult]:
    """Run scan_patterns against each mapped Paradigm CTF challenge."""
    results = []

    for challenge_key, mapping in sorted(PARADIGM_CTF_MAP.items()):
        year = mapping["year"]
        eth_ids = mapping["eth_ids"]

        if year not in repo_paths:
            print(f"  [SKIP] {challenge_key} — repo for {year} not cloned")
            result = BenchmarkResult(contract=challenge_key, expected_ids=eth_ids, detected_ids=[])
            result.compute()
            results.append(result)
            continue

        repo_path = repo_paths[year]

        # If no expected patterns (non-static or sanity check), mark as N/A
        if not eth_ids:
            na_tag = "N/A" if not mapping["static"] else "PASS"
            print(f"  [{na_tag}] {challenge_key}: no static patterns expected "
                  f"({mapping['description'][:60]})")
            result = BenchmarkResult(contract=challenge_key, expected_ids=[], detected_ids=[])
            result.compute()
            results.append(result)
            continue

        # Copy challenge files to temp dir and scan
        with tempfile.TemporaryDirectory() as tmpdir:
            import shutil
            found_any = False
            for rel_path in mapping["files"]:
                src = os.path.join(repo_path, rel_path)
                if os.path.exists(src):
                    fname = os.path.basename(rel_path)
                    shutil.copy2(src, os.path.join(tmpdir, fname))
                    found_any = True

            if not found_any:
                print(f"  [SKIP] {challenge_key} — no files found")
                result = BenchmarkResult(contract=challenge_key, expected_ids=eth_ids, detected_ids=[])
                result.compute()
                results.append(result)
                continue

            findings = scan_patterns(tmpdir)
            detected_ids = list(set(f.id for f in findings))

            result = BenchmarkResult(
                contract=challenge_key,
                expected_ids=eth_ids,
                detected_ids=detected_ids,
            )
            result.compute()
            results.append(result)

            status = "PASS" if result.detected else "MISS"
            print(f"  [{status}] {challenge_key}: expected {eth_ids}, detected {detected_ids}")

    return results


def print_paradigm_report(results: list[BenchmarkResult]):
    """Print Paradigm CTF benchmark summary."""
    # Separate static-detectable from non-static
    static_challenges = [r for r in results if PARADIGM_CTF_MAP.get(r.contract, {}).get("static", False)]
    dynamic_challenges = [r for r in results if not PARADIGM_CTF_MAP.get(r.contract, {}).get("static", True)]
    with_patterns = [r for r in static_challenges if r.expected_ids]

    total = len(results)
    total_static = len(with_patterns)
    detected_static = sum(1 for r in with_patterns if r.detected)
    all_tp = sum(len(r.true_positives) for r in with_patterns)
    all_expected = sum(len(r.expected_ids) for r in with_patterns)

    print("\n" + "=" * 70)
    print("CTF BENCHMARK REPORT — Paradigm CTF (2021 + 2022 + 2023)")
    print("=" * 70)
    print(f"\nTotal challenges:           {total}")
    print(f"Statically testable:        {total_static} (with expected ETH patterns)")
    print(f"Dynamic/Reversing only:     {len(dynamic_challenges)} (not statically detectable)")
    print(f"\nStatic detection rate:      {detected_static}/{total_static} "
          f"({100*detected_static//total_static if total_static else 0}%)")
    print(f"Pattern matches:            {all_tp}/{all_expected} "
          f"({100*all_tp//all_expected if all_expected else 0}%)")

    # Missed static challenges
    missed = [r for r in with_patterns if not r.detected]
    if missed:
        print("\n--- Missed Challenges (Static) ---")
        for r in missed:
            mapping = PARADIGM_CTF_MAP.get(r.contract, {})
            print(f"  {r.contract}: expected {r.expected_ids} — {mapping.get('description', '')}")
            if r.detected_ids:
                print(f"    detected: {r.detected_ids}")

    # By year
    print("\n--- Detection by Year ---")
    for year in [2021, 2022, 2023]:
        year_results = [r for r in with_patterns
                        if PARADIGM_CTF_MAP.get(r.contract, {}).get("year") == year]
        if not year_results:
            continue
        yr_detected = sum(1 for r in year_results if r.detected)
        yr_total = len(year_results)
        pct = 100 * yr_detected // yr_total if yr_total else 0
        bar = "#" * (pct // 5) + "." * (20 - pct // 5)
        print(f"  {year}  [{bar}] {yr_detected}/{yr_total} ({pct}%)")

    # By category
    print("\n--- Detection by Category ---")
    categories = {}
    for r in with_patterns:
        cat = PARADIGM_CTF_MAP.get(r.contract, {}).get("category", "Unknown")
        if cat not in categories:
            categories[cat] = {"total": 0, "detected": 0}
        categories[cat]["total"] += 1
        if r.detected:
            categories[cat]["detected"] += 1

    for cat, counts in sorted(categories.items()):
        pct = 100 * counts["detected"] // counts["total"] if counts["total"] else 0
        bar = "#" * (pct // 5) + "." * (20 - pct // 5)
        print(f"  {cat:<20} [{bar}] {counts['detected']}/{counts['total']} ({pct}%)")

    # Pattern coverage
    print("\n--- Pattern Coverage ---")
    all_detected_patterns = set()
    for r in with_patterns:
        all_detected_patterns.update(r.true_positives)
    all_expected_patterns = set()
    for r in with_patterns:
        all_expected_patterns.update(r.expected_ids)
    covered = all_detected_patterns & all_expected_patterns
    missing = all_expected_patterns - all_detected_patterns
    print(f"  Patterns tested:    {len(all_expected_patterns)}")
    print(f"  Patterns covered:   {len(covered)}")
    if missing:
        print(f"  Missing: {', '.join(sorted(missing))}")


def print_report(results: list[BenchmarkResult]):
    """Print benchmark summary report."""
    total = len(results)
    detected = sum(1 for r in results if r.detected)
    all_tp = sum(len(r.true_positives) for r in results)
    all_fn = sum(len(r.false_negatives) for r in results)
    all_expected = sum(len(r.expected_ids) for r in results)

    print("\n" + "=" * 70)
    print("CTF BENCHMARK REPORT — DeFiVulnLabs")
    print("=" * 70)
    print(f"\nContracts tested:    {total}")
    print(f"Contracts detected:  {detected}/{total} ({100*detected//total if total else 0}%)")
    print(f"Pattern matches:     {all_tp}/{all_expected} ({100*all_tp//all_expected if all_expected else 0}%)")
    print(f"False negatives:     {all_fn}")

    if any(not r.detected for r in results):
        print("\n--- Missed Contracts ---")
        for r in results:
            if not r.detected:
                mapping = DEFI_VULN_LABS_MAP.get(r.contract, {})
                print(f"  {r.contract}: expected {r.expected_ids} "
                      f"({mapping.get('description', '')})")

    # Coverage by category
    print("\n--- Coverage by Category ---")
    categories = {}
    for contract_file, mapping in DEFI_VULN_LABS_MAP.items():
        cat = mapping["category"]
        if cat not in categories:
            categories[cat] = {"total": 0, "detected": 0}
        categories[cat]["total"] += 1
        result = next((r for r in results if r.contract == contract_file), None)
        if result and result.detected:
            categories[cat]["detected"] += 1

    for cat, counts in sorted(categories.items()):
        pct = 100 * counts["detected"] // counts["total"] if counts["total"] else 0
        bar = "#" * (pct // 5) + "." * (20 - pct // 5)
        print(f"  {cat:<20} [{bar}] {counts['detected']}/{counts['total']} ({pct}%)")

    print("\n--- Scanner Pattern Coverage ---")
    all_detected_patterns = set()
    for r in results:
        all_detected_patterns.update(r.true_positives)
    all_expected_patterns = set()
    for mapping in DEFI_VULN_LABS_MAP.values():
        all_expected_patterns.update(mapping["eth_ids"])

    covered = all_detected_patterns & all_expected_patterns
    missing = all_expected_patterns - all_detected_patterns
    print(f"  Patterns tested:    {len(all_expected_patterns)}")
    print(f"  Patterns covered:   {len(covered)}")
    print(f"  Patterns missing:   {len(missing)}")
    if missing:
        print(f"  Missing: {', '.join(sorted(missing))}")


def print_dry_run():
    """Print the mapping without cloning or scanning."""
    print("=" * 70)
    print("CTF BENCHMARK — DeFiVulnLabs Pattern Mapping (dry run)")
    print("=" * 70)
    print(f"\n{'Contract':<30} {'ETH Pattern(s)':<20} {'Category':<18} Description")
    print("-" * 100)
    for contract, mapping in sorted(DEFI_VULN_LABS_MAP.items()):
        ids = ", ".join(mapping["eth_ids"])
        print(f"  {contract:<28} {ids:<18} {mapping['category']:<18} {mapping['description']}")

    print(f"\nTotal: {len(DEFI_VULN_LABS_MAP)} contracts mapped")
    unique_patterns = set()
    for m in DEFI_VULN_LABS_MAP.values():
        unique_patterns.update(m["eth_ids"])
    print(f"Unique ETH patterns: {len(unique_patterns)} — {', '.join(sorted(unique_patterns))}")

    print("\n--- Additional CTF Sources (not benchmarked) ---")
    for name, info in ADDITIONAL_CTF_SOURCES.items():
        print(f"  {name:<28} {info['count']:>5} challenges  {info['url']}")


def main():
    parser = argparse.ArgumentParser(
        description="CTF Benchmark — Validate SolidityGuard against CTF challenges"
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Show mapping without cloning/scanning")
    parser.add_argument("--paradigm", action="store_true",
                        help="Run Paradigm CTF benchmark (2021+2022+2023)")
    parser.add_argument("--all", action="store_true",
                        help="Run all benchmarks (DeFiVulnLabs + Paradigm CTF)")
    parser.add_argument("--repo-path", help="Path to existing DeFiVulnLabs clone")
    parser.add_argument("--output", help="Write JSON results to file")

    args = parser.parse_args()

    if args.dry_run:
        print_dry_run()
        return

    run_defi = not args.paradigm or args.all
    run_paradigm = args.paradigm or args.all

    all_results = {}

    # ── DeFiVulnLabs benchmark ──
    if run_defi:
        if args.repo_path:
            repo_path = args.repo_path
            if not os.path.isdir(repo_path):
                print(f"Error: {repo_path} does not exist")
                sys.exit(1)
        else:
            repo_path = os.path.join(tempfile.gettempdir(), "DeFiVulnLabs")
            if not os.path.isdir(repo_path):
                if not clone_repo(repo_path):
                    sys.exit(1)
            else:
                print(f"Using existing clone at {repo_path}")

        print(f"\nRunning DeFiVulnLabs benchmark against {repo_path}...")
        defi_results = run_benchmark(repo_path)
        print_report(defi_results)
        all_results["DeFiVulnLabs"] = defi_results

    # ── Paradigm CTF benchmark ──
    if run_paradigm:
        print("\n" + "=" * 70)
        print("PARADIGM CTF BENCHMARK")
        print("=" * 70)
        repo_paths = ensure_paradigm_repos()
        if repo_paths:
            print("\nRunning Paradigm CTF benchmark...")
            paradigm_results = run_paradigm_benchmark(repo_paths)
            print_paradigm_report(paradigm_results)
            all_results["ParadigmCTF"] = paradigm_results

    # ── Combined summary ──
    if args.all and len(all_results) > 1:
        print("\n" + "=" * 70)
        print("COMBINED BENCHMARK SUMMARY")
        print("=" * 70)
        for name, results in all_results.items():
            with_patterns = [r for r in results if r.expected_ids]
            detected = sum(1 for r in with_patterns if r.detected)
            total = len(with_patterns)
            tp = sum(len(r.true_positives) for r in with_patterns)
            expected = sum(len(r.expected_ids) for r in with_patterns)
            print(f"  {name:<20} Contracts: {detected}/{total} "
                  f"({100*detected//total if total else 0}%)  "
                  f"Patterns: {tp}/{expected} "
                  f"({100*tp//expected if expected else 0}%)")

    if args.output:
        output_data = {}
        for name, results in all_results.items():
            output_data[name] = {
                "total_contracts": len(results),
                "detected": sum(1 for r in results if r.detected),
                "results": [
                    {
                        "contract": r.contract,
                        "expected": r.expected_ids,
                        "detected": r.detected_ids,
                        "true_positives": r.true_positives,
                        "false_negatives": r.false_negatives,
                        "status": "PASS" if r.detected else "MISS",
                    }
                    for r in results
                ],
            }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"\nResults written to {args.output}")


if __name__ == "__main__":
    main()
