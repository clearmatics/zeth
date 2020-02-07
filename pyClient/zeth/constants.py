#!/usr/bin/env python3

# Copyright (c) 2015-2019 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from typing import List

# DEPLOYMENT GAS
DEPLOYMENT_GAS_WEI: int = 4000000

# GROTH16 constants
GROTH16_ZKSNARK: str = "GROTH16"
GROTH16_MIXER_CONTRACT: str = "Groth16Mixer"

# PGHR13 constants
PGHR13_ZKSNARK: str = "PGHR13"
PGHR13_MIXER_CONTRACT: str = "Pghr13Mixer"

# Set of valid snarks
VALID_ZKSNARKS: List[str] = [GROTH16_ZKSNARK, PGHR13_ZKSNARK]

# Merkle tree depth
ZETH_MERKLE_TREE_DEPTH: int = 4

# Nb of input notes
JS_INPUTS: int = 2

# Nb of output notes
JS_OUTPUTS: int = 2

# Order of the largest prime order subgroup of the elliptic curve group.  See:
# https://github.com/ethereum/go-ethereum/blob/master/crypto/bn256/cloudflare/constants.go#L23
# # noqa
ZETH_PRIME: int = \
    21888242871839275222246405745257275088548364400416034343698204186575808495617

# Field capacity (=floor(log_2(ZETH_PRIME)))
FIELD_CAPACITY: int = 253

# Hash digest length (for commitment and PRFs)
DIGEST_LENGTH: int = 256

# Public value length (v_pub_in and v_pub_out)
PUBLIC_VALUE_LENGTH: int = 64

# Solidity compiler version
SOL_COMPILER_VERSION = 'v0.5.16'

# Seed for MIMC
MIMC_MT_SEED: str = "clearmatics_mt_seed"
