#!/usr/bin/env python3

# Copyright (c) 2015-2019 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from typing import List

# DEPLOYMENT GAS
DEPLOYMENT_GAS_WEI: int = 4000000

# GROTH16 constants
GROTH16_ZKSNARK: str = "GROTH16"
GROTH16_VERIFIER_CONTRACT: str = "Groth16Verifier"
GROTH16_MIXER_CONTRACT: str = "Groth16Mixer"

# PGHR13 constants
PGHR13_ZKSNARK: str = "PGHR13"
PGHR13_VERIFIER_CONTRACT: str = "Pghr13Verifier"
PGHR13_MIXER_CONTRACT: str = "Pghr13Mixer"

# Set of valid snarks
VALID_ZKSNARKS: List[str] = [GROTH16_ZKSNARK, PGHR13_ZKSNARK]

# OTSCHNORR constants
SCHNORR_VERIFIER_CONTRACT: str = "OTSchnorrVerifier"

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
