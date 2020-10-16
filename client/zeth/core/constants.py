#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

"""
Constants used by zeth.  By convention lengths are given in bits as
`*_LENGTH` and the corresponding `*_LENGTH_BYTES` variable holds the size in
bytes (where this is meaningful).
"""

from typing import List


# Defined here instead of utils.py to avoid circular imports, since utils.py
# depends on some of the values defined here.
def bit_length_to_byte_length(bit_length: int) -> int:
    """
    Convert bit length to byte length
    """
    assert \
        bit_length >= 0 and bit_length % 8 == 0, \
        "Not valid bit_length inserted"
    return int(bit_length/8)


# GROTH16 constants
GROTH16_ZKSNARK: str = "GROTH16"
GROTH16_MIXER_CONTRACT: str = "Groth16Mixer"

# PGHR13 constants
PGHR13_ZKSNARK: str = "PGHR13"
PGHR13_MIXER_CONTRACT: str = "Pghr13Mixer"

# Set of valid snarks
VALID_ZKSNARKS: List[str] = [GROTH16_ZKSNARK, PGHR13_ZKSNARK]

# Merkle tree depth
ZETH_MERKLE_TREE_DEPTH: int = 32

# Nb of input notes
JS_INPUTS: int = 2

# Nb of output notes
JS_OUTPUTS: int = 2

# Gas cost estimates
DEPLOYMENT_GAS_WEI: int = ZETH_MERKLE_TREE_DEPTH * 250000

DEFAULT_MIX_GAS_WEI: int = DEPLOYMENT_GAS_WEI

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
PUBLIC_VALUE_LENGTH_BYTES: int = bit_length_to_byte_length(PUBLIC_VALUE_LENGTH)
PUBLIC_VALUE_MASK: int = (1 << PUBLIC_VALUE_LENGTH) - 1

# Number of residual bits when encoding digests into field values
DIGEST_RESIDUAL_BITS: int = max(0, DIGEST_LENGTH - FIELD_CAPACITY)

PHI_LENGTH: int = 256
PHI_LENGTH_BYTES: int = bit_length_to_byte_length(PHI_LENGTH)

APK_LENGTH: int = 256
APK_LENGTH_BYTES: int = bit_length_to_byte_length(APK_LENGTH)

RHO_LENGTH: int = 256
RHO_LENGTH_BYTES: int = bit_length_to_byte_length(RHO_LENGTH)

TRAPR_LENGTH: int = 256
TRAPR_LENGTH_BYTES: int = bit_length_to_byte_length(TRAPR_LENGTH)

NOTE_LENGTH: int = APK_LENGTH + PUBLIC_VALUE_LENGTH + RHO_LENGTH + TRAPR_LENGTH
NOTE_LENGTH_BYTES: int = bit_length_to_byte_length(NOTE_LENGTH)

# Public inputs are (see BaseMixer.sol):
#   [0                 ] - 1     x merkle root
#   [1                 ] - jsOut x commitment
#   [1 + jsOut         ] - jsIn  x nullifier (partial)
#   [1 + jsOut + jsIn  ] - 1     x hsig (partial)
#   [2 + jsOut + jsIn  ] - JsIn  x message auth tags (partial)
#   [2 + jsOut + 2*jsIn] - 1     x residual bits, v_in, v_out

# Index (in public inputs) of residual bits
RESIDUAL_BITS_INDEX: int = (2 * JS_INPUTS) + JS_OUTPUTS + 2

# Number of full-length digests to be encoded in public inputs
NUM_INPUT_DIGESTS: int = (2 * JS_INPUTS) + 1

# Total number of residual bits corresponding to digests in public inputs
TOTAL_DIGEST_RESIDUAL_BITS: int = NUM_INPUT_DIGESTS * DIGEST_RESIDUAL_BITS

# Solidity compiler version
SOL_COMPILER_VERSION: str = 'v0.5.16'

# Seed for MIMC
MIMC_MT_SEED: str = "clearmatics_mt_seed"

# Units for vpub_in and vpub_out, given in Wei. i.e.
#   Value (in Wei) = vpub_{in,out} * ZETH_PUBLIC_UNIT_VALUE
ZETH_PUBLIC_UNIT_VALUE: int = 1000000000000  # 1 Szabo (10^12 Wei).
