#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from typing import List

# GROTH16 constants
GROTH16_ZKSNARK: str = "GROTH16"
GROTH16_MIXER_CONTRACT: str = "Groth16Mixer"

# PGHR13 constants
PGHR13_ZKSNARK: str = "PGHR13"
PGHR13_MIXER_CONTRACT: str = "Pghr13Mixer"

# Set of valid snarks
VALID_ZKSNARKS: List[str] = [GROTH16_ZKSNARK, PGHR13_ZKSNARK]

# Default zk-snark
ZKSNARK_DEFAULT = GROTH16_ZKSNARK

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

# Number of residual bits when encoding digests into field values
DIGEST_RESIDUAL_BITS = max(0, DIGEST_LENGTH - FIELD_CAPACITY)

# Bits per public value (embedded into the 'residual bits" public input)
PUBLIC_VALUE_BITS = 64
PUBLIC_VALUE_BYTES = PUBLIC_VALUE_BITS >> 3
PUBLIC_VALUE_MASK = (1 << PUBLIC_VALUE_BITS) - 1

# Public inputs are (see BaseMixer.sol):
#   [0                 ] - 1     x merkle root
#   [1                 ] - jsOut x commitment
#   [1 + jsOut         ] - jsIn  x nullifier (partial)
#   [1 + jsOut + jsIn  ] - 1     x hsig (partial)
#   [2 + jsOut + jsIn  ] - JsIn  x message auth tags (partial)
#   [2 + jsOut + 2*jsIn] - 1     x residual bits, v_in, v_out

# Index (in public inputs) of residual bits
RESIDUAL_BITS_INDEX = (2 * JS_INPUTS) + JS_OUTPUTS + 2

# Number of full-length digests to be encoded in public inputs
NUM_INPUT_DIGESTS = (2 * JS_INPUTS) + 1

# Total number of residual bits corresponding to digests in public inputs
TOTAL_DIGEST_RESIDUAL_BITS = NUM_INPUT_DIGESTS * DIGEST_RESIDUAL_BITS

# Solidity compiler version
SOL_COMPILER_VERSION = 'v0.5.16'

# Seed for MIMC
MIMC_MT_SEED: str = "clearmatics_mt_seed"

# Units for vpub_in and vpub_out, given in Wei. i.e.
#   Value (in Wei) = vpub_{in,out} * ZETH_PUBLIC_UNIT_VALUE
ZETH_PUBLIC_UNIT_VALUE = 1000000000000  # 1 Szabo (10^12 Wei).

COMMITMENT_VALUE_PADDING = bytes(int(192/8))

# Key Derivation Tag "ZethEnc" utf-8 encoding
KDF_TAG: bytes = b'ZethEnc'

# Note constants
APK_LENGTH: int = 256
NOTE_VALUE_LENGTH: int = 64
RHO_LENGTH: int = 256
TRAPR_LENGTH: int = 384
NOTE_LENGTH: int = 960

# Encryption constants length in bits
EC_PRIVATE_KEY_LENGTH: int = 256
EC_PUBLIC_KEY_LENGTH: int = 256
SYM_KEY_LENGTH: int = 256
MAC_KEY_LENGTH: int = 256
TAG_LENGTH: int = 128
KEY_MATERIAL: int = SYM_KEY_LENGTH + MAC_KEY_LENGTH
SYM_NONCE_LENGTH: int = 128

# Encryption constants values
SYM_NONCE_VALUE: int = 0
