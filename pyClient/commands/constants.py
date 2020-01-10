# Copyright (c) 2015-2019 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+


"""
Constants and defaults specific to the CLI interface.
"""

from zeth.constants import GROTH16_ZKSNARK


ZKSNARK_DEFAULT = GROTH16_ZKSNARK
ETH_RPC_ENDPOINT_DEFAULT = "http://localhost:8545"
PROVER_SERVER_ENDPOINT_DEFAULT = "localhost:50051"

ADDRESSFILE_DEFAULT = "zeth-address.json"
INSTANCEFILE_DEFAULT = "zeth-instance.json"
ETH_ADDRESS_DEFAULT = "eth-address"

WALLET_DIR_DEFAULT = "./notes"
WALLET_USERNAME = "zeth"

MERKLE_TREE_FILE_DEFAULT = "./merkle_tree"
