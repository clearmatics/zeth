# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+


"""
Constants and defaults specific to the CLI interface.
"""

ETH_RPC_ENDPOINT_DEFAULTS = {
    "ganache": "http://localhost:8545",
    "autonity-helloworld": "http://localhost:8541",
}

ETH_NETWORK_FILE_DEFAULT = "eth-network"
ETH_NETWORK_DEFAULT = "ganache"
PROVER_SERVER_ENDPOINT_DEFAULT = "localhost:50051"

# Note that these must satisfy:
#   ZETH_PUBLIC_ADDRESS_FILE_DEFAULT == \
#     commands.utils.find_pub_address_file(ZETH_SECRET_ADDRESS_FILE_DEFAULT)
ZETH_SECRET_ADDRESS_FILE_DEFAULT = "zeth-address.priv"
ZETH_PUBLIC_ADDRESS_FILE_DEFAULT = "zeth-address.pub"

INSTANCE_FILE_DEFAULT = "zeth-instance"
ETH_ADDRESS_DEFAULT = "eth-address"
ETH_PRIVATE_KEY_FILE_DEFAULT = "eth-private-key"

PROVER_CONFIGURATION_FILE_DEFAULT = "prover-config.cache"

WALLET_DIR_DEFAULT = "./wallet"
WALLET_USERNAME = "zeth"
