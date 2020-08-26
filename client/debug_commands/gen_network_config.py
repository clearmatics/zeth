#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from commands.constants import ETH_NETWORK_FILE_DEFAULT, ETH_NETWORK_DEFAULT
from commands.utils import NetworkConfig, get_eth_network
from click import command, option, argument
from typing import Optional


@command()
@argument("eth-network", default=ETH_NETWORK_DEFAULT)
@option("--eth-rpc-endpoint", help="(Optional) Override endpoint URL.")
@option(
    "--output-file",
    default=ETH_NETWORK_FILE_DEFAULT,
    help=f"Output filename (default: {ETH_NETWORK_FILE_DEFAULT})")
def generate_network_config(
        eth_network: str,
        eth_rpc_endpoint: Optional[str],
        output_file: str) -> None:
    """
    Generate a network config file. ETH_NETWORK is a network name or
    pre-existing network config file.

    Examples:

    \b
        # Write default config for "ganache" to the default file
        $ zeth_debug generate_network_config ganache

    \b
        # Write "geth" config with a custom endpoint to default file
        $ zeth_debug generate_network_config geth \\
            --eth-rpc-endpoint http://localhost:8080

    \b
        # Write default network and endpoint to file "default-network"
        $ zeth_debug generate_network_config --output-file default-network
    """

    if eth_rpc_endpoint is not None:
        network = NetworkConfig(eth_network, eth_rpc_endpoint)
    else:
        network = get_eth_network(eth_network)

    network_json = network.to_json()
    print(f"network: {network_json}")

    with open(output_file, "w") as eth_network_f:
        eth_network_f.write(network_json)
    print(f"written to \"{output_file}\"")
