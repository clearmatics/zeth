#!/usr/bin/env python3

# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.cli.constants import ETH_NETWORK_FILE_DEFAULT, ETH_NETWORK_DEFAULT
from zeth.cli.utils import NetworkConfig, get_eth_network
from click import command, option, argument
from typing import Optional


@command()
@argument("eth-network", default=ETH_NETWORK_DEFAULT)
@option("--eth-rpc-endpoint", help="(Optional) Override endpoint URL.")
@option(
    "--eth-rpc-certificate",
    help="(Optional) Path to TLS certificate for endpoint")
@option(
    "--eth-rpc-insecure",
    is_flag=True,
    help="(Optional) Skip TLS certificate checks")
@option(
    "--output-file",
    default=ETH_NETWORK_FILE_DEFAULT,
    help=f"Output filename (default: {ETH_NETWORK_FILE_DEFAULT})")
def eth_gen_network_config(
        eth_network: str,
        eth_rpc_endpoint: Optional[str],
        eth_rpc_certificate: Optional[str],
        eth_rpc_insecure: bool,
        output_file: str) -> None:
    """
    Generate a network config file. ETH_NETWORK is a network name or
    pre-existing network config file.

    Examples:

    \b
        # Write default config for "ganache" to the default file
        $ zeth-helper eth-gen-network-config ganache

    \b
        # Write "geth" config with a custom endpoint to default file
        $ zeth-helper eth-gen-network-config geth \\
            --eth-rpc-endpoint http://localhost:8080

    \b
        # Write a custom https endpoint to file, specifying the certificate
        $ zeth-helper eth-gen-network-config \\
            my-network \\
            --eth-rpc-endpoint https://rpc.my-network.io:8545 \\
            --eth-rpc-certificate rpc.my-network.io.crt

    \b
        # Write default network and endpoint to file "default-network"
        $ zeth-helper eth-gen-network-config --output-file default-network
    """

    if eth_rpc_endpoint is not None:
        network = NetworkConfig(
            name=eth_network,
            endpoint=eth_rpc_endpoint,
            certificate=eth_rpc_certificate,
            insecure=eth_rpc_insecure)
    else:
        network = get_eth_network(eth_network)

    network_json = network.to_json()
    print(f"network: {network_json}")

    with open(output_file, "w") as eth_network_f:
        eth_network_f.write(network_json)
    print(f"written to \"{output_file}\"")
