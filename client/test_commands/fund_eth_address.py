#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.cli.constants import ETH_ADDRESS_DEFAULT, \
    ETH_NETWORK_FILE_DEFAULT, ETH_NETWORK_DEFAULT
from zeth.cli.utils import \
    get_eth_network, load_eth_address, EtherValue, open_web3_from_network
from click import command, option
from typing import Optional

FUND_AMOUNT_DEFAULT = 1000000


@command()
@option(
    "--eth-addr",
    help=f"Address or address filename (default: {ETH_ADDRESS_DEFAULT})")
@option("--source-addr", help="Address or address filename (optional)")
@option(
    "--eth-network",
    default=None,
    help="Ethereum RPC endpoint, network or config file "
    f"(default: '{ETH_NETWORK_FILE_DEFAULT}' if it exists, otherwise "
    f"'{ETH_NETWORK_DEFAULT}')")
@option(
    "--amount",
    type=int,
    default=FUND_AMOUNT_DEFAULT,
    help=f"Amount to fund (default: {FUND_AMOUNT_DEFAULT})")
def fund_eth_address(
        eth_network: Optional[str],
        eth_addr: Optional[str],
        source_addr: Optional[str],
        amount: int) -> None:
    """
    Fund an address. If no source address is given, the first hosted account on
    the RPC host is used.
    """
    eth_addr = load_eth_address(eth_addr)
    network = get_eth_network(eth_network)
    web3 = open_web3_from_network(network)

    if not source_addr:
        # Use the first hosted address.
        source_addr = web3.eth.accounts[0]  # pylint: disable=no-member

        if network.name == "autonity-helloworld":
            # The Autonity helloworld network supplies hosted accounts, secured
            # with the password 'test'. Attempt to unlock it.
            # pylint: disable=import-outside-toplevel, no-member
            from web3.middleware import geth_poa_middleware  # type: ignore
            web3.middleware_stack.inject(geth_poa_middleware, layer=0)
            web3.personal.unlockAccount(source_addr, "test")

    print(f"eth_addr = {eth_addr}")
    print(f"source_addr = {source_addr}")
    print(f"amount = {amount}")

    web3.eth.sendTransaction({  # pylint: disable=no-member
        "from": source_addr,
        "to": eth_addr,
        "value": EtherValue(amount).wei
    })


if __name__ == "__main__":
    fund_eth_address()  # pylint: disable=no-value-for-parameter
