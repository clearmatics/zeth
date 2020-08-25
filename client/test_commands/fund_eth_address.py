#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from commands.constants import ETH_ADDRESS_DEFAULT
from commands.utils import \
    get_eth_network, load_eth_address, EtherValue, open_web3_from_network
from click import command, option, pass_context
from typing import Optional, Any

FUND_AMOUNT_DEFAULT = 1000000


@command()
@option(
    "--eth-addr",
    help=f"Address or address filename (default: {ETH_ADDRESS_DEFAULT})")
@option("--source-addr", help="Address or address filename (optional)")
@option(
    "--amount",
    type=int,
    default=FUND_AMOUNT_DEFAULT,
    help=f"Amount to fund (default: {FUND_AMOUNT_DEFAULT})")
@pass_context
def fund_eth_address(
        ctx: Any,
        eth_addr: Optional[str],
        source_addr: Optional[str],
        amount: int) -> None:
    """
    Fund an address. If no source address is given, the first hosted account on
    the RPC host is used.
    """
    eth_addr = load_eth_address(eth_addr)
    eth_network = get_eth_network(ctx.obj["eth_network"])
    web3 = open_web3_from_network(eth_network)

    if not source_addr:
        # Use the first hosted address.
        source_addr = web3.eth.accounts[0]  # pylint: disable=no-member

    print(f"eth_addr = {eth_addr}")
    print(f"source_addr = {source_addr}")
    print(f"amount = {amount}")

    web3.eth.sendTransaction({  # pylint: disable=no-member
        "from": source_addr,
        "to": eth_addr,
        "value": EtherValue(amount).wei
    })
