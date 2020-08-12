#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from commands.constants import ETH_RPC_ENDPOINT_DEFAULT
from commands.utils import load_eth_address, EtherValue
from zeth.utils import open_web3
from click import command, option
from typing import Optional


@command()
@option(
    "--eth-rpc",
    default=ETH_RPC_ENDPOINT_DEFAULT,
    help="Ethereum rpc end-point")
@option("--eth-addr", help="Address or address filename")
@option("--source-addr", help="Address or address filename")
@option("--amount", type=int, default=1000000, help="Amount to fund")
def fund_eth_address(
        eth_rpc: str,
        eth_addr: Optional[str],
        source_addr: Optional[str],
        amount: int) -> None:
    """
    Fund an address from an unlocked account. If no source address is given,
    the first account is used.
    """
    eth_addr = load_eth_address(eth_addr)
    web3 = open_web3(eth_rpc)
    source_addr = source_addr or web3.eth.accounts[0]  # pylint: disable=no-member

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
