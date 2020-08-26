# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth_cli.constants import ETH_ADDRESS_DEFAULT
from zeth_cli.utils import \
    load_eth_address, get_eth_network, open_web3_from_network
from core.utils import EtherValue
from click import command, option, pass_context
from typing import Optional, Any


@command()
@option(
    "--eth-addr",
    help=f"Address or address filename (default: {ETH_ADDRESS_DEFAULT})")
@option(
    "--wei",
    is_flag=True,
    default=False,
    help="Display in Wei instead of Ether")
@pass_context
def eth_get_balance(ctx: Any, eth_addr: Optional[str], wei: bool) -> None:
    """
    Command to get the balance of specific addresses. Support multiple queries
    per invocation (outputs one per line), for efficiency.
    """
    eth_addr = load_eth_address(eth_addr)
    web3 = open_web3_from_network(get_eth_network(ctx.obj["eth_network"]))
    balance_wei = web3.eth.getBalance(eth_addr)  # pylint: disable=no-member
    if wei:
        print(balance_wei)
    else:
        print(EtherValue(balance_wei, "wei").ether())
