# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from test_commands.mock import open_test_web3
from zeth.utils import EtherValue
from click import command, argument, option
from typing import List


@command()
@argument("addresses", nargs=-1)
@option(
    "--wei",
    is_flag=True,
    default=False,
    help="Display in Wei instead of Ether")
def get_balance(addresses: List[str], wei: bool) -> None:
    """
    Command to get the balance of specific addresses. Support multiple queries
    per invocation (outputs one per line), for efficiency.
    """
    _, eth = open_test_web3()
    for address in addresses:
        value = EtherValue(eth.getBalance(address), "wei")
        print((wei and value.wei) or value.ether())


if __name__ == "__main__":
    get_balance()  # pylint: disable=no-value-for-parameter
