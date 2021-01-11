# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.cli.utils import load_contract_address
from click import command, argument


@command()
@argument("instance-file")
def eth_get_contract_address(instance_file: str) -> None:
    """
    Extract the address from a contract instance description file.
    """
    print(load_contract_address(instance_file))
