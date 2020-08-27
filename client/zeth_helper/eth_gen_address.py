#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.cli.constants import ETH_ADDRESS_DEFAULT, ETH_PRIVATE_KEY_FILE_DEFAULT
from zeth.cli.utils import write_eth_private_key, write_eth_address
from zeth.core.utils import eth_address_from_private_key
from click import command, option
from web3 import Web3  # type: ignore
import os
import sys
from typing import Optional


@command()
@option("--eth-addr-file", help="Address output filename")
@option("--eth-private-key-file", help="Private key output filename")
def eth_gen_address(
        eth_addr_file: Optional[str],
        eth_private_key_file: Optional[str]) -> None:
    """
    Locally generate a new Ethereum private key and address file, and write
    them to the current directory.
    """
    sys.stderr.write(
        "*** WARNING: this address should not be used in production ***\n")

    eth_addr_file = eth_addr_file or ETH_ADDRESS_DEFAULT
    eth_private_key_file = eth_private_key_file or ETH_PRIVATE_KEY_FILE_DEFAULT

    eth_private_key = gen_eth_private_key()
    write_eth_private_key(eth_private_key, eth_private_key_file)
    eth_address = eth_address_from_private_key(eth_private_key)
    write_eth_address(eth_address, eth_addr_file)
    print(
        f"{eth_address}: written to {eth_addr_file}, "
        f"private key to {eth_private_key_file}")


def gen_eth_private_key() -> bytes:
    """
    Simple private key generation function. Not for production use.
    """
    return Web3.sha3(os.urandom(4096))
