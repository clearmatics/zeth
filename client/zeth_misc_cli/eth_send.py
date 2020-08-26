#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth_cli.constants import ETH_ADDRESS_DEFAULT, ETH_PRIVATE_KEY_FILE_DEFAULT
from zeth_cli.utils import \
    get_eth_network, load_eth_address, EtherValue, open_web3_from_network, \
    load_eth_private_key
from click import command, option, pass_context, argument, ClickException
from typing import Optional, Any

FUND_AMOUNT_DEFAULT = 1000000


@command()
@option(
    "--eth-addr",
    help=f"Source address or filename (default: {ETH_ADDRESS_DEFAULT})")
@option(
    "--eth-private-key",
    help=f"Source private key file (default: {ETH_PRIVATE_KEY_FILE_DEFAULT})")
@option(
    "--amount",
    type=str,
    default=FUND_AMOUNT_DEFAULT,
    help=f"Amount to fund in Ether (default: {FUND_AMOUNT_DEFAULT})")
@argument("dest-addr")
@pass_context
def eth_send(
        ctx: Any,
        dest_addr: str,
        eth_private_key: Optional[str],
        eth_addr: Optional[str],
        amount: str) -> None:
    """
    Send Ether from the local eth-addr to a destination address.
    """
    dest_addr = load_eth_address(dest_addr)
    eth_private_key_data = load_eth_private_key(eth_private_key)
    eth_addr = load_eth_address(eth_addr)
    eth_network = get_eth_network(ctx.obj["eth_network"])
    web3 = open_web3_from_network(eth_network)

    if eth_private_key_data is None:
        raise ClickException("hosted accounts are not supported")

    print(f"eth_addr = {eth_addr}")
    print(f"dest_addr = {dest_addr}")
    print(f"amount = {amount}")

    # pylint: disable=no-member
    send_tx_desc = {
        "from": eth_addr,
        "to": dest_addr,
        "value": EtherValue(amount).wei,
        "gasPrice": web3.eth.gasPrice,
        "nonce": web3.eth.getTransactionCount(eth_addr)
    }
    send_tx_desc["gas"] = web3.eth.estimateGas(send_tx_desc)

    signed_tx = web3.eth.account.signTransaction(
        send_tx_desc, eth_private_key_data)

    tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
    # pylint: enable=no-member

    print(tx_hash.hex())
