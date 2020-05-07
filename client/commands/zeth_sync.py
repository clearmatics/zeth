# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from commands.utils import open_web3_from_ctx, load_zeth_address_secret, \
    open_wallet, do_sync, load_mixer_description_from_ctx, zeth_note_short_print
from click import command, option, pass_context, Context
from typing import Optional


@command()
@option("--wait-tx", help="Wait for tx hash")
@pass_context
def sync(ctx: Context, wait_tx: Optional[str]) -> None:
    """
    Attempt to retrieve new notes for the key in <key-file>
    """
    client_ctx = ctx.obj
    web3 = open_web3_from_ctx(client_ctx)
    mixer_desc = load_mixer_description_from_ctx(client_ctx)
    mixer_instance = mixer_desc.mixer.instantiate(web3)
    js_secret = load_zeth_address_secret(client_ctx)
    wallet = open_wallet(mixer_instance, js_secret, client_ctx)
    chain_block_number = do_sync(web3, wallet, wait_tx, zeth_note_short_print)
    print(f"SYNCED to {chain_block_number}")
