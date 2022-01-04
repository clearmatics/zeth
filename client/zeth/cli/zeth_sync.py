# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.cli.utils import open_web3_from_ctx, create_prover_client, \
    load_zeth_address_secret, open_wallet, do_sync, \
    load_mixer_description_from_ctx, zeth_note_short_print
from click import command, option, pass_context, Context
from typing import Optional


@command()
@option("--wait-tx", help="Wait for tx hash")
@option("--batch-size", type=int, help="Override blocks per query")
@pass_context
def sync(ctx: Context, wait_tx: Optional[str], batch_size: Optional[int]) -> None:
    """
    Attempt to retrieve new notes for the key in <key-file>
    """
    client_ctx = ctx.obj
    web3 = open_web3_from_ctx(client_ctx)
    mixer_desc = load_mixer_description_from_ctx(client_ctx)
    mixer_instance = mixer_desc.mixer.instantiate(web3)
    js_secret = load_zeth_address_secret(client_ctx)
    wallet = open_wallet(mixer_instance, js_secret, client_ctx)
    prover_client = create_prover_client(client_ctx)
    pp = prover_client.get_configuration().pairing_parameters
    chain_block_number = do_sync(
        web3, wallet, pp, wait_tx, zeth_note_short_print, batch_size)
    print(f"SYNCED to {chain_block_number}")
