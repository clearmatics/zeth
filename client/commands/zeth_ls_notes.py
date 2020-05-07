# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from commands.utils import open_web3_from_ctx, load_zeth_address_secret, \
    open_wallet, load_mixer_description_from_ctx
from zeth.utils import EtherValue
from click import Context, command, option, pass_context


@command()
@option("--balance", is_flag=True, help="Show total balance")
@option("--spent", is_flag=True, help="Show spent notes")
@pass_context
def ls_notes(ctx: Context, balance: bool, spent: bool) -> None:
    """
    List the set of notes owned by this wallet
    """
    client_ctx = ctx.obj
    web3 = open_web3_from_ctx(client_ctx)
    mixer_desc = load_mixer_description_from_ctx(client_ctx)
    mixer_instance = mixer_desc.mixer.instantiate(web3)
    js_secret = load_zeth_address_secret(client_ctx)
    wallet = open_wallet(mixer_instance, js_secret, client_ctx)

    total = EtherValue(0)
    for addr, short_commit, value in wallet.note_summaries():
        print(f"{short_commit}: value={value.ether()}, addr={addr}")
        total = total + value

    if balance:
        print(f"TOTAL BALANCE: {total.ether()}")

    if not spent:
        return

    print("SPENT NOTES:")
    for addr, short_commit, value in wallet.spent_note_summaries():
        print(f"{short_commit}: value={value.ether()}, addr={addr}")
