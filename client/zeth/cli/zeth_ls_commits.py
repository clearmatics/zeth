# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.cli.utils import \
    create_mixer_client_and_mixer_desc, load_zeth_address, open_wallet
from zeth.core.utils import short_commitment
from click import Context, command, pass_context


@command()
@pass_context
def ls_commits(ctx: Context) -> None:
    """
    List all commitments in the Zeth mixer contract
    """
    client_ctx = ctx.obj
    zeth_client, _mixer_desc = create_mixer_client_and_mixer_desc(client_ctx)
    zeth_address = load_zeth_address(client_ctx)
    wallet = open_wallet(
        zeth_client.mixer_instance, zeth_address.addr_sk, client_ctx)
    print("COMMITMENTS:")
    for commit in wallet.merkle_tree.get_leaves():
        print(f"  {short_commitment(commit)}")
