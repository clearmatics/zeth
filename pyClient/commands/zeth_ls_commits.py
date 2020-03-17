# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from commands.utils import \
    create_zeth_client_and_mixer_desc, load_zeth_address, open_wallet
from zeth.utils import short_commitment
from click import Context, command, pass_context


@command()
@pass_context
def ls_commits(ctx: Context) -> None:
    """
    List all commitments in the joinsplit contract
    """
    zeth_client, _mixer_desc = create_zeth_client_and_mixer_desc(ctx)
    zeth_address = load_zeth_address(ctx)
    wallet = open_wallet(zeth_client.mixer_instance, zeth_address.addr_sk, ctx)
    print("COMMITMENTS:")
    for commit in wallet.merkle_tree.get_leaves():
        print(f"  {short_commitment(commit)}")
