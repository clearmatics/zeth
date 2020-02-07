# Copyright (c) 2015-2019 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from commands.utils import open_merkle_tree
from zeth.utils import short_commitment
from click import Context, command, pass_context


@command()
@pass_context
def ls_commits(ctx: Context) -> None:
    """
    List all commitments in the joinsplit contract
    """
    merkle_tree = open_merkle_tree(ctx)
    print("COMMITMENTS:")
    for commit in merkle_tree.get_leaves():
        print(f"  {short_commitment(commit)}")
