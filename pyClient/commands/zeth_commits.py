from commands.utils import open_web3_from_ctx, load_zeth_instance
from zeth.contracts import get_commitments
from zeth.utils import short_commitment
from click import command, pass_context
from typing import Any


@command()
@pass_context
def commits(ctx: Any) -> None:
    """
    List all commitments in the joinsplit contract
    """
    web3 = open_web3_from_ctx(ctx)
    zeth_instance = load_zeth_instance(ctx, web3)
    null = bytes(32)
    print("COMMITMENTS:")
    for commit in get_commitments(zeth_instance):
        if commit == null:
            return
        print(f"  {short_commitment(commit)}")
