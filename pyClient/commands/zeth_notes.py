from commands.utils import \
    open_web3_from_ctx, load_zeth_instance, load_zeth_address_secret, open_wallet
from click import command, pass_context
from typing import Any


@command()
@pass_context
def notes(ctx: Any) -> None:
    """
    List the set of notes owned by this wallet
    """
    web3 = open_web3_from_ctx(ctx)
    mixer_instance = load_zeth_instance(ctx, web3)
    js_secret = load_zeth_address_secret(ctx)
    wallet = open_wallet(mixer_instance, js_secret, ctx)
    for addr, short_commit, value in wallet.note_summaries():
        print(f"{short_commit}: value={value.ether()}, addr={addr}")
