from commands.utils import \
    load_zeth_instance, load_zeth_address_secret, open_wallet
from click import command, pass_context
from typing import Any


@command()
@pass_context
def notes(ctx: Any) -> None:
    """
    List the set of notes owned by this wallet
    """
    mixer_instance = load_zeth_instance(ctx)
    js_secret = load_zeth_address_secret(ctx)
    wallet = open_wallet(mixer_instance, js_secret, ctx)
    for addr, short_commit, value in wallet.note_summaries():
        print(f"{short_commit}: value={value.ether()}, addr={addr}")
