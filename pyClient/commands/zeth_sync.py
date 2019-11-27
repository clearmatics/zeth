from commands.utils import \
    load_zeth_instance, load_zeth_address_secret, open_wallet, do_sync
from click import command, option, pass_context
from typing import Optional, Any


@command()
@option("--wait-tx", help="Wait for tx hash")
@pass_context
def sync(ctx: Any, wait_tx: Optional[str]) -> None:
    """
    Attempt to retrieve new notes for the key in <key-file>
    """
    mixer_instance = load_zeth_instance(ctx)
    js_secret = load_zeth_address_secret(ctx)
    wallet = open_wallet(mixer_instance, js_secret, ctx)
    chain_block_number = do_sync(mixer_instance, wallet, wait_tx)
    print(f"SYNCED to {chain_block_number}")
