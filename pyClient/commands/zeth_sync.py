from commands.constants import KEYFILE_DEFAULT, WALLET_DIR_DEFAULT
from commands.utils import \
    load_zeth_instance, load_zeth_address_secret, do_sync
from click import command, option, pass_context
from typing import Optional, Any


@command()
@option(
    "--key-file",
    default=KEYFILE_DEFAULT,
    help=f"Zeth keyfile (\"{KEYFILE_DEFAULT}\")")
@option(
    "--wallet-dir",
    default=WALLET_DIR_DEFAULT,
    help=f"Zeth wallet dir")
@option("--wait-tx", help="Wait for tx hash")
@pass_context
def sync(
        ctx: Any,
        key_file: str,
        wallet_dir: str,
        wait_tx: Optional[str]) -> None:
    """
    Attempt to retrieve new notes for the key in <key-file>
    """
    mixer_instance = load_zeth_instance(ctx.obj["INSTANCE_FILE"])
    js_secret = load_zeth_address_secret(key_file)
    chain_block_number = do_sync(mixer_instance, js_secret, wallet_dir, wait_tx)
    print(f"SYNCED to {chain_block_number}")
