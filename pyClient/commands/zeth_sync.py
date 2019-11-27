from commands.constants import KEYFILE_DEFAULT, WALLET_DIR_DEFAULT
from commands.utils import load_zeth_instance, open_wallet, zeth_note_short
from zeth.contracts import get_block_number, get_mix_results
from click import command, option, pass_context
from typing import Any


@command()
@option(
    "--key-file",
    default=KEYFILE_DEFAULT,
    help=f"Zeth keyfile (\"{KEYFILE_DEFAULT}\")")
@option(
    "--wallet-dir",
    default=WALLET_DIR_DEFAULT,
    help=f"Zeth wallet dir")
@pass_context
def sync(ctx: Any, key_file: str, wallet_dir: str) -> None:
    """
    Attempt to retrieve new notes for the key in <key-file>
    """
    mixer_instance = load_zeth_instance(ctx.obj["INSTANCE_FILE"])
    wallet = open_wallet(mixer_instance, key_file, wallet_dir)
    wallet_next_block = wallet.get_next_block()
    chain_block_number: int = get_block_number()

    if chain_block_number >= wallet_next_block:
        print(f"SYNCHING blocks ({wallet_next_block} - {chain_block_number})")
        for mix_result in get_mix_results(
                mixer_instance, wallet_next_block, chain_block_number):
            for note_desc in wallet.receive_notes(
                    mix_result.encrypted_notes, mix_result.sender_k_pk):
                print(f" NEW NOTE: {zeth_note_short(note_desc)}")
        wallet.set_next_block(chain_block_number + 1)

    print(f"SYNCED to {chain_block_number}")
