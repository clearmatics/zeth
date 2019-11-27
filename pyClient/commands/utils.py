from commands.constants import WALLET_USERNAME
from zeth.constants import ZETH_MERKLE_TREE_DEPTH
from zeth.contracts import \
    InstanceDescription, contract_instance, contract_description, \
    get_block_number, get_mix_results, eth
from zeth.joinsplit import \
    ZethAddressPub, ZethAddressPriv, ZethAddress, ZethClient, from_zeth_units
from zeth.utils import short_commitment
from zeth.wallet import ZethNoteDescription, Wallet
from click import ClickException, Context
from os.path import exists
from typing import Optional, Any


def load_zeth_instance(ctx: Context) -> Any:
    """
    Load the mixer instance ID from a file
    """
    instance_file = ctx.obj["INSTANCE_FILE"]
    with open(instance_file, "r") as instance_f:
        instance_desc = InstanceDescription.from_json(instance_f.read())
    return contract_instance(instance_desc)


def write_zeth_instance(zeth_instance: Any, instance_file: str) -> None:
    """
    Write the mixer instance ID to a file
    """
    with open(instance_file, "w") as instance_f:
        instance_f.write(contract_description(zeth_instance).to_json())


def load_zeth_address_public(ctx: Context) -> ZethAddressPub:
    """
    Load a ZethAddressPub from a key file.
    """
    secret_key_file = ctx.obj["KEY_FILE"]
    key_file = pub_key_file_name(secret_key_file)
    with open(key_file, "r") as pub_key_f:
        return ZethAddressPub.parse(pub_key_f.read())


def write_zeth_address_public(
        pub_key: ZethAddressPub, key_file: str) -> None:
    """
    Write a ZethAddressPub to a file
    """
    with open(key_file, "w") as pub_key_f:
        pub_key_f.write(str(pub_key))


def load_zeth_address_secret(ctx: Context) -> ZethAddressPriv:
    """
    Read ZethAddressPriv
    """
    key_file = ctx.obj["KEY_FILE"]
    with open(key_file, "r") as key_f:
        return ZethAddressPriv.from_json(key_f.read())


def write_zeth_address_secret(
        secret_key: ZethAddressPriv, key_file: str) -> None:
    """
    Write ZethAddressPriv to file
    """
    with open(key_file, "w") as key_f:
        key_f.write(secret_key.to_json())


def load_zeth_address(ctx: Context) -> ZethAddress:
    """
    Load a ZethAddress secret from a file, and the associated public address,
    and return as a ZethAddress.
    """
    return ZethAddress.from_secret_public(
        load_zeth_address_secret(ctx),
        load_zeth_address_public(ctx))


def open_wallet(
        mixer_instance: Any,
        js_secret: ZethAddressPriv,
        ctx: Context) -> Wallet:
    """
    Load a wallet using a secret key.
    """
    wallet_dir = ctx.obj["WALLET_DIR"]
    return Wallet(mixer_instance, WALLET_USERNAME, wallet_dir, js_secret.k_sk)


def do_sync(
        mixer_instance: Any,
        wallet: Wallet,
        wait_tx: Optional[str]) -> int:
    """
    Implementation of sync, reused by several commands.  Returns the
    block_number synced to.
    """
    def _do_sync() -> int:
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
        return chain_block_number

    # Do a sync upfront (it would be a waste of time to wait for a tx before
    # syncing, as it can take time to traverse all blocks).  Then wait for a tx
    # if requested, and sync again.

    if wait_tx:
        _do_sync()
        eth.waitForTransactionReceipt(wait_tx, 10000)

    return _do_sync()


def pub_key_file_name(key_file: str) -> str:
    """
    The name of a public key file, given the secret key file.
    """
    return key_file + ".pub"


def find_pub_key_file(base_file: str) -> str:
    """
    Given a file name, which could point to a private or public key file, guess
    at the name of the public key file.
    """
    pub_key_file = pub_key_file_name(base_file)
    if exists(pub_key_file):
        return pub_key_file
    if exists(base_file):
        return base_file

    raise ClickException(f"No public key file {pub_key_file} or {base_file}")


def create_zeth_client(ctx: Context) -> ZethClient:
    """
    Create a ZethClient for an existing deployment, given all appropriate
    information.
    """
    mixer_instance = load_zeth_instance(ctx)
    prover_client = ctx.obj["PROVER_CLIENT"]
    zksnark = ctx.obj["ZKSNARK"]
    return ZethClient.open(
        prover_client,
        ZETH_MERKLE_TREE_DEPTH,
        mixer_instance,
        zksnark)


def zeth_note_short(note_desc: ZethNoteDescription) -> str:
    """
    Generate a short human-readable description of a commitment.
    """
    value = from_zeth_units(int(note_desc.note.value, 16)).ether()
    cm = short_commitment(note_desc.commitment)
    return f"{cm}: value={value} ETH, addr={note_desc.address}"
