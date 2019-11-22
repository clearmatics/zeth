from zeth.joinsplit import generate_joinsplit_keypair
from commands.constants import KEYFILE_DEFAULT
from commands.utils import \
    pub_key_file_name, write_joinsplit_secret_key, write_joinsplit_public_key
from click import command, option, pass_context, ClickException
from typing import Any
from os.path import exists


@command()
@option("--key-file", default=KEYFILE_DEFAULT)
@pass_context
def key(ctx: Any, key_file: str) -> None:
    """
    Generate a new Zeth secret key and public address
    """
    pub_key_file = pub_key_file_name(key_file)
    if exists(key_file):
        raise ClickException(f"key file {key_file} exists")

    if exists(pub_key_file):
        raise ClickException(f"pub key file {pub_key_file} exists")

    joinsplit_keypair = generate_joinsplit_keypair()
    write_joinsplit_secret_key(joinsplit_keypair.addr_sk, key_file)
    print(f"Secret key written to {key_file}")
    write_joinsplit_public_key(joinsplit_keypair.addr_pk, pub_key_file)
    print(f"Public key written to {pub_key_file}")
