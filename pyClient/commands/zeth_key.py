# Copyright (c) 2015-2019 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.joinsplit import generate_zeth_address
from commands.constants import KEYFILE_DEFAULT
from commands.utils import \
    pub_key_file_name, write_zeth_address_secret, write_zeth_address_public
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
        raise ClickException(f"ZethAddress secret key file {key_file} exists")

    if exists(pub_key_file):
        raise ClickException(f"ZethAddress pub key file {pub_key_file} exists")

    zeth_address = generate_zeth_address()
    write_zeth_address_secret(zeth_address.addr_sk, key_file)
    print(f"ZethAddress Secret key written to {key_file}")
    write_zeth_address_public(zeth_address.addr_pk, pub_key_file)
    print(f"Public ZethAddress written to {pub_key_file}")
