# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.zeth_address import generate_zeth_address
from commands.utils import get_zeth_address_file, pub_address_file, \
    write_zeth_address_secret, write_zeth_address_public
from click import command, pass_context, ClickException, Context
from os.path import exists


@command()
@pass_context
def gen_address(ctx: Context) -> None:
    """
    Generate a new Zeth secret key and public address
    """
    client_ctx = ctx.obj
    addr_file = get_zeth_address_file(client_ctx)
    if exists(addr_file):
        raise ClickException(f"ZethAddress file {addr_file} exists")

    pub_addr_file = pub_address_file(addr_file)
    if exists(pub_addr_file):
        raise ClickException(f"ZethAddress pub file {pub_addr_file} exists")

    zeth_address = generate_zeth_address()
    write_zeth_address_secret(zeth_address.addr_sk, addr_file)
    print(f"ZethAddress Secret key written to {addr_file}")
    write_zeth_address_public(zeth_address.addr_pk, pub_addr_file)
    print(f"Public ZethAddress written to {pub_addr_file}")
