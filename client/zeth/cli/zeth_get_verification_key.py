# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from click import command, option, Context, pass_context

from zeth.core.zksnark import get_zksnark_provider
from zeth.cli.utils import create_prover_client
import json
from typing import Optional


@command()
@option("--vk-out", "-o", help="Output file")
@pass_context
def get_verification_key(ctx: Context, vk_out: Optional[str]) -> None:
    """
    Command help text.
    """

    # Get the VK (proto object)
    client_ctx = ctx.obj
    prover_client = create_prover_client(client_ctx)
    vk_proto = prover_client.get_verification_key()

    # Get a zksnark provider and convert the VK to json
    zksnark_name = prover_client.get_configuration().zksnark_name
    zksnark = get_zksnark_provider(zksnark_name)
    vk = zksnark.verification_key_from_proto(vk_proto)
    vk_json = vk.to_json_dict()

    # Write the json to stdout or a file
    if vk_out:
        with open(vk_out, "w") as vk_f:
            json.dump(vk_json, vk_f)
    else:
        print(json.dumps(vk_json))
