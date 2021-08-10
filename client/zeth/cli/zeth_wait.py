# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.cli.utils import load_mixer_description_from_ctx, open_web3_from_ctx
from zeth.core.contracts import get_event_logs_from_tx_receipt
from click import command, pass_context, Context, argument


@command()
@argument("transaction-id")
@pass_context
def wait(ctx: Context, transaction_id: str) -> None:
    """
    Wait for a mix transaction and dump all log data. Does not update the
    wallet. Use sync to scan the chain for new notes.
    """
    client_ctx = ctx.obj
    mixer_desc = load_mixer_description_from_ctx(client_ctx)
    instance_desc = mixer_desc.mixer

    # Retrieve the tx receipt and dump logs
    web3 = open_web3_from_ctx(client_ctx)  # type: ignore
    instance = instance_desc.instantiate(web3)
    tx_receipt = web3.eth.waitForTransactionReceipt(transaction_id, 10000) \
        # pylint: disable=no-member

    print("LogDebug events:")
    logs = get_event_logs_from_tx_receipt(instance, "LogDebug", tx_receipt)
    for log in logs:
        print(
            f" {log.args['message']}: {log.args['value']} "
            f"({hex(log.args['value'])})")

    print("LogMix events:")
    logs = get_event_logs_from_tx_receipt(instance, "LogMix", tx_receipt)
    for log in logs:
        print(f" {log}")
