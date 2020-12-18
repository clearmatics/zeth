#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.core.constants import \
    JS_INPUTS, JS_OUTPUTS, PUBLIC_VALUE_LENGTH, ZETH_PUBLIC_UNIT_VALUE
from zeth.core.prover_client import ProverClient
from zeth.core.mixer_client import MixerClient
from typing import Any
import test_commands.mock as mock

# pylint: disable=line-too-long

# TODO: These test is specific to AltBN128MixerBase, however the mixer that is
# deployed is a function of the currently running prover server. Change this to
# deploy a test contract (inheriting from AltBN128MixerBase) which then calls
# the given methods with the expected data (i.e. remove the requirement for a
# running prover_server, and support type-checking of the test code against
# interface changes).

# Primary inputs

ROOT = 0

NULLIFIERS = [
    int(
        "0010000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000011000",
        2),
    int(
        "0100000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000100001",
        2),
]

COMMITMENTS = [
    int(
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000001",
        2),
    int(
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000010",
        2),
]

HSIG = int(
    "1010000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000101111",
    2)

HTAGS = [
    int(
        "1100000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000110010",
        2),
    int(
        "1110000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000111011",
        2),
]

VPUB = (0x5555555555555500, 0x00eeeeeeeeeeeeee)

# 255                                         128         64           0
# |<empty>|<h_sig>|<nullifiers>|<msg_auth_tags>|<v_pub_in>)|<v_pub_out>|
RESIDUAL_BITS = int(
    "101"  # h_sig
    "010"  # nf_1
    "001"  # nf_0
    "111"  # htag_1
    "110"  # htag_0
    "0101010101010101010101010101010101010101010101010101010100000000"  # vin
    "0000000011101110111011101110111011101110111011101110111011101110",  # vout
    2)

PACKED_PRIMARY_INPUTS = \
    [ROOT] + COMMITMENTS + NULLIFIERS + [HSIG] + HTAGS + [RESIDUAL_BITS]


def test_assemble_nullifiers(mixer_instance: Any) -> int:
    # Test retrieving nullifiers
    print("--- testing ", "test_assemble_nullifiers")
    for i in range(JS_INPUTS):
        res = mixer_instance.functions.\
            assemble_nullifier(i, PACKED_PRIMARY_INPUTS).call()
        val = int.from_bytes(res, byteorder="big")
        if val != NULLIFIERS[i]:
            print(f"ERROR: extracted wrong nullifier[{i}]")
            print(f"expected: {NULLIFIERS[i]}")
            print(f"got: {val}")
            return 1
    return 0


def test_assemble_hsig(mixer_instance: Any) -> int:
    # Test retrieving commitments
    print("--- testing ", "test_assemble_hsig")
    res = mixer_instance.functions.\
        assemble_hsig(PACKED_PRIMARY_INPUTS).call()
    hsig = int.from_bytes(res, byteorder="big")
    if hsig != HSIG:
        print("ERROR: extracted wrong h_sig")
        print(f"expected: {hsig}")
        print(f"got: {hsig}")
        return 1
    return 0


def test_assemble_vpub(mixer_instance: Any) -> int:
    # Test retrieving commitments
    print("--- testing ", "test_assemble_vpub")
    v_in, v_out = mixer_instance.functions.assemble_public_values(
        PACKED_PRIMARY_INPUTS[-1]).call()
    v_in_expect = VPUB[0] * ZETH_PUBLIC_UNIT_VALUE
    v_out_expect = VPUB[1] * ZETH_PUBLIC_UNIT_VALUE
    if v_in != v_in_expect or v_out != v_out_expect:
        print("ERROR: extracted wrong public values")
        print(f"expected: {(v_in_expect, v_out_expect)}")
        print(f"actual  : {(v_in, v_out)}")
        return 1
    return 0


def main() -> None:
    print("-------------------- Evaluating MixerBase.sol --------------------")

    web3, eth = mock.open_test_web3()

    # Ethereum addresses
    deployer_eth_address = eth.accounts[0]

    prover_client = ProverClient(mock.TEST_PROVER_SERVER_ENDPOINT)
    zeth_client, _ = MixerClient.deploy(
        web3, prover_client, deployer_eth_address, None)

    mixer_instance = zeth_client.mixer_instance

    # We can now call the instance and test its functions.
    print("[INFO] 4. Running tests")
    result = 0
    result += test_assemble_nullifiers(mixer_instance)
    result += test_assemble_vpub(mixer_instance)
    result += test_assemble_hsig(mixer_instance)
    # We do not re-assemble of h_is in the contract

    if result == 0:
        print("base_mixer tests PASS\n")


if __name__ == '__main__':
    main()
