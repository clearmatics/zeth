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

# The UNPACKED_PRIMARY_INPUTS variable represents a dummy primary input,
# it is structured as follows,

ROOT = 0

NULLIFIERS = [
    24,  # nf_0 = "0...01 1000"
    33,  # nf_1 = "0...010 0001"
]

COMMITMENTS = [
    1,  # cm_0 = "0...01"
    2,  # cm_1 = "0...010"
]

HSIG = 47  # h_sig = "0...010 1111"

HTAGS = [
    50,  # htag_0 = "0...011 0010"
    59,  # htag_1 = "0...011 1011"
]

VPUB = (0xffffffffffffffff, 0)

# 255                                         128         64           0
# |<empty>|<h_sig>|<nullifiers>|<msg_auth_tags>|<v_pub_in>)|<v_pub_out>|
RESIDUAL_BITS = int(
    "000" # h_sig
    "000" # nf_2
    "000" # nf_1
    "000" # htag_0
    "000" # htag_1
    "1111111111111111111111111111111111111111111111111111111111111111" # vin
    "0000000000000000000000000000000000000000000000000000000000000000", # vout
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
