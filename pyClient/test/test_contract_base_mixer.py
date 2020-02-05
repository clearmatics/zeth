#!/usr/bin/env python3

# Copyright (c) 2015-2019 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.constants import JS_INPUTS, JS_OUTPUTS, ZETH_MERKLE_TREE_DEPTH,\
    PUBLIC_VALUE_LENGTH
from zeth.joinsplit import ZethClient
from zeth.zksnark import get_zksnark_provider
from typing import Any
import test_commands.mock as mock


# The UNPACKED_PRIMARY_INPUTS variable represents a dummy primary input,
# it is structured as follows,
UNPACKED_PRIMARY_INPUTS = [
    0,  # rt
    8,  # nf_0 = "...1 000"
    9,  # nf_1 = "...1 001"
    18,  # cm_0 = "...10 010"
    19,  # cm_1 = "...10 011"
    2**PUBLIC_VALUE_LENGTH - 1,  # v_in = "1...1"
    0,  # v_out = "0...0"
    31,  # h_sig = "...11 111"
    36,  # htag_0 = "...100 100"
    37  # htag_1 = "...100 101"
]
# The values were set so that the RESIDUAL_BITS are easily distinguishable.

# PACKED_PRIMARY_INPUTS =
#   rt || {nf}_1,2 || {cm}_1,2 || h_sig || {h}_1,2 || RESIDUAL_BITS
PACKED_PRIMARY_INPUTS = [
    0,  # root
    1,  # nf_0
    1,  # nf_1
    2,  # cm_0
    2,  # cm_1
    3,  # h_sig
    4,  # h_0
    4,  # h_1
    713623846352979940490457358497079434602616037] \
        # pylint: disable=no-member,invalid-name

# RESIDUAL_BITS =
#   v_in || v_out || h_sig || {nf}_1,2  || {cm}_1,2  || {h}_1,2
# We set dummy values for all variables. The residual_bits are as follows:
# RESIDUAL_BITS = 713623846352979940490457358497079434602616037, or in bits
# 1-4:   00000000 00000000 00000000 00000000
# 5-8:   00000000 00000000 00000000 00000000
# 9-12:  00000000 00000000 00000000 00000000
# 13-16: 00000000 00011111 11111111 11111111
# 17-20: 11111111 11111111 11111111 11111111
# 21-24: 11111111 11100000 00000000 00000000
# 25-28: 00000000 00000000 00000000 00000000
# 29-32: 00000000 00011100 00010100 11100101
# This corresponds to
# v_in  = "0xFFFFFFFFFFFFFFFF" = 2**PUBLIC_VALUE_LENGTH - 1
# v_out = "0x0000000000000000" = 0
# h_sig = "111" = 7
# nf_0  = "000" = 0
# nf_1  = "001" = 1
# cm_0  = "010" = 2
# cm_1  = "011" = 3
# h_0   = "100" = 4
# h_1   = "101" = 5
RESIDUAL_BITS = [
    2**PUBLIC_VALUE_LENGTH - 1,  # v_in
    0,  # v_out
    7,  # h_sig
    0,  # nf_0
    1,  # nf_1
    2,  # cm_0
    3,  # cm_1
    4,  # h_0
    5  # h_1
    ]  # pylint: disable=no-member,invalid-name


def test_assemble_nullifiers(mixer_instance: Any) -> int:
    # Test retrieving nullifiers
    print("--- testing ", "test_assemble_nullifiers")
    for i in range(JS_INPUTS):
        res = mixer_instance.functions.\
            assemble_nullifier(i, PACKED_PRIMARY_INPUTS).call()
        val = int.from_bytes(res, byteorder="big")
        if val != UNPACKED_PRIMARY_INPUTS[1+i]:
            print("ERROR: extracted wrong nullifier")
            print("expected:", UNPACKED_PRIMARY_INPUTS[1+i], i)
            print("got:", val, i)
            return 1
    return 0


def test_assemble_commitments(mixer_instance: Any) -> int:
    # Test retrieving commitments
    print("--- testing ", "test_assemble_commitments")
    for i in range(JS_OUTPUTS):
        res = mixer_instance.functions.\
            assemble_commitment(i, PACKED_PRIMARY_INPUTS).call()
        val = int.from_bytes(res, byteorder="big")
        if val != UNPACKED_PRIMARY_INPUTS[1 + JS_INPUTS + i]:
            print("ERROR: extracted wrong commitment")
            print("expected:", UNPACKED_PRIMARY_INPUTS[1 + JS_INPUTS + i], i)
            print("got:", val, i)
            return 1
    return 0


def test_assemble_hsig(mixer_instance: Any) -> Any:
    # Test retrieving commitments
    print("--- testing ", "test_assemble_hsig")
    res = mixer_instance.functions.\
        assemble_hsig(PACKED_PRIMARY_INPUTS).call()
    hsig = int.from_bytes(res, byteorder="big")
    if hsig != UNPACKED_PRIMARY_INPUTS[JS_INPUTS + JS_OUTPUTS + 3]:
        print("ERROR: extracted wrong public values")
        print("expected:", UNPACKED_PRIMARY_INPUTS[JS_INPUTS + JS_OUTPUTS + 3])
        print("got:", hsig)
        return 1
    return 0


def test_assemble_vpub(mixer_instance: Any) -> Any:
    # Test retrieving commitments
    print("--- testing ", "test_assemble_vpub")
    v_in, v_out = mixer_instance.functions.\
        assemble_public_values(PACKED_PRIMARY_INPUTS).call()
    if v_in != UNPACKED_PRIMARY_INPUTS[JS_INPUTS + JS_OUTPUTS + 1] or\
            v_out != UNPACKED_PRIMARY_INPUTS[JS_INPUTS + JS_OUTPUTS + 2]:
        print("ERROR: extracted wrong public values")
        print(
            "expected:",
            UNPACKED_PRIMARY_INPUTS[JS_INPUTS + JS_OUTPUTS + 1],
            UNPACKED_PRIMARY_INPUTS[JS_INPUTS + JS_OUTPUTS + 2]
        )
        print("got:", v_in, v_out)
        return 1
    return 0


def main() -> None:
    print("-------------------- Evaluating BaseMixer.sol --------------------")

    web3, eth = mock.open_test_web3()

    # Ethereum addresses
    deployer_eth_address = eth.accounts[0]

    zksnark = get_zksnark_provider("GROTH16")
    prover_client = mock.open_test_prover_client()
    zeth_client = ZethClient.deploy(
        web3,
        prover_client,
        ZETH_MERKLE_TREE_DEPTH,
        deployer_eth_address,
        zksnark)

    mixer_instance = zeth_client.mixer_instance

    # We can now call the instance and test its functions.
    print("[INFO] 4. Running tests")
    result = 0
    result += test_assemble_commitments(mixer_instance)
    result += test_assemble_nullifiers(mixer_instance)
    result += test_assemble_vpub(mixer_instance)
    result += test_assemble_hsig(mixer_instance)
    # We do not re-assemble of h_is in the contract

    if result == 0:
        print("base_mixer tests PASS\n")


if __name__ == '__main__':
    main()
