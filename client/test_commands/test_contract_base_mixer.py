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
UNPACKED_PRIMARY_INPUTS = [
    0,  # rt
    24,  # nf_0 = "0...01 1000"
    33,  # nf_1 = "0...010 0001"
    1,  # cm_0 = "0...01"
    2,  # cm_1 = "0...010"
    2**PUBLIC_VALUE_LENGTH - 1,  # v_in = "1...1"
    0,  # v_out = "0...0"
    47,  # h_sig = "0...010 1111"
    50,  # htag_0 = "0...011 0010"
    59  # htag_1 = "0...011 1011"
]
# The values were set so that the RESIDUAL_BITS are easily distinguishable.

# PACKED_PRIMARY_INPUTS =
#   rt || {nf}_1,2 || {cm}_1,2 || h_sig || {h}_1,2 || RESIDUAL_BITS
PACKED_PRIMARY_INPUTS = [
    0,  # root
    1,  # cm_0
    2,  # cm_1
    3,  # nf_0
    4,  # nf_1
    5,  # h_sig
    6,  # h_0
    7,  # h_1
    11150372599265311570163396226516866165665875] \
        # pylint: disable=no-member,invalid-name

# RESIDUAL_BITS =
#   v_in || v_out || h_sig || {nf}_1,2 || {h}_1,2
# We set dummy values for all variables. The residual_bits are as follows:
# RESIDUAL_BITS = 713623846352979940490457358497079434602616037, or in bits
# 1-4:   00000000 00000000 00000000 00000000
# 5-8:   00000000 00000000 00000000 00000000
# 9-12:  00000000 00000000 00000000 00000000
# 13-16: 00000000 00000000 01111111 11111111
# 17-20: 11111111 11111111 11111111 11111111
# 21-24: 11111111 11111111 10000000 00000000
# 25-28: 00000000 00000000 00000000 00000000
# 29-32: 00000000 00000000 01110000 01010011
# This corresponds to
# v_in  = "0xFFFFFFFFFFFFFFFF" = 2**PUBLIC_VALUE_LENGTH - 1
# v_out = "0x0000000000000000" = 0
# h_sig = "111" = 7
# nf_0  = "000" = 0
# nf_1  = "001" = 1
# h_0   = "010" = 2
# h_1   = "011" = 3
RESIDUAL_BITS = [
    2**PUBLIC_VALUE_LENGTH - 1,  # v_in
    0,  # v_out
    7,  # h_sig
    0,  # nf_0
    1,  # nf_1
    2,  # h_0
    3  # h_1
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


def test_assemble_vpub(mixer_instance: Any) -> int:
    # Test retrieving commitments
    print("--- testing ", "test_assemble_vpub")
    v_in, v_out = mixer_instance.functions.assemble_public_values(
        PACKED_PRIMARY_INPUTS).call()
    v_in_expect = UNPACKED_PRIMARY_INPUTS[JS_INPUTS + JS_OUTPUTS + 1] \
        * ZETH_PUBLIC_UNIT_VALUE
    v_out_expect = UNPACKED_PRIMARY_INPUTS[JS_INPUTS + JS_OUTPUTS + 2] \
        * ZETH_PUBLIC_UNIT_VALUE

    if v_in != v_in_expect or v_out != v_out_expect:
        print("ERROR: extracted wrong public values")
        print(f"expected: {(v_in_expect, v_out_expect)}")
        print(f"actual  : {(v_in, v_out)}")
        return 1
    return 0


def main() -> None:
    print("-------------------- Evaluating BaseMixer.sol --------------------")

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
