#!/usr/bin/env python3

# Copyright (c) 2015-2019 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from typing import Any
import test_commands.mock as mock
from zeth.constants import DIGEST_LENGTH, FIELD_CAPACITY,\
    JS_INPUTS, JS_OUTPUTS, ZETH_MERKLE_TREE_DEPTH
import zeth.joinsplit

# The variable inputs represents a dummy primary input array,
# it is structured as follows,
# inputs =
#   rt || {sn}_1,2 || {cm}_1,2 || h_sig || {h}_1,2 || residual_bits
# residual_bits =
#   v_in || v_out || h_sig || {sn}_1,2  || {cm}_1,2  || {h}_1,2
# We set dummy values for all variables but residual_bits as follows:
# residual_bits = 713623846352979940490457358497079434602616037, or in bits
# 1-4:   00000000 00000000 00000000 00000000
# 5-8:   00000000 00000000 00000000 00000000
# 9-12:  00000000 00000000 00000000 00000000
# 13-16: 00000000 00011111 11111111 11111111
# 17-20: 11111111 11111111 11111111 11111111
# 21-24: 11111111 11100000 00000000 00000000
# 25-28: 00000000 00000000 00000000 00000000
# 29-32: 00000000 00011100 00010100 11100101
# This corresponds to
# v_in  = 0xFFFFFFFFFFFFFFFF
# v_out = 0x0000000000000000
# h_sig = 111
# sn_0  = 000
# sn_1  = 001
# cm_0  = 010
# cm_1  = 011
# h_0   = 100
# h_1   = 101
# The values were set to be easily distinguishable.
INPUTS = [
    0,  # root
    1,  # sn_0
    1,  # sn_1
    2,  # cm_0
    2,  # cm_1
    3,  # h_sig
    4,  # h_0
    4,  # h_1
    713623846352979940490457358497079434602616037] \
        # residual bits ; pylint: disable=no-member,invalid-name


def test_assemble_nullifiers(mixer_instance: Any) -> int:
    # Test retrieving nullifiers
    print("--- testing ", "test_assemble_nullifiers")
    for i in range(JS_INPUTS):
        res = mixer_instance.functions.assemble_nullifier(i, INPUTS).call()
        val = int.from_bytes(res, byteorder="big")
        # We need to recompute the expected value
        # To do so, we load the variable's first FIELD_CAPACITY bits from `INPUTS`
        # and remove the padding (of size DIGEST_LENGTH-FIELD_CAPACITY)
        # Before adding the value defined in `residual bits`
        expected_val = INPUTS[1+i]*2**(DIGEST_LENGTH-FIELD_CAPACITY) +\
            int(("{0:03b}".format(i)), 2)
        if val != expected_val:
            print("ERROR: extracted wrong nullifier")
            print("expected:", expected_val, i)
            print("got:", val, i)
            return 1
    return 0


def test_assemble_commitments(mixer_instance: Any) -> int:
    # Test retrieving commitments
    print("--- testing ", "test_assemble_commitments")
    for i in range(JS_OUTPUTS):
        res = mixer_instance.functions.assemble_commitment(i, INPUTS).call()
        val = int.from_bytes(res, byteorder="big")
        # We need to recompute the expected value
        # To do so, we load the variable's first FIELD_CAPACITY bits from `INPUTS`
        # and remove the padding (of size DIGEST_LENGTH-FIELD_CAPACITY)
        # Before adding the value defined in `residual bits`
        expected_val = INPUTS[1+JS_INPUTS+i]*2**(DIGEST_LENGTH-FIELD_CAPACITY) +\
            int(("{0:03b}".format(2+i)), 2)
        if val != expected_val:
            print("ERROR: extracted wrong commitment")
            print("expected:", expected_val, i)
            print("got:", val, i)
            return 1
    return 0


def test_assemble_hsig(mixer_instance: Any) -> Any:
    # Test retrieving commitments
    print("--- testing ", "test_assemble_hsig")
    res = mixer_instance.functions.assemble_hsig(INPUTS).call()
    hsig = int.from_bytes(res, byteorder="big")
    # We need to recompute the expected value
    # To do so, we load the variable's first FIELD_CAPACITY bits from `INPUTS`
    # and remove the padding (of size DIGEST_LENGTH-FIELD_CAPACITY)
    # Before adding the value defined in `residual bits`
    expected_val = INPUTS[1+JS_INPUTS+JS_OUTPUTS] *\
        2**(DIGEST_LENGTH-FIELD_CAPACITY) + int("111", 2)
    if hsig != expected_val:
        print("ERROR: extracted wrong public values")
        print("expected:", expected_val)
        print("got:", hsig)
        return 1
    return 0


def test_assemble_vpub(mixer_instance: Any) -> Any:
    # Test retrieving commitments
    print("--- testing ", "test_assemble_vpub")
    v_in, v_out = mixer_instance.functions.assemble_public_values(INPUTS).call()
    if v_in != int("0xFFFFFFFFFFFFFFFF", 16) or\
            v_out != int("0x0000000000000000", 16):
        print("ERROR: extracted wrong public values")
        print(
            "expected:",
            int("0xFFFFFFFFFFFFFFFF", 16),
            int("0x0000000000000000", 16)
        )
        print("got:", v_in, v_out)
        return 1
    return 0


def main() -> None:
    print("-------------------- Evaluating BaseMixer.sol --------------------")

    zksnark = zeth.zksnark.get_zksnark_provider(zeth.utils.parse_zksnark_arg())

    web3, eth = mock.open_test_web3()

    # Ethereum addresses
    deployer_eth_address = eth.accounts[0]

    prover_client = mock.open_test_prover_client()

    # Deploy Zeth contracts
    zeth_client = zeth.joinsplit.ZethClient.deploy(
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

    if result == 0:
        print("base_mixer tests PASS")


if __name__ == '__main__':
    main()
