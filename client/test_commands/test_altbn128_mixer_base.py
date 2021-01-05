#!/usr/bin/env python3

# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.core.constants import \
    JS_INPUTS, ZETH_PUBLIC_UNIT_VALUE, ZETH_MERKLE_TREE_DEPTH
import test_commands.mock as mock
from typing import Any

# pylint: disable=line-too-long

# TODO: These tests are specific to AltBN128MixerBase, however the mixer that
# is deployed is a function of the currently running prover server. Change this
# to deploy a test contract (inheriting from AltBN128MixerBase) which then
# calls the given methods with the expected data (i.e. remove the requirement
# for a running prover_server, and support type-checking of the test code
# against interface changes).

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


def test_assemble_nullifiers(mixer_instance: Any) -> None:
    # Test retrieving nullifiers
    print("--- test_assemble_nullifiers")
    for i in range(JS_INPUTS):
        res = mixer_instance.functions.\
            assemble_nullifier_test(i, PACKED_PRIMARY_INPUTS).call()
        val = int.from_bytes(res, byteorder="big")
        assert val == NULLIFIERS[i], f"expected: {NULLIFIERS[i]}, got: {val}"


def test_assemble_hsig(mixer_instance: Any) -> None:
    # Test retrieving hsig
    print("--- test_assemble_hsig")
    res = mixer_instance.functions.\
        assemble_hsig_test(PACKED_PRIMARY_INPUTS).call()
    hsig = int.from_bytes(res, byteorder="big")
    assert hsig == HSIG, f"expected: {HSIG}, got {hsig}"


def test_assemble_vpub(mixer_instance: Any) -> None:
    # Test retrieving public values
    print("--- test_assemble_vpub")
    v_in, v_out = mixer_instance.functions.assemble_public_values_test(
        PACKED_PRIMARY_INPUTS[-1]).call()
    v_in_expect = VPUB[0] * ZETH_PUBLIC_UNIT_VALUE
    v_out_expect = VPUB[1] * ZETH_PUBLIC_UNIT_VALUE
    assert v_in == v_in_expect, f"expected: {v_in_expect}, got: {v_in}"
    assert v_out == v_out_expect, f"expected: {v_out_expect}, got: {v_out}"


def main() -> None:
    print("Deploying AltBN128MixerBase_test.sol")
    _web3, eth = mock.open_test_web3()
    deployer_eth_address = eth.accounts[0]
    _mixer_interface, mixer_instance = mock.deploy_contract(
        eth,
        deployer_eth_address,
        "AltBN128MixerBase_test",
        {
            'mk_depth': ZETH_MERKLE_TREE_DEPTH,
        })

    print("Testing ...")
    test_assemble_nullifiers(mixer_instance)
    test_assemble_vpub(mixer_instance)
    test_assemble_hsig(mixer_instance)

    print("========================================")
    print("==              PASSED                ==")
    print("========================================")


if __name__ == '__main__':
    main()
