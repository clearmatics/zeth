#!/usr/bin/env python3

# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.core.constants import \
    JS_INPUTS, ZETH_PUBLIC_UNIT_VALUE, ZETH_MERKLE_TREE_DEPTH
import test_commands.mock as mock
from unittest import TestCase
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

MIXER_INSTANCE: Any = None


class TestAltBN128MixerBaseContract(TestCase):

    @staticmethod
    def setUpClass() -> None:
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
        global MIXER_INSTANCE   # pylint: disable=global-statement
        MIXER_INSTANCE = mixer_instance

    def test_assemble_nullifiers(self) -> None:
        # Test retrieving nullifiers
        for i in range(JS_INPUTS):
            res = MIXER_INSTANCE.functions.\
                assemble_nullifier_test(i, PACKED_PRIMARY_INPUTS).call()
            val = int.from_bytes(res, byteorder="big")
            self.assertEqual(NULLIFIERS[i], val)

    def test_assemble_hsig(self) -> None:
        # Test retrieving hsig
        res = MIXER_INSTANCE.functions.\
            assemble_hsig_test(PACKED_PRIMARY_INPUTS).call()
        hsig = int.from_bytes(res, byteorder="big")
        self.assertEqual(HSIG, hsig)

    def test_assemble_vpub(self) -> None:
        # Test retrieving public values
        v_in, v_out = MIXER_INSTANCE.functions.assemble_public_values_test(
            PACKED_PRIMARY_INPUTS[-1]).call()
        v_in_expect = VPUB[0] * ZETH_PUBLIC_UNIT_VALUE
        v_out_expect = VPUB[1] * ZETH_PUBLIC_UNIT_VALUE
        self.assertEqual(v_in_expect, v_in)
        self.assertEqual(v_out_expect, v_out)
