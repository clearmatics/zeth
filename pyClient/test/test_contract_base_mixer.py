#!/usr/bin/env python3

# Copyright (c) 2015-2019 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

import os
from typing import Any
from solcx import compile_files  # type: ignore
import test_commands.mock as mock

from zeth.constants import DIGEST_LENGTH, FIELD_CAPACITY,\
    JS_INPUTS, JS_OUTPUTS, ZETH_MERKLE_TREE_DEPTH, PUBLIC_VALUE_LENGTH
import zeth.contracts as contracts


# The variable inputs represents a dummy primary input array,
# it is structured as follows,
# inputs =
#   rt || {sn}_1,2 || {cm}_1,2 || h_sig || {h}_1,2 || residual_bits
# residual_bits =
#   v_in || v_out || h_sig || {sn}_1,2  || {cm}_1,2  || {h}_1,2
# We set dummy values for all variables. The residual_bits are as follows:
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
# v_in  = "0xFFFFFFFFFFFFFFFF" = 2**PUBLIC_VALUE_LENGTH - 1
# v_out = "0x0000000000000000" = 0
# h_sig = "111" = 7
# sn_0  = "000" = 0
# sn_1  = "001" = 1
# cm_0  = "010" = 2
# cm_1  = "011" = 3
# h_0   = "100" = 4
# h_1   = "101" = 5
# The values were set to be easily distinguishable.

PRIMARY_INPUTS = [
    0,  # root
    1,  # sn_0
    1,  # sn_1
    2,  # cm_0
    2,  # cm_1
    3,  # h_sig
    4,  # h_0
    4,  # h_1
    713623846352979940490457358497079434602616037] \
        # pylint: disable=no-member,invalid-name

RESIDUAL_BITS = [
    2**PUBLIC_VALUE_LENGTH - 1,  # v_in
    0,  # v_out
    7,  # h_sig
    0,  # sn_0
    1,  # sn_1
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
            assemble_nullifier(i, PRIMARY_INPUTS).call()
        val = int.from_bytes(res, byteorder="big")
        # We need to recompute the expected value
        # To do so, we load the variable's first FIELD_CAPACITY bits from
        # `PRIMARY_INPUTS` and remove the padding
        # (of size DIGEST_LENGTH-FIELD_CAPACITY)
        # Before adding the value defined in `residual bits`
        expected_val = PRIMARY_INPUTS[1+i]*2**(DIGEST_LENGTH-FIELD_CAPACITY) +\
            RESIDUAL_BITS[3+i]
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
        res = mixer_instance.functions.\
            assemble_commitment(i, PRIMARY_INPUTS).call()
        val = int.from_bytes(res, byteorder="big")
        # We need to recompute the expected value
        # To do so, we load the variable's first FIELD_CAPACITY bits from
        # `PRIMARY_INPUTS` and remove the padding
        # (of size DIGEST_LENGTH-FIELD_CAPACITY)
        # Before adding the value defined in `residual bits`
        expected_val = PRIMARY_INPUTS[1+JS_INPUTS+i] *\
            2**(DIGEST_LENGTH-FIELD_CAPACITY) +\
            RESIDUAL_BITS[3+JS_INPUTS+i]
        if val != expected_val:
            print("ERROR: extracted wrong commitment")
            print("expected:", expected_val, i)
            print("got:", val, i)
            return 1
    return 0


def test_assemble_hsig(mixer_instance: Any) -> Any:
    # Test retrieving commitments
    print("--- testing ", "test_assemble_hsig")
    res = mixer_instance.functions.\
        assemble_hsig(PRIMARY_INPUTS).call()
    hsig = int.from_bytes(res, byteorder="big")
    # We need to recompute the expected value
    # To do so, we load the variable's first FIELD_CAPACITY bits from
    # `PRIMARY_INPUTS` and remove the padding
    # (of size DIGEST_LENGTH-FIELD_CAPACITY)
    # Before adding the value defined in `residual bits`
    expected_val = PRIMARY_INPUTS[1+JS_INPUTS+JS_OUTPUTS] *\
        2**(DIGEST_LENGTH-FIELD_CAPACITY) + RESIDUAL_BITS[2]
    if hsig != expected_val:
        print("ERROR: extracted wrong public values")
        print("expected:", expected_val)
        print("got:", hsig)
        return 1
    return 0


def test_assemble_vpub(mixer_instance: Any) -> Any:
    # Test retrieving commitments
    print("--- testing ", "test_assemble_vpub")
    v_in, v_out = mixer_instance.functions.\
        assemble_public_values(PRIMARY_INPUTS).call()
    if v_in != RESIDUAL_BITS[0] or v_out != RESIDUAL_BITS[1]:
        print("ERROR: extracted wrong public values")
        print(
            "expected:",
            RESIDUAL_BITS[0],
            RESIDUAL_BITS[1]
        )
        print("got:", v_in, v_out)
        return 1
    return 0


def main() -> None:
    print("-------------------- Evaluating BaseMixer.sol --------------------")

    web3, eth = mock.open_test_web3()

    # Ethereum addresses
    deployer_eth_address = eth.accounts[0]

    contracts_dir = os.environ['ZETH_CONTRACTS_DIR']
    path_to_mixer = os.path.join(contracts_dir, "BaseMixer.sol")
    compiled_sol = compile_files([path_to_mixer])
    mixer_interface = compiled_sol[path_to_mixer + ':' + "BaseMixer"]

    hasher_interface, _ = contracts.compile_util_contracts()
    # Deploy MiMC contract
    _, hasher_address = contracts.deploy_mimc_contract(
        web3, hasher_interface, deployer_eth_address)

    token_address = "0x0000000000000000000000000000000000000000"

    mixer = web3.eth.contract(
        abi=mixer_interface['abi'], bytecode=mixer_interface['bin'])
    tx_hash = mixer.constructor(
            depth=ZETH_MERKLE_TREE_DEPTH,
            token_address=token_address,
            hasher_address=hasher_address
        ).transact({'from': deployer_eth_address})

    # Get tx receipt to get Mixer contract address
    tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash, 10000)
    mixer_address = tx_receipt['contractAddress']
    # Get the mixer contract instance
    mixer_instance = web3.eth.contract(
        address=mixer_address,
        abi=mixer_interface['abi']
    )

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
