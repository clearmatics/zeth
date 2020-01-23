#!/usr/bin/env python3

# Copyright (c) 2015-2019 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

import os
from solcx import compile_files  # type: ignore
from web3 import Web3, HTTPProvider  # type: ignore

W3 = Web3(HTTPProvider("http://localhost:8545"))
eth = W3.eth  # pylint: disable=no-member,invalid-name


def main() -> None:
    print("-------------------- Evaluating Bytes.sol --------------------")
    contracts_dir = os.environ['ZETH_CONTRACTS_DIR']
    path_to_bytes = os.path.join(contracts_dir, "Bytes.sol")
    path_to_bytes_tests = os.path.join(contracts_dir, "Bytes_tests.sol")
    compiled_sol = compile_files([path_to_bytes, path_to_bytes_tests])
    bytes_interface = compiled_sol[path_to_bytes_tests + ':' + "Bytes_tests"]
    contract = eth.contract(
        abi=bytes_interface['abi'],
        bytecode=bytes_interface['bin'])
    tx_hash = contract.constructor().transact({'from': eth.accounts[1]})
    tx_receipt = eth.waitForTransactionReceipt(tx_hash, 100000)
    address = tx_receipt['contractAddress']
    bytes_instance = eth.contract(address=address, abi=bytes_interface['abi'])

    result = 0

    print("--- testing ", "testReverseByte")
    test_reverse_byte = bytes_instance.functions.testReverseByte().call()
    if not test_reverse_byte:
        print("testReverseByte FAILS")
        result += 1

    print("--- testing ", "testGetLastByte")
    test_get_last_byte = bytes_instance.functions.testGetLastByte().call()
    if not test_get_last_byte:
        print("testGetLastByte FAILS")
        result += 1

    print("--- testing ", "testFlipEndiannessBytes32")
    test_flip_endianness_bytes32 = \
        bytes_instance.functions.testFlipEndiannessBytes32().call()
    if not test_flip_endianness_bytes32:
        print("testFlipEndiannessBytes32 FAILS")
        result += 1

    print("--- testing ", "testBytesToBytes32")
    test_bytes_to_bytes32 = \
        bytes_instance.functions.testBytesToBytes32().call()
    if not test_bytes_to_bytes32:
        print("testBytesToBytes32 FAILS")
        result += 1

    print("--- testing ", "testSha256DigestFromFieldElements")
    test_sha256_digest_from_field_elements = \
        bytes_instance.functions.testSha256DigestFromFieldElements().call()
    if not test_sha256_digest_from_field_elements:
        print("testSha256DigestFromFieldElements FAILS")
        result += 1

    if result == 0:
        print("All Bytes tests PASS")


if __name__ == '__main__':
    main()
