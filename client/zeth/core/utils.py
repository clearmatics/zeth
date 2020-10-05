#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

# Parse the arguments given to the script

from __future__ import annotations
from . import constants
from . import errors

import argparse
import sys
import os
from os.path import join, dirname, normpath, exists
import eth_abi
import eth_keys  # type: ignore
from web3 import Web3, HTTPProvider  # type: ignore
from py_ecc import bn128 as ec
from typing import Sequence, List, Tuple, Union, Iterable, Any, Optional, cast

# Some Ethereum node implementations can cause a timeout if the contract
# execution takes too long. We expect the contract to complete in under 30s on
# most machines, but allow 1 min.
WEB3_HTTP_PROVIDER_TIMEOUT_SEC = 60


def open_web3(
        url: str,
        certificate: Optional[str] = None,
        insecure: bool = False) -> Any:
    """
    Create a Web3 context from an http URL.
    """
    if certificate and not exists(certificate):
        raise FileNotFoundError(f"certificate file not found: {certificate}")
    assert not certificate or exists(certificate)
    request_verify: Union[str, bool, None] = False if insecure else certificate
    request_kwargs = {
        'timeout': WEB3_HTTP_PROVIDER_TIMEOUT_SEC,
        'verify': request_verify,
    }
    return Web3(HTTPProvider(url, request_kwargs=request_kwargs))


FQ = ec.FQ
G1 = Tuple[ec.FQ, ec.FQ]


class EtherValue:
    """
    Representation of some amount of Ether (or any token) in terms of Wei.
    Disambiguates Ether values from other units such as zeth_units.
    """
    def __init__(self, val: Union[str, int, float], units: str = 'ether'):
        self.wei = Web3.toWei(val, units)

    def __str__(self) -> str:
        return str(self.wei)

    def __add__(self, other: EtherValue) -> EtherValue:
        return EtherValue(self.wei + other.wei, 'wei')

    def __sub__(self, other: EtherValue) -> EtherValue:
        return EtherValue(self.wei - other.wei, 'wei')

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, EtherValue):
            return False
        return self.wei == other.wei

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def __lt__(self, other: EtherValue) -> bool:
        return self.wei < other.wei

    def __le__(self, other: EtherValue) -> bool:
        return self.wei <= other.wei

    def __gt__(self, other: EtherValue) -> bool:
        return self.wei > other.wei

    def __ge__(self, other: EtherValue) -> bool:
        return self.wei >= other.wei

    def __bool__(self) -> bool:
        return int(self.wei) != 0

    def ether(self) -> str:
        return str(Web3.fromWei(self.wei, 'ether'))


def encode_single(type_name: str, data: Any) -> bytes:
    """
    Typed wrapper around eth_abi.encode_single
    """
    return eth_abi.encode_single(type_name, data)  # type: ignore


def encode_abi(type_names: List[str], data: List[Any]) -> bytes:
    """
    Typed wrapper around eth_abi.encode_abi
    """
    return eth_abi.encode_abi(type_names, data)  # type: ignore


def eth_address_to_bytes(eth_addr: str) -> bytes:
    """
    Binary encoding of ethereum address to 20 bytes
    """
    # Strip the leading '0x' and hex-decode.
    assert len(eth_addr) == 42
    assert eth_addr.startswith("0x")
    return bytes.fromhex(eth_addr[2:])


def eth_address_to_bytes32(eth_addr: str) -> bytes:
    """
    Binary encoding of ethereum address to 32 bytes
    """
    return extend_32bytes(eth_address_to_bytes(eth_addr))


def eth_uint256_to_int(eth_uint256: str) -> int:
    assert isinstance(eth_uint256, str)
    assert eth_uint256.startswith("0x")
    return int.from_bytes(
        bytes.fromhex(hex_extend_32bytes(eth_uint256[2:])),
        byteorder='big')


def eth_address_from_private_key(eth_private_key: bytes) -> str:
    pk = eth_keys.keys.PrivateKey(eth_private_key)
    return pk.public_key.to_address()


def g1_to_bytes(group_el: G1) -> bytes:
    """
    Encode a group element into a byte string
    We assume here the group prime $p$ is written in less than 256 bits
    to conform with Ethereum bytes32 type.
    """
    return \
        int(group_el[0]).to_bytes(32, byteorder='big') + \
        int(group_el[1]).to_bytes(32, byteorder='big')


def int_and_bytelen_from_hex(value_hex: str) -> Tuple[int, int]:
    """
    Decode prefixed / non-prefixed hex string and extract the length in bytes
    as well as the value.
    """
    assert len(value_hex) % 2 == 0
    if value_hex.startswith("0x"):
        num_bytes = int((len(value_hex) - 2) / 2)
    else:
        num_bytes = int(len(value_hex) / 2)
    return (int(value_hex, 16), num_bytes)


def int_to_hex(value: int, num_bytes: int) -> str:
    """
    Create prefixed hex string enforcing a specific byte-length.
    """
    return "0x" + value.to_bytes(num_bytes, byteorder='big').hex()


def int64_to_bytes(number: int) -> bytes:
    return number.to_bytes(8, 'big')


def int64_to_hex(number: int) -> str:
    return int64_to_bytes(number).hex()


def hex_digest_to_binary_string(digest: str) -> str:
    if len(digest) % 2 == 1:
        digest = "0" + digest
    return "".join(["{0:04b}".format(int(c, 16)) for c in digest])


def digest_to_binary_string(digest: bytes) -> str:
    return "".join(["{0:08b}".format(b) for b in digest])


def hex_to_uint256_list(hex_str: str) -> Iterable[int]:
    """
    Given a hex string of arbitrary size, split into uint256 ints, left padding
    with 0s.
    """
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    assert len(hex_str) % 2 == 0
    start_idx = 0
    next_idx = len(hex_str) - int((len(hex_str) - 1) / 64) * 64
    while next_idx <= len(hex_str):
        sub_str = hex_str[start_idx:next_idx]
        yield int(sub_str, 16)
        start_idx = next_idx
        next_idx = next_idx + 64


def hex_list_to_uint256_list(
        elements: Sequence[Union[str, List[str]]]) -> List[int]:
    """
    Given an array of hex strings, return an array of int values by converting
    each hex string to evm uint256 words, and flattening the final list.
    """
    # In reality, we need to cope with lists of lists, to handle all
    # field extension degrees for all curve coordinate types.
    # TODO: Create a new type to describe this safely.
    flat_elements = string_list_flatten(elements)
    return [i for hex_str in flat_elements for i in hex_to_uint256_list(hex_str)]


def extend_32bytes(value: bytes) -> bytes:
    """
    Pad value on the left with zeros, to make 32 bytes.
    """
    assert len(value) <= 32
    return bytes(32-len(value)) + value


def hex_extend_32bytes(element: str) -> str:
    """
    Extend a hex string to represent 32 bytes
    """
    res = str(element)
    if len(res) % 2 != 0:
        res = "0" + res
    return extend_32bytes(bytes.fromhex(res)).hex()


def to_zeth_units(value: EtherValue) -> int:
    """
    Convert a quantity of ether / token to Zeth units
    """
    return int(value.wei / constants.ZETH_PUBLIC_UNIT_VALUE)


def from_zeth_units(zeth_units: int) -> EtherValue:
    """
    Convert a quantity of ether / token to Zeth units
    """
    return EtherValue(zeth_units * constants.ZETH_PUBLIC_UNIT_VALUE, "wei")


def parse_zksnark_arg() -> str:
    """
    Parse the zksnark argument and return its value
    """
    parser = argparse.ArgumentParser(
        description="Testing Zeth transactions using the specified zkSNARK " +
        "('GROTH16' or 'PGHR13').\nNote that the zkSNARK must match the one " +
        "used on the prover server.")
    parser.add_argument("zksnark", help="Set the zkSNARK to use")
    args = parser.parse_args()
    if args.zksnark not in constants.VALID_ZKSNARKS:
        return sys.exit(errors.SNARK_NOT_SUPPORTED)
    return args.zksnark


def get_zeth_dir() -> str:
    return os.environ.get(
        'ZETH',
        normpath(join(dirname(__file__), "..", "..", "..")))


def get_contracts_dir() -> str:
    return os.environ.get(
        'ZETH_CONTRACTS_DIR',
        join(get_zeth_dir(), "zeth_contracts", "contracts"))


def string_list_flatten(str_list: Sequence[Union[str, List[str]]]) -> List[str]:
    """
    Flatten a list containing strings or lists of strings.
    """
    if any(isinstance(el, (list, tuple)) for el in str_list):
        strs: List[str] = []
        for el in str_list:
            if isinstance(el, (list, tuple)):
                strs.extend(el)
            else:
                strs.append(cast(str, el))
        return strs

    return cast(List[str], str_list)


def message_to_bytes(message_list: Any) -> bytes:
    # message_list: Union[List[str], List[Union[int, str, List[str]]]]) -> bytes:
    """
    Encode a list of variables, or list of lists of variables into a byte
    vector
    """

    messages = string_list_flatten(message_list)

    data_bytes = bytearray()
    for m in messages:
        # For each element
        m_hex = m

        # Convert it into a hex
        if isinstance(m, int):
            m_hex = "{0:0>4X}".format(m)
        elif isinstance(m, str) and (m[1] == "x"):
            m_hex = m[2:]

        # [SANITY CHECK] Make sure the hex is 32 byte long
        m_hex = hex_extend_32bytes(m_hex)

        # Encode the hex into a byte array and append it to result
        data_bytes += encode_single("bytes32", bytes.fromhex(m_hex))

    return data_bytes


def short_commitment(cm: bytes) -> str:
    """
    Summary of the commitment value, in some standard format.
    """
    return cm[0:4].hex()
