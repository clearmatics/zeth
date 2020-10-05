# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

"""
Generic pairing types and operations
"""

from __future__ import annotations
from ..api import ec_group_messages_pb2
import json
from math import ceil
from typing import Dict, List, Union, Any


def int_to_uint256_list(value: int, values_uint256s: int) -> List[int]:
    """
    Decompose an int into some number of 256-bit words, highest order first.
    """
    words = list(range(values_uint256s))
    mask = (1 << 256) - 1
    for i in range(values_uint256s):
        words[values_uint256s - i - 1] = value & mask
        value = value >> 256
    return words


def int_list_to_uint256_list(values: List[int], value_uint256s: int) -> List[int]:
    return [
        x for y in values for x in int_to_uint256_list(y, value_uint256s)]


def bit_length_to_uint256_length(num_bits: int) -> int:
    """
    Compute the number of uint256s required to fully represent a bit string of
    length `num_bits`.
    """
    return ceil(num_bits / 256)


class GenericG1Point:
    """
    G1 Group Points. A typed tuple of strings, stored as a JSON array.
    """
    def __init__(self, x_coord: int, y_coord: int):
        self.x_coord = x_coord
        self.y_coord = y_coord

    def to_json_list(self) -> List[str]:
        return [hex(self.x_coord), hex(self.y_coord)]

    @staticmethod
    def from_json_list(json_list: List[str]) -> GenericG1Point:
        return GenericG1Point(int(json_list[0], 16), int(json_list[1], 16))


def group_point_g1_from_proto(
        point: ec_group_messages_pb2.Group1Point) -> GenericG1Point:
    x_coord = int(json.loads(point.x_coord), 16)
    y_coord = int(json.loads(point.y_coord), 16)
    return GenericG1Point(x_coord, y_coord)


def group_point_g1_to_proto(
        g1: GenericG1Point,
        g1_proto: ec_group_messages_pb2.Group1Point) -> None:
    g1_proto.x_coord = json.dumps(hex(g1.x_coord))
    g1_proto.y_coord = json.dumps(hex(g1.y_coord))


def group_point_g1_to_contract_parameters(
        g1: GenericG1Point,
        pairing_parameters: PairingParameters) -> List[int]:
    num_uint256s = pairing_parameters.q_uint256_words
    return \
        int_to_uint256_list(g1.x_coord, num_uint256s) + \
        int_to_uint256_list(g1.y_coord, num_uint256s)


class GenericG2Point:
    """
    G2 Group Points. Depending on the curve, coordinates may be in the base
    (non-extension) field (i.e. simple json strings), or an extension field
    (i.e. a list of strings).
    """
    def __init__(self, x_coord: List[int], y_coord: List[int]):
        self.x_coord = x_coord
        self.y_coord = y_coord

    def to_json_list(self) -> List[Union[str, List[str]]]:
        return [
            [hex(x) for x in self.x_coord],
            [hex(y) for y in self.y_coord],
        ]

    @staticmethod
    def from_json_list(json_list: List[List[str]]) -> GenericG2Point:
        return GenericG2Point(
            [int(x, 16) for x in json_list[0]],
            [int(y, 16) for y in json_list[1]])


def group_point_g2_from_proto(
        point: ec_group_messages_pb2.Group2Point) -> GenericG2Point:
    x_coord = json.loads(point.x_coord)
    y_coord = json.loads(point.y_coord)
    # Depending on the curve, coordinates may be in a base (non-extension)
    # field (i.e. simple json strings)
    if isinstance(x_coord, str):
        assert isinstance(y_coord, str)
        return GenericG2Point([int(x_coord, 16)], [int(y_coord, 16)])

    assert isinstance(x_coord, list)
    assert isinstance(y_coord, list)
    return GenericG2Point(
        [int(x, 16) for x in x_coord],
        [int(y, 16) for y in y_coord])


def group_point_g2_to_proto(
        g2: GenericG2Point,
        g2_proto: ec_group_messages_pb2.Group2Point) -> None:
    if len(g2.x_coord) == 1:
        assert len(g2.y_coord) == 1
        g2_proto.x_coord = json.dumps(hex(g2.x_coord[0]))
        g2_proto.y_coord = json.dumps(hex(g2.y_coord[0]))
    else:
        g2_proto.x_coord = json.dumps([hex(x) for x in g2.x_coord])
        g2_proto.y_coord = json.dumps([hex(y) for y in g2.y_coord])


def group_point_g2_to_contract_parameters(
        g2: GenericG2Point, pairing_parameters: PairingParameters) -> List[int]:
    num_uint256s = pairing_parameters.q_uint256_words
    return \
        int_list_to_uint256_list(g2.x_coord, num_uint256s) + \
        int_list_to_uint256_list(g2.y_coord, num_uint256s)


class PairingParameters:
    """
    The parameters for a specific pairing
    """
    def __init__(
            self,
            r: int,
            q: int,
            generator_g1: GenericG1Point,
            generator_g2: GenericG2Point):
        self.r = r
        self.q = q
        self.generator_g1 = generator_g1
        self.generator_g2 = generator_g2

        # Compute some resultant properties
        self.r_uint256_words = bit_length_to_uint256_length(self.r.bit_length())
        self.q_uint256_words = bit_length_to_uint256_length(self.q.bit_length())

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            "r": hex(self.r),
            "q": hex(self.q),
            "generator_g1": self.generator_g1.to_json_list(),
            "generator_g2": self.generator_g2.to_json_list(),
        }


def pairing_parameters_from_proto(
        pairing_params_proto: ec_group_messages_pb2.PairingParameters
) -> PairingParameters:
    return PairingParameters(
        r=int(pairing_params_proto.r, 16),
        q=int(pairing_params_proto.q, 16),
        generator_g1=group_point_g1_from_proto(pairing_params_proto.generator_g1),
        generator_g2=group_point_g2_from_proto(pairing_params_proto.generator_g2))


def field_element_negate(value: int, mod: int) -> int:
    return mod - (value % mod)


def g1_element_negate(
        g1: GenericG1Point,
        pairing_parameters: PairingParameters) -> GenericG1Point:
    return GenericG1Point(
        g1.x_coord, field_element_negate(g1.y_coord, pairing_parameters.q))


def g2_element_negate(
        g2: GenericG2Point,
        pairing_parameters: PairingParameters) -> GenericG2Point:
    q = pairing_parameters.q
    y_coord = g2.y_coord
    if isinstance(y_coord, list):
        y_coord = [field_element_negate(y, q) for y in y_coord]
    else:
        assert isinstance(y_coord, int)
        y_coord = field_element_negate(y_coord, pairing_parameters.q)
    return GenericG2Point(g2.x_coord, y_coord)
