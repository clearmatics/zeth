# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

"""
Generic pairing types and operations
"""

from __future__ import annotations
from ..api import ec_group_messages_pb2
from .utils import hex_to_uint256_list, hex_list_to_uint256_list, \
    int_and_bytelen_from_hex, int_to_hex
import json
from typing import Dict, List, Union, Any


class G1Point:
    """
    G1 Group Points. A typed tuple of strings, stored as a JSON array.
    """
    def __init__(self, x_coord: str, y_coord: str):
        self.x_coord = x_coord
        self.y_coord = y_coord

    def __str__(self) -> str:
        return str(self.to_json_list())

    def __repr__(self) -> str:
        return self.__str__()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, G1Point):
            return False
        return (self.x_coord == other.x_coord) and (self.y_coord == other.y_coord)

    def to_json_list(self) -> List[str]:
        return [self.x_coord, self.y_coord]

    @staticmethod
    def from_json_list(json_list: List[str]) -> G1Point:
        return G1Point(json_list[0], json_list[1])


def g1_point_from_proto(
        point: ec_group_messages_pb2.Group1Point) -> G1Point:
    x_coord = json.loads(point.x_coord)
    y_coord = json.loads(point.y_coord)
    assert isinstance(x_coord, str)
    assert isinstance(y_coord, str)
    return G1Point(x_coord, y_coord)


def g1_point_to_proto(
        g1: G1Point,
        g1_proto: ec_group_messages_pb2.Group1Point) -> None:
    g1_proto.x_coord = json.dumps(g1.x_coord)
    g1_proto.y_coord = json.dumps(g1.y_coord)


def g1_point_to_contract_parameters(g1: G1Point) -> List[int]:
    return \
        list(hex_to_uint256_list(g1.x_coord)) + \
        list(hex_to_uint256_list(g1.y_coord))


class G2Point:
    """
    G2 Group Points. Depending on the curve, coordinates may be in the base
    (non-extension) field (i.e. simple json strings), or an extension field
    (i.e. a list of strings).
    """
    def __init__(
            self,
            x_coord: Union[str, List[str]],
            y_coord: Union[str, List[str]]):
        self.x_coord = x_coord
        self.y_coord = y_coord

    def __str__(self) -> str:
        return str(self.to_json_list())

    def __repr__(self) -> str:
        return self.__str__()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, G2Point):
            return False
        return (self.x_coord == other.x_coord) and (self.y_coord == other.y_coord)

    def to_json_list(self) -> List[Union[str, List[str]]]:
        return [self.x_coord, self.y_coord]

    @staticmethod
    def from_json_list(json_list: List[Union[str, List[str]]]) -> G2Point:
        return G2Point(json_list[0], json_list[1])


def g2_point_from_proto(
        point: ec_group_messages_pb2.Group2Point) -> G2Point:
    return G2Point(
        x_coord=json.loads(point.x_coord),
        y_coord=json.loads(point.y_coord))


def g2_point_to_proto(
        g2: G2Point,
        g2_proto: ec_group_messages_pb2.Group2Point) -> None:
    g2_proto.x_coord = json.dumps(g2.x_coord)
    g2_proto.y_coord = json.dumps(g2.y_coord)


def g2_point_to_contract_parameters(g2: G2Point) -> List[int]:
    if isinstance(g2.x_coord, str):
        assert isinstance(g2.y_coord, str)
        return \
            list(hex_to_uint256_list(g2.x_coord)) + \
            list(hex_to_uint256_list(g2.y_coord))
    return \
        hex_list_to_uint256_list(g2.x_coord) + \
        hex_list_to_uint256_list(g2.y_coord)


class PairingParameters:
    """
    The parameters for a specific pairing
    """
    def __init__(
            self,
            r: str,
            q: str,
            generator_g1: G1Point,
            generator_g2: G2Point):
        self.r = r
        self.q = q
        self.generator_g1 = generator_g1
        self.generator_g2 = generator_g2

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            "r": self.r,
            "q": self.q,
            "generator_g1": self.generator_g1.to_json_list(),
            "generator_g2": self.generator_g2.to_json_list(),
        }

    @staticmethod
    def from_json_dict(json_dict: Dict[str, Any]) -> PairingParameters:
        return PairingParameters(
            r=json_dict["r"],
            q=json_dict["q"],
            generator_g1=G1Point.from_json_list(json_dict["generator_g1"]),
            generator_g2=G2Point.from_json_list(json_dict["generator_g2"]))


def pairing_parameters_from_proto(
        pairing_params_proto: ec_group_messages_pb2.PairingParameters
) -> PairingParameters:
    return PairingParameters(
        r=pairing_params_proto.r,
        q=pairing_params_proto.q,
        generator_g1=g1_point_from_proto(pairing_params_proto.generator_g1),
        generator_g2=g2_point_from_proto(pairing_params_proto.generator_g2))


def field_element_negate(value_hex: str, mod_hex: str) -> str:
    mod, num_bytes = int_and_bytelen_from_hex(mod_hex)
    value = int(value_hex, 16)
    value = mod - (value % mod)
    return int_to_hex(value, num_bytes)


def g1_point_negate(
        g1: G1Point,
        pairing_parameters: PairingParameters) -> G1Point:
    return G1Point(
        g1.x_coord, field_element_negate(g1.y_coord, pairing_parameters.q))


def g2_point_negate(
        g2: G2Point,
        pp: PairingParameters) -> G2Point:
    if isinstance(g2.y_coord, str):
        return G2Point(g2.x_coord, field_element_negate(g2.y_coord, pp.q))
    return G2Point(
        g2.x_coord, [field_element_negate(y, pp.q) for y in g2.y_coord])
