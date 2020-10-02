# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

"""
Generic pairing types and operations
"""

from __future__ import annotations
from .utils import hex_to_uint256_list, hex_list_to_uint256_list
from ..api import ec_group_messages_pb2
import json
from typing import Dict, List, Union, Any


class GenericG1Point:
    """
    G1 Group Points. A typed tuple of strings, stored as a JSON array.
    """
    def __init__(self, x_coord: str, y_coord: str):
        self.x_coord = x_coord
        self.y_coord = y_coord

    def to_json_list(self) -> List[str]:
        return [self.x_coord, self.y_coord]

    @staticmethod
    def from_json_list(json_list: List[str]) -> GenericG1Point:
        return GenericG1Point(json_list[0], json_list[1])


def group_point_g1_from_proto(
        point: ec_group_messages_pb2.Group1Point) -> GenericG1Point:
    x_coord = json.loads(point.x_coord)
    y_coord = json.loads(point.y_coord)
    assert isinstance(x_coord, str)
    assert isinstance(y_coord, str)
    return GenericG1Point(x_coord, y_coord)


def group_point_g1_to_proto(
        g1: GenericG1Point,
        g1_proto: ec_group_messages_pb2.Group1Point) -> None:
    g1_proto.x_coord = json.dumps(g1.x_coord)
    g1_proto.y_coord = json.dumps(g1.y_coord)


def group_point_g1_to_contract_parameters(g1: GenericG1Point) -> List[int]:
    return \
        list(hex_to_uint256_list(g1.x_coord)) + \
        list(hex_to_uint256_list(g1.y_coord))


class GenericG2Point:
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

    def to_json_list(self) -> List[Union[str, List[str]]]:
        return [self.x_coord, self.y_coord]

    @staticmethod
    def from_json_list(json_list: List[Union[str, List[str]]]) -> GenericG2Point:
        return GenericG2Point(json_list[0], json_list[1])


def group_point_g2_from_proto(
        point: ec_group_messages_pb2.Group2Point) -> GenericG2Point:
    x_coord = json.loads(point.x_coord)
    y_coord = json.loads(point.y_coord)
    # Depending on the curve, coordinates may be in a base (non-extension)
    # field (i.e. simple json strings)
    if isinstance(x_coord, str):
        assert isinstance(y_coord, str)
    else:
        assert isinstance(x_coord, list)
        assert isinstance(y_coord, list)
    return GenericG2Point(x_coord, y_coord)


def group_point_g2_to_proto(
        g2: GenericG2Point,
        g2_proto: ec_group_messages_pb2.Group2Point) -> None:
    g2_proto.x_coord = json.dumps(g2.x_coord)
    g2_proto.y_coord = json.dumps(g2.y_coord)


def group_point_g2_to_contract_parameters(g2: GenericG2Point) -> List[int]:
    if isinstance(g2.x_coord, str):
        assert isinstance(g2.y_coord, str)
        return \
            list(hex_to_uint256_list(g2.x_coord)) + \
            list(hex_to_uint256_list(g2.y_coord))

    assert isinstance(g2.x_coord, list)
    assert isinstance(g2.y_coord, list)
    return \
        hex_list_to_uint256_list(g2.x_coord) + \
        hex_list_to_uint256_list(g2.y_coord)


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

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            "r": str(self.r),
            "q": str(self.q),
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
