#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

"""
zk-SNARK abstraction
"""

from zeth.core.utils import hex_to_int
import zeth.core.constants as constants
from zeth.api import snark_messages_pb2
from zeth.api import ec_group_messages_pb2

import json
from abc import (ABC, abstractmethod)
from typing import Dict, List, Tuple, Any, Union
# pylint: disable=unnecessary-pass

# JSON-based objects. These live python dictionaries must match the form of the
# JSON output from libzeth C++ library.
#
# TODO: consider implementing classes with json (de)serialization functions,
# similar to other objects.

# Dictionary representing a VerificationKey from any supported snark
GenericVerificationKey = Dict[str, Any]

# Dictionary representing a Proof from any supported snark
GenericProof = Dict[str, Any]

# Group Points. G1 should be a tuple of strings, for all pairings. G2 may be a
# tuple of strings, or a tuple of tuples of strings.
GenericG1Point = Tuple[str, str]
GenericG2Point = Tuple[Union[str, Tuple[str, ...]], Union[str, Tuple[str, ...]]]


class IZKSnarkProvider(ABC):
    """
    Interface to be implemented by specific zk-snark providers. Ideally, the
    rest of the logic should deal only with this interface and have no
    understanding of the underlying mechanisms.
    """

    @staticmethod
    @abstractmethod
    def get_contract_name() -> str:
        """
        Get the verifier and mixer contracts for this SNARK.
        """
        pass

    @staticmethod
    @abstractmethod
    def verification_key_parameters(
            vk: GenericVerificationKey) -> Dict[str, List[int]]:
        pass

    @staticmethod
    @abstractmethod
    def verification_key_from_proto(
            vk_obj: snark_messages_pb2.VerificationKey) -> GenericVerificationKey:
        pass

    @staticmethod
    @abstractmethod
    def verification_key_to_proto(
            vk: GenericVerificationKey) -> snark_messages_pb2.VerificationKey:
        pass

    @staticmethod
    @abstractmethod
    def proof_from_proto(
            proof_obj: snark_messages_pb2.ExtendedProof) -> GenericProof:
        pass

    @staticmethod
    @abstractmethod
    def proof_to_proto(
            extproof: GenericProof) -> snark_messages_pb2.ExtendedProof:
        pass

    @staticmethod
    @abstractmethod
    def mixer_proof_parameters(extproof: GenericProof) -> List[List[Any]]:
        """
        Generate the leading parameters to the mix function for this SNARK, from a
        GenericProof object.
        """
        pass


class Groth16SnarkProvider(IZKSnarkProvider):

    @staticmethod
    def get_contract_name() -> str:
        return constants.GROTH16_MIXER_CONTRACT

    @staticmethod
    def verification_key_parameters(
            vk: GenericVerificationKey) -> Dict[str, List[int]]:
        return {
            "Alpha": hex_to_int(vk["alpha"]),
            "Beta1": hex_to_int(vk["beta"][0]),
            "Beta2": hex_to_int(vk["beta"][1]),
            "Delta1": hex_to_int(vk["delta"][0]),
            "Delta2": hex_to_int(vk["delta"][1]),
            "ABC_coords": hex_to_int(sum(vk["ABC"], [])),
        }

    @staticmethod
    def verification_key_from_proto(
            vk_obj: snark_messages_pb2.VerificationKey) -> GenericVerificationKey:
        vk = vk_obj.groth16_verification_key
        return {
            "alpha": group_point_g1_from_proto(vk.alpha_g1),
            "beta": group_point_g2_from_proto(vk.beta_g2),
            "delta": group_point_g2_from_proto(vk.delta_g2),
            "ABC": json.loads(vk.abc_g1),
        }

    @staticmethod
    def verification_key_to_proto(
            vk: GenericVerificationKey) -> snark_messages_pb2.VerificationKey:
        vk_obj = snark_messages_pb2.VerificationKey()
        groth16_key = vk_obj.groth16_verification_key  # pylint: disable=no-member
        group_point_g1_to_proto(vk["alpha"], groth16_key.alpha_g1)
        group_point_g2_to_proto(vk["beta"], groth16_key.beta_g2)
        group_point_g2_to_proto(vk["delta"], groth16_key.delta_g2)
        groth16_key.abc_g1 = json.dumps(vk["ABC"])
        return vk_obj

    @staticmethod
    def proof_from_proto(
            proof_obj: snark_messages_pb2.ExtendedProof) -> GenericProof:
        proof = proof_obj.groth16_extended_proof
        return {
            "proof": {
                "a": group_point_g1_from_proto(proof.a),
                "b": group_point_g2_from_proto(proof.b),
                "c": group_point_g1_from_proto(proof.c),
            },
            "inputs": json.loads(proof.inputs),
        }

    @staticmethod
    def proof_to_proto(
            extproof: GenericProof) -> snark_messages_pb2.ExtendedProof:
        proof = extproof["proof"]
        extproof_proto = snark_messages_pb2.ExtendedProof()
        proof_proto = extproof_proto.groth16_extended_proof \
            # pylint: disable=no-member
        group_point_g1_to_proto(proof["a"], proof_proto.a)
        group_point_g2_to_proto(proof["b"], proof_proto.b)
        group_point_g1_to_proto(proof["c"], proof_proto.c)
        proof_proto.inputs = json.dumps(extproof["inputs"])
        return extproof_proto

    @staticmethod
    def mixer_proof_parameters(extproof: GenericProof) -> List[List[Any]]:
        # We assume that G2 elements are defined over a non-trivial extension
        # field, i.e. that each coordinate is a JSON list rather than a a
        # single base-field element. If the assert below triggers, then it may
        # be necessary to generalize this function a bit.
        proof = extproof["proof"]
        assert isinstance(proof["b"][0], (list, tuple))
        return [
            hex_to_int(proof["a"]),
            hex_to_int(proof["b"][0] + proof["b"][1]),
            hex_to_int(proof["c"]),
        ]


class PGHR13SnarkProvider(IZKSnarkProvider):

    @staticmethod
    def get_contract_name() -> str:
        return constants.PGHR13_MIXER_CONTRACT

    @staticmethod
    def verification_key_parameters(
            vk: GenericVerificationKey) -> Dict[str, List[int]]:
        return {
            "A1": hex_to_int(vk["a"][0]),
            "A2": hex_to_int(vk["a"][1]),
            "B": hex_to_int(vk["b"]),
            "C1": hex_to_int(vk["c"][0]),
            "C2": hex_to_int(vk["c"][1]),
            "gamma1": hex_to_int(vk["g"][0]),
            "gamma2": hex_to_int(vk["g"][1]),
            "gammaBeta1": hex_to_int(vk["gb1"]),
            "gammaBeta2_1": hex_to_int(vk["gb2"][0]),
            "gammaBeta2_2": hex_to_int(vk["gb2"][1]),
            "Z1": hex_to_int(vk["z"][0]),
            "Z2": hex_to_int(vk["z"][1]),
            "IC_coefficients": hex_to_int(sum(vk["IC"], [])),
        }

    @staticmethod
    def verification_key_from_proto(
            vk_obj: snark_messages_pb2.VerificationKey) -> GenericVerificationKey:
        vk = vk_obj.pghr13_verification_key
        return {
            "a": group_point_g2_from_proto(vk.a),
            "b": group_point_g1_from_proto(vk.b),
            "c": group_point_g2_from_proto(vk.c),
            "g": group_point_g2_from_proto(vk.gamma),
            "gb1": group_point_g1_from_proto(vk.gamma_beta_g1),
            "gb2": group_point_g2_from_proto(vk.gamma_beta_g2),
            "z": group_point_g2_from_proto(vk.z),
            "IC": json.loads(vk.ic),
        }

    @staticmethod
    def verification_key_to_proto(
            vk: GenericVerificationKey) -> snark_messages_pb2.VerificationKey:
        raise Exception("not implemented")

    @staticmethod
    def proof_from_proto(
            proof_obj: snark_messages_pb2.ExtendedProof) -> GenericProof:
        proof = proof_obj.pghr13_extended_proof
        return {
            "proof": {
                "a": group_point_g1_from_proto(proof.a),
                "a_p": group_point_g1_from_proto(proof.a_p),
                "b": group_point_g2_from_proto(proof.b),
                "b_p": group_point_g1_from_proto(proof.b_p),
                "c": group_point_g1_from_proto(proof.c),
                "c_p": group_point_g1_from_proto(proof.c_p),
                "h": group_point_g1_from_proto(proof.h),
                "k": group_point_g1_from_proto(proof.k),
            },
            "inputs": json.loads(proof.inputs),
        }

    @staticmethod
    def proof_to_proto(
            extproof: GenericProof) -> snark_messages_pb2.ExtendedProof:
        proof = extproof["proof"]
        extproof_proto = snark_messages_pb2.ExtendedProof()
        proof_proto = extproof_proto.pghr13_extended_proof \
            # pylint: disable=no-member
        group_point_g1_to_proto(proof["a"], proof_proto.a)
        group_point_g1_to_proto(proof["a_p"], proof_proto.a_p)
        group_point_g2_to_proto(proof["b"], proof_proto.b)
        group_point_g1_to_proto(proof["b_p"], proof_proto.b_p)
        group_point_g1_to_proto(proof["c"], proof_proto.c)
        group_point_g1_to_proto(proof["c_p"], proof_proto.c_p)
        group_point_g1_to_proto(proof["h"], proof_proto.h)
        group_point_g1_to_proto(proof["k"], proof_proto.k)
        proof_proto.inputs = json.dumps(extproof["inputs"])
        return extproof_proto

    @staticmethod
    def mixer_proof_parameters(extproof: GenericProof) -> List[List[Any]]:
        proof = extproof["proof"]
        return [
            hex_to_int(proof["a"]) +
            hex_to_int(proof["a_p"]),
            [hex_to_int(proof["b"][0]), hex_to_int(proof["b"][1])],
            hex_to_int(proof["b_p"]),
            hex_to_int(proof["c"]),
            hex_to_int(proof["c_p"]),
            hex_to_int(proof["h"]),
            hex_to_int(proof["k"])]


def get_zksnark_provider(zksnark_name: str) -> IZKSnarkProvider:
    if zksnark_name == constants.PGHR13_ZKSNARK:
        return PGHR13SnarkProvider()
    if zksnark_name == constants.GROTH16_ZKSNARK:
        return Groth16SnarkProvider()
    raise Exception(f"unknown zk-SNARK name: {zksnark_name}")


def group_point_g1_from_proto(
        point: ec_group_messages_pb2.HexPointBaseGroup1Affine) -> GenericG1Point:
    x_coord = json.loads(point.x_coord)
    y_coord = json.loads(point.y_coord)
    assert isinstance(x_coord, str)
    assert isinstance(y_coord, str)
    return (x_coord, y_coord)


def group_point_g1_to_proto(
        g1: GenericG1Point,
        g1_proto: ec_group_messages_pb2.HexPointBaseGroup1Affine) -> None:
    assert len(g1) == 2
    assert isinstance(g1[0], str)
    assert isinstance(g1[1], str)
    g1_proto.x_coord = json.dumps(g1[0])
    g1_proto.y_coord = json.dumps(g1[1])


def group_point_g2_from_proto(
        point: ec_group_messages_pb2.HexPointBaseGroup2Affine) -> GenericG2Point:
    x_coord = json.loads(point.x_coord)
    y_coord = json.loads(point.y_coord)
    # Depending on the curve, coordinates may be in a base (non-extension)
    # field (i.e. simple json strings)
    if isinstance(x_coord, str):
        assert isinstance(y_coord, str)
        return (x_coord, y_coord)
    assert isinstance(x_coord, list)
    assert isinstance(y_coord, list)
    return (tuple(x_coord), tuple(y_coord))


def group_point_g2_to_proto(
        g2: GenericG2Point,
        g2_proto: ec_group_messages_pb2.HexPointBaseGroup2Affine) -> None:
    assert len(g2) == 2
    g2_proto.x_coord = json.dumps(g2[0])
    g2_proto.y_coord = json.dumps(g2[1])
