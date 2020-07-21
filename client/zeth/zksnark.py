#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

"""
zk-SNARK abstraction
"""

from zeth.utils import hex_to_int
import zeth.constants as constants
from api.snark_messages_pb2 import VerificationKey, ExtendedProof
from api.ec_group_messages_pb2 import HexPointBaseGroup1Affine, \
    HexPointBaseGroup2Affine

import json
from abc import (ABC, abstractmethod)
from typing import Dict, List, Tuple, Any
# pylint: disable=unnecessary-pass

# Dictionary representing a VerificationKey from any supported snark
GenericVerificationKey = Dict[str, Any]

# Dictionary representing a Proof from any supported snark
GenericProof = Dict[str, Any]


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
    def parse_verification_key(
            vk_obj: VerificationKey) -> GenericVerificationKey:
        pass

    @staticmethod
    @abstractmethod
    def parse_proof(proof_obj: ExtendedProof) -> GenericProof:
        pass

    @staticmethod
    @abstractmethod
    def mixer_proof_parameters(parsed_proof: GenericProof) -> List[List[int]]:
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
            "Alpha": hex_to_int(vk["alpha_g1"]),
            "Beta1": hex_to_int(vk["beta_g2"][0]),
            "Beta2": hex_to_int(vk["beta_g2"][1]),
            "Delta1": hex_to_int(vk["delta_g2"][0]),
            "Delta2": hex_to_int(vk["delta_g2"][1]),
            "ABC_coords": hex_to_int(sum(vk["abc_g1"], [])),
        }

    @staticmethod
    def parse_verification_key(
            vk_obj: VerificationKey) -> GenericVerificationKey:
        vk = vk_obj.groth16_verification_key
        return {
            "alpha_g1": _parse_hex_point_base_group1_affine(vk.alpha_g1),
            "beta_g2": _parse_hex_point_base_group2_affine(vk.beta_g2),
            "delta_g2": _parse_hex_point_base_group2_affine(vk.delta_g2),
            "abc_g1": json.loads(vk.abc_g1),
        }

    @staticmethod
    def parse_proof(proof_obj: ExtendedProof) -> GenericProof:
        proof = proof_obj.groth16_extended_proof
        return {
            "a": _parse_hex_point_base_group1_affine(proof.a),
            "b": _parse_hex_point_base_group2_affine(proof.b),
            "c": _parse_hex_point_base_group1_affine(proof.c),
            "inputs": json.loads(proof.inputs),
        }

    @staticmethod
    def mixer_proof_parameters(parsed_proof: GenericProof) -> List[List[Any]]:
        return [
            hex_to_int(parsed_proof["a"]),
            hex_to_int(parsed_proof["b"][0] + parsed_proof["b"][1]),
            hex_to_int(parsed_proof["c"])]


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
    def parse_verification_key(vk_obj: VerificationKey) -> GenericVerificationKey:
        vk = vk_obj.pghr13_verification_key
        return {
            "a": _parse_hex_point_base_group2_affine(vk.a),
            "b": _parse_hex_point_base_group1_affine(vk.b),
            "c": _parse_hex_point_base_group2_affine(vk.c),
            "g": _parse_hex_point_base_group2_affine(vk.gamma),
            "gb1": _parse_hex_point_base_group1_affine(vk.gamma_beta_g1),
            "gb2": _parse_hex_point_base_group2_affine(vk.gamma_beta_g2),
            "z": _parse_hex_point_base_group2_affine(vk.z),
            "IC": json.loads(vk.ic),
        }

    @staticmethod
    def parse_proof(proof_obj: ExtendedProof) -> GenericProof:
        proof = proof_obj.pghr13_extended_proof
        return {
            "a": _parse_hex_point_base_group1_affine(proof.a),
            "a_p": _parse_hex_point_base_group1_affine(proof.a_p),
            "b": _parse_hex_point_base_group2_affine(proof.b),
            "b_p": _parse_hex_point_base_group1_affine(proof.b_p),
            "c": _parse_hex_point_base_group1_affine(proof.c),
            "c_p": _parse_hex_point_base_group1_affine(proof.c_p),
            "h": _parse_hex_point_base_group1_affine(proof.h),
            "k": _parse_hex_point_base_group1_affine(proof.k),
            "inputs": json.loads(proof.inputs),
        }

    @staticmethod
    def mixer_proof_parameters(parsed_proof: GenericProof) -> List[List[Any]]:
        return [
            hex_to_int(parsed_proof["a"]) +
            hex_to_int(parsed_proof["a_p"]),
            [hex_to_int(parsed_proof["b"][0]),
             hex_to_int(parsed_proof["b"][1])],
            hex_to_int(parsed_proof["b_p"]),
            hex_to_int(parsed_proof["c"]),
            hex_to_int(parsed_proof["c_p"]),
            hex_to_int(parsed_proof["h"]),
            hex_to_int(parsed_proof["k"])]


def get_zksnark_provider(zksnark_name: str) -> IZKSnarkProvider:
    if zksnark_name == constants.PGHR13_ZKSNARK:
        return PGHR13SnarkProvider()
    if zksnark_name == constants.GROTH16_ZKSNARK:
        return Groth16SnarkProvider()
    raise Exception(f"unknown zk-SNARK name: {zksnark_name}")


def _parse_hex_point_base_group1_affine(
        point: HexPointBaseGroup1Affine) -> Tuple[str, str]:
    return (point.x_coord, point.y_coord)


def _parse_hex_point_base_group2_affine(
        point: HexPointBaseGroup2Affine
) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    return (tuple(point.x_coord), tuple(point.y_coord))
