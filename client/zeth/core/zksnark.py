#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

"""
zk-SNARK abstraction
"""

from __future__ import annotations
from zeth.core.utils import hex_to_uint256_list, hex_list_to_uint256_list
import zeth.core.constants as constants
from zeth.api import snark_messages_pb2
from zeth.api import ec_group_messages_pb2

import json
from abc import (ABC, abstractmethod)
from typing import Dict, List, Any, Union, cast
# pylint: disable=unnecessary-pass


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


class IVerificationKey(ABC):
    """
    Abstract base class of verification keys
    """
    @abstractmethod
    def to_json_dict(self) -> Dict[str, Any]:
        pass

    @staticmethod
    @abstractmethod
    def from_json_dict(json_dict: Dict[str, Any]) -> IVerificationKey:
        pass


class IProof(ABC):
    """
    Abstract base class of proofs
    """
    @abstractmethod
    def to_json_dict(self) -> Dict[str, Any]:
        pass

    @staticmethod
    @abstractmethod
    def from_json_dict(json_dict: Dict[str, Any]) -> IProof:
        pass


class ExtendedProof:
    """
    A GenericProof and associated inputs
    """
    def __init__(self, proof: IProof, inputs: List[str]):
        self.proof = proof
        self.inputs = inputs

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            "proof": self.proof.to_json_dict(),
            "inputs": self.inputs,
        }

    @staticmethod
    def from_json_dict(
            zksnark: IZKSnarkProvider,
            json_dict: Dict[str, Any]) -> ExtendedProof:
        return ExtendedProof(
            proof=zksnark.proof_from_json_dict(json_dict["proof"]),
            inputs=json_dict["inputs"])


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
    def verification_key_to_contract_parameters(
            vk: IVerificationKey) -> List[int]:
        pass

    @staticmethod
    @abstractmethod
    def verification_key_from_proto(
            vk_obj: snark_messages_pb2.VerificationKey) -> IVerificationKey:
        pass

    @staticmethod
    @abstractmethod
    def verification_key_to_proto(
            vk: IVerificationKey) -> snark_messages_pb2.VerificationKey:
        pass

    @staticmethod
    @abstractmethod
    def verification_key_from_json_dict(
            json_dict: Dict[str, Any]) -> IVerificationKey:
        pass

    @staticmethod
    @abstractmethod
    def proof_from_json_dict(json_dict: Dict[str, Any]) -> IProof:
        pass

    @staticmethod
    @abstractmethod
    def extended_proof_from_proto(
            ext_proof_proto: snark_messages_pb2.ExtendedProof
    ) -> ExtendedProof:
        pass

    @staticmethod
    @abstractmethod
    def extended_proof_to_proto(
            ext_proof: ExtendedProof) -> snark_messages_pb2.ExtendedProof:
        pass

    @staticmethod
    @abstractmethod
    def proof_to_contract_parameters(proof: IProof) -> List[int]:
        """
        Generate the leading parameters to the mix function for this SNARK, from a
        GenericProof object.
        """
        pass


class Groth16(IZKSnarkProvider):

    class VerificationKey(IVerificationKey):
        def __init__(
                self,
                alpha: GenericG1Point,
                beta: GenericG2Point,
                delta: GenericG2Point,
                abc: List[GenericG1Point]):
            self.alpha = alpha
            self.beta = beta
            self.delta = delta
            self.abc = abc

        def to_json_dict(self) -> Dict[str, Any]:
            return {
                "alpha": self.alpha.to_json_list(),
                "beta": self.beta.to_json_list(),
                "delta": self.delta.to_json_list(),
                "ABC": [abc.to_json_list() for abc in self.abc],
            }

        @staticmethod
        def from_json_dict(json_dict: Dict[str, Any]) -> Groth16.VerificationKey:
            return Groth16.VerificationKey(
                alpha=GenericG1Point.from_json_list(json_dict["alpha"]),
                beta=GenericG2Point.from_json_list(json_dict["beta"]),
                delta=GenericG2Point.from_json_list(json_dict["delta"]),
                abc=[GenericG1Point.from_json_list(abc)
                     for abc in json_dict["ABC"]])

    class Proof(IProof):
        def __init__(
                self,
                a: GenericG1Point,
                minus_b: GenericG2Point,
                c: GenericG1Point):
            self.a = a
            self.minus_b = minus_b
            self.c = c

        def to_json_dict(self) -> Dict[str, Any]:
            return {
                "a": self.a.to_json_list(),
                "minus_b": self.minus_b.to_json_list(),
                "c": self.c.to_json_list(),
            }

        @staticmethod
        def from_json_dict(json_dict: Dict[str, Any]) -> Groth16.Proof:
            return Groth16.Proof(
                a=GenericG1Point.from_json_list(json_dict["a"]),
                minus_b=GenericG2Point.from_json_list(json_dict["minus_b"]),
                c=GenericG1Point.from_json_list(json_dict["c"]))

    @staticmethod
    def get_contract_name() -> str:
        return constants.GROTH16_MIXER_CONTRACT

    @staticmethod
    def verification_key_to_contract_parameters(
            vk: IVerificationKey) -> List[int]:
        assert isinstance(vk, Groth16.VerificationKey)
        return \
            group_point_g1_to_contract_parameters(vk.alpha) + \
            group_point_g2_to_contract_parameters(vk.beta) + \
            group_point_g2_to_contract_parameters(vk.delta) + \
            sum(
                [group_point_g1_to_contract_parameters(abc) for abc in vk.abc],
                [])

    @staticmethod
    def verification_key_from_proto(
            vk_obj: snark_messages_pb2.VerificationKey
    ) -> Groth16.VerificationKey:
        vk = vk_obj.groth16_verification_key
        return Groth16.VerificationKey(
            alpha=group_point_g1_from_proto(vk.alpha_g1),
            beta=group_point_g2_from_proto(vk.beta_g2),
            delta=group_point_g2_from_proto(vk.delta_g2),
            abc=[GenericG1Point.from_json_list(abc)
                 for abc in json.loads(vk.abc_g1)])

    @staticmethod
    def verification_key_to_proto(
            vk: IVerificationKey) -> snark_messages_pb2.VerificationKey:
        assert isinstance(vk, Groth16.VerificationKey)
        vk_obj = snark_messages_pb2.VerificationKey()
        groth16_key = vk_obj.groth16_verification_key  # pylint: disable=no-member
        group_point_g1_to_proto(vk.alpha, groth16_key.alpha_g1)
        group_point_g2_to_proto(vk.beta, groth16_key.beta_g2)
        group_point_g2_to_proto(vk.delta, groth16_key.delta_g2)
        groth16_key.abc_g1 = json.dumps([abc.to_json_list() for abc in vk.abc])
        return vk_obj

    @staticmethod
    def verification_key_from_json_dict(
            json_dict: Dict[str, Any]) -> Groth16.VerificationKey:
        return Groth16.VerificationKey.from_json_dict(json_dict)

    @staticmethod
    def proof_from_json_dict(json_dict: Dict[str, Any]) -> Groth16.Proof:
        return Groth16.Proof.from_json_dict(json_dict)

    @staticmethod
    def extended_proof_from_proto(
            ext_proof_proto: snark_messages_pb2.ExtendedProof) -> ExtendedProof:
        ext_proof = ext_proof_proto.groth16_extended_proof
        return ExtendedProof(
            proof=Groth16.Proof(
                a=group_point_g1_from_proto(ext_proof.a),
                minus_b=group_point_g2_from_proto(ext_proof.minus_b),
                c=group_point_g1_from_proto(ext_proof.c)),
            inputs=json.loads(ext_proof.inputs))

    @staticmethod
    def extended_proof_to_proto(
            ext_proof: ExtendedProof) -> snark_messages_pb2.ExtendedProof:
        proof = ext_proof.proof
        assert isinstance(proof, Groth16.Proof)
        extproof_proto = snark_messages_pb2.ExtendedProof()
        proof_proto = extproof_proto.groth16_extended_proof \
            # pylint: disable=no-member
        group_point_g1_to_proto(proof.a, proof_proto.a)
        group_point_g2_to_proto(proof.minus_b, proof_proto.minus_b)
        group_point_g1_to_proto(proof.c, proof_proto.c)
        proof_proto.inputs = json.dumps(ext_proof.inputs)
        return extproof_proto

    @staticmethod
    def proof_to_contract_parameters(proof: IProof) -> List[int]:
        assert isinstance(proof, Groth16.Proof)
        return \
            group_point_g1_to_contract_parameters(proof.a) + \
            group_point_g2_to_contract_parameters(proof.minus_b) + \
            group_point_g1_to_contract_parameters(proof.c)


class PGHR13(IZKSnarkProvider):

    class VerificationKey(IVerificationKey):
        def __init__(
                self,
                a: GenericG2Point,
                b: GenericG1Point,
                c: GenericG2Point,
                g: GenericG2Point,
                gb1: GenericG1Point,
                gb2: GenericG2Point,
                z: GenericG2Point,
                ic: List[GenericG1Point]):
            self.a = a
            self.b = b
            self.c = c
            self.g = g
            self.gb1 = gb1
            self.gb2 = gb2
            self.z = z
            self.ic = ic

        def to_json_dict(self) -> Dict[str, Any]:
            return {
                "a": self.a.to_json_list(),
                "b": self.b.to_json_list(),
                "c": self.c.to_json_list(),
                "g": self.g.to_json_list(),
                "gb1": self.gb1.to_json_list(),
                "gb2": self.gb2.to_json_list(),
                "z": self.z.to_json_list(),
                "ic": [ic.to_json_list() for ic in self.ic],
            }

        @staticmethod
        def from_json_dict(json_dict: Dict[str, Any]) -> PGHR13.VerificationKey:
            return PGHR13.VerificationKey(
                a=GenericG2Point.from_json_list(json_dict["a"]),
                b=GenericG1Point.from_json_list(json_dict["b"]),
                c=GenericG2Point.from_json_list(json_dict["c"]),
                g=GenericG2Point.from_json_list(json_dict["g"]),
                gb1=GenericG1Point.from_json_list(json_dict["gb1"]),
                gb2=GenericG2Point.from_json_list(json_dict["gb2"]),
                z=GenericG2Point.from_json_list(json_dict["z"]),
                ic=[GenericG1Point.from_json_list(ic) for ic in json_dict["ic"]])

    class Proof(IProof):
        def __init__(
                self,
                a: GenericG1Point,
                a_p: GenericG1Point,
                b: GenericG2Point,
                b_p: GenericG1Point,
                c: GenericG1Point,
                c_p: GenericG1Point,
                h: GenericG1Point,
                k: GenericG1Point):
            self.a = a
            self.a_p = a_p
            self.b = b
            self.b_p = b_p
            self.c = c
            self.c_p = c_p
            self.h = h
            self.k = k

        def to_json_dict(self) -> Dict[str, Any]:
            return {
                "a": self.a.to_json_list(),
                "a_p": self.a_p.to_json_list(),
                "b": self.b.to_json_list(),
                "b_p": self.b_p.to_json_list(),
                "c": self.c.to_json_list(),
                "c_p": self.c_p.to_json_list(),
                "h": self.h.to_json_list(),
                "k": self.k.to_json_list(),
            }

        @staticmethod
        def from_json_dict(json_dict: Dict[str, Any]) -> PGHR13.Proof:
            return PGHR13.Proof(
                a=GenericG1Point.from_json_list(json_dict["a"]),
                a_p=GenericG1Point.from_json_list(json_dict["a_p"]),
                b=GenericG2Point.from_json_list(json_dict["b"]),
                b_p=GenericG1Point.from_json_list(json_dict["b_p"]),
                c=GenericG1Point.from_json_list(json_dict["c"]),
                c_p=GenericG1Point.from_json_list(json_dict["c_p"]),
                h=GenericG1Point.from_json_list(json_dict["h"]),
                k=GenericG1Point.from_json_list(json_dict["k"]))

    @staticmethod
    def get_contract_name() -> str:
        return constants.PGHR13_MIXER_CONTRACT

    @staticmethod
    def verification_key_to_contract_parameters(
            vk: IVerificationKey) -> List[int]:
        assert isinstance(vk, PGHR13.VerificationKey)
        return \
            group_point_g2_to_contract_parameters(vk.a) + \
            group_point_g1_to_contract_parameters(vk.b) + \
            group_point_g2_to_contract_parameters(vk.c) + \
            group_point_g2_to_contract_parameters(vk.g) + \
            group_point_g1_to_contract_parameters(vk.gb1) + \
            group_point_g2_to_contract_parameters(vk.gb2) + \
            group_point_g2_to_contract_parameters(vk.z) + \
            sum([group_point_g1_to_contract_parameters(ic) for ic in vk.ic], [])

    @staticmethod
    def verification_key_from_proto(
            vk_obj: snark_messages_pb2.VerificationKey) -> PGHR13.VerificationKey:
        vk = vk_obj.pghr13_verification_key
        return PGHR13.VerificationKey(
            a=group_point_g2_from_proto(vk.a),
            b=group_point_g1_from_proto(vk.b),
            c=group_point_g2_from_proto(vk.c),
            g=group_point_g2_from_proto(vk.gamma),
            gb1=group_point_g1_from_proto(vk.gamma_beta_g1),
            gb2=group_point_g2_from_proto(vk.gamma_beta_g2),
            z=group_point_g2_from_proto(vk.z),
            ic=[GenericG1Point.from_json_list(ic) for ic in json.loads(vk.ic)])

    @staticmethod
    def verification_key_to_proto(
            vk: IVerificationKey) -> snark_messages_pb2.VerificationKey:
        raise Exception("not implemented")

    @staticmethod
    def verification_key_from_json_dict(
            json_dict: Dict[str, Any]) -> PGHR13.VerificationKey:
        return PGHR13.VerificationKey.from_json_dict(json_dict)

    @staticmethod
    def proof_from_json_dict(json_dict: Dict[str, Any]) -> PGHR13.Proof:
        return PGHR13.Proof.from_json_dict(json_dict)

    @staticmethod
    def extended_proof_from_proto(
            ext_proof_proto: snark_messages_pb2.ExtendedProof) -> ExtendedProof:
        ext_proof = ext_proof_proto.pghr13_extended_proof
        return ExtendedProof(
            proof=PGHR13.Proof(
                a=group_point_g1_from_proto(ext_proof.a),
                a_p=group_point_g1_from_proto(ext_proof.a_p),
                b=group_point_g2_from_proto(ext_proof.b),
                b_p=group_point_g1_from_proto(ext_proof.b_p),
                c=group_point_g1_from_proto(ext_proof.c),
                c_p=group_point_g1_from_proto(ext_proof.c_p),
                h=group_point_g1_from_proto(ext_proof.h),
                k=group_point_g1_from_proto(ext_proof.k)),
            inputs=cast(List[str], json.loads(ext_proof.inputs)))

    @staticmethod
    def extended_proof_to_proto(
            ext_proof: ExtendedProof) -> snark_messages_pb2.ExtendedProof:
        proof = ext_proof.proof
        assert isinstance(proof, PGHR13.Proof)
        extproof_proto = snark_messages_pb2.ExtendedProof()
        proof_proto = extproof_proto.pghr13_extended_proof \
            # pylint: disable=no-member
        group_point_g1_to_proto(proof.a, proof_proto.a)
        group_point_g1_to_proto(proof.a_p, proof_proto.a_p)
        group_point_g2_to_proto(proof.b, proof_proto.b)
        group_point_g1_to_proto(proof.b_p, proof_proto.b_p)
        group_point_g1_to_proto(proof.c, proof_proto.c)
        group_point_g1_to_proto(proof.c_p, proof_proto.c_p)
        group_point_g1_to_proto(proof.h, proof_proto.h)
        group_point_g1_to_proto(proof.k, proof_proto.k)
        proof_proto.inputs = json.dumps(ext_proof.inputs)
        return extproof_proto

    @staticmethod
    def proof_to_contract_parameters(proof: IProof) -> List[int]:
        assert isinstance(proof, PGHR13.Proof)
        return \
            group_point_g1_to_contract_parameters(proof.a) + \
            group_point_g1_to_contract_parameters(proof.a_p) + \
            group_point_g2_to_contract_parameters(proof.b) + \
            group_point_g1_to_contract_parameters(proof.b_p) + \
            group_point_g1_to_contract_parameters(proof.c) + \
            group_point_g1_to_contract_parameters(proof.c_p) + \
            group_point_g1_to_contract_parameters(proof.h) + \
            group_point_g1_to_contract_parameters(proof.k)


def get_zksnark_provider(zksnark_name: str) -> IZKSnarkProvider:
    if zksnark_name == constants.PGHR13_ZKSNARK:
        return PGHR13()
    if zksnark_name == constants.GROTH16_ZKSNARK:
        return Groth16()
    raise Exception(f"unknown zk-SNARK name: {zksnark_name}")


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
