#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from .pairing import PairingParameters, pairing_parameters_from_proto
from zeth.api.zeth_messages_pb2 import ProofInputs
from zeth.api.snark_messages_pb2 import VerificationKey, ExtendedProof
from zeth.api import prover_pb2  # type: ignore
from zeth.api import prover_pb2_grpc  # type: ignore
import grpc  # type: ignore
from google.protobuf import empty_pb2
from typing import Dict, Any


class ProverConfiguration:
    """
    In-memory version of protobuf ProverConfig object
    """
    def __init__(self, zksnark_name: str, pairing_parameters: PairingParameters):
        self.zksnark_name = zksnark_name
        self.pairing_parameters = pairing_parameters

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            "zksnark_name": self.zksnark_name,
            "pairing_parameters": self.pairing_parameters.to_json_dict(),
        }


def prover_configuration_from_proto(
        prover_config_proto: prover_pb2.ProverConfiguration
) -> ProverConfiguration:
    return ProverConfiguration(
        zksnark_name=prover_config_proto.zksnark,
        pairing_parameters=pairing_parameters_from_proto(
            prover_config_proto.pairing_parameters))


class ProverClient:
    def __init__(self, endpoint: str):
        self.endpoint = endpoint

    def get_configuration(self) -> ProverConfiguration:
        """
        Get the ProverConfiguration for the connected server.
        """
        with grpc.insecure_channel(self.endpoint) as channel:
            stub = prover_pb2_grpc.ProverStub(channel)  # type: ignore
            prover_config_proto = stub.GetConfiguration(_make_empty_message())
            return prover_configuration_from_proto(prover_config_proto)

    def get_verification_key(self) -> VerificationKey:
        """
        Fetch the verification key from the proving service
        """
        with grpc.insecure_channel(self.endpoint) as channel:
            stub = prover_pb2_grpc.ProverStub(channel)  # type: ignore
            print("-------------- Get the verification key --------------")
            verificationkey = stub.GetVerificationKey(_make_empty_message())
            return verificationkey

    def get_proof(
            self,
            proof_inputs: ProofInputs) -> ExtendedProof:
        """
        Request a proof generation to the proving service
        """
        with grpc.insecure_channel(self.endpoint) as channel:
            stub = prover_pb2_grpc.ProverStub(channel)  # type: ignore
            print("-------------- Get the proof --------------")
            proof = stub.Prove(proof_inputs)
            return proof


def _make_empty_message() -> empty_pb2.Empty:
    return empty_pb2.Empty()
