#!/usr/bin/env python3

# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from zeth.core.zksnark import IZKSnarkProvider, get_zksnark_provider, \
    IVerificationKey, ExtendedProof
from zeth.core.pairing import PairingParameters, pairing_parameters_from_proto
from zeth.api.zeth_messages_pb2 import ProofInputs
from zeth.api import prover_pb2  # type: ignore
from zeth.api import prover_pb2_grpc  # type: ignore
import grpc  # type: ignore
from os.path import exists
from os import unlink
import json
from google.protobuf import empty_pb2
from typing import Dict, List, Tuple, Optional, Any


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

    @staticmethod
    def from_json_dict(json_dict: Dict[str, Any]) -> ProverConfiguration:
        return ProverConfiguration(
            json_dict["zksnark_name"],
            PairingParameters.from_json_dict(json_dict["pairing_parameters"]))


def prover_configuration_from_proto(
        prover_config_proto: prover_pb2.ProverConfiguration
) -> ProverConfiguration:
    return ProverConfiguration(
        zksnark_name=prover_config_proto.zksnark,
        pairing_parameters=pairing_parameters_from_proto(
            prover_config_proto.pairing_parameters))


class ProverClient:
    def __init__(
            self,
            endpoint: str,
            prover_config_file: Optional[str] = None):
        """
        If config_file is not None, the ProverConfiguration will be cached in the
        given file.
        """
        self.endpoint = endpoint
        self.prover_config_file = prover_config_file
        self.prover_config: Optional[ProverConfiguration] = None

    def get_configuration(self) -> ProverConfiguration:
        """
        Get the ProverConfiguration for the connected server, caching in memory
        and in `config_file` if given.
        """
        if self.prover_config is not None:
            return self.prover_config

        if (self.prover_config_file is not None) and \
           exists(self.prover_config_file):
            try:
                with open(self.prover_config_file, "r") as prover_config_f:
                    self.prover_config = ProverConfiguration.from_json_dict(
                        json.load(prover_config_f))
                    return self.prover_config
            except Exception as ex:
                print(
                    f"prover config error '{self.prover_config_file}': {str(ex)}")
                unlink(self.prover_config_file)

        with grpc.insecure_channel(self.endpoint) as channel:
            stub = prover_pb2_grpc.ProverStub(channel)  # type: ignore
            prover_config_proto = stub.GetConfiguration(_make_empty_message())
            self.prover_config = prover_configuration_from_proto(
                prover_config_proto)

        if self.prover_config_file is not None:
            with open(self.prover_config_file, "w") as prover_config_f:
                json.dump(self.prover_config.to_json_dict(), prover_config_f)

        return self.prover_config

    def get_zksnark_provider(self) -> IZKSnarkProvider:
        """
        Get the appropriate zksnark provider, based on the server configuration.
        """
        config = self.get_configuration()
        return get_zksnark_provider(config.zksnark_name)

    def get_verification_key(self) -> IVerificationKey:
        """
        Fetch the verification key from the proving service
        """
        with grpc.insecure_channel(self.endpoint) as channel:
            stub = prover_pb2_grpc.ProverStub(channel)  # type: ignore
            vk_proto = stub.GetVerificationKey(_make_empty_message())
            zksnark = self.get_zksnark_provider()
            return zksnark.verification_key_from_proto(vk_proto)

    def get_proof(
            self,
            proof_inputs: ProofInputs) -> Tuple[ExtendedProof, List[int]]:
        """
        Request a proof generation to the proving service
        """
        with grpc.insecure_channel(self.endpoint) as channel:
            stub = prover_pb2_grpc.ProverStub(channel)  # type: ignore
            print("-------------- Get the proof --------------")
            extproof_and_pub_data = stub.Prove(proof_inputs)
            zksnark = self.get_zksnark_provider()
            extproof = zksnark.extended_proof_from_proto(
                extproof_and_pub_data.extended_proof)
            public_data = [int(x, 16) for x in extproof_and_pub_data.public_data]
            return extproof, public_data


def _make_empty_message() -> empty_pb2.Empty:
    return empty_pb2.Empty()
