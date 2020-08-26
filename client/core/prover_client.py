#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

import grpc  # type: ignore
from google.protobuf import empty_pb2
from api.zeth_messages_pb2 import ProofInputs
from api.snark_messages_pb2 import VerificationKey, ExtendedProof
from api import prover_pb2_grpc  # type: ignore


class ProverClient:
    def __init__(self, endpoint: str):
        self.endpoint = endpoint

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
