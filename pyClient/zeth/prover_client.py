
import grpc  # type: ignore
from google.protobuf import empty_pb2
from api import prover_pb2  # type: ignore
from api import prover_pb2_grpc  # type: ignore


class ProverClient(object):
    def __init__(self, endpoint: str):
        self.endpoint = endpoint

    def get_verification_key(self) -> prover_pb2.VerificationKey:
        """
        Fetch the verification key from the proving service
        """
        with grpc.insecure_channel(self.endpoint) as channel:
            stub = prover_pb2_grpc.ProverStub(channel)
            print("-------------- Get the verification key --------------")
            verificationkey = stub.GetVerificationKey(_make_empty_message())
            return verificationkey

    def get_proof(
            self,
            proof_inputs: prover_pb2.ProofInputs) -> prover_pb2.ExtendedProof:
        """
        Request a proof generation to the proving service
        """
        with grpc.insecure_channel(self.endpoint) as channel:
            stub = prover_pb2_grpc.ProverStub(channel)
            print("-------------- Get the proof --------------")
            proof = stub.Prove(proof_inputs)
            return proof


def _make_empty_message() -> empty_pb2.Empty:
    return empty_pb2.Empty()
