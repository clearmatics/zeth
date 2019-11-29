
"""
Constants and defaults specific to the CLI interface.
"""

from zeth.constants import GROTH16_ZKSNARK


ZKSNARK_DEFAULT = GROTH16_ZKSNARK
ETH_RPC_ENDPOINT_DEFAULT = "http://localhost:8545"
PROVER_SERVER_ENDPOINT_DEFAULT = "localhost:50051"

KEYFILE_DEFAULT = "zeth-key.json"
NOTESFILE_DEFAULT = "zeth-notes.json"
INSTANCEFILE_DEFAULT = "zeth-instance.json"
ETH_ADDRESS_DEFAULT = "eth-address"

WALLET_DIR_DEFAULT = "./notes"
WALLET_USERNAME = "zeth"
