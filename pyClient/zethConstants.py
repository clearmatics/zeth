# GROTH16 constants
GROTH16_ZKSNARK = "GROTH16"
GROTH16_VERIFIER_CONTRACT = "Groth16Verifier"
GROTH16_MIXER_CONTRACT = "Groth16Mixer"

# PGHR13 constants
PGHR13_ZKSNARK = "PGHR13"
PGHR13_VERIFIER_CONTRACT = "Pghr13Verifier"
PGHR13_MIXER_CONTRACT = "Pghr13Mixer"

# OTSCHNORR constants
SCHNORR_VERIFIER_CONTRACT = "OTSchnorrVerifier"

# RPC endpoint
RPC_ENDPOINT = "localhost:50051"

# Web3 HTTP provider
WEB3_HTTP_PROVIDER = "http://localhost:8545"

# Merkle tree depth
ZETH_MERKLE_TREE_DEPTH = 4

# Nb of input notes
JS_INPUTS = 2

# Nb of output notes
JS_OUTPUTS = 2

# Size of public values (v_in and v_out)
SIZE_VALUE = 64

# Length of the hash digest used for commitment and prf generation
DIGEST_LENGTH = 256

# Order of the largest prime order subgroup of the elliptic curve group
# See: https://github.com/ethereum/go-ethereum/blob/master/crypto/bn256/cloudflare/constants.go#L23
ZETH_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617

# Nb Field size
FIELD_CAPACITY = 253 # = floor(log(ZETH_PRIME, 2))
