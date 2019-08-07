from zethMimc import sha3_256

# C++ code generation for constants of a given seed see src/circuits/mimc/round_constants.tcc

try:
    # pysha3
    from sha3 import keccak_256
except ImportError:
    # pycryptodome
    from Crypto.Hash import keccak
    keccak_256 = lambda *args: keccak.new(digest_bits=256)

print("round_constants.push_back(FieldT(\"0\"));")

# First hash is skipped
res = sha3_256(b"clearmatics_mt_seed")
# We generate the round constants for the remaining 90 rounds (total number of rounds = 91)
for i in range(90):
    res = sha3_256(res)
    print("round_constants.push_back(FieldT(\"" + str(res) + "\"));")
