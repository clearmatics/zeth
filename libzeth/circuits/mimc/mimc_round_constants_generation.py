# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

try:
    # pysha3
    from sha3 import keccak_256
except ImportError:
    # pycryptodome
    from Crypto.Hash import keccak
    keccak_256 = lambda *args: keccak.new(digest_bits=256)

# Functions taken from zeth/client/zethMimc.py
def to_bytes(*args):
    for i, _ in enumerate(args):
        if isinstance(_, str):
            yield _.encode('ascii')
        elif not isinstance(_, int) and hasattr(_, 'to_bytes'):
            # for 'F_p' or 'FQ' class etc.
            yield _.to_bytes('big')
        elif isinstance(_, bytes):
            yield _
        else:
            # Try conversion to integer first?
            yield int(_).to_bytes(32, 'big')

def sha3_256(*args):
    data = b''.join(to_bytes(*args))
    hashed = keccak_256(data).digest()
    return int.from_bytes(hashed, 'big')

# C++ code generation for constants of a given seed see src/circuits/mimc/round_constants.tcc
def main():
    print("round_constants.push_back(FieldT(\"0\"));")

    # First hash is skipped
    res = sha3_256(b"clearmatics_mt_seed")
    # We generate the round constants for the remaining 90 rounds (total number of rounds = 91)
    for i in range(90):
        res = sha3_256(res)
        print("round_constants.push_back(FieldT(\"" + str(res) + "\"));")

if __name__ == "__main__":
    import sys
    sys.exit(main())
