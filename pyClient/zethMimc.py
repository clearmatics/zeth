from random import randint

try:
    # pysha3
    from sha3 import keccak_256
except ImportError:
    # pycryptodome
    from Crypto.Hash import keccak
    keccak_256 = lambda *args: keccak.new(digest_bits=256)

from zethConstants import ZETH_MIMC_PRIME

class MiMC7:
    def __init__(self, seed="clearmatics_mt_seed", prime=ZETH_MIMC_PRIME):
        self.prime = prime
        self.seed = seed

    def mimc_round(self, message, key, rc):
        xored = (message + key + rc) % self.prime
        return xored ** 7 % self.prime

    def mimc_encrypt(self, message, ek, seed = "clearmatics_mt_seed", rounds = 91):
        res = message % self.prime
        key = ek % self.prime

        #In the paper the first round constant is set to 0
        res = self.mimc_round(res, key,  0)

        round_constant = sha3_256(seed)

        for i in range(rounds - 1):
            round_constant = sha3_256(round_constant)
            res = self.mimc_round(res, key, round_constant)

        return (res + key) % self.prime

    def mimc_mp(self, x, y):

        x = x % self.prime
        y = y % self.prime
        return (self.mimc_encrypt(x, y, self.seed) + x + y) % self.prime

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

def to_int(value):
    if type(value) != int:
        if type(value) == bytes:
            return int.from_bytes(value, "big")
        elif type(value) == str:
            return int.from_bytes(bytes(value, "utf8"), "big")
        else:
            return -1
    else :
        return value

def sha3_256(*args):
    data = b''.join(to_bytes(*args))
    hashed = keccak_256(data).digest()
    return int.from_bytes(hashed, 'big')

# Tests

def test_round():
    m = MiMC7("Clearmatics")
    x = 340282366920938463463374607431768211456
    k = 28948022309329048855892746252171976963317496166410141009864396001978282409983
    c = 14220067918847996031108144435763672811050758065945364308986253046354060608451
    assert m.mimc_round(x,k,c) == 7970444205539657036866618419973693567765196138501849736587140180515018751924
    print("Test Round passed")

def test_sha3():
  assert sha3_256(b"Clearmatics") == 14220067918847996031108144435763672811050758065945364308986253046354060608451
  print("Test Sha3 passed")

def main():
    test_round()
    test_sha3()

    # Generating test vector for mimc encrypt
    m = MiMC7("clearmatics_mt_seed")
    ct = m.mimc_encrypt(
      3703141493535563179657531719960160174296085208671919316200479060314459804651,
      15683951496311901749339509118960676303290224812129752890706581988986633412003)
    print("Ciphertext:")
    print(ct)

    #Generating test vector for MimC Hash
    m = MiMC7("clearmatics_mt_seed")
    hash = m.mimc_mp(
      3703141493535563179657531719960160174296085208671919316200479060314459804651,
      15683951496311901749339509118960676303290224812129752890706581988986633412003)
    print("Hash result:")
    print(hash)

    # Generating test vectors for testing the MimC Merkle Tree contract
    print("Test vector for testMimCHash")

    res = m.mimc_mp(
      0,0)
    print("Level 2")
    print(res)

    res = m.mimc_mp(
      res,res)
    print("Level 1")
    print(res)

    res = m.mimc_mp(
      res,res)
    print("Root")
    print(res)

if __name__ == "__main__":
    import sys
    sys.exit(main())
