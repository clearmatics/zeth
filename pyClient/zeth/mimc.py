from zeth.constants import ZETH_PRIME
from Crypto.Hash import keccak
from typing import Any, Tuple, Iterable, cast


def keccak_256(data: bytes) -> keccak.Keccak_Hash:
    return keccak.new(data, digest_bits=256)


class MiMC7:
    def __init__(
            self,
            seed: str = "clearmatics_mt_seed",
            prime: int = ZETH_PRIME):
        self.prime = prime
        self.seed = seed

    def mimc_round(self, message: int, key: int, rc: int) -> int:
        xored = (message + key + rc) % self.prime
        return xored ** 7 % self.prime

    def mimc_encrypt(
            self,
            message: int,
            ek: int,
            seed: str = "clearmatics_mt_seed",
            rounds: int = 91) -> int:
        res = message % self.prime
        key = ek % self.prime

        # In the paper the first round constant is set to 0
        res = self.mimc_round(res, key,  0)

        round_constant: int = sha3_256(seed)  # type: ignore

        for i in range(rounds - 1):
            round_constant = sha3_256(round_constant)  # type: ignore
            res = self.mimc_round(res, key, round_constant)

        return (res + key) % self.prime

    def mimc_mp(self, x: int, y: int) -> int:
        x = x % self.prime
        y = y % self.prime
        return (self.mimc_encrypt(x, y, self.seed) + x + y) % self.prime


def to_bytes(*args: Tuple[Any]) -> Iterable[bytes]:
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


def to_int(value: Any) -> int:
    if type(value) != int:
        if type(value) == bytes:
            return int.from_bytes(value, "big")
        elif type(value) == str:
            return int.from_bytes(bytes(value, "utf8"), "big")
        else:
            return -1
    else:
        return value


def sha3_256(*args: Tuple[Any]) -> int:
    data = b''.join(to_bytes(*args))
    hashed = keccak_256(data).digest()
    return int.from_bytes(hashed, 'big')

# Tests


def test_round() -> None:
    m = MiMC7("Clearmatics")
    x = 340282366920938463463374607431768211456
    k = 28948022309329048855892746252171976963317496166410141009864396001978282409983
    c = 14220067918847996031108144435763672811050758065945364308986253046354060608451
    assert m.mimc_round(x, k, c) == 7970444205539657036866618419973693567765196138501849736587140180515018751924
    print("Test Round passed")


def test_sha3() -> None:
    assert sha3_256(cast(Tuple[Any], b"Clearmatics")) == \
        14220067918847996031108144435763672811050758065945364308986253046354060608451
    print("Test Sha3 passed")


def main() -> int:
    test_round()
    test_sha3()

    # Generating test vector for mimc encrypt
    m = MiMC7("clearmatics_mt_seed")
    ct = m.mimc_encrypt(
      3703141493535563179657531719960160174296085208671919316200479060314459804651,
      15683951496311901749339509118960676303290224812129752890706581988986633412003)
    print("Ciphertext:")
    print(ct)

    # Generating test vector for MimC Hash
    m = MiMC7("clearmatics_mt_seed")
    hash = m.mimc_mp(
        3703141493535563179657531719960160174296085208671919316200479060314459804651,
        15683951496311901749339509118960676303290224812129752890706581988986633412003)
    print("Hash result:")
    print(hash)

    # Generating test vectors for testing the MimC Merkle Tree contract
    print("Test vector for testMimCHash")

    res = m.mimc_mp(0, 0)
    print("Level 2")
    print(res)

    res = m.mimc_mp(res, res)
    print("Level 1")
    print(res)

    res = m.mimc_mp(res, res)
    print("Root")
    print(res)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
