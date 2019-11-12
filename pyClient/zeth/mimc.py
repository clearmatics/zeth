from zeth.constants import ZETH_PRIME, MIMC_MT_SEED
from Crypto.Hash import keccak
from typing import Any, Iterable, Optional, Union


class MiMC7:
    def __init__(
            self,
            seed: str = MIMC_MT_SEED,
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
            seed: Optional[str] = None,
            rounds: int = 91) -> int:
        seed = seed or self.seed
        res = message % self.prime
        key = ek % self.prime

        # In the paper the first round constant is set to 0
        res = self.mimc_round(res, key, 0)

        round_constant: int = keccak_256(seed)  # type: ignore

        for _ in range(rounds - 1):
            round_constant = keccak_256(round_constant)  # type: ignore
            res = self.mimc_round(res, key, round_constant)

        return (res + key) % self.prime

    def mimc_mp(self, x: int, y: int) -> int:
        x = x % self.prime
        y = y % self.prime
        return (self.mimc_encrypt(x, y, self.seed) + x + y) % self.prime


def to_bytes(*args: Union[int, str]) -> Iterable[bytes]:
    for arg in args:
        if isinstance(arg, str):
            yield arg.encode('ascii')
        elif (not isinstance(arg, int)) and hasattr(arg, 'to_bytes'):
            # for 'F_p' or 'FQ' class etc.
            yield arg.to_bytes('big')  # type: ignore
        elif isinstance(arg, bytes):
            yield arg
        else:
            # Try conversion to integer first?
            yield int(arg).to_bytes(32, 'big')  # type: ignore


def to_int(value: Any) -> int:
    if not isinstance(value, int):
        if isinstance(value, bytes):
            return int.from_bytes(value, "big")
        if isinstance(value, str):
            return int.from_bytes(bytes(value, "utf8"), "big")
        return -1
    return value


def keccak_256(data: Union[int, str]) -> int:
    data_bytes = b''.join(to_bytes(data))
    h = keccak.new(digest_bits=256)
    h.update(data_bytes)
    hashed = h.digest()
    return int.from_bytes(hashed, 'big')
