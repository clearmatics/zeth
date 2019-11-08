from nacl.public import PrivateKey  # type: ignore
import nacl.encoding  # type: ignore
from typing import Tuple, List


def gen_keys_utility(
        to_print: bool = False) -> Tuple[List[bytes], List[bytes], List[bytes]]:
    """
    Generates private/public keys (kP, k) over Curve25519 for Alice, Bob and
    Charlie
    """

    # Encoder
    encoder = nacl.encoding.RawEncoder

    # Alice
    sk_alice = PrivateKey.generate()
    sk_alice_bytes = sk_alice.encode(encoder)
    pk_alice_bytes = sk_alice.public_key.encode(encoder)

    alice_keys_bytes = [pk_alice_bytes, sk_alice_bytes]

    # Bob
    sk_bob = PrivateKey.generate()
    sk_bob_bytes = sk_bob.encode(encoder)
    pk_bob_bytes = sk_bob.public_key.encode(encoder)

    bob_keys_bytes = [pk_bob_bytes, sk_bob_bytes]

    # Charlie
    sk_charlie = PrivateKey.generate()
    sk_charlie_bytes = sk_charlie.encode(encoder)
    pk_charlie_bytes = sk_charlie.public_key.encode(encoder)

    charlie_keys_bytes = [pk_charlie_bytes, sk_charlie_bytes]

    if to_print:
        print("Alice")
        print(pk_alice_bytes)
        print(sk_alice_bytes)

        print("Bob")
        print(pk_bob_bytes)
        print(sk_bob_bytes)

        print("Charlie")
        print(pk_charlie_bytes)
        print(sk_charlie_bytes)

    return alice_keys_bytes, bob_keys_bytes, charlie_keys_bytes
