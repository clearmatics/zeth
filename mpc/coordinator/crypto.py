#!/usr/bin/env python3

import ecdsa                    # type: ignore
from hashlib import blake2b


HASH = blake2b
HASH_LENGTH = 64
CURVE = ecdsa.NIST521p
VerificationKey = ecdsa.VerifyingKey
SigningKey = ecdsa.SigningKey
Signature = bytes


def export_digest(digest: bytes) -> str:
    """
    Digest to string
    """
    assert(len(digest) == HASH_LENGTH)
    return digest.hex()


def import_digest(digest_s: str) -> bytes:
    """
    Digest from string
    """
    if len(digest_s) != 2 * HASH_LENGTH:
        raise Exception(f"unexpected digest string length: {len(digest_s)}")
    assert len(digest_s) == 2 * HASH_LENGTH
    return bytes.fromhex(digest_s)


def import_contribution_digest(digest_str: str) -> bytes:
    """
    Digest from string, as output by contribution tools: abcdef01 23456789 ...
    """
    assert(len(digest_str) == 16 * 9)
    digest = bytearray(HASH_LENGTH)
    for i in range(0, 4):
        str_offset = i * 4 * 9
        line = digest_str[str_offset:str_offset + 4*9]
        words = line.rstrip().split(" ")
        digest_offset = 16 * i
        digest[digest_offset:digest_offset+4] = bytes.fromhex(words[0])
        digest[digest_offset+4:digest_offset+8] = bytes.fromhex(words[1])
        digest[digest_offset+8:digest_offset+12] = bytes.fromhex(words[2])
        digest[digest_offset+12:digest_offset+16] = bytes.fromhex(words[3])
    assert(len(digest) == HASH_LENGTH)
    return digest


def generate_signing_key() -> ecdsa.SigningKey:
    return ecdsa.SigningKey.generate(curve=CURVE)


def export_signing_key(sk: ecdsa.SigningKey) -> bytes:
    return sk.to_der()


def import_signing_key(sk_b: bytes) -> ecdsa.SigningKey:
    return ecdsa.SigningKey.from_der(sk_b)


def get_verification_key(sk: ecdsa.SigningKey) -> ecdsa.VerifyingKey:
    return sk.get_verifying_key()


def export_verification_key(vk: ecdsa.VerifyingKey) -> str:
    return vk.to_der().hex()


def import_verification_key(vk_s: str) -> ecdsa.VerifyingKey:
    return ecdsa.VerifyingKey.from_der(bytes.fromhex(vk_s))


def export_signature(sig: bytes) -> str:
    return sig.hex()


def import_signature(sig_s: str) -> bytes:
    return bytes.fromhex(sig_s)


def read_contribution_digest(file_name: str) -> bytes:
    with open(file_name, "r") as digest_f:
        digest_str = digest_f.read()
    return import_contribution_digest(digest_str)


def sign(sk: ecdsa.SigningKey, digest: bytes) -> bytes:
    return sk.sign_digest(digest)


def verify(sig: bytes, vk: ecdsa.VerifyingKey, digest: bytes) -> bool:
    return vk.verify_digest(sig, digest)
