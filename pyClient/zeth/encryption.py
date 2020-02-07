#!/usr/bin/env python3

# Copyright (c) 2015-2019 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from nacl.public import PrivateKey, PublicKey  # type: ignore
import nacl.encoding  # type: ignore
from typing import NewType

# Thin wrapper around the nacl PublicKey and PrivateKey.  Note nacl doesn't
# include much type information, so we try to enforce strict types.


# Represents a PublicKey from
EncryptionSecretKey = NewType('EncryptionSecretKey', object)


# EncryptionPublicKey = PublicKey
EncryptionPublicKey = NewType('EncryptionPublicKey', object)


class EncryptionKeyPair:
    """
    Key-pair for encrypting joinsplit notes.
    """
    def __init__(self, k_sk: EncryptionSecretKey, k_pk: EncryptionPublicKey):
        self.k_pk: EncryptionPublicKey = k_pk
        self.k_sk: EncryptionSecretKey = k_sk


def encode_encryption_public_key(pk: EncryptionPublicKey) -> bytes:
    return pk.encode(encoder=nacl.encoding.RawEncoder)  # type: ignore


def encode_encryption_secret_key(sk: EncryptionSecretKey) -> bytes:
    return sk.encode(encoder=nacl.encoding.RawEncoder)  # type: ignore


def encryption_secret_key_as_hex(sk: EncryptionSecretKey) -> str:
    return sk.encode(encoder=nacl.encoding.RawEncoder).hex()  # type: ignore


def encryption_secret_key_from_hex(pk_str: str) -> EncryptionSecretKey:
    return EncryptionSecretKey(
        PrivateKey(bytes.fromhex(pk_str), encoder=nacl.encoding.RawEncoder))


def decode_encryption_public_key(pk_data: bytes) -> EncryptionPublicKey:
    return EncryptionPublicKey(
        PublicKey(pk_data, encoder=nacl.encoding.RawEncoder))


def encryption_public_key_as_hex(pk: EncryptionPublicKey) -> str:
    return encode_encryption_public_key(pk).hex()


def encryption_public_key_from_hex(pk_str: str) -> EncryptionPublicKey:
    return decode_encryption_public_key(bytes.fromhex(pk_str))


def get_encryption_public_key(
        enc_secret: EncryptionSecretKey) -> EncryptionPublicKey:
    return enc_secret.public_key  # type: ignore


def generate_encryption_secret_key() -> EncryptionSecretKey:
    return PrivateKey.generate()  # type: ignore


def generate_encryption_keypair() -> EncryptionKeyPair:
    sk = generate_encryption_secret_key()
    return EncryptionKeyPair(sk, get_encryption_public_key(sk))
