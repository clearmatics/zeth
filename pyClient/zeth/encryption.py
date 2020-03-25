#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from nacl.public import PrivateKey, PublicKey, Box  # type: ignore
import nacl.encoding  # type: ignore
from typing import NewType

# Thin wrapper around the nacl PublicKey and PrivateKey.  Note nacl doesn't
# include much type information, so we try to enforce strict types.


# Represents a secret key for encryption
EncryptionSecretKey = NewType('EncryptionSecretKey', object)


def encode_encryption_secret_key(sk: EncryptionSecretKey) -> bytes:
    return sk.encode(encoder=nacl.encoding.RawEncoder)  # type: ignore


def decode_encryption_secret_key(sk_bytes: bytes) -> EncryptionSecretKey:
    return EncryptionSecretKey(
        PrivateKey(sk_bytes, encoder=nacl.encoding.RawEncoder))


def encryption_secret_key_as_hex(sk: EncryptionSecretKey) -> str:
    return encode_encryption_secret_key(sk).hex()


def encryption_secret_key_from_hex(sk_hex: str) -> EncryptionSecretKey:
    return decode_encryption_secret_key(bytes.fromhex(sk_hex))


def generate_encryption_secret_key() -> EncryptionSecretKey:
    return PrivateKey.generate()  # type: ignore


# Public key for decryption
EncryptionPublicKey = NewType('EncryptionPublicKey', object)


def encode_encryption_public_key(pk: EncryptionPublicKey) -> bytes:
    return pk.encode(encoder=nacl.encoding.RawEncoder)  # type: ignore


def decode_encryption_public_key(pk_data: bytes) -> EncryptionPublicKey:
    return EncryptionPublicKey(
        PublicKey(pk_data, encoder=nacl.encoding.RawEncoder))


def encryption_public_key_as_hex(pk: EncryptionPublicKey) -> str:
    return encode_encryption_public_key(pk).hex()


def encryption_public_key_from_hex(pk_str: str) -> EncryptionPublicKey:
    return decode_encryption_public_key(bytes.fromhex(pk_str))


def get_encryption_public_key(
        enc_secret: EncryptionSecretKey) -> EncryptionPublicKey:
    """
    Derive the public key from the secret key
    """
    return enc_secret.public_key  # type: ignore


class EncryptionKeyPair:
    """
    Key-pair for encrypting joinsplit notes.
    """
    def __init__(self, k_sk: EncryptionSecretKey, k_pk: EncryptionPublicKey):
        self.k_pk: EncryptionPublicKey = k_pk
        self.k_sk: EncryptionSecretKey = k_sk


def generate_encryption_keypair() -> EncryptionKeyPair:
    sk = generate_encryption_secret_key()
    return EncryptionKeyPair(sk, get_encryption_public_key(sk))


def encrypt(message: str, pk_receiver: PublicKey, sk_sender: PrivateKey) -> bytes:
    """
    Encrypts a string message by using valid ec25519 public key and
    private key objects. See: https://pynacl.readthedocs.io/en/stable/public/
    """
    # Init encryption box instance
    encryption_box = Box(sk_sender, pk_receiver)

    # Encode str message to bytes
    message_bytes = message.encode('utf-8')

    # Encrypt the message. The nonce is chosen randomly.
    encrypted = encryption_box.encrypt(
        message_bytes,
        encoder=nacl.encoding.RawEncoder)

    # Need to cast to the parent class Bytes of nacl.utils.EncryptedMessage
    # to make it accepted from `Mix` Solidity function
    return bytes(encrypted)


def decrypt(
        encrypted_message: bytes,
        pk_sender: PublicKey,
        sk_receiver: PrivateKey) -> str:
    """
    Decrypts a string message by using valid ec25519 public key and private key
    objects.  See: https://pynacl.readthedocs.io/en/stable/public/
    """
    assert(isinstance(pk_sender, PublicKey)), \
        f"PublicKey: {pk_sender} ({type(pk_sender)})"
    assert(isinstance(sk_receiver, PrivateKey)), \
        f"PrivateKey: {sk_receiver} ({type(sk_receiver)})"

    # Init encryption box instance
    decryption_box = Box(sk_receiver, pk_sender)

    # Check integrity of the ciphertext and decrypt it
    message = decryption_box.decrypt(encrypted_message)
    return str(message, encoding='utf-8')
