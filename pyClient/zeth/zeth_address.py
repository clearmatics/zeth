# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from zeth.ownership import OwnershipPublicKey, OwnershipSecretKey, \
    OwnershipKeyPair, ownership_key_as_hex, gen_ownership_keypair, \
    ownership_public_key_from_hex, ownership_secret_key_from_hex
from zeth.encryption import \
    EncryptionKeyPair, EncryptionPublicKey, EncryptionSecretKey, \
    generate_encryption_keypair, encryption_public_key_as_hex, \
    encryption_public_key_from_hex, encryption_secret_key_as_hex, \
    encryption_secret_key_from_hex
import json
from typing import Dict, Any


class ZethAddressPub:
    """
    Public half of a zethAddress.  addr_pk = (a_pk and k_pk)
    """
    def __init__(self, a_pk: OwnershipPublicKey, k_pk: EncryptionPublicKey):
        self.a_pk: OwnershipPublicKey = a_pk
        self.k_pk: EncryptionPublicKey = k_pk

    def __str__(self) -> str:
        """
        Write the address as "<ownership-key-hex>:<encryption_key_hex>".
        (Technically the ":" is not required, since the first key is written
        with fixed length, but a separator provides some limited sanity
        checking).
        """
        a_pk_hex = ownership_key_as_hex(self.a_pk)
        k_pk_hex = encryption_public_key_as_hex(self.k_pk)
        return f"{a_pk_hex}:{k_pk_hex}"

    @staticmethod
    def parse(key_hex: str) -> ZethAddressPub:
        owner_enc = key_hex.split(":")
        if len(owner_enc) != 2:
            raise Exception("invalid JoinSplitPublicKey format")
        a_pk = ownership_public_key_from_hex(owner_enc[0])
        k_pk = encryption_public_key_from_hex(owner_enc[1])
        return ZethAddressPub(a_pk, k_pk)


class ZethAddressPriv:
    """
    Secret half of a zethAddress. addr_sk = (a_sk and k_sk)
    """
    def __init__(self, a_sk: OwnershipSecretKey, k_sk: EncryptionSecretKey):
        self.a_sk: OwnershipSecretKey = a_sk
        self.k_sk: EncryptionSecretKey = k_sk

    def to_json(self) -> str:
        return json.dumps(self._to_json_dict())

    @staticmethod
    def from_json(key_json: str) -> ZethAddressPriv:
        return ZethAddressPriv._from_json_dict(json.loads(key_json))

    def _to_json_dict(self) -> Dict[str, Any]:
        return {
            "a_sk": ownership_key_as_hex(self.a_sk),
            "k_sk": encryption_secret_key_as_hex(self.k_sk),
        }

    @staticmethod
    def _from_json_dict(key_dict: Dict[str, Any]) -> ZethAddressPriv:
        return ZethAddressPriv(
            ownership_secret_key_from_hex(key_dict["a_sk"]),
            encryption_secret_key_from_hex(key_dict["k_sk"]))


class ZethAddress:
    """
    Secret and public keys for both ownership and encryption (referrred to as
    "zethAddress" in the paper).
    """
    def __init__(
            self,
            a_pk: OwnershipPublicKey,
            k_pk: EncryptionPublicKey,
            a_sk: OwnershipSecretKey,
            k_sk: EncryptionSecretKey):
        self.addr_pk = ZethAddressPub(a_pk, k_pk)
        self.addr_sk = ZethAddressPriv(a_sk, k_sk)

    @staticmethod
    def from_key_pairs(
            ownership: OwnershipKeyPair,
            encryption: EncryptionKeyPair) -> ZethAddress:
        return ZethAddress(
            ownership.a_pk,
            encryption.k_pk,
            ownership.a_sk,
            encryption.k_sk)

    @staticmethod
    def from_secret_public(
            js_secret: ZethAddressPriv,
            js_public: ZethAddressPub) -> ZethAddress:
        return ZethAddress(
            js_public.a_pk, js_public.k_pk, js_secret.a_sk, js_secret.k_sk)

    def ownership_keypair(self) -> OwnershipKeyPair:
        return OwnershipKeyPair(self.addr_sk.a_sk, self.addr_pk.a_pk)


def generate_zeth_address() -> ZethAddress:
    ownership_keypair = gen_ownership_keypair()
    encryption_keypair = generate_encryption_keypair()
    return ZethAddress.from_key_pairs(ownership_keypair, encryption_keypair)
