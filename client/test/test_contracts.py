# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

"""
Tests for zeth.core.contracts module
"""

from zeth.core.contracts import MixParameters
from zeth.core.encryption import generate_encryption_keypair, encrypt
from zeth.core.signing import gen_signing_keypair, sign, encode_vk_to_bytes
from zeth.core.constants import NOTE_LENGTH_BYTES
from unittest import TestCase
from secrets import token_bytes


class TestContracts(TestCase):

    def test_mix_parameters(self) -> None:

        ext_proof = {
            "a": ["1234", "2345"],
            "b": [["3456", "4567"], ["5678", "6789"]],
            "c": ["789a", "89ab"],
            "inputs": [
                "9abc",
                "abcd",
                "bcde",
                "cdef",
            ],
        }
        sig_keypair = gen_signing_keypair()
        sig_vk = sig_keypair.vk
        sig = sign(sig_keypair.sk, bytes.fromhex("00112233"))
        receiver_enc_keypair = generate_encryption_keypair()
        ciphertexts = [
            encrypt(token_bytes(NOTE_LENGTH_BYTES), receiver_enc_keypair.k_pk),
            encrypt(token_bytes(NOTE_LENGTH_BYTES), receiver_enc_keypair.k_pk),
        ]

        mix_params = MixParameters(ext_proof, sig_vk, sig, ciphertexts)

        mix_params_json = mix_params.to_json()
        mix_params_2 = MixParameters.from_json(mix_params_json)

        self.assertEqual(mix_params.extended_proof, mix_params_2.extended_proof)
        self.assertEqual(
            encode_vk_to_bytes(mix_params.signature_vk),
            encode_vk_to_bytes(mix_params_2.signature_vk))
        self.assertEqual(mix_params.signature, mix_params_2.signature)
        self.assertEqual(mix_params.ciphertexts, mix_params_2.ciphertexts)
