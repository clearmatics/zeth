# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.core.zksnark import ExtendedProof, Groth16
from zeth.core.mixer_client import MixParameters
from zeth.core.encryption import generate_encryption_keypair, encrypt
from zeth.core.signing import gen_signing_keypair, sign
from zeth.core.constants import NOTE_LENGTH_BYTES
from unittest import TestCase
from secrets import token_bytes


class TestMixerClient(TestCase):

    def test_mix_parameters(self) -> None:
        zksnark = Groth16()

        ext_proof = ExtendedProof(
            proof=Groth16.proof_from_json_dict({
                "a": ["1234", "2345"],
                "b": [["3456", "4567"], ["5678", "6789"]],
                "c": ["789a", "89ab"],
            }),
            inputs=[
                "9abc",
                "abcd",
                "bcde",
                "cdef",
            ])
        public_data = [1234, 4321, 9876, 6789]
        sig_keypair = gen_signing_keypair()
        sig_vk = sig_keypair.vk
        sig = sign(sig_keypair.sk, bytes.fromhex("00112233"))
        receiver_enc_keypair = generate_encryption_keypair()
        ciphertexts = [
            encrypt(token_bytes(NOTE_LENGTH_BYTES), receiver_enc_keypair.k_pk),
            encrypt(token_bytes(NOTE_LENGTH_BYTES), receiver_enc_keypair.k_pk),
        ]

        mix_params = MixParameters(
            ext_proof, public_data, sig_vk, sig, ciphertexts)

        mix_params_json = mix_params.to_json()
        mix_params_2 = MixParameters.from_json(zksnark, mix_params_json)

        self.assertEqual(
            mix_params.extended_proof.to_json_dict(),
            mix_params_2.extended_proof.to_json_dict())
        self.assertEqual(
            mix_params.signature_vk.to_bytes(),
            mix_params_2.signature_vk.to_bytes())
        self.assertEqual(mix_params.signature, mix_params_2.signature)
        self.assertEqual(mix_params.ciphertexts, mix_params_2.ciphertexts)
