#!/usr/bin/env python3

# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.core.constants import \
    JS_INPUTS, ZETH_PUBLIC_UNIT_VALUE, ZETH_MERKLE_TREE_DEPTH
from zeth.core.prover_client import ProverConfiguration
from zeth.core.zksnark import get_zksnark_provider
from zeth.core.utils import EtherValue, hex_list_to_uint256_list
from zeth.core.signing import SigningKeyPair
from zeth.core.mixer_client import MixParameters, MixerClient, joinsplit_sign, \
    mix_parameters_to_dispatch_parameters
import zeth.core.contracts as contracts
import tests.test_pairing as test_pairing
import test_commands.mock as mock
from unittest import TestCase
from typing import Dict, Optional, Any

# pylint: disable=line-too-long

# TODO: These tests are specific to AltBN128MixerBase, however the mixer that
# is deployed is a function of the currently running prover server. Change this
# to deploy a test contract (inheriting from AltBN128MixerBase) which then
# calls the given methods with the expected data (i.e. remove the requirement
# for a running prover_server, and support type-checking of the test code
# against interface changes).

# Primary inputs

ROOT = 0

NULLIFIERS = [
    int(
        "0010000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000011000",
        2),
    int(
        "0100000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000100001",
        2),
]

COMMITMENTS = [
    int(
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000001",
        2),
    int(
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000010",
        2),
]

HSIG = int(
    "1010000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000101111",
    2)

HTAGS = [
    int(
        "1100000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000110010",
        2),
    int(
        "1110000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000111011",
        2),
]

VPUB = (0x5555555555555500, 0x00eeeeeeeeeeeeee)

# 255                                         128         64           0
# |<empty>|<h_sig>|<nullifiers>|<msg_auth_tags>|<v_pub_in>)|<v_pub_out>|
RESIDUAL_BITS = int(
    "101"  # h_sig
    "010"  # nf_1
    "001"  # nf_0
    "111"  # htag_1
    "110"  # htag_0
    "0101010101010101010101010101010101010101010101010101010100000000"  # vin
    "0000000011101110111011101110111011101110111011101110111011101110",  # vout
    2)

PACKED_PRIMARY_INPUTS = \
    [ROOT] + COMMITMENTS + NULLIFIERS + [HSIG] + HTAGS + [RESIDUAL_BITS]

PROVER_CONFIG = ProverConfiguration(
    zksnark_name="GROTH16",
    pairing_parameters=test_pairing.ALT_BN128_PAIRING)

VK_HASH = 1

MIX_PARAMETERS_VIN = EtherValue(200)

# Signing key and mix parameters obtained from the test_zeth_cli scripts. See
# scripts/test_zeth_cli.

MIX_PARAMETERS_SIGNING_KEYPAIR = SigningKeyPair.from_json_dict({
    "sk": {
        "psk": "19cca1b1f0a3389880a51c5dad6da41885f1aa2a85d3895a7ee57cd93b91d92d",
        "ssk_y": "091f01468410d87af0308ca0e27580de7ce59b5771dbadf47c1831dcbd8d2ec2",  # noqa
        "ssk_y_g1": {
            "x": "0f9a984abbea6e4f61a927d7fc7aa1ac997fd98edc7c57f43888ec025ba58de9",  # noqa
            "y": "08c7c8dcea11753d8ce4c77b70f3da5f497f3ecd6745e108d5080fae9936e66f",  # noqa
        },
    },
    "vk": {
        "ppk": {
            "x": "2142d7e3c856f37296366fbde935161d62f3e51685d91e541b2c44df830e9fd7",  # noqa
            "y": "2da8644fa7c59b29d23d6a16591838dbfee30d281e0837dcdbf18fcca9eea54a",  # noqa
        },
        "spk": {
            "x": "0f9a984abbea6e4f61a927d7fc7aa1ac997fd98edc7c57f43888ec025ba58de9",  # noqa
            "y": "08c7c8dcea11753d8ce4c77b70f3da5f497f3ecd6745e108d5080fae9936e66f",  # noqa
        }
    }
})

MIX_PARAMETERS_DICT: Dict[str, Any] = {
    "extended_proof": {
        "proof": {
            "a": ["0x022fc050ed6c153dcbfb1f18fdffd86e99e76bf9f9ceeb74b921be467df44d4f", "0x0473a961d1990f60799eff2bc2b8cb33cbeb4644fb87c3a2b5fa16b3cb662c80"],  # noqa
            "b": [["0x14f5918361b5f09955f822b378d4cb363265cdbf43ac3eae9594f93b25c740a5", "0x1caab696a800e657558485215194cfb5915ddea3fc9001537d1811fba04068b3"], ["0x1e2552d77e7af276b2d92a3a61e4fdeab0487af08c63f65902de91a7d5a21824", "0x0f1380685f4aba028770692dd3ccdbdc3ba4758482344784e34cee54f9f8b4a1"]],  # noqa
            "c": ["0x2bc2e2bfe646a10d5f220b21b5149bf724a8d34fd5f713775095b65f108ce90e", "0x1dc8f1acf805daf143686385f17ad06f4768e600555abbd1b21b65393ff196e8"],  # noqa
        },
        "inputs": [
            "0x01e202cf4ac3721b9bfd398ec65969c811f32cb1e46df020337e9fc2fda0f014",
            "0x19917fa2eea86a9082ef7766c7e7737c4153a499796baf01f68787d267b278cc",
            "0x15e8587966977c5c5430cb9e84e686ee5f327ec2651a86c978ed7973ee8cd4b9",
            "0x10c16790b950db6a0fd94ee66015d37e506e7a970cbbc962325839188ddd4875",
            "0x029eae0aed749a8e05565a5228b825ac6e9a8ad034dbc7b674786783bae64be2",
            "0x0945c9391ddd49eb41234a2249c78203040bf337ab27e1dd7a3c112010bc160d",
            "0x03fb8ae204697d92aa1cb161a8fd533d62c9d4113db1de78547aa330f8148510",
            "0x03dc42c147cc05ef3e5c3aae875a860dd73e7be3bc9578499a171f52cc5949e7",
            "0x00000000000000000000000000001663000000000bebc2000000000000000000",
        ],
    },
    "signature_vk": [
        "15044425925993845483393126099570793906913594542449620874334342139863918092247",  # noqa
        "20651600815268664951459086661967759114548020657233676039273591752689993033034",  # noqa
        "7057838256995470367292750127543080978509804434882431937449883270040531602921",  # noqa
        "3971491659664912517391994943672743161518296354269326311016522861877057218159",  # noqa
    ],
    "signature": "10654946530806799981365073476369904106395106992608919376340445285630856100688",  # noqa
    "ciphertexts": [
        "f976f9b61cb10cb3275c7dc5941c314e8a6f894e312426f005322fdc7cc7ec3ba895de2033c09e19e35720f416ac8cbfd131048e38e244a56bf0ade2a9367c5fbf8a7976f59d270f590f6eb5ab9fbf35afa4550866837a29553bb6610cd0a5f57ca5b9ae6cf1d536ace98f1a58b7fde2030d013a6c4869875c3689ffbe535dbe2dcaad2b7f396eb2124d2d328a88e54c4ff524e417f1b57b",  # noqa
        "31424a6831ff6b7b5948ba5d7472030cf3427eeb730e974475d756995e48a1266b4ba550b6e28eb8b6b6367b3e7b7308ff2c1d641adcebaa818d3f325869bc66889c5e269673acbdfaa481feb5c57ef0ecccdcb58a8293dd347cf9a8423717dbea48119ebdc5b660f94a9ad1f43848299e02bcf07c59d3c594d65a486aa850c7adb7793673b965dfe27309631de9cad66638669afc16abea",  # noqa
    ],
}

WEB3: Optional[Any] = None

ETH: Optional[Any] = None

MIXER_INSTANCE: Any = None

MIXER_CLIENT: Optional[MixerClient] = None


class TestAltBN128MixerBaseContract(TestCase):

    @staticmethod
    def setUpClass() -> None:
        print("Deploying AltBN128MixerBase_test.sol")
        web3, eth = mock.open_test_web3()
        deployer_eth_address = eth.accounts[0]
        _mixer_interface, mixer_instance = mock.deploy_contract(
            eth,
            deployer_eth_address,
            "AltBN128MixerBase_test",
            {
                'mk_depth': ZETH_MERKLE_TREE_DEPTH,
                'permitted_dispatcher': deployer_eth_address,
                'vk_hash': VK_HASH,
            })

        global WEB3  # pylint: disable=global-statement
        WEB3 = web3
        global ETH  # pylint: disable=global-statement
        ETH = eth
        global MIXER_INSTANCE  # pylint: disable=global-statement
        MIXER_INSTANCE = mixer_instance
        global MIXER_CLIENT  # pylint: disable=global-statement
        MIXER_CLIENT = MixerClient(web3, PROVER_CONFIG, MIXER_INSTANCE)

    def test_assemble_nullifiers(self) -> None:
        # Test retrieving nullifiers
        for i in range(JS_INPUTS):
            res = MIXER_INSTANCE.functions.\
                assemble_nullifier_test(i, PACKED_PRIMARY_INPUTS).call()
            val = int.from_bytes(res, byteorder="big")
            self.assertEqual(NULLIFIERS[i], val)

    def test_assemble_hsig(self) -> None:
        # Test retrieving hsig
        res = MIXER_INSTANCE.functions.\
            assemble_hsig_test(PACKED_PRIMARY_INPUTS).call()
        hsig = int.from_bytes(res, byteorder="big")
        self.assertEqual(HSIG, hsig)

    def test_assemble_vpub(self) -> None:
        # Test retrieving public values
        v_in, v_out = MIXER_INSTANCE.functions.assemble_public_values_test(
            PACKED_PRIMARY_INPUTS[-1]).call()
        v_in_expect = VPUB[0] * ZETH_PUBLIC_UNIT_VALUE
        v_out_expect = VPUB[1] * ZETH_PUBLIC_UNIT_VALUE
        self.assertEqual(v_in_expect, v_in)
        self.assertEqual(v_out_expect, v_out)

    def test_dispatch_call(self) -> None:
        # Test calling dispatch. Use the "dummy" MixParameters and signing key,
        # recreating the signature for the sender.

        zksnark = get_zksnark_provider(PROVER_CONFIG.zksnark_name)
        sender_eth_address = ETH.accounts[0]  # type: ignore
        mix_params = MixParameters.from_json_dict(zksnark, MIX_PARAMETERS_DICT)
        new_signature = joinsplit_sign(
            zksnark=get_zksnark_provider(PROVER_CONFIG.zksnark_name),
            pp=PROVER_CONFIG.pairing_parameters,
            signing_keypair=MIX_PARAMETERS_SIGNING_KEYPAIR,
            sender_eth_address=sender_eth_address,
            ciphertexts=mix_params.ciphertexts,
            extproof=mix_params.extended_proof,
            for_dispatch_call=True)
        mix_params.signature = new_signature

        nested_inputs = hex_list_to_uint256_list(mix_params.extended_proof.inputs)
        nested_parameters = mix_parameters_to_dispatch_parameters(mix_params)
        mixer_call = MIXER_INSTANCE.functions.dispatch(
            VK_HASH, nested_inputs, nested_parameters)

        # Broadcast transaction and wait for the result.
        tx_id = contracts.send_contract_call(
            web3=WEB3,
            call=mixer_call,
            sender_eth_addr=sender_eth_address,
            sender_eth_private_key=None,
            value=MIX_PARAMETERS_VIN)
        tx_receipt = ETH.waitForTransactionReceipt(tx_id, 10000)  # type: ignore
        status = tx_receipt.status
        self.assertEqual(True, status)
