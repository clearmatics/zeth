#!/usr/bin/env python3

# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.core.constants import \
    JS_INPUTS, ZETH_PUBLIC_UNIT_VALUE, ZETH_MERKLE_TREE_DEPTH
from zeth.core.prover_client import ProverConfiguration
from zeth.core.mimc import MiMC7
from zeth.core.input_hasher import InputHasher
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
        "psk": "0094c3bd11c967ded0712fb8aa833dc34c2e9e36a298f9bca75ca47b014f525b",
        "ssk_y": "26762feff4e7a0fe3f24182caf13b7709818bef122c3c8395c9cc71664925e2f",  # noqa
        "ssk_y_g1": {
            "x": "065495bf33403570a2c0bc2e5eb193dce106c82270ff72a68df1f3255019c37c",  # noqa
            "y": "12ef732b1e3d2afe712f6414eb68f4bdf0bd610e2bb199dd3ba9c3b7a49e34b3"  # noqa
        }
    },
    "vk": {
        "ppk": {
            "x": "03ff72a98c117f06526da1ecf485ddc46130bd97f6254678ab42dec92b9b533b",  # noqa
            "y": "1cd3a1f4ceb50551d9aec66aace46e630a3f6ff17106696ea1937ed573df82aa"  # noqa
        },
        "spk": {
            "x": "065495bf33403570a2c0bc2e5eb193dce106c82270ff72a68df1f3255019c37c",  # noqa
            "y": "12ef732b1e3d2afe712f6414eb68f4bdf0bd610e2bb199dd3ba9c3b7a49e34b3"  # noqa
        }
    }
})

MIX_PARAMETERS_DICT: Dict[str, Any] = {
    "extended_proof": {
        "proof": {
            "a": ["0x19bb99d61b9fd80f83c62301b8b49a7721ff4b9169304ee2e565967dff6c1f50","0x10cf81855def824e4ebb56df71e63271c9c24778fb5022db0c0e5266c5dac8c0"],  # noqa
            "b": [["0x2e8709a700d887a6d98b5c9e8154dd5aa2e8b37e176f7ee4dde254a4f01cb5f2", "0x26776b5283e39376a076ea7c9effd6ac6a2eb4e153ff33beccc50ea8c9ea77f6"], ["0x21d59a0bded4b94e995d1056fa08a5b44626f936bc7ce90556f288f558a4d6bc", "0x0dfe988bdd7e0f793df7d9d2136ccc2bd2fb9187eaf8f38430a7bfbdd0b7a8d2"]],  # noqa
            "c": ["0x2e0f8bec7eebad06fab29c558e96cbd68d2d729bca8b56640b0f00f93593e372", "0x2276552ff16f6b4e67c06495941c1988eca4bc60c9aa75cfc57098beb4f19156"]  # noqa
        },
        "inputs": ["0x01a5e7daab7ee618030641a16ae09ec8f67e121f209e6241b65924122f2ed94b"]  # noqa
    },
    "public_data": [
        "0x1e202cf4ac3721b9bfd398ec65969c811f32cb1e46df020337e9fc2fda0f014",
        "0xda3f23b4b07b9cf6ae3ddce133f7de065b1f933e2df5653b52ddc57a79b4ce7",
        "0x153319f1ecdd7a6d25380dc08566a8b5a6a46cb7a14a920b5400d834ca66bdbe",
        "0xd1179e6c517a300b86e6e99bba141ca6bd95ac41a02ecd4eeb2a19176de1069",
        "0x16f67a9d4ad2656c1f2fbc0d39e4e7ddcbad04bb83e7a38511b1b5f42d5e5983",
        "0xfa8d8b70f091bc6d9e5186c91968d37dcc5153e2ff39b5508c1e15016e2bace",
        "0x91ac4bd99ed6bc7ff73df5cbfe6330f4875e2c180daccbf568d8146f86ba24b",
        "0xd146d5f49d6461012ae4ab3f6f670e275098ed6369406c6f0e5bc4fd4828bce",
        "0x9a7000000000bebc2000000000000000000"
    ],
    "signature_vk": [
        "1808275917333726390675593630676660592284499790243906329164148357633591169851",  # noqa
        "13038682272157317746935630690273139043012615829064107162576212284919309632170",  # noqa
        "2863325759893808656457455214623293696676979172082516149962341594639946597244",  # noqa
        "8564702586272948230916163901148349984070935330485128468603906018200747127987"  # noqa
    ],
    "signature": "19090395247809983100415210093724020502485107107595263044457463522078345927435",  # noqa
    "ciphertexts": [
        "642149825d05b2b6e40d5e479ac27718adde77563e1e4a924a10a01afc9f5c63bd72e87a9710c2ea97c78a051fcb82cd1cdc23817f5781baa8d3508189fc0963fa3f6209df70aa95db14f24080da94e32374da6e9ce6dc4c3c0efbcbb428e605d683034f672750dd8c1533bf814339800731330f74fd5d67fa24e2207e1b8225aab47ca918d5583f27305f3ea0fcd3c1689a25add0bbad50",  # noqa
        "296909be36fb44361a34134c5acc47b01f5037c1be0f021734b993d0c766be10acc611836e9b77a67b59f4cbb74479402daa2e3d7b6a0ca780de9d0802bd751c0191bcaed8b2b7d5d334c7eb3bc339795cfeb7e7ace9ede7c1ebb8f4fa79f01342856dc557b680dd6e2ead876a7a281ab935c94aeba77f48097038cc8df1b36b56a97f6a2cdd42e05ed6f3ca26622ae87b405276b9544dcd"  # noqa
    ]
}

WEB3: Optional[Any] = None

ETH: Optional[Any] = None

MIXER_INSTANCE: Any = None

MIXER_CLIENT: Optional[MixerClient] = None


class TestGroth16AltBN128MixerBaseContract(TestCase):

    @staticmethod
    def setUpClass() -> None:
        print("Deploying AltBN128MixerBase_test.sol")
        web3, eth = mock.open_test_web3()
        deployer_eth_address = eth.accounts[0]
        _mixer_interface, mixer_instance = mock.deploy_contract(
            eth,
            deployer_eth_address,
            "Groth16AltBN128MixerBase_test",
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

    def test_hash_public_inputs(self) -> None:
        zksnark = get_zksnark_provider(PROVER_CONFIG.zksnark_name)
        mix_params = MixParameters.from_json_dict(zksnark, MIX_PARAMETERS_DICT)
        public_data = mix_params.public_data
        expect_hash = InputHasher(MiMC7()).hash(public_data)
        actual_hash = MIXER_INSTANCE.functions.\
            hash_public_proof_data_test(public_data).call()
        self.assertEqual(expect_hash, actual_hash)

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
            public_data=mix_params.public_data,
            for_dispatch_call=True)
        mix_params.signature = new_signature

        nested_inputs = \
            hex_list_to_uint256_list(mix_params.extended_proof.inputs)
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
