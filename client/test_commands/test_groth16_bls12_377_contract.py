# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.core.utils import get_contracts_dir, hex_list_to_uint256_list
from zeth.core.zksnark import Groth16
from zeth.core.contracts import InstanceDescription
from zeth.cli.utils import get_eth_network, open_web3_from_network
from tests.test_pairing import BLS12_377_PAIRING
from os.path import join
import sys
from typing import List, Any


# pylint: disable=line-too-long
VERIFICATION_KEY = Groth16.VerificationKey.from_json_dict({
    "alpha": [
        "0x002a586f4738bdc629cfeffae788183586416cf2255ca2dfdca0866fa39a0ff27a75ab2fc8230815a3263da828707bb6",  # noqa
        "0x009797441005cca3c8e1b0ec78e7d5c5da95091ae0d9ca7396fb2245ab99101b34d7c5f0175aafd35ede91dc09f9532d"  # noqa
    ],
    "beta": [
        ["0x003d46509bd7f4e68ce267343ee8e555570ef1ab465bfe36756ba76f8059f2714573e6a2833e15a03c5c078c80ed06d5",  # noqa
         "0x010f8805ac1719b1c76cb7e12f0d548a53f30a0caad7f6f9b0eb1ed676aae1faa6476daa60f60916bfdd1fa63f389728"],  # noqa
        ["0x003a0ac1e41533af971fb2faca7e2cf662142c8b329b01efd299bc5ec263617127d5599f36b2038c58dfee7cc009b0ec",  # noqa
         "0x01595cb8a7e1401cd60c4b132ac611affec72d56c20624c1237fa318fb9c007dee7f92c08db7d910022b0ef1c7f95ff4"]  # noqa
    ],
    "delta": [
        ["0x001e2716cb3ffbfe3cc1e76c6fa548018b3f9b12bfc2aa07640c9071fb7a95b4bdaf0ee15a0a4f6ddddc85834efc9009",  # noqa
         "0x0098df94239036766b474b3a800d6edbc561e0cc37b251fa94f7cbcaeb01388646016163cd3d6a784a5c63f1879f0cf6"],  # noqa
        ["0x008fd1d23577ded8f806c31e5d34b863b534382c83030c4382025cf3a06bdc14534f79861e9d8c17c98c3ad75d4bd46c",  # noqa
         "0x003b5aeb59778b91048df1827f71209950b0e397cb9430632e2f194d37f51318bff10a37d88c2c86f2c21f71126bc909"]  # noqa
    ],
    "ABC": [
        ["0x01768261e5d9e312768c75fde3c50cd800a3ab94572c55f3482993bc406ea7cac091c0a450c4a2f1a5ad7aa9e3f6eb10",  # noqa
         "0x012b1728cf8b05ebfb588d307f432deebf428c202a8572cec70ab403559b2999abfdbe830ffe51558876936facfc967b"],  # noqa
        ["0x00ecfad9e9ebc8a46b3a5664abdcea154d30565f04c90e75e8bdf157a019ddda540d58621a6543745b62e6d856b5a962",  # noqa
         "0x0042421dd9c1f425afd48f2b1814712cc8a5238b96b3db9edc24f80e25e370351c80aa0cd2c79bdf1fc4a4319fea6209"]  # noqa
    ]
})

PROOF = Groth16.Proof.from_json_dict({
    "a": [
        "0x0122d4c743e0b0a9a1bc920d070c536390096eedc60ac427943f01acf8f95011d0d9ee51539c338f5f31b74e9138646c",  # noqa
        "0x0117f63edf1996607168c711e5d6c9add5dbad4df22c344bcb8f5a20026148a2cf1a3b905388ab952e05903944ed1f47"  # noqa
    ],
    "b": [
        ["0x019df27cf0dae60f1a6107cd36838b2379af2da7765e9a0257f424db9d58224f45b133d7085bf350885afe7ffcae16b9",  # noqa
         "0x019cc9fec349ada5065075e7d42355f9bdc413d2b481f62b71ad9cf7af560f555714291ff3ed277ac973d1a83b4fc193"],  # noqa
        ["0x009db56d5960ce13e15e93cb3985eb94d8b4ca033917757bf362baccac5462668cd900800f4de4861a5a92a542b81aef",  # noqa
         "0x019e188316b82cc8a95ae6e7fb27ea5c6abaed28610152d421fc6fa090e406299cbb40e5f25c18339a5bc04c23bd6822"]  # noqa
    ],
    "c": [
        "0x00ae39a12b92b09e1ec1e256f7bf0522c067806f1ed46e959f018ec859b3a200506c7a7993243df77cc911ff35c1a0c8",  # noqa
        "0x0016b89bd7d30c7a34d25780ef14fd027e2515c7449afe9d7dbf21f183673aefffb196e5959fcedd0dcf6064f1186d4c"  # noqa
    ]
})

INPUTS_VALID = [
    "0x0000000000000000000000000000000000000000000000000000000000000007"
]

INPUTS_INVALID = [
    "0x0000000000000000000000000000000000000000000000000000000000000008"
]
# pylint: enable=line-too-long


def _invoke_groth16_bls12_377_verify(
        contract_instance: Any,
        vk: Groth16.VerificationKey,
        proof: Groth16.Proof,
        inputs: List[str]) -> bool:
    vk_evm = Groth16.verification_key_to_contract_parameters(
        vk, BLS12_377_PAIRING)
    proof_evm = Groth16.proof_to_contract_parameters(proof, BLS12_377_PAIRING)
    inputs_evm = hex_list_to_uint256_list(inputs)
    return contract_instance.functions.test_verify(
        vk_evm, proof_evm, inputs_evm).call()


def test_groth16_bls12_377_valid(contract_instance: Any) -> None:
    assert _invoke_groth16_bls12_377_verify(
        contract_instance, VERIFICATION_KEY, PROOF, INPUTS_VALID)


def test_groth16_bls12_377_invalid(contract_instance: Any) -> None:
    assert not _invoke_groth16_bls12_377_verify(
        contract_instance, VERIFICATION_KEY, PROOF, INPUTS_INVALID)


def main() -> int:
    web3: Any = open_web3_from_network(get_eth_network(None))
    contracts_dir = get_contracts_dir()
    contract_instance_desc = InstanceDescription.deploy(
        web3,
        join(contracts_dir, "Groth16BLS12_377_test.sol"),
        "Groth16BLS12_377_test",
        web3.eth.accounts[0],  # pylint: disable=no-member
        None,
        500000,
        {"allow_paths": contracts_dir})
    contract_instance = contract_instance_desc.instantiate(web3)

    test_groth16_bls12_377_valid(contract_instance)
    test_groth16_bls12_377_invalid(contract_instance)

    print("========================================")
    print("==              PASSED                ==")
    print("========================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())
