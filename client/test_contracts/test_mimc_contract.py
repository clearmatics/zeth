# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.core.utils import get_contracts_dir
from zeth.core.contracts import InstanceDescription
from zeth.core.mimc import MiMCAltBN128, MiMCBLS12_377
from zeth.cli.utils import get_eth_network, open_web3_from_network
from os.path import join
from unittest import TestCase
from typing import Any

CONTRACT_INSTANCE: Any = None

"""
Test data here matches that used in test_mimc.py, which is also used in the
tests of mimc circuits.
"""


class TestMiMCContract(TestCase):

    @staticmethod
    def setUpClass() -> None:
        web3: Any = open_web3_from_network(get_eth_network(None))
        contracts_dir = get_contracts_dir()
        contract_instance_desc = InstanceDescription.deploy(
            web3,
            join(contracts_dir, "TestMiMC.sol"),
            "TestMiMC",
            web3.eth.accounts[0],  # pylint: disable=no-member
            None,
            500000,
            {"allow_paths": contracts_dir})
        global CONTRACT_INSTANCE  # pylint: disable=global-statement
        CONTRACT_INSTANCE = contract_instance_desc.instantiate(web3)

    def test_mimc_alt_bn128(self) -> None:
        # pylint: disable=line-too-long
        x = int(28948022309329048855892746252171976963317496166410141009864396001978282409983).to_bytes(32, 'big')  # noqa
        y = int(14220067918847996031108144435763672811050758065945364308986253046354060608451).to_bytes(32, 'big')  # noqa
        # pylint: enable=line-too-long
        h = MiMCAltBN128().hash(x, y)

        result = CONTRACT_INSTANCE.functions.testMimcAltBN128(x, y).call()
        self.assertEqual(h, result)

    def test_mimc_bls12_377(self) -> None:
        # pylint: disable=line-too-long
        x = int(28948022309329048855892746252171976963317496166410141009864396001978282409983).to_bytes(32, 'big')  # noqa
        y = int(14220067918847996031108144435763672811050758065945364308986253046354060608451).to_bytes(32, 'big')  # noqa
        # pylint: enable=line-too-long
        h = MiMCBLS12_377().hash(x, y)

        result = CONTRACT_INSTANCE.functions.testMimcBLS12_377(x, y).call()
        self.assertEqual(h, result)
