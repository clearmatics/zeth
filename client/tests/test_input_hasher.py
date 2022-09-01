# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.core.mimc import MiMCAltBN128, MiMCBLS12_377
from zeth.core.input_hasher import InputHasher
from unittest import TestCase

DUMMY_INPUT_VALUES = [-1, 0, 1]


class TestInputHasher(TestCase):

    def test_input_hasher_simple(self) -> None:
        # Some very simple cases
        mimc = MiMCAltBN128()
        input_hasher = InputHasher(mimc, 7)
        self.assertEqual(mimc.hash_int(7, 0), input_hasher.hash([]))
        self.assertEqual(
            mimc.hash_int(mimc.hash_int(7, 1), 1), input_hasher.hash([1]))
        self.assertEqual(
            mimc.hash_int(
                mimc.hash_int(
                    mimc.hash_int(7, 1), 2),
                2),
            input_hasher.hash([1, 2]))

    def test_input_hasher_mimc_alt_bn128(self) -> None:
        mimc = MiMCAltBN128()
        input_hasher = InputHasher(mimc)
        values = [x % mimc.prime for x in DUMMY_INPUT_VALUES]
        # pylint:disable=line-too-long
        expect = 1147542777914688064255377945014225852776952826405497760158376896026758431650  # noqa
        # pylint:enable=line-too-long
        self.assertEqual(expect, input_hasher.hash(values))

    def test_input_hasher_mimc_bls12_377(self) -> None:
        mimc = MiMCBLS12_377()
        input_hasher = InputHasher(mimc)
        values = [x % mimc.prime for x in DUMMY_INPUT_VALUES]
        # pylint: disable=line-too-long
        expect = 3481757288350338818975783012202519902801563645563026508811358096682731778741  # noqa
        # pylint: enable=line-too-long
        self.assertEqual(expect, input_hasher.hash(values))
