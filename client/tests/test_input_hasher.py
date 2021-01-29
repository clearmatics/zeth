# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.core.mimc import MiMC7, MiMC31
from zeth.core.input_hasher import InputHasher
from unittest import TestCase

DUMMY_INPUT_VALUES = [-1, 0, 1]


class TestInputHasher(TestCase):

    def test_input_hasher_simple(self) -> None:
        # Some very simple cases
        mimc = MiMC7()
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

    def test_input_hasher_mimc7(self) -> None:
        mimc = MiMC7()
        input_hasher = InputHasher(mimc)
        values = [x % mimc.prime for x in DUMMY_INPUT_VALUES]
        # pylint:disable=line-too-long
        expect = 5568471640435576440988459485125198359192118312228711462978763973844457667180  # noqa
        # pylint:enable=line-too-long
        self.assertEqual(expect, input_hasher.hash(values))

    def test_input_hasher_mimc31(self) -> None:
        mimc = MiMC31()
        input_hasher = InputHasher(mimc)
        values = [x % mimc.prime for x in DUMMY_INPUT_VALUES]
        # pylint: disable=line-too-long
        expect = 1029772481427643815119825324071277815354972734622711297984795198139876181749  # noqa
        # pylint: enable=line-too-long
        self.assertEqual(expect, input_hasher.hash(values))
