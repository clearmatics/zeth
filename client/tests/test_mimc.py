# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.core.mimc import MiMC7, MiMC31
from unittest import TestCase

# pylint: disable=line-too-long


class TestMiMC(TestCase):

    def test_mimc7_round(self) -> None:
        mimc = MiMC7("Clearmatics")
        msg = 340282366920938463463374607431768211456
        key = 28948022309329048855892746252171976963317496166410141009864396001978282409983  # noqa
        round_const = 14220067918847996031108144435763672811050758065945364308986253046354060608451  # noqa
        expect_result = 7970444205539657036866618419973693567765196138501849736587140180515018751924  # noqa
        self.assertEqual(expect_result, mimc.mimc_round(msg, key, round_const))

    def test_mimc7(self) -> None:
        left = 28948022309329048855892746252171976963317496166410141009864396001978282409983  # noqa
        right = 14220067918847996031108144435763672811050758065945364308986253046354060608451  # noqa
        expect_result = 14404914332179247771191118015445305957789480573634910846417052002923707343766  # noqa
        result = MiMC7().hash(_int_to_bytes(left), _int_to_bytes(right))
        self.assertEqual(_int_to_bytes(expect_result), result)

    def test_mimc31_round(self) -> None:
        msg = 340282366920938463463374607431768211456
        key = 3614637061043937583146271435827337369189798160947949526058695634226054692860  # noqa
        round_const = 5775606169419625606859319496982126279674858730791300481051019590436651369410  # noqa
        expect_result = 5523634951166384704739554074217840169048851347397743343350526776025419511991  # noqa
        self.assertEqual(
            expect_result, MiMC31().mimc_round(msg, key, round_const))

    def test_mimc31(self) -> None:
        left = 3614637061043937583146271435827337369189798160947949526058695634226054692860  # noqa
        right = 5775606169419625606859319496982126279674858730791300481051019590436651369410  # noqa
        expect_result = 7575204549404107478830739557698679330537656688050664462892741835534561279075  # noqa
        result = MiMC31().hash(_int_to_bytes(left), _int_to_bytes(right))
        self.assertEqual(_int_to_bytes(expect_result), result)


# pylint: enable=line-too-long
def _int_to_bytes(value: int) -> bytes:
    return value.to_bytes(32, byteorder='big')
