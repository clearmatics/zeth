# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.core.mimc import MiMCAltBN128, MiMCBLS12_377
from unittest import TestCase

# pylint: disable=line-too-long


class TestMiMC(TestCase):

    def test_mimc_alt_bn128_round(self) -> None:
        mimc = MiMCAltBN128("Clearmatics")
        msg = 340282366920938463463374607431768211456
        key = 28948022309329048855892746252171976963317496166410141009864396001978282409983  # noqa
        round_const = 14220067918847996031108144435763672811050758065945364308986253046354060608451  # noqa
        expect_result = 15194574649778181158537940501307832704788048781286507777438072456493095881604  # noqa
        self.assertEqual(expect_result, mimc.mimc_round(msg, key, round_const))

    def test_mimc_alt_bn128_hash(self) -> None:
        left = 340282366920938463463374607431768211456
        right = 28948022309329048855892746252171976963317496166410141009864396001978282409983  # noqa
        expect_result = 14599678357063082723814206975733222579132256174923645170354481857040188426666  # noqa
        result = MiMCAltBN128().hash(_int_to_bytes(left), _int_to_bytes(right))
        self.assertEqual(expect_result, _bytes_to_int(result))

    def test_mimc_bls12_377_round(self) -> None:
        msg = 340282366920938463463374607431768211456
        key = 3614637061043937583146271435827337369189798160947949526058695634226054692860  # noqa
        round_const = 5775606169419625606859319496982126279674858730791300481051019590436651369410  # noqa
        expect_result = 706529233840138407487116494744828417642056684171152884149736992660816802274  # noqa
        self.assertEqual(
            expect_result, MiMCBLS12_377().mimc_round(msg, key, round_const))

    def test_mimc_bls12_377_hash(self) -> None:
        left = 3614637061043937583146271435827337369189798160947949526058695634226054692860  # noqa
        right = 5775606169419625606859319496982126279674858730791300481051019590436651369410  # noqa
        expect_result = 5803106354831571205534057512593837953191890709037390680911925249983717812220  # noqa
        result = MiMCBLS12_377().hash(_int_to_bytes(left), _int_to_bytes(right))
        self.assertEqual(expect_result, _bytes_to_int(result))


# pylint: enable=line-too-long
def _int_to_bytes(value: int) -> bytes:
    return value.to_bytes(32, byteorder='big')


def _bytes_to_int(value: bytes) -> int:
    return int.from_bytes(value, byteorder='big')
