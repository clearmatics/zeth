# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.core.mimc import MiMC7
from unittest import TestCase


class TestMiMC(TestCase):

    @staticmethod
    def test_mimc_round() -> None:
        m = MiMC7("Clearmatics")
        x = 340282366920938463463374607431768211456
        k = 28948022309329048855892746252171976963317496166410141009864396001978282409983  # noqa
        c = 14220067918847996031108144435763672811050758065945364308986253046354060608451  # noqa
        assert m.mimc_round(x, k, c) == \
            7970444205539657036866618419973693567765196138501849736587140180515018751924  # noqa
