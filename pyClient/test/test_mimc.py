# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.mimc import MiMC7
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

    @staticmethod
    def test_mimc_encrypt() -> None:
        # Generating test vector for MiMC encrypt
        m = MiMC7()
        msg = 3703141493535563179657531719960160174296085208671919316200479060314459804651  # noqa
        ek = \
            15683951496311901749339509118960676303290224812129752890706581988986633412003  # noqa
        ct = m.mimc_encrypt(msg, ek)
        print("MiMC encrypt test vector:")
        print(f"msg = {msg}")
        print(f"ek  = {ek}")
        print(f"ct  = {ct}\n")

    @staticmethod
    def test_mimc_mp() -> None:
        # Generating test vector for MiMC Hash
        m = MiMC7()
        x = 3703141493535563179657531719960160174296085208671919316200479060314459804651  # noqa
        y = 15683951496311901749339509118960676303290224812129752890706581988986633412003  # noqa

        digest = m.mimc_mp(x, y)
        print("MiMC MP test vector:")
        print(f"x      = {x}")
        print(f"y      = {y}")
        print(f"digest = {digest}\n")

    @staticmethod
    def test_mimc_tree() -> None:
        # Generating test vectors for testing the MiMC Merkle Tree contract.  A
        # 16 entry (4 level) merkle tree with 0 values everywhere.

        m = MiMC7()
        level_3 = m.mimc_mp(0, 0)
        level_2 = m.mimc_mp(level_3, level_3)
        level_1 = m.mimc_mp(level_2, level_2)
        root = m.mimc_mp(level_1, level_1)

        print("MiMC Tree test vector (4 entries, all zero):")

        print(f"Level 2 = {level_3}")
        print(f"Level 2 = {level_2}")
        print(f"Level 1 = {level_1}")
        print(f"Root    = {root}\n")
