#!/usr/bin/env python3

# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from unittest import TestCase
from coordinator.crypto import import_verification_key, export_verification_key


TEST_VK = \
    "30" + \
    "819b301006072a8648ce3d020106052b810400230381860004010b0bcea9b4fa" + \
    "331695817099759bcc2d21105603a308c0957212975e1b355c43f3d204b66652" + \
    "a0786e53cf3448771809a05fe1fe97e4086de26f84b33a70e31ebc00aa568907" + \
    "3aa89da9ecb036c1031aa27c7839de62f097cf1d46704b594c021cde001ebd0e" + \
    "3f0033b98817ffa466905ce81b7916432666b490e3cbf4ca8808ebf401"


class TestCrypto(TestCase):

    def test_vk_import_export(self) -> None:
        vk = import_verification_key(TEST_VK)
        self.assertEqual(
            TEST_VK,
            export_verification_key(vk))
