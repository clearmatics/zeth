#!/usr/bin/env python3

from unittest import TestCase
from coordinator.crypto import HASH, import_verification_key, \
    export_verification_key, import_contribution_digest


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

    def test_contribution_digest_import(self) -> None:
        hash_string = \
            "786a02f7 42015903 c6c6fd85 2552d272\n" \
            "912f4740 e1584761 8a86e217 f71f5419\n" \
            "d25e1031 afee5853 13896444 934eb04b\n" \
            "903a685b 1448b755 d56f701a fe9be2ce\n"
        h = HASH()
        expect_digest = h.digest()
        digest = import_contribution_digest(hash_string)
        self.assertEqual(expect_digest, digest)
