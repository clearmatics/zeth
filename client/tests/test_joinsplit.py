# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.core.mixer_client import compute_commitment
from zeth.api.zeth_messages_pb2 import ZethNote
import zeth.core.constants as constants

from unittest import TestCase


class TestJoinsplit(TestCase):

    def test_compute_commitment(self) -> None:
        """
        Test the commitment value for a note, as computed by the circuit.
        """
        apk = "44810c8d62784f5e9ce862925ebb889d1076a453677a5d73567387cd5717a402"
        value = "0000000005f5e100"
        rho = "0b0bb358233326ce4d346d86f9a0c3778ed8ce15efbf7640aad6e9359145659f"
        r = "1e3063320fd43f2d6c456d7f1ee11b7ab486308133e2a5afe916daa4ff5357f6"
        cm_expect = int(
            "fdf5279335a2fa36fb0d664509808db8d02b6f05f9e5639960952a7038363cfc",
            16)
        cm_expect_field = cm_expect % constants.ZETH_PRIME

        note = ZethNote(apk=apk, value=value, rho=rho, trap_r=r)
        cm = int.from_bytes(compute_commitment(note), byteorder="big")

        self.assertEqual(cm_expect_field, cm)
