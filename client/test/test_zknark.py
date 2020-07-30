# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth import zksnark
from api import ec_group_messages_pb2
from unittest import TestCase


class TestZKSnark(TestCase):

    def test_g1_proto_encode_decode(self) -> None:
        self._do_test_g1_proto_encode_decode(("0xaabbccdd", "0x11223344"))

    def test_g2_proto_encode_decode(self) -> None:
        self._do_test_g2_proto_encode_decode(
            ("0xaabbccdd", "0x11223344"))
        self._do_test_g2_proto_encode_decode(
            (("0xcdeeff00", "0x11223344"), ("0x55667788", "0x99aabbcc")))

    def _do_test_g1_proto_encode_decode(self, g1: zksnark.GenericG1Point) -> None:
        g1_proto = ec_group_messages_pb2.HexPointBaseGroup1Affine()
        zksnark.group_point_g1_to_proto(g1, g1_proto)
        g1_decoded = zksnark.group_point_g1_from_proto(g1_proto)
        self.assertEqual(g1, g1_decoded)

    def _do_test_g2_proto_encode_decode(self, g2: zksnark.GenericG2Point) -> None:
        g2_proto = ec_group_messages_pb2.HexPointBaseGroup2Affine()
        zksnark.group_point_g2_to_proto(g2, g2_proto)
        g2_decoded = zksnark.group_point_g2_from_proto(g2_proto)
        self.assertEqual(g2, g2_decoded)
