#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.core.utils import EtherValue
from unittest import TestCase


class TestEthereValue(TestCase):

    def test_conversion(self) -> None:
        aval = EtherValue(75641320, 'wei')
        aval_eth = aval.ether()
        bval = EtherValue(aval_eth, 'ether')
        self.assertEqual(aval.wei, bval.wei)
        self.assertEqual(aval.ether(), bval.ether())

    def test_equality(self) -> None:
        aval = EtherValue(1.2)
        aval_same = EtherValue(1.2)
        bval = EtherValue(0.8)

        self.assertEqual(aval, aval)
        self.assertEqual(aval, aval_same)
        self.assertNotEqual(aval, bval)

    def test_arithmetic(self) -> None:
        aval = EtherValue(1.2)
        bval = EtherValue(0.8)
        cval = EtherValue(0.4)

        self.assertEqual(aval, bval + cval)
        self.assertEqual(bval, aval - cval)

    def test_comparison(self) -> None:
        big = EtherValue(1.2)
        small = EtherValue(0.8)
        small_same = EtherValue(0.8)

        self.assertTrue(small < big)
        self.assertTrue(small <= big)
        self.assertTrue(big > small)
        self.assertTrue(big >= small)
        self.assertTrue(small_same >= small)
        self.assertTrue(small_same <= small)

        self.assertFalse(small > big)
        self.assertFalse(small >= big)
        self.assertFalse(big < small)
        self.assertFalse(big <= small)
        self.assertFalse(small_same > small)
        self.assertFalse(small_same < small)

    def test_bool(self) -> None:
        zero = EtherValue(0)
        self.assertFalse(zero)
        self.assertTrue(not zero)

        non_zero = EtherValue(0.1)
        self.assertTrue(non_zero)
        self.assertFalse(not non_zero)
