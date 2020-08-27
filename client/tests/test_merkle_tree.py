# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+


from zeth.core.merkle_tree import MerkleTree, PersistentMerkleTree, ZERO_ENTRY, \
    compute_merkle_path
from zeth.core.utils import extend_32bytes
from os.path import exists, join
from os import makedirs
from shutil import rmtree
from unittest import TestCase
from typing import List

MERKLE_TREE_TEST_DIR = "_merkle_tests"
MERKLE_TREE_TEST_DEPTH = 4
MERKLE_TREE_TEST_NUM_LEAVES = pow(2, MERKLE_TREE_TEST_DEPTH)
TEST_VALUES = [
    extend_32bytes(i.to_bytes(1, 'big'))
    for i in range(1, MERKLE_TREE_TEST_NUM_LEAVES)]


class TestMerkleTree(TestCase):

    @staticmethod
    def setUpClass() -> None:
        TestMerkleTree.tearDownClass()
        makedirs(MERKLE_TREE_TEST_DIR)

    @staticmethod
    def tearDownClass() -> None:
        if exists(MERKLE_TREE_TEST_DIR):
            rmtree(MERKLE_TREE_TEST_DIR)

    def test_combine(self) -> None:
        # Use test vectors used to test the MiMC contract (generated in
        # test_mimc.py)

        left = self._test_vector_to_bytes32(
            3703141493535563179657531719960160174296085208671919316200479060314459804651)  # noqa
        right = self._test_vector_to_bytes32(
            15683951496311901749339509118960676303290224812129752890706581988986633412003)  # noqa
        expect = self._test_vector_to_bytes32(
            16797922449555994684063104214233396200599693715764605878168345782964540311877)  # noqa

        result = MerkleTree.combine(left, right)
        self.assertEqual(expect, result)

    def test_empty(self) -> None:
        mktree = MerkleTree.empty_with_size(MERKLE_TREE_TEST_NUM_LEAVES)
        root = mktree.recompute_root()
        num_entries = mktree.get_num_entries()

        self.assertEqual(0, num_entries)
        self.assertEqual(self._expected_empty(), root)

    def test_empty_save_load(self) -> None:
        mktree_file = join(MERKLE_TREE_TEST_DIR, "empty_save_load")
        mktree = PersistentMerkleTree.open(
            mktree_file, MERKLE_TREE_TEST_NUM_LEAVES)
        mktree.save()

        mktree = PersistentMerkleTree.open(
            mktree_file, MERKLE_TREE_TEST_NUM_LEAVES)
        root = mktree.recompute_root()
        mktree.save()

        self.assertEqual(self._expected_empty(), root)

    def test_single_entry(self) -> None:
        mktree_file = join(MERKLE_TREE_TEST_DIR, "single")
        data = TEST_VALUES[0]

        mktree = PersistentMerkleTree.open(
            mktree_file, MERKLE_TREE_TEST_NUM_LEAVES)
        mktree.insert(data)
        self.assertEqual(1, mktree.get_num_entries())
        self.assertEqual(data, mktree.get_leaf(0))
        self.assertEqual(ZERO_ENTRY, mktree.get_leaf(1))
        root_1 = mktree.recompute_root()
        self.assertEqual(
            MerkleTree.combine(data, ZERO_ENTRY), mktree.get_node(1, 0))
        self.assertNotEqual(self._expected_empty(), root_1)
        mktree.save()

        mktree = PersistentMerkleTree.open(
            mktree_file, MERKLE_TREE_TEST_NUM_LEAVES)
        self.assertEqual(1, mktree.get_num_entries())
        self.assertEqual(data, mktree.get_leaf(0))
        self.assertEqual(ZERO_ENTRY, mktree.get_leaf(1))
        root_2 = mktree.recompute_root()
        self.assertEqual(root_1, root_2)

    def test_single_entry_all_nodes(self) -> None:
        mktree = MerkleTree.empty_with_size(MERKLE_TREE_TEST_NUM_LEAVES)
        mktree.insert(TEST_VALUES[0])
        _ = mktree.recompute_root()
        self._check_tree_nodes([TEST_VALUES[0]], mktree)

        self.assertEqual(
            mktree.recompute_root(),
            mktree.get_node(MERKLE_TREE_TEST_DEPTH, 0))

    def test_multiple_entries_all_nodes(self) -> None:
        mktree = MerkleTree.empty_with_size(MERKLE_TREE_TEST_NUM_LEAVES)
        mktree.insert(TEST_VALUES[0])
        mktree.insert(TEST_VALUES[1])
        mktree.insert(TEST_VALUES[2])
        _ = mktree.recompute_root()
        self._check_tree_nodes(
            [TEST_VALUES[0], TEST_VALUES[1], TEST_VALUES[2]], mktree)

    def test_merkle_path(self) -> None:
        tree_size = MERKLE_TREE_TEST_NUM_LEAVES

        def _check_path_for_num_entries(num_entries: int, address: int) -> None:
            mktree = MerkleTree.empty_with_size(tree_size)
            for val in TEST_VALUES[0:num_entries]:
                mktree.insert(val)
            _ = mktree.recompute_root()
            mkpath = compute_merkle_path(address, mktree)
            self._check_merkle_path(address, mkpath, mktree)

        _check_path_for_num_entries(3, 0)
        _check_path_for_num_entries(3, 1)
        _check_path_for_num_entries(3, 2)
        _check_path_for_num_entries(4, 0)
        _check_path_for_num_entries(4, 1)
        _check_path_for_num_entries(4, 2)
        _check_path_for_num_entries(4, 3)
        _check_path_for_num_entries(5, 0)
        _check_path_for_num_entries(5, 1)
        _check_path_for_num_entries(5, 2)
        _check_path_for_num_entries(5, 3)
        _check_path_for_num_entries(5, 4)

    @staticmethod
    def _test_vector_to_bytes32(value: int) -> bytes:
        return value.to_bytes(32, byteorder='big')

    def _expected_empty(self) -> bytes:
        self.assertEqual(16, MERKLE_TREE_TEST_NUM_LEAVES)
        # Test vector generated by test_mimc.py
        return self._test_vector_to_bytes32(
            1792447880902456454889084480864374954299744757125100424674028184042059183092)  # noqa

    def _check_merkle_path(
            self, address: int, mkpath: List[str], mktree: MerkleTree) -> None:
        self.assertEqual(len(mkpath), mktree.depth)
        current = mktree.get_node(0, address)
        for i in range(mktree.depth):
            if address & 1:
                current = MerkleTree.combine(bytes.fromhex(mkpath[i]), current)
            else:
                current = MerkleTree.combine(current, bytes.fromhex(mkpath[i]))
            address = address >> 1

        self.assertEqual(mktree.get_root(), current)

    def _check_tree_nodes(self, leaves: List[bytes], mktree: MerkleTree) -> None:
        def layer_size(layer: int) -> int:
            return int(MERKLE_TREE_TEST_NUM_LEAVES / pow(2, layer))

        # Check layer 0
        _, layer_0 = next(mktree.get_layers())
        self.assertEqual(leaves, layer_0)

        # Check layer `layer`
        for layer in range(1, MERKLE_TREE_TEST_DEPTH):
            for i in range(layer_size(layer)):
                self.assertEqual(
                    MerkleTree.combine(
                        mktree.get_node(layer - 1, 2 * i),
                        mktree.get_node(layer - 1, 2 * i + 1)),
                    mktree.get_node(layer, i),
                    f"Layer {layer}, node {i}")
