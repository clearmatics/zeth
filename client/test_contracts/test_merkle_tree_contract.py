#!/usr/bin/env python3

# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.core.constants import ZETH_MERKLE_TREE_DEPTH
from zeth.core.merkle_tree import MerkleTree
from zeth.core.utils import extend_32bytes
from zeth.core.mimc import MiMC7
from typing import Any
from unittest import TestCase
import test_commands.mock as mock


TEST_VALUES = [
    extend_32bytes(bytes.fromhex("f0")),
    extend_32bytes(bytes.fromhex("f1")),
    extend_32bytes(bytes.fromhex("f2")),
    extend_32bytes(bytes.fromhex("f3")),
    extend_32bytes(bytes.fromhex("f4")),
    extend_32bytes(bytes.fromhex("f5")),
    extend_32bytes(bytes.fromhex("f6")),
    extend_32bytes(bytes.fromhex("f7")),
    extend_32bytes(bytes.fromhex("f8")),
    extend_32bytes(bytes.fromhex("f9")),
    extend_32bytes(bytes.fromhex("fa")),
    extend_32bytes(bytes.fromhex("fb")),
    extend_32bytes(bytes.fromhex("fc")),
    extend_32bytes(bytes.fromhex("fd")),
    extend_32bytes(bytes.fromhex("fe")),
    extend_32bytes(bytes.fromhex("ff")),
]

MKTREE_INSTANCE: Any = None


class TestMerkleTreeContract(TestCase):

    @staticmethod
    def setUpClass() -> None:
        _web3, eth = mock.open_test_web3()
        deployer_eth_address = eth.accounts[0]
        _mktree_interface, mktree_instance = mock.deploy_contract(
            eth,
            deployer_eth_address,
            "TestMerkleTreeMiMC7",
            {'treeDepth': ZETH_MERKLE_TREE_DEPTH})
        global MKTREE_INSTANCE  # pylint: disable=global-statement
        MKTREE_INSTANCE = mktree_instance

    def test_tree_empty(self) -> None:
        mktree = MerkleTree.empty_with_depth(ZETH_MERKLE_TREE_DEPTH, MiMC7())
        expected_root = mktree.recompute_root()
        root = MKTREE_INSTANCE.functions.addLeavesTest([], []).call()
        self.assertEqual(expected_root, root, "test_tree_empty")

    def _test_partial(self, num_entries: int, step: int = 1) -> None:
        """
        Take the first 'num_entries' from TEST_VALUES. Cut them at each possible
        place and submit them as two halves to the contract, receiving back the
        root for the updated tree.
        """
        leaves = TEST_VALUES[:num_entries]

        mktree = MerkleTree.empty_with_depth(ZETH_MERKLE_TREE_DEPTH, MiMC7())
        for leaf in leaves:
            mktree.insert(leaf)
        expected_root = mktree.recompute_root()

        for cut in range(0, num_entries + 1, step):
            print(f"_test_partial: num_entries={num_entries}, cut={cut}")
            first = leaves[:cut]
            second = leaves[cut:]
            root = MKTREE_INSTANCE.functions.addLeavesTest(first, second).call()
            self.assertEqual(
                expected_root,
                root,
                f"num_entries: {num_entries}, cut: {cut}: ")

    def test_tree_partial(self) -> None:
        """
        Send a series of different arrays of leaves to the contract and check that
        the root is as expected. Send as 2 batches, to test updating the tree,
        from various states.
        """
        # Perform the filling tests using arrays of these sizes
        self._test_partial(1)
        self._test_partial(7)
        self._test_partial(8)
        self._test_partial(9)
        self._test_partial(15, 3)
        self._test_partial(16, 3)
