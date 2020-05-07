#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.constants import ZETH_MERKLE_TREE_DEPTH
from zeth.merkle_tree import MerkleTree
from zeth.utils import extend_32bytes
from typing import List, Any
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


def assert_root(expect_root: bytes, nodes: List[bytes], msg: str) -> None:
    if nodes[0] != expect_root:
        print(f"FAILED: {msg}")
        print(f"Expected: {expect_root.hex()}")
        print("Actual  :")
        for layer_idx in range(0, ZETH_MERKLE_TREE_DEPTH + 1):
            layer_size = pow(2, layer_idx)
            layer_start = layer_size - 1
            layer = nodes[layer_start:layer_start + layer_size]
            layer_hex = [node.hex() for node in layer]
            print(f" {layer_hex}")
        raise Exception(f"failed")


def test_tree_empty(contract: Any) -> None:
    mktree = MerkleTree.empty_with_depth(ZETH_MERKLE_TREE_DEPTH)
    expect_root = mktree.recompute_root()
    nodes = contract.functions.testAddLeaves([], []).call()
    assert_root(expect_root, nodes, "test_tree_empty")


def test_tree_partial(contract: Any) -> None:
    """
    Send a series of different arrays of leaves to the contract and check that
    the root is as expected.  Send as 2 batches, to test updating the tree, from
    various states.
    """

    def _test_partial(num_entries: int, step: int = 1) -> None:
        """
        Take the first 'num_entries' from TEST_VALUES.  Cut them at each possible
        place and submit them as two halves to the contract, receiving back the
        set of nodes.
        """
        leaves = TEST_VALUES[:num_entries]

        mktree = MerkleTree.empty_with_depth(ZETH_MERKLE_TREE_DEPTH)
        for leaf in leaves:
            mktree.insert(leaf)
        expect_root = mktree.recompute_root()

        for cut in range(0, num_entries + 1, step):
            print(f"_test_partial: num_entries={num_entries}, cut={cut}")
            first = leaves[:cut]
            second = leaves[cut:]
            nodes = contract.functions.testAddLeaves(first, second).call()
            assert_root(
                expect_root,
                nodes,
                f"num_entries: {num_entries}, cut: {cut}: ")

    # Perform the filling tests using arrays of these sizes
    _test_partial(1)
    _test_partial(7)
    _test_partial(8)
    _test_partial(9)
    _test_partial(15, 3)
    _test_partial(16, 3)


def main() -> None:
    _web3, eth = mock.open_test_web3()
    deployer_eth_address = eth.accounts[0]
    _mktree_interface, mktree_instance = mock.deploy_contract(
        eth,
        deployer_eth_address,
        "MerkleTreeMiMC7_test",
        {'treeDepth': ZETH_MERKLE_TREE_DEPTH})

    test_tree_empty(mktree_instance)
    test_tree_partial(mktree_instance)


if __name__ == '__main__':
    main()
