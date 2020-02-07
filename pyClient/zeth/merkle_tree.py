# Copyright (c) 2015-2019 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from zeth.mimc import MiMC7
from os.path import exists
import json
import math
from web3 import Web3  # type: ignore
from typing import List, Tuple, Iterator, Optional, cast


ZERO_ENTRY = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000")

HASH = MiMC7()


class MerkleTree:
    """
    Merkle tree structure matching that used in the mixer contract. Simple
    implementation where unpopulated values (zeroes) are also stored.
    """
    def __init__(self, leaves: List[bytes], max_leaves: int):
        assert len(leaves) <= max_leaves
        tree_depth = int(math.log(max_leaves, 2))
        assert math.pow(2, tree_depth) == max_leaves, "non-power-of-2 tree size"
        self.leaves = leaves
        self.max_leaves = max_leaves
        self.tree_depth = tree_depth

    @staticmethod
    def empty_with_depth(depth: int) -> MerkleTree:
        num_leaves = int(math.pow(2, depth))
        return MerkleTree([], num_leaves)

    @staticmethod
    def empty_with_size(num_leaves: int) -> MerkleTree:
        return MerkleTree([], num_leaves)

    @staticmethod
    def combine(left: bytes, right: bytes) -> bytes:
        result_i = HASH.mimc_mp(
            int.from_bytes(left, byteorder='big'),
            int.from_bytes(right, byteorder='big'))
        return result_i.to_bytes(32, byteorder='big')

    def get_num_entries(self) -> int:
        return len(self.leaves)

    def get_entry(self, index: int) -> bytes:
        if index < len(self.leaves):
            return self.leaves[index]
        return ZERO_ENTRY

    def get_leaves(self) -> Iterator[bytes]:
        return iter(self.leaves)

    def compute_root(self) -> bytes:

        scratch_size = int((len(self.leaves) + 1) / 2)
        scratch = [bytes() for _ in range(scratch_size)]

        def reduce_sparse_layer(
                source: List[bytes],
                dest: List[bytes],
                num_present: int,
                layer_size: int,
                default_value: Optional[bytes]) -> Tuple[int, Optional[bytes]]:
            # Given a layer of the tree with `num_present` values, where the
            # remaining values are known to be `default_value`, write the next
            # layer into `dest`, returning the number values present and the new
            # default_value for this new layer.

            # Compute how many entries can be created from entries that are
            # present, and whether there is a "partial" entry.  Then fill in
            # each kind of entry, computing the new default as required.

            num_full_present = int(num_present / 2)
            num_partial_present = num_present - (2 * num_full_present)

            for i in range(num_full_present):
                dest[i] = self.combine(source[2*i], source[2*i + 1])

            if num_partial_present:
                assert default_value
                dest[num_full_present] = \
                    self.combine(source[num_present - 1], default_value)

            new_num_present = num_full_present + num_partial_present
            new_default: Optional[bytes] = None
            if num_present < layer_size - 1:
                assert default_value
                new_default = self.combine(default_value, default_value)

            return (new_num_present, new_default)

        # Fill the scratch pad from the current set of leaves + zeros.  Then
        # recursively compute on the scratch pad.

        (num_present, default_value) = reduce_sparse_layer(
            self.leaves, scratch, len(self.leaves), self.max_leaves, ZERO_ENTRY)
        layer_size = int(self.max_leaves / 2)

        while layer_size > 1:
            (num_present, default_value) = reduce_sparse_layer(
                scratch, scratch, num_present, layer_size, default_value)
            layer_size = int(layer_size / 2)

        # If the tree was empty, the scratch pad will have nothing in it and
        # default_value is the root.  If the tree was not empty, there must be
        # at least one present value at every level.

        if num_present:
            return scratch[0]

        assert default_value
        return default_value

    def compute_tree_values(self) -> List[bytes]:
        """
        Full merkle tree as flattened list, for computing paths
        """
        empty = bytes()
        tree_size = self.max_leaves * 2 - 1
        merkle_tree: List[bytes] = [empty for _ in range(tree_size)]
        # Leaves
        for i in range(len(self.leaves)):
            merkle_tree[(self.max_leaves - 1) + i] = self.leaves[i]
        for i in range(len(self.leaves), self.max_leaves):
            merkle_tree[(self.max_leaves - 1) + i] = ZERO_ENTRY

        # Internal nodes
        for i in range(self.max_leaves - 2, -1, -1):
            left_idx = 2 * i + 1
            merkle_tree[i] = \
                self.combine(merkle_tree[left_idx], merkle_tree[left_idx + 1])

        return merkle_tree

    def set_entry(self, index: int, entry: bytes) -> None:
        assert index == len(self.leaves)
        assert index < self.max_leaves
        self.leaves.append(entry)


def compute_merkle_path(
        address: int,
        tree_depth: int,
        tree_values: List[bytes]) -> List[str]:
    merkle_path: List[str] = []
    address_bits = []
    address = _leaf_address_to_node_address(address, tree_depth)
    if address == -1:
        return merkle_path  # return empty merkle_path
    for _ in range(0, tree_depth):
        address_bits.append(address % 2)
        if (address % 2) == 0:
            # [2:] to strip the 0x prefix
            merkle_path.append(Web3.toHex(tree_values[address - 1])[2:])
            # -1 because we decided to start counting from 0 (which is the
            # index of the root node)
            address = int(address/2) - 1
        else:
            merkle_path.append(Web3.toHex(tree_values[address + 1])[2:])
            address = int(address/2)
    return merkle_path


def _leaf_address_to_node_address(
        address_leaf: int, tree_depth: int) -> int:
    """
    Converts the relative address of a leaf to an absolute address in the tree
    Important note: The merkle root index is 0 (not 1!)
    """
    address = address_leaf + (2 ** tree_depth - 1)
    if address > (2 ** (tree_depth + 1) - 1):
        return -1
    return address


class PersistentMerkleTree(MerkleTree):
    """
    Version of MerkleTree that also supports persistence.
    """
    def __init__(self, filename: str, leaves: List[bytes], max_leaves: int):
        MerkleTree.__init__(self, leaves, max_leaves)
        self.filename = filename

    @staticmethod
    def open(filename: str, max_leaves: int) -> PersistentMerkleTree:
        expect_tree_depth = int(math.log(max_leaves, 2))
        assert max_leaves == int(math.pow(2, expect_tree_depth))
        if exists(filename):
            with open(filename, "r") as tree_f:
                json_dict = json.load(tree_f)
                tree_depth = cast(int, json_dict["depth"])
                assert isinstance(tree_depth, int)
                assert tree_depth == expect_tree_depth
                leaves_hex = cast(List[str], json_dict["leaves"])
                leaves = [bytes.fromhex(leaf_hex) for leaf_hex in leaves_hex]
                assert max_leaves >= len(leaves)
        else:
            leaves = []

        return PersistentMerkleTree(filename, leaves, max_leaves)

    def save(self) -> None:
        leaves_hex = [leaf.hex() for leaf in self.leaves]
        json_dict = {
            "depth": self.tree_depth,
            "leaves": leaves_hex,
        }
        with open(self.filename, "w") as tree_f:
            json.dump(json_dict, tree_f)
