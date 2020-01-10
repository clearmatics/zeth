# Copyright (c) 2015-2019 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from zeth.mimc import MiMC7
from os.path import exists
import json
import math
from web3 import Web3  # type: ignore
from typing import List, Iterator, cast


ZERO_ENTRY = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000")

HASH = MiMC7()


class MerkleTree:
    """
    Merkle tree structure matching that used in the mixer contract. Simple
    implementation where unpopulated values (zeroes) are also stored.
    """
    def __init__(self, num_populated: int, leaves: List[bytes]):
        num_leaves = len(leaves)
        tree_depth = int(math.log(num_leaves, 2))
        assert math.pow(2, tree_depth) == num_leaves, "non-power-of-2 tree size"
        self.num_leaves = num_leaves
        self.tree_depth = tree_depth
        self.num_populated = num_populated
        self.leaves = leaves

    @staticmethod
    def empty_with_depth(depth: int) -> MerkleTree:
        num_leaves = int(math.pow(2, depth))
        return MerkleTree(0, [ZERO_ENTRY for _ in range(num_leaves)])

    @staticmethod
    def empty_with_size(num_leaves: int) -> MerkleTree:
        return MerkleTree(0, [ZERO_ENTRY for _ in range(num_leaves)])

    @staticmethod
    def combine(left: bytes, right: bytes) -> bytes:
        result_i = HASH.mimc_mp(
            int.from_bytes(left, byteorder='big'),
            int.from_bytes(right, byteorder='big'))
        return result_i.to_bytes(32, byteorder='big')

    def get_num_entries(self) -> int:
        return self.num_populated

    def get_entry(self, index: int) -> bytes:
        return self.leaves[index]

    def get_leaves(self) -> Iterator[bytes]:
        for leaf in self.leaves:
            if leaf == ZERO_ENTRY:
                return
            yield leaf

    def compute_root(self) -> bytes:
        leaves = self.leaves
        layer_size = int(self.num_leaves / 2)

        scratch: List[bytes] = [
            self.combine(leaves[2*i], leaves[2*i + 1]) for i in range(layer_size)]

        while layer_size > 1:
            layer_size = int(layer_size / 2)
            for i in range(layer_size):
                scratch[i] = self.combine(scratch[2*i], scratch[2*i + 1])

        return scratch[0]

    def compute_tree_values(self) -> List[bytes]:
        """
        Full merkle tree as flattened list, for computing paths
        """
        empty = bytes()
        tree_size = self.num_leaves * 2 - 1
        merkle_tree: List[bytes] = [empty for _ in range(tree_size)]
        # Leaves
        for i in range(len(self.leaves)):
            merkle_tree[(self.num_leaves - 1) + i] = self.leaves[i]

        # Internal nodes
        for i in range(self.num_leaves - 2, -1, -1):
            left_idx = 2 * i + 1
            merkle_tree[i] = \
                self.combine(merkle_tree[left_idx], merkle_tree[left_idx + 1])

        return merkle_tree

    def set_entry(self, index: int, entry: bytes) -> None:
        assert index == self.num_populated
        assert index < len(self.leaves)
        self.leaves[index] = entry
        self.num_populated = self.num_populated + 1


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
    def __init__(self, filename: str, num_populated: int, leaves: List[bytes]):
        MerkleTree.__init__(self, num_populated, leaves)
        self.filename = filename

    @staticmethod
    def open(filename: str, num_leaves: int) -> PersistentMerkleTree:
        if exists(filename):
            with open(filename, "r") as tree_f:
                json_dict = json.load(tree_f)
                num_populated = cast(int, json_dict["num_populated"])
                assert isinstance(num_populated, int)
                leaves_hex = cast(List[str], json_dict["leaves"])
                leaves = [bytes.fromhex(leaf_hex) for leaf_hex in leaves_hex]
                assert num_leaves == len(leaves)
        else:
            num_populated = 0
            leaves = [ZERO_ENTRY for _ in range(num_leaves)]
        return PersistentMerkleTree(filename, num_populated, leaves)

    def save(self) -> None:
        leaves_hex = [leaf.hex() for leaf in self.leaves]
        json_dict = {
            "num_populated": self.num_populated,
            "leaves": leaves_hex,
        }
        with open(self.filename, "w") as tree_f:
            json.dump(json_dict, tree_f)
