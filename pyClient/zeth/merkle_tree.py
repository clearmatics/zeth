# Copyright (c) 2015-2019 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from zeth.mimc import MiMC7
from os.path import exists
import json
import math
from typing import List, cast


ZERO_ENTRY = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000")

HASH = MiMC7()


class MerkleTreeData:
    """
    Merkle tree persisted data model.
    """
    def __init__(self, num_leaves: int, num_populated: int, leaves: List[bytes]):
        assert math.pow(2, math.log(num_leaves, 2)) == num_leaves, \
            "non-power-of-2 merkle tree size"
        self.num_leaves = num_leaves
        self.num_populated = num_populated
        self.leaves = leaves

    def set_entry(self, index: int, entry: bytes) -> None:
        assert index == self.num_populated
        assert index < len(self.leaves)
        self.leaves[index] = entry
        self.num_populated = self.num_populated + 1

    @staticmethod
    def load(filename: str, num_leaves: int) -> MerkleTreeData:
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
        return MerkleTreeData(num_leaves, num_populated, leaves)

    def save(self, filename: str) -> None:
        leaves_hex = [leaf.hex() for leaf in self.leaves]
        json_dict = {
            "num_populated": self.num_populated,
            "leaves": leaves_hex,
        }
        with open(filename, "w") as tree_f:
            json.dump(json_dict, tree_f)


class MerkleTree:
    """
    Persistent fixed-size MerkelTree to replicate the structure in the contract.
    """

    def __init__(self, filename: str, leaves: MerkleTreeData):
        self.filename = filename
        self.leaves = leaves

    @staticmethod
    def open(filename: str, num_leaves: int) -> MerkleTree:
        return MerkleTree(filename, MerkleTreeData.load(filename, num_leaves))

    def save(self) -> None:
        self.leaves.save(self.filename)

    @staticmethod
    def combine(left: bytes, right: bytes) -> bytes:
        result_i = HASH.mimc_mp(
            int.from_bytes(left, byteorder='big'),
            int.from_bytes(right, byteorder='big'))
        return result_i.to_bytes(32, byteorder='big')

    def get_num_entries(self) -> int:
        return self.leaves.num_populated

    def get_entry(self, index: int) -> bytes:
        return self.leaves.leaves[index]

    def compute_root(self) -> bytes:
        leaves = self.leaves.leaves
        layer_size = int(self.leaves.num_leaves / 2)

        scratch: List[bytes] = [
            self.combine(leaves[2*i], leaves[2*i + 1]) for i in range(layer_size)]

        while layer_size > 1:
            layer_size = int(layer_size / 2)
            for i in range(layer_size):
                scratch[i] = self.combine(scratch[2*i], scratch[2*i + 1])

        return scratch[0]

    def set_entry(self, index: int, value: bytes) -> None:
        self.leaves.set_entry(index, value)
