# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from __future__ import annotations
from zeth.mimc import MiMC7
from os.path import exists
import json
import math
from typing import Dict, List, Tuple, Iterator, cast, Any


ZERO_ENTRY = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000")

HASH = MiMC7()


class MerkleTreeData:
    """
    Simple container to be persisted for a client-side Merkle tree. Does not
    perform any computation.  Layers are ordered from top (smallest) to bottom.
    """
    def __init__(
            self,
            depth: int,
            default_values: List[bytes],
            layers: List[List[bytes]]):
        self.depth = depth
        self.default_values = default_values
        self.layers = layers

    @staticmethod
    def empty_with_depth(depth: int) -> MerkleTreeData:
        # Compute default values for each layer
        default_values = [ZERO_ENTRY] * (depth + 1)
        for i in range(depth - 1, -1, -1):
            default_values[i] = MerkleTree.combine(
                default_values[i + 1], default_values[i + 1])

        # Initial layer data (fill the 0-th layer with the default root so it's
        # always available).
        layers: List[List[bytes]] = [[default_values[0]]]
        layers.extend([[] for _ in range(depth)])
        assert len(default_values) == depth + 1
        assert len(layers) == depth + 1
        return MerkleTreeData(depth, default_values, layers)

    @staticmethod
    def from_json_dict(json_dict: Dict[str, Any]) -> MerkleTreeData:
        depth = cast(int, json_dict["depth"])
        default_values = _to_list_bytes(
            cast(List[str], json_dict["default_values"]))
        layers = [
            _to_list_bytes(layer)
            for layer in cast(List[List[str]], json_dict["layers"])]
        return MerkleTreeData(depth, default_values, layers)

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            "depth": self.depth,
            "default_values": _to_list_str(self.default_values),
            "layers": [_to_list_str(layer) for layer in self.layers],
        }


class MerkleTree:
    """
    Merkle tree structure matching that used in the mixer contract. Simple
    implementation where unpopulated values (zeroes) are also stored.
    """
    def __init__(self, tree_data: MerkleTreeData, depth: int):
        self.max_num_leaves = pow(2, depth)
        self.depth = tree_data.depth
        self.tree_data = tree_data
        self.num_new_leaves = 0

    @staticmethod
    def empty_with_depth(depth: int) -> MerkleTree:
        return MerkleTree(MerkleTreeData.empty_with_depth(depth), depth)

    @staticmethod
    def empty_with_size(num_leaves: int) -> MerkleTree:
        depth = int(math.log(num_leaves, 2))
        assert pow(2, depth) == num_leaves, f"Non-pow-2 size {num_leaves} given"
        return MerkleTree.empty_with_depth(depth)

    @staticmethod
    def combine(left: bytes, right: bytes) -> bytes:
        result_i = HASH.mimc_mp(
            int.from_bytes(left, byteorder='big'),
            int.from_bytes(right, byteorder='big'))
        return result_i.to_bytes(32, byteorder='big')

    def get_num_entries(self) -> int:
        return len(self.tree_data.layers[self.depth])

    def get_leaf(self, index: int) -> bytes:
        leaves = self.tree_data.layers[self.depth]
        if index < len(leaves):
            return leaves[index]
        return ZERO_ENTRY

    def get_leaves(self) -> List[bytes]:
        return self.tree_data.layers[self.depth]

    def get_node(self, layer_idx: int, node_idx: int) -> bytes:
        assert layer_idx <= self.depth
        assert self.num_new_leaves == 0
        layer_idx = self.depth - layer_idx
        layer = self.tree_data.layers[layer_idx]
        if node_idx < len(layer):
            return layer[node_idx]
        return self.tree_data.default_values[layer_idx]

    def get_layers(self) -> Iterator[Tuple[bytes, List[bytes]]]:
        """
        Public layers iterator.
        """
        assert self.num_new_leaves == 0
        return self._get_layers()

    def get_root(self) -> bytes:
        assert self.num_new_leaves == 0
        return self.tree_data.layers[0][0]

    def insert(self, value: bytes) -> None:
        leaves = self.tree_data.layers[self.depth]
        assert len(leaves) < self.max_num_leaves
        leaves.append(value)
        self.num_new_leaves = self.num_new_leaves + 1

    def recompute_root(self) -> bytes:
        """
        After some new leaves have been added, perform the minimal set of hashes
        to recompute the tree, expanding each layer to accommodate new nodes.
        """
        if self.num_new_leaves == 0:
            return self.get_root()

        layers_it = self._get_layers()

        layer_default, layer = next(layers_it)
        end_idx = len(layer)
        start_idx = end_idx - self.num_new_leaves
        layer_size = self.max_num_leaves

        for parent_default, parent_layer in layers_it:
            # Computation for each layer is performed in _recompute_layer, which
            # also computes the start and end indices for the next layer in the
            # tree.
            start_idx, end_idx = _recompute_layer(
                layer,
                start_idx,
                end_idx,
                layer_default,
                parent_layer)
            layer = parent_layer
            layer_default = parent_default
            layer_size = int(layer_size / 2)

        self.num_new_leaves = 0
        assert len(layer) == 1
        assert layer_size == 1
        return layer[0]

    def _get_layers(self) -> Iterator[Tuple[bytes, List[bytes]]]:
        """
        Internal version of layers iterator for use during updating.
        With 0-th layer as the leaves (matching the public interface).
        """
        default_values = self.tree_data.default_values
        layers = self.tree_data.layers
        for i in range(self.depth, -1, -1):
            yield (default_values[i], layers[i])


def compute_merkle_path(address: int, mk_tree: MerkleTree) -> List[str]:
    """
    Given an "address" (index into leaves of a Merkle tree), compute the path to
    the root.
    """
    merkle_path: List[str] = []
    if address == -1:
        return merkle_path

    # Check each bit of address in turn.  If it is set, take the left node,
    # otherwise take the right node.
    for depth in range(mk_tree.depth):
        address_bit = address & 0x1
        if address_bit:
            merkle_path.append(mk_tree.get_node(depth, address - 1).hex())
        else:
            merkle_path.append(mk_tree.get_node(depth, address + 1).hex())
        address = address >> 1
    return merkle_path


class PersistentMerkleTree(MerkleTree):
    """
    Version of MerkleTree that also supports persistence.
    """
    def __init__(
            self, filename: str, tree_data: MerkleTreeData, depth: int):
        MerkleTree.__init__(self, tree_data, depth)
        self.filename = filename

    @staticmethod
    def open(filename: str, max_num_leaves: int) -> PersistentMerkleTree:
        depth = int(math.log(max_num_leaves, 2))
        assert max_num_leaves == int(math.pow(2, depth))
        if exists(filename):
            with open(filename, "r") as tree_f:
                json_dict = json.load(tree_f)
                tree_data = MerkleTreeData.from_json_dict(json_dict)
                assert depth == tree_data.depth
        else:
            tree_data = MerkleTreeData.empty_with_depth(depth)

        return PersistentMerkleTree(filename, tree_data, depth)

    def save(self) -> None:
        with open(self.filename, "w") as tree_f:
            json.dump(self.tree_data.to_json_dict(), tree_f)


def _leaf_address_to_node_address(address_leaf: int, tree_depth: int) -> int:
    """
    Converts the relative address of a leaf to an absolute address in the tree
    Important note: The merkle root index is 0 (not 1!)
    """
    address = address_leaf + (2 ** tree_depth - 1)
    if address > (2 ** (tree_depth + 1) - 1):
        return -1
    return address


def _recompute_layer(
        child_layer: List[bytes],
        child_start_idx: int,
        child_end_idx: int,
        child_default_value: bytes,
        parent_layer: List[bytes]) -> Tuple[int, int]:
    """
    Recompute nodes in the parent layer that are affected by entries
    [child_start_idx, child_end_idx[ in the child layer.  If `child_end_idx` is
    required in the calculation, the final entry of the child layer is used
    (since this contains the default entry for the layer if the tree is not
    full).  Returns the start and end indices (within the parent layer) of
    touched parent nodes.
    """

    #            /     \         /     \         /     \
    # Parent:   ?       ?       F       G       H       0
    #          / \     / \     / \     / \     / \     / \
    # Child:  ?   ?   ?   ?   A   B   C   D   E   ?   ?   0
    #                         ^                   ^
    #                child_start_idx         child_end_idx

    # Extend the parent layer to ensure it has enough capacity.
    new_parent_layer_length = int((child_end_idx + 1) / 2)
    parent_layer.extend(
        [ZERO_ENTRY] * (new_parent_layer_length - len(parent_layer)))

    # Compute the further right pair to compute, and iterate left until we reach
    # `child_idx_rend` (reverse-end).  `child_idx_rend` is the `child_start_idx`
    # rounded down to the next even number.
    child_left_idx_rend = int(child_start_idx / 2) * 2

    # If the child_end_idx is odd, the first hash must use the child layer's
    # default value on the right.
    if child_end_idx & 1:
        child_left_idx = child_end_idx - 1
        parent_layer[child_left_idx >> 1] = MerkleTree.combine(
            child_layer[child_left_idx], child_default_value)
    else:
        child_left_idx = child_end_idx

    # At this stage, all remaining pairs are populated.  Hash pairs and write
    # them to the parent layer.
    while child_left_idx > child_left_idx_rend:
        child_left_idx = child_left_idx - 2
        parent_layer[child_left_idx >> 1] = MerkleTree.combine(
            child_layer[child_left_idx], child_layer[child_left_idx + 1])

    return child_start_idx >> 1, new_parent_layer_length


def _to_list_bytes(list_str: List[str]) -> List[bytes]:
    return [bytes.fromhex(entry) for entry in list_str]


def _to_list_str(list_bytes: List[bytes]) -> List[str]:
    return [entry.hex() for entry in list_bytes]
