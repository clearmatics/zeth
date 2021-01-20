# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zeth.core.mimc import MiMCBase
from typing import List


# Default seed, generated as:
#   zeth.core.mimc._keccak_256(
#       zeth.core.mimc._str_to_bytes("clearmatics_hash_seed"))
DEFAULT_IV_UINT256 = \
    13196537064117388418196223856311987714388543839552400408340921397545324034315


class InputHasher:
    """
    Note that this is currently experimental code. Hash a series of field
    elements via the Merkle-Damgard construction on a MiMC compression
    function. Note that since this function only accepts whole numbers of
    scalar field elements, there is no ambiguity w.r.t to padding and we could
    technically omit the finalization step. It has been kept for now, to allow
    time for further consideration, and in case the form of the hasher changes
    (e.g. in case we want to be able to hash arbitrary bit strings in the
    future).
    """
    def __init__(self, compression_fn: MiMCBase, iv: int = DEFAULT_IV_UINT256):
        assert compression_fn.prime < (2 << 256)
        self._compression_fn = compression_fn
        self._iv = iv % compression_fn.prime

    def hash(self, values: List[int]) -> int:
        current = self._iv
        for m in values:
            current = self._compression_fn.hash_int(current, m)
        return self._compression_fn.hash_int(current, len(values))
