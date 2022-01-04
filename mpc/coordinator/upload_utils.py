#!/usr/bin/env python3

# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from Crypto.Hash import SHA512  # pylint: disable=import-error,no-name-in-module
from typing import Optional
import io

READ_CHUNK_SIZE = 4096


def _read_part_headers(stream: io.IOBase) -> int:
    total_bytes = 0
    while True:
        line = stream.readline()
        bytes_read = len(line)
        total_bytes = total_bytes + bytes_read

        l_str = line.decode()
        # print(f"read_part_headers: line({len(line)} bytes): '{l_str}'")
        if bytes_read < 3:
            if l_str in ["\r\n", "\n"]:
                break
            if bytes_read == 0:
                raise Exception("unexpected 0-length line")

    return total_bytes


def _read_to_file(
        stream: io.BufferedIOBase,
        file_name: str,
        bytes_to_read: int) -> Optional[bytes]:
    """
    Stream bytes to a file, while computing the digest. Return the digest or
    None if there is an error.
    """

    h = SHA512.new()
    with open(file_name, "wb") as out_f:
        while bytes_to_read > 0:
            read_size = min(READ_CHUNK_SIZE, bytes_to_read)
            chunk = stream.read(read_size)
            if len(chunk) == 0:
                return None

            h.update(chunk)
            out_f.write(chunk)
            bytes_to_read = bytes_to_read - len(chunk)

    # print(f"_read_to_file: digest={h.hexdigest()}")
    return h.digest()


def _read_to_memory(
        stream: io.BufferedIOBase,
        bytes_to_read: int) -> Optional[bytes]:
    data = io.BytesIO()
    while bytes_to_read > 0:
        chunk = stream.read(bytes_to_read)
        if len(chunk) == 0:
            return None

        data.write(chunk)
        bytes_to_read = bytes_to_read - len(chunk)

    return data.getvalue()


def handle_upload_request(
        content_length: int,
        content_boundary: str,
        expect_digest: bytes,
        stream: io.BufferedIOBase,
        file_name: str) -> None:
    """
    Given sufficient header data and an input stream, stream raw content to a
    file, hashing it at the same time to verify the given signature.
    """

    final_boundary = f"\r\n--{content_boundary}--\r\n"
    final_boundary_size = len(final_boundary)

    # Expect the stream to be formatted:
    #   --------------------------985b875979d96dfa          <boundary>
    #   Content-Disposition: form-data; ....                <part-header>
    #   Content-Type: application/octet-stream              <part-header>
    #   ...                                                 <part-header>
    #                                                       <blank-line>
    #   <raw-content>                                       <part-data>
    #   --------------------------985b875979d96dfa--        <final-boundary>
    # Note, for simplicity we assume content is single-part

    remaining_bytes = content_length - final_boundary_size

    # Skip the headers
    header_bytes = _read_part_headers(stream)
    remaining_bytes = remaining_bytes - header_bytes

    # Read up to the final boundary,
    # print(f"expecting {remaining_bytes} file bytes")
    digest = _read_to_file(stream, file_name, remaining_bytes)
    if digest is None:
        raise Exception("invalid part format")
    if digest != expect_digest:
        raise Exception("digest mismatch")

    # Read final boundary and sanity check
    tail = _read_to_memory(stream, final_boundary_size)
    if tail is None or tail.decode() != final_boundary:
        raise Exception("invalid part tail")
