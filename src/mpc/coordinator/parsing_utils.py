#!/usr/bin/env python3

import io
from werkzeug.datastructures import EnvironHeaders
from Crypto.Hash import SHA512
# from Crypto.PublicKey import ECC
# from Crypto.Signature import DSS
from typing import Optional
from .crypto import import_signature, import_verification_key, verify


TEST_VK = import_verification_key(
    "30" +
    "819b301006072a8648ce3d020106052b810400230381860004010b0bcea9b4fa" +
    "331695817099759bcc2d21105603a308c0957212975e1b355c43f3d204b66652" +
    "a0786e53cf3448771809a05fe1fe97e4086de26f84b33a70e31ebc00aa568907" +
    "3aa89da9ecb036c1031aa27c7839de62f097cf1d46704b594c021cde001ebd0e" +
    "3f0033b98817ffa466905ce81b7916432666b490e3cbf4ca8808ebf401")


def _read_part_headers(stream: io.IOBase) -> int:
    total_bytes = 0
    while True:
        line = stream.readline()
        bytes_read = len(line)
        total_bytes = total_bytes + bytes_read

        l_str = line.decode()
        print(f"read_part_headers: line({len(line)} bytes): '{l_str}'")
        if bytes_read < 3:
            if l_str == "\r\n" or l_str == "\n":
                break
            if bytes_read == 0:
                raise Exception("unexpected 0-length line")

    return total_bytes


def _read_to_file(
        stream: io.BufferedIOBase,
        file_name: str,
        bytes_to_read: int) -> Optional[bytes]:
    """
    Stream bytes to a file, while computing the digest.  Return the digest or
    None if there is an error.
    """

    CHUNK_SIZE = 4096

    h = SHA512.new()
    with open(file_name, "wb") as out_f:
        while bytes_to_read > 0:
            read_size = min(CHUNK_SIZE, bytes_to_read)
            chunk = stream.read(read_size)
            if 0 == len(chunk):
                return None

            h.update(chunk)
            out_f.write(chunk)
            bytes_to_read = bytes_to_read - len(chunk)

    print(f"_read_to_file: digest={h.hexdigest()}")
    return h.digest()


def _read_to_memory(
        stream: io.BufferedIOBase,
        bytes_to_read: int) -> Optional[bytes]:
    data = io.BytesIO()
    while bytes_to_read > 0:
        chunk = stream.read(bytes_to_read)
        if 0 == len(chunk):
            return None

        data.write(chunk)
        bytes_to_read = bytes_to_read - len(chunk)

    return data.getvalue()


def handle_upload_request(
        headers: EnvironHeaders,
        stream: io.BufferedIOBase,
        # public_key: str,
        file_name: str) -> None:
    """
    Given headers and an input stream, extract raw content to a file.
    """

    content_length = int(headers['Content-Length'])
    # print(f"content_length: {content_length}")

    content_type = headers['Content-Type']
    # print(f"content_type: {content_type}")

    sig_s = headers.get('X-Signature', None)
    if sig_s is None:
        raise Exception("signature not present")
    sig = import_signature(sig_s)

    boundary: str
    for val in content_type.split("; "):
        if val.startswith("boundary="):
            boundary = val[len("boundary="):]
    # print(f"boundary: {boundary}")

    final_boundary = f"\r\n--{boundary}--\r\n"
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
    print(f"expecting {remaining_bytes} file bytes")
    digest = _read_to_file(stream, 'upload', remaining_bytes)
    if digest is None:
        raise Exception("invalid part format")

    print(f"handle_upload_request: digest: {digest.hex()}")

    # Read final boundary and sanity check
    tail = _read_to_memory(stream, final_boundary_size)
    if tail is None or tail.decode() != final_boundary:
        raise Exception("invalid part tail")

    # check signature
    if not verify(sig, TEST_VK, digest):
        raise Exception("signature check failed")
