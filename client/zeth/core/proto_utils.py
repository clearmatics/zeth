# Copyright (c) 2015-2022 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

"""
Utilities to handle protobuf types
"""

from zeth.core import constants
from zeth.api.zeth_messages_pb2 import ZethNote

from typing import Dict


# ZethNote binary serialization format:
#   [apk   : APK_LENGTH_BYTES]
#   [value : PUBLIC_VALUE_LENGTH_BYTES]
#   [rho   : RHO_LENGTH_BYTES]
#   [trapr : TRAPR_LENGTH_BYTES]
_APK_OFFSET_BYTES = 0
_VALUE_OFFSET_BYTES = _APK_OFFSET_BYTES + constants.APK_LENGTH_BYTES
_RHO_OFFSET_BYTES = _VALUE_OFFSET_BYTES + constants.PUBLIC_VALUE_LENGTH_BYTES
_TRAPR_OFFSET_BYTES = _RHO_OFFSET_BYTES + constants.RHO_LENGTH_BYTES
assert _TRAPR_OFFSET_BYTES + constants.TRAPR_LENGTH_BYTES \
    == constants.NOTE_LENGTH_BYTES


def zeth_note_to_json_dict(zeth_note_grpc_obj: ZethNote) -> Dict[str, str]:
    return {
        "a_pk": zeth_note_grpc_obj.apk,
        "value": zeth_note_grpc_obj.value,
        "rho": zeth_note_grpc_obj.rho,
        "trap_r": zeth_note_grpc_obj.trap_r,
    }


def zeth_note_from_json_dict(parsed_zeth_note: Dict[str, str]) -> ZethNote:
    note = ZethNote(
        apk=parsed_zeth_note["a_pk"],
        value=parsed_zeth_note["value"],
        rho=parsed_zeth_note["rho"],
        trap_r=parsed_zeth_note["trap_r"]
    )
    return note


def zeth_note_to_bytes(zeth_note_grpc_obj: ZethNote) -> bytes:
    apk_bytes = bytes.fromhex(zeth_note_grpc_obj.apk)
    value_bytes = bytes.fromhex(zeth_note_grpc_obj.value)
    rho_bytes = bytes.fromhex(zeth_note_grpc_obj.rho)
    trap_r_bytes = bytes.fromhex(zeth_note_grpc_obj.trap_r)
    note_bytes = apk_bytes + value_bytes + rho_bytes + trap_r_bytes
    assert len(note_bytes) == (constants.NOTE_LENGTH_BYTES)
    return note_bytes


def zeth_note_from_bytes(note_bytes: bytes) -> ZethNote:
    if len(note_bytes) != (constants.NOTE_LENGTH_BYTES):
        raise ValueError(
            f"note_bytes len {len(note_bytes)}, "
            f"(expected {constants.NOTE_LENGTH_BYTES})")
    apk = note_bytes[
        _APK_OFFSET_BYTES:_APK_OFFSET_BYTES + constants.APK_LENGTH_BYTES]
    value = note_bytes[
        _VALUE_OFFSET_BYTES:
        _VALUE_OFFSET_BYTES + constants.PUBLIC_VALUE_LENGTH_BYTES]
    rho = note_bytes[
        _RHO_OFFSET_BYTES:_RHO_OFFSET_BYTES + constants.RHO_LENGTH_BYTES]
    trap_r = note_bytes[_TRAPR_OFFSET_BYTES:]
    return ZethNote(
        apk=apk.hex(), value=value.hex(), rho=rho.hex(), trap_r=trap_r.hex())
