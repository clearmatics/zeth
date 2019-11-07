#include "util_api.hpp"

// Message formatting and parsing utility

namespace libzeth
{

zeth_note parse_zeth_note(const prover_proto::ZethNote &note)
{
    bits256 note_apk = hex_digest_to_bits256(note.apk());
    bits64 note_value = hex_value_to_bits64(note.value());
    bits256 note_rho = hex_digest_to_bits256(note.rho());
    bits384 note_trap_r =
        get_bits384_from_vector(hex_str_to_binary_vector(note.trap_r()));

    return zeth_note(note_apk, note_value, note_rho, note_trap_r);
}

prover_proto::HexPointBaseGroup1Affine format_hexPointBaseGroup1Affine(
    libff::alt_bn128_G1 point)
{
    libff::alt_bn128_G1 aff = point;
    aff.to_affine_coordinates();
    std::string x_coord =
        "0x" + hex_string_from_libsnark_bigint(aff.X.as_bigint());
    std::string y_coord =
        "0x" + hex_string_from_libsnark_bigint(aff.Y.as_bigint());

    prover_proto::HexPointBaseGroup1Affine res;
    res.set_x_coord(x_coord);
    res.set_y_coord(y_coord);

    return res;
}

prover_proto::HexPointBaseGroup2Affine format_hexPointBaseGroup2Affine(
    libff::alt_bn128_G2 point)
{
    libff::alt_bn128_G2 aff = point;
    aff.to_affine_coordinates();
    std::string x_c1_coord =
        "0x" + hex_string_from_libsnark_bigint(aff.X.c1.as_bigint());
    std::string x_c0_coord =
        "0x" + hex_string_from_libsnark_bigint(aff.X.c0.as_bigint());
    std::string y_c1_coord =
        "0x" + hex_string_from_libsnark_bigint(aff.Y.c1.as_bigint());
    std::string y_c0_coord =
        "0x" + hex_string_from_libsnark_bigint(aff.Y.c0.as_bigint());

    prover_proto::HexPointBaseGroup2Affine res;
    res.set_x_c0_coord(x_c0_coord);
    res.set_x_c1_coord(x_c1_coord);
    res.set_y_c0_coord(y_c0_coord);
    res.set_y_c1_coord(y_c1_coord);

    return res;
}

} // namespace libzeth
