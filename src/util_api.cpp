#include "util_api.hpp"

// Message formatting and parsing utility

namespace libzeth {

ZethNote ParseZethNote(const proverpkg::ZethNote& note) {
    bits256 noteAPK = hexadecimal_digest_to_bits256(note.apk());
    bits64 noteValue = hexadecimal_value_to_bits64(note.value());
    bits256 noteRho = hexadecimal_digest_to_bits256(note.rho());
    bits384 noteTrapR = get_bits384_from_vector(hexadecimal_str_to_binary_vector(note.trapr()));

    return ZethNote(
        noteAPK,
        noteValue,
        noteRho,
        noteTrapR
    );
}

proverpkg::HexadecimalPointBaseGroup1Affine FormatHexadecimalPointBaseGroup1Affine(libff::alt_bn128_G1 point) {
    libff::alt_bn128_G1 aff = point;
    aff.to_affine_coordinates();
    std::string xCoord = "0x" + HexStringFromLibsnarkBigint(aff.X.as_bigint());
    std::string yCoord = "0x" + HexStringFromLibsnarkBigint(aff.Y.as_bigint());

    proverpkg::HexadecimalPointBaseGroup1Affine res;
    res.set_xcoord(xCoord);
    res.set_ycoord(yCoord);

    return res;
}

proverpkg::HexadecimalPointBaseGroup2Affine FormatHexadecimalPointBaseGroup2Affine(libff::alt_bn128_G2 point) {
    libff::alt_bn128_G2 aff = point;
    aff.to_affine_coordinates();
    std::string xC1Coord = "0x" + HexStringFromLibsnarkBigint(aff.X.c1.as_bigint());
    std::string xC0Coord = "0x" + HexStringFromLibsnarkBigint(aff.X.c0.as_bigint());
    std::string yC1Coord = "0x" + HexStringFromLibsnarkBigint(aff.Y.c1.as_bigint());
    std::string yC0Coord = "0x" + HexStringFromLibsnarkBigint(aff.Y.c0.as_bigint());

    proverpkg::HexadecimalPointBaseGroup2Affine res;
    res.set_xc0coord(xC0Coord);
    res.set_xc1coord(xC1Coord);
    res.set_yc0coord(yC0Coord);
    res.set_yc1coord(yC1Coord);

    return res;
}

} // libzeth
