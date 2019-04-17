#include "util_api.hpp"

// Message formatting and parsing utility

namespace libzeth {

libsnark::merkle_authentication_node ParseMerkleNode(std::string mk_node) {
    return libff::bit_vector(libzeth::hexadecimal_digest_to_binary_vector(mk_node));
}

libzeth::ZethNote ParseZethNote(const proverpkg::ZethNote& note) {
    libzeth::bits256 noteAPK = libzeth::hexadecimal_digest_to_bits256(note.apk());
    libzeth::bits64 noteValue = libzeth::hexadecimal_value_to_bits64(note.value());
    libzeth::bits256 noteRho = libzeth::hexadecimal_digest_to_bits256(note.rho());
    libzeth::bits384 noteTrapR = libzeth::get_bits384_from_vector(libzeth::hexadecimal_str_to_binary_vector(note.trapr()));

    return libzeth::ZethNote(
        noteAPK,
        noteValue,
        noteRho,
        noteTrapR
    );
}

libzeth::JSInput ParseJSInput(const proverpkg::JSInput& input) {
    if (ZETH_MERKLE_TREE_DEPTH != input.merklenode_size()) {
        throw std::invalid_argument("Invalid merkle path length");
    }

    libzeth::ZethNote inputNote = ParseZethNote(input.note());
    size_t inputAddress = input.address();
    libzeth::bitsAddr inputAddressBits = libzeth::get_bitsAddr_from_vector(libzeth::address_bits_from_address(inputAddress, ZETH_MERKLE_TREE_DEPTH));
    libzeth::bits256 inputSpendingASK = libzeth::hexadecimal_digest_to_bits256(input.spendingask());
    libzeth::bits256 inputNullifier = libzeth::hexadecimal_digest_to_bits256(input.nullifier());

    std::vector<libsnark::merkle_authentication_node> inputMerklePath;
    for(int i = 0; i < ZETH_MERKLE_TREE_DEPTH; i++) {
        libsnark::merkle_authentication_node mk_node = ParseMerkleNode(input.merklenode(i));
        inputMerklePath.push_back(mk_node);
    }

    return libzeth::JSInput(
        inputMerklePath,
        inputAddress,
        inputAddressBits,
        inputNote,
        inputSpendingASK,
        inputNullifier
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

}
