#ifndef __ZETH_UTIL_API_TCC__
#define __ZETH_UTIL_API_TCC__


// Message formatting and parsing utility

namespace libzeth {

template<typename FieldT>
FieldT ParseMerkleNode(std::string mk_node) {
    return string_to_field<FieldT>(mk_node);
}

template<typename FieldT>
libzeth::ZethNote<FieldT> ParseZethNote(const proverpkg::ZethNote& note) {

    FieldT noteAPK = string_to_field<FieldT>(note.apk());

    FieldT noteValue = string_to_field<FieldT>(note.value());

    FieldT noteRho = string_to_field<FieldT>(note.rho());

    FieldT noteTrapR0 = string_to_field<FieldT>(note.trapr0());

    FieldT noteTrapR1 = string_to_field<FieldT>(note.trapr1());

    return libzeth::ZethNote<FieldT>(
        noteAPK,
        noteValue,
        noteRho,
        noteTrapR0,
        noteTrapR1
    );
}

template<typename FieldT>
libzeth::JSInput<FieldT> ParseJSInput(const proverpkg::JSInput& input) {
    if (ZETH_MERKLE_TREE_DEPTH != input.merklenode_size()) {
        throw std::invalid_argument("Invalid merkle path length");
    }

    libzeth::ZethNote<FieldT> inputNote = ParseZethNote<FieldT>(input.note());
    size_t inputAddress = input.address();

    libzeth::bitsAddr inputAddressBits = libzeth::get_bitsAddr_from_vector(libzeth::address_bits_from_address(inputAddress, ZETH_MERKLE_TREE_DEPTH));
    FieldT inputSpendingASK = string_to_field<FieldT>(input.spendingask());
    FieldT inputNullifier = string_to_field<FieldT>(input.nullifier());

    std::vector<FieldT> inputMerklePath;

    for(int i = 0; i < ZETH_MERKLE_TREE_DEPTH; i++) {
        FieldT mk_node = ParseMerkleNode<FieldT>(input.merklenode(i));
        inputMerklePath.push_back(mk_node);
    }

    return libzeth::JSInput<FieldT>(
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

} // libzeth

#endif // __ZETH_UTIL_TCC__

