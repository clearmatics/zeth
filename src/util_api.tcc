#ifndef __ZETH_UTIL_API_TCC__
#define __ZETH_UTIL_API_TCC__

namespace libzeth {

template<typename FieldT>
FieldT ParseMerkleNode(std::string mk_node) {
    return string_to_field<FieldT>(mk_node);
}

template<typename FieldT>
libzeth::JSInput<FieldT> ParseJSInput(const proverpkg::JSInput& input) {
    if (ZETH_MERKLE_TREE_DEPTH != input.merklenode_size()) {
        throw std::invalid_argument("Invalid merkle path length");
    }

    libzeth::ZethNote inputNote = ParseZethNote(input.note());
    size_t inputAddress = input.address();
    libzeth::bitsAddr inputAddressBits = libzeth::get_bitsAddr_from_vector(libzeth::address_bits_from_address(inputAddress, ZETH_MERKLE_TREE_DEPTH));
    libzeth::bits256 inputSpendingASK = libzeth::hexadecimal_digest_to_bits256(input.spendingask());
    libzeth::bits256 inputNullifier = libzeth::hexadecimal_digest_to_bits256(input.nullifier());

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

} //libzeth

#endif
