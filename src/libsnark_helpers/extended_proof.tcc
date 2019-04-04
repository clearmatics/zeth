#ifndef __ZETH_EXTENDED_PROOF_TCC__
#define __ZETH_EXTENDED_PROOF_TCC__

namespace libzeth {

template<typename ppT>
extended_proof<ppT>::extended_proof(proofT<ppT> &in_proof, libsnark::r1cs_primary_input<libff::Fr<ppT>> &in_primary_input)
{
    this->proof = std::make_shared<proofT<ppT>>(in_proof);
    this->primary_inputs = std::make_shared<libsnark::r1cs_primary_input<libff::Fr<ppT>>>(in_primary_input);
}

template<typename ppT>
proofT<ppT> extended_proof<ppT>::get_proof()
{
    return *this->proof;
}

template<typename ppT>
libsnark::r1cs_primary_input<libff::Fr<ppT>> extended_proof<ppT>::get_primary_input()
{
    return *this->primary_inputs;
}

template<typename ppT>
void extended_proof<ppT>::write_primary_input(boost::filesystem::path path)
{
	if (path.empty()) {
		boost::filesystem::path tmp_path = getPathToDebugDir(); // Used for a debug purpose
		boost::filesystem::path primary_input_json("primary_input.json");
		path = tmp_path / primary_input_json;
	}
    // Convert the boost path into char*
    const char* str_path = path.string().c_str();

    std::stringstream ss;
    std::ofstream fh;
    fh.open(str_path, std::ios::binary);

    ss << "{\n";
    ss << " \"inputs\" :" << "["; // 1 should always be the first variable passed
    for (size_t i = 0; i < *this->primary_inputs.size(); ++i) {
        ss << "\"0x" << HexStringFromLibsnarkBigint(*this->primary_inputs[i].as_bigint()) << "\"";
        if ( i < *this->primary_inputs.size() - 1 ) {
            ss<< ", ";
        }
    }
    ss << "]\n";
    ss << "}";

    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

} // libzeth

#endif // __ZETH_EXTENDED_PROOF_TCC__
