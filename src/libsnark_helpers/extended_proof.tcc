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
void extended_proof<ppT>::write_extended_proof(boost::filesystem::path path)
{
	proofAndInputToJson(*this->proof, *this->primary_inputs, path);
}

template<typename ppT>
void extended_proof<ppT>::write_primary_input(boost::filesystem::path path)
{
	primaryInputToJson<ppT>(*this->primary_inputs, path);
}

template<typename ppT>
void extended_proof<ppT>::write_proof(boost::filesystem::path path)
{
	proofToJson(*this->proof, path);
}


template<typename ppT>
void extended_proof<ppT>::dump_proof()
{
	displayProof(*this->proof);
}

template<typename ppT>
void extended_proof<ppT>::dump_primary_inputs()
{
	display_primary_input<ppT>(*this->primary_inputs);
}

} // libzeth

#endif // __ZETH_EXTENDED_PROOF_TCC__
