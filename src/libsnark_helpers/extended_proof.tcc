#ifndef __ZETH_EXTENDED_PROOF_TCC__
#define __ZETH_EXTENDED_PROOF_TCC__

namespace libzeth {

template<typename ppT>
extended_proof<ppT>::extended_proof(libsnark::r1cs_ppzksnark_proof<ppT> &in_proof,
                                    libsnark::r1cs_ppzksnark_primary_input<ppT> &in_primary_input)
{
    this->proof = std::make_shared<libsnark::r1cs_ppzksnark_proof<ppT>>(in_proof);
    this->primary_inputs = std::make_shared<libsnark::r1cs_ppzksnark_primary_input<ppT>>(in_primary_input);
}

template<typename ppT>
libsnark::r1cs_ppzksnark_proof<ppT> extended_proof<ppT>::get_proof()
{
    return *this->proof;
}

template<typename ppT>
libsnark::r1cs_ppzksnark_primary_input<ppT> extended_proof<ppT>::get_primary_input()
{
    return *this->primary_inputs;
}

template<typename ppT>
void extended_proof<ppT>::write_extended_proof(boost::filesystem::path path)
{
	proof_and_input_to_json(*this->proof, *this->primary_inputs, path);
}

template<typename ppT>
void extended_proof<ppT>::write_primary_input(boost::filesystem::path path)
{
	primary_input_to_json<ppT>(*this->primary_inputs, path);
}

template<typename ppT>
void extended_proof<ppT>::write_proof(boost::filesystem::path path)
{
	proof_to_json(*this->proof, path);
}


template<typename ppT>
void extended_proof<ppT>::dump_proof()
{
	display_proof(*this->proof);
}

template<typename ppT>
void extended_proof<ppT>::dump_primary_inputs()
{
	display_primary_input<ppT>(*this->primary_inputs);
}

} // libzeth

#endif
