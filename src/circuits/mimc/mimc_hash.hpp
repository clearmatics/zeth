// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/mimc.hpp

#ifndef __ZETH_MIMC_HASH_HPP__
#define __ZETH_MIMC_HASH_HPP__

#include "snarks_alias.hpp"
#include "mimc.hpp"

namespace libzeth {

template<typename FieldT>
class MiMC_hash_gadget:public libsnark::gadget<FieldT> {
/*
  MiMC_hash_gadget enforces correct computation of a MiMCHash based on a MiMC permutation with exponent 7
  */
public:
	std::vector<MiMCe7_permutation_gadget<FieldT>> m_ciphers; // vector of permutation gadgets
	std::vector<libsnark::pb_variable<FieldT>> m_messages;  //  vector of messages to process
	libsnark::pb_variable_array<FieldT> m_outputs; // vector of round outputs variables
	const libsnark::pb_variable<FieldT> m_IV; // initial vector variable
  const libsnark::pb_variable<FieldT> out;

	MiMC_hash_gadget(
		libsnark::protoboard<FieldT> &in_pb,
		const libsnark::pb_variable<FieldT> in_IV,
		const std::vector<libsnark::pb_variable<FieldT>>& in_messages,
    const libsnark::pb_variable<FieldT> out,
		const std::string &in_annotation_prefix
	);

	const libsnark::pb_variable<FieldT>& result() const;
	void generate_r1cs_constraints ();
	void generate_r1cs_witness () const;
};

} // libzeth

#include "mimc_hash.tcc"

#endif // __ZETH_MIMC_HASH_HPP__
