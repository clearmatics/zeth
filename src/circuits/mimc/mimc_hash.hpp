// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/mimc.hpp

#ifndef __ZETH_MIMC_HASH_HPP__
#define __ZETH_MIMC_HASH_HPP__

#include "snarks_alias.hpp"
#include "mimc.hpp"

namespace libzeth {

class MiMC_hash_gadget:public GadgetT {
/*
  MiMC_hash_gadget enforces correct computation of a MiMCHash based on a MiMC permutation with exponent 7
  */
public:
	std::vector<MiMCe7_permutation_gadget> m_ciphers; // vector of permutation gadgets
	const std::vector<VariableT> m_messages;  //  vector of messages to process
	const VariableArrayT m_outputs; // vector of round outputs variables
	const VariableT m_IV; // initial vector variable
  const VariableT out;

	MiMC_hash_gadget(
		ProtoboardT &in_pb,
		const VariableT in_IV,
		const std::vector<VariableT>& in_messages,
    const VariableT out,
		const std::string &in_annotation_prefix
	);

	const VariableT& result() const;
	void generate_r1cs_constraints ();
	void generate_r1cs_witness () const;
};

} // libzeth

#include "mimc_hash.tcc"

#endif // __ZETH_MIMC_HASH_HPP__
