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
	std::vector<MiMCe7_permutation_gadget<FieldT>> permutation_gadgets; // Vector of permutation gadgets
	std::vector<libsnark::pb_variable<FieldT>> messages; 				// Vector of messages to process
	libsnark::pb_variable_array<FieldT> outputs; 						// Vector of round gadget outputs
	libsnark::pb_variable<FieldT> iv; 									// Initialization vector variable

	MiMC_hash_gadget(
		libsnark::protoboard<FieldT> &pb,
		const std::vector<libsnark::pb_variable<FieldT>>& messages,		// Vector of messages to hash
    	const libsnark::pb_variable<FieldT> iv,							// Miyagushi-Preneel IV
		const std::string& round_constant_iv,							// MiMC round constants iv
		const std::string &annotation_prefix = "MiMC_hash_gadget"
	);

	void generate_r1cs_constraints ();

	void generate_r1cs_witness () const;

	// Returns the hash computed from the message inputs and iv
	const libsnark::pb_variable<FieldT>& result() const;

};

// Returns the hash (not constrained) of a vector of message and iv
template<typename FieldT>
FieldT get_hash(const std::vector<FieldT>& messages, FieldT iv, const std::string& round_constant_iv);

} // libzeth

#include "mimc_hash.tcc"

#endif // __ZETH_MIMC_HASH_HPP__
