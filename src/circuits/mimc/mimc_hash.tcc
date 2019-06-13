// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/mimc.hpp

#ifndef __ZETH_MIMC_HASH_TCC__
#define __ZETH_MIMC_HASH_TCC__

namespace libzeth {

template<typename FieldT>
MiMC_hash_gadget<FieldT>::MiMC_hash_gadget(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_variable<FieldT> iv,
    const std::vector<libsnark::pb_variable<FieldT>>& messages,
    libsnark::pb_variable<FieldT>& out,
    const std::string &annotation_prefix
  ) :
    libsnark::gadget<FieldT>(pb, annotation_prefix),
    messages(messages),
    iv(iv),
    out(out)
  {
    // allocate output variables array
    outputs.allocate(pb, messages.size(), FMT(annotation_prefix, ".outputs"));

    for( size_t i = 0; i < messages.size(); i++ ) {
        const libsnark::pb_variable<FieldT>& m = messages[i];

        // round key variable is set to be the output variable of the previous permutation gadget, except for round 0 where is used the initial vector
        const libsnark::pb_variable<FieldT>& round_key = (i == 0 ? iv : outputs[i-1]);

        // allocate a permutation gadget for each message
        permutation_gadgets.emplace_back( pb, m, round_key, FMT(annotation_prefix, ".cipher[%d]", i) );
    }
  }

template<typename FieldT>
const libsnark::pb_variable<FieldT>& MiMC_hash_gadget<FieldT>::result() const {
    return out;
  }

template<typename FieldT>
void MiMC_hash_gadget<FieldT>::generate_r1cs_constraints (){

    // Setting constraints for all permutation gadgets (except the last one)
    for( size_t i = 0; i < permutation_gadgets.size() ; i++ ) {

        permutation_gadgets[i].generate_r1cs_constraints();
        const libsnark::pb_variable<FieldT>& round_key = (i == 0 ? iv : outputs[i-1]);

        // Adding constraint for the Miyaguchi-Preneel equation
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
              round_key + permutation_gadgets[i].result() + messages[i],
              1,
              outputs[i]),
            ".out = k + E_k(m_i) + m_i");
    }


    }

template<typename FieldT>
void MiMC_hash_gadget<FieldT>::generate_r1cs_witness () const {
    for( size_t i = 0; i < permutation_gadgets.size(); i++ ) {

        // Generating witness for each permutation gadget (except last one)
        permutation_gadgets[i].generate_r1cs_witness();

        const FieldT round_key = i == 0 ? this->pb.val(iv) : this->pb.val(outputs[i-1]);

        // Filling output variables for Miyaguchi-Preenel equation
        this->pb.val( outputs[i] ) = round_key + this->pb.val(permutation_gadgets[i].result()) + this->pb.val(messages[i]);
        }

        // Filling output variable
        this->pb.val(out) = this->pb.val( outputs[permutation_gadgets.size()-1]);
}
}  // libzeth

#endif // __ZETH_MIMC_HASH_TCC__
