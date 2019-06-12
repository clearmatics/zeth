// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/mimc.hpp

#ifndef __ZETH_MIMC_HASH_TCC__
#define __ZETH_MIMC_HASH_TCC__

namespace libzeth {

template<typename FieldT>
MiMC_hash_gadget<FieldT>::MiMC_hash_gadget(
    libsnark::protoboard<FieldT> &in_pb,
    const libsnark::pb_variable<FieldT> in_iv,
    const std::vector<libsnark::pb_variable<FieldT>>& in_messages,
    const libsnark::pb_variable<FieldT> in_out,
    const std::string &in_annotation_prefix
  ) :
    libsnark::gadget<FieldT>(in_pb, in_annotation_prefix),
    messages(in_messages),
    iv(in_iv),
    out(in_out)
  {
    // allocate output variables array
    outputs.allocate(in_pb, in_messages.size(), FMT(in_annotation_prefix, ".outputs"));

    for( size_t i = 0; i < in_messages.size(); i++ ) {
        const libsnark::pb_variable<FieldT>& m = in_messages[i];

        // round key variable is set to be the output variable of the previous permutation gadget, except for round 0 where is used the initial vector
        const libsnark::pb_variable<FieldT>& round_key = (i == 0 ? in_iv : outputs[i-1]);

        // allocate a permutation gadget for each message
        permutation_gadgets.emplace_back( in_pb, m, round_key, FMT(in_annotation_prefix, ".cipher[%d]", i) );
    }
  }

template<typename FieldT>
const libsnark::pb_variable<FieldT>& MiMC_hash_gadget<FieldT>::result() const {
    return out; //TODO: review it if return out or outputs[in_messages.size()-1] and in case modify the tests
  }

template<typename FieldT>
void MiMC_hash_gadget<FieldT>::generate_r1cs_constraints (){

    // Setting constraints for all permutation gadgets (except the last one)
    for( size_t i = 0; i < permutation_gadgets.size() - 1; i++ ) {

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

    // Setting constraints for the last permutation gadget
    permutation_gadgets[permutation_gadgets.size()-1].generate_r1cs_constraints();
    const libsnark::pb_variable<FieldT>& round_key = outputs[permutation_gadgets.size()-2];


    // Adding constraint for the Miyaguchi-Preneel equation to be equal to `in_out/out`
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(
          round_key + permutation_gadgets[permutation_gadgets.size()-1].result() + messages[permutation_gadgets.size()-1],
          1,
          out),
        ".out = k + E_k(m_i) + m_i");

    }

template<typename FieldT>
void MiMC_hash_gadget<FieldT>::generate_r1cs_witness () const {
    for( size_t i = 0; i < permutation_gadgets.size() - 1; i++ ) {

        // Generating witness for each permutation gadget (except last one)
        permutation_gadgets[i].generate_r1cs_witness();

        const FieldT round_key = i == 0 ? this->pb.val(iv) : this->pb.val(outputs[i-1]);

        // Filling output variables for Miyaguchi-Preenel equation
        this->pb.val( outputs[i] ) = round_key + this->pb.val(permutation_gadgets[i].result()) + this->pb.val(messages[i]);
        }

      // Generating witness for last one permutation gadget, Miyaguchi-Preneel out variable is filled yet
      permutation_gadgets[permutation_gadgets.size()-1].generate_r1cs_witness();
}
}  // libzeth

#endif // __ZETH_MIMC_HASH_TCC__
