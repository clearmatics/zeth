// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/mimc.hpp

#ifndef __ZETH_MIMC_HASH_TCC__
#define __ZETH_MIMC_HASH_TCC__

namespace libzeth {

template<typename FieldT>
MiMC_hash_gadget<FieldT>::MiMC_hash_gadget(
    libsnark::protoboard<FieldT> &pb,
    const std::vector<libsnark::pb_variable<FieldT>>& messages,
    const libsnark::pb_variable<FieldT> iv,
    const std::string& round_constant_iv,
    const std::string &annotation_prefix
  ) :
    libsnark::gadget<FieldT>(pb, annotation_prefix),
    messages(messages),
    iv(iv)
  {
    // allocate output variables array
    outputs.allocate(pb, messages.size(), FMT(annotation_prefix, ".outputs"));

    for( size_t i = 0; i < messages.size(); i++ ) {
        const libsnark::pb_variable<FieldT>& m = messages[i];

        // round key variable is set to be the output variable of the previous permutation gadget, except for round 0 where is used the initial vector
        const libsnark::pb_variable<FieldT>& round_key = (i == 0 ? iv : outputs[i-1]);

        // allocate a permutation gadget for each message
        permutation_gadgets.emplace_back( pb, m, round_key, round_constant_iv, FMT(annotation_prefix, ".cipher[%d]", i) );
    }
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
      std::cout << "iv:" << std::endl;
      std::cout << this->pb.val(iv)  << std::endl;

      std::cout << "messages:" << std::endl;
      for (size_t i = 0; i < this->messages.size(); i++)
      {
        std::cout << this->pb.val(messages[i]) << std::endl;
      }
      std::cout << "hash res: " << this->pb.val( outputs[messages.size()-1]) << std::endl;
}

template<typename FieldT>
const libsnark::pb_variable<FieldT>& MiMC_hash_gadget<FieldT>::result() const {
    // Returns the last round gadget ouput
    return outputs[messages.size()-1];
}

template<typename FieldT>
FieldT get_hash(const std::vector<FieldT>& messages, FieldT iv, const std::string& round_constant_iv)
{
    libsnark::protoboard<FieldT> pb;

    // Allocates and fill the message inputs
    std::vector<libsnark::pb_variable<FieldT>> inputs;
    for (size_t i = 0; i < messages.size(); i++)
    {
      libsnark::pb_variable<FieldT> input;
      input.allocate(pb, std::to_string(i));
      pb.val(input) = messages[i];
      inputs.push_back(input);
    }

    // Allocates and fill the iv
    libsnark::pb_variable<FieldT> init_vector;
    init_vector.allocate(pb, "iv");
    pb.val(init_vector) = iv;

    // Initialize the Hash
    MiMC_hash_gadget<FieldT> mimc_hasher(pb, inputs, init_vector, round_constant_iv, "mimc_hash");

    // Computes the hash
    mimc_hasher.generate_r1cs_witness();

    // Returns the hash
    return pb.val(mimc_hasher.result());
}

}  // libzeth

#endif // __ZETH_MIMC_HASH_TCC__
