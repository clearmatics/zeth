// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/mimc.hpp

#ifndef __ZETH_MIMC_HASH_TCC__
#define __ZETH_MIMC_HASH_TCC__

namespace libzeth {

MiMC_hash_gadget::MiMC_hash_gadget(
		ProtoboardT &in_pb,
		const VariableT in_IV,
		const std::vector<VariableT>& in_messages,
    const VariableT out,
		const std::string &in_annotation_prefix
	) :
		GadgetT(in_pb, in_annotation_prefix),
		m_messages(in_messages),
		m_outputs(make_var_array(in_pb, in_messages.size(), FMT(in_annotation_prefix, ".outputs"))),
		m_IV(in_IV),
    out(out)
	{
		for( size_t i = 0; i < in_messages.size(); i++ )
		{
			const auto& m_i = in_messages[i];

			const VariableT& round_key = (i == 0 ? in_IV : m_outputs[i-1]);

			m_ciphers.emplace_back( in_pb, m_i, round_key, FMT(in_annotation_prefix, ".cipher[%d]", i) );
		}

	}

const VariableT& MiMC_hash_gadget::result() const {
		//return m_outputs[m_outputs.size() - 1];
    return out;
	}

void MiMC_hash_gadget::generate_r1cs_constraints (){
		for( size_t i = 0; i < m_ciphers.size() - 1; i++ )
		{
			m_ciphers[i].generate_r1cs_constraints();
			const VariableT& round_key = (i == 0 ? m_IV : m_outputs[i-1]);

			this->pb.add_r1cs_constraint(
				ConstraintT(
					round_key + m_ciphers[i].result() + m_messages[i],
					1,
					m_outputs[i]),
				".out = k + E_k(m_i) + m_i");
		}

    // enforce constraint for the output
    m_ciphers[m_ciphers.size()-1].generate_r1cs_constraints();
		const VariableT& round_key = m_outputs[m_ciphers.size()-2];

		this->pb.add_r1cs_constraint(
			ConstraintT(
				round_key + m_ciphers[m_ciphers.size()-1].result() + m_messages[m_ciphers.size()-1],
				1,
				out),
			".out = k + E_k(m_i) + m_i");

	}

void MiMC_hash_gadget::generate_r1cs_witness () const {
		for( size_t i = 0; i < m_ciphers.size() - 1; i++ )
		{
			m_ciphers[i].generate_r1cs_witness();

			const FieldT round_key = i == 0 ? pb.val(m_IV) : pb.val(m_outputs[i-1]);

			this->pb.val( m_outputs[i] ) = round_key + pb.val(m_ciphers[i].result()) + pb.val(m_messages[i]);
		}

      m_ciphers[m_ciphers.size()-1].generate_r1cs_witness();
	}
}  // libzeth

#endif // __ZETH_MIMC_HASH_TCC__
