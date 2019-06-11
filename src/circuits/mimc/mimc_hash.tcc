// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/mimc.hpp

#ifndef __ZETH_MIMC_HASH_TCC__
#define __ZETH_MIMC_HASH_TCC__

namespace libzeth {

template<typename FieldT>
MiMC_hash_gadget<FieldT>::MiMC_hash_gadget(
		libsnark::protoboard<FieldT> &in_pb,
		const libsnark::pb_variable<FieldT> in_IV,
		const std::vector<libsnark::pb_variable<FieldT>>& in_messages,
    const libsnark::pb_variable<FieldT> out,
		const std::string &in_annotation_prefix
	) :
		libsnark::gadget<FieldT>(in_pb, in_annotation_prefix),
		m_messages(in_messages),
		m_IV(in_IV),
    out(out)
	{
    m_outputs.allocate(in_pb, in_messages.size(), FMT(in_annotation_prefix, ".outputs"));

		for( size_t i = 0; i < in_messages.size(); i++ )
		{
			const auto& m_i = in_messages[i];

			const libsnark::pb_variable<FieldT>& round_key = (i == 0 ? in_IV : m_outputs[i-1]);

			m_ciphers.emplace_back( in_pb, m_i, round_key, FMT(in_annotation_prefix, ".cipher[%d]", i) );
		}

	}

template<typename FieldT>
const libsnark::pb_variable<FieldT>& MiMC_hash_gadget<FieldT>::result() const {
    return out;
	}

template<typename FieldT>
void MiMC_hash_gadget<FieldT>::generate_r1cs_constraints (){
		for( size_t i = 0; i < m_ciphers.size() - 1; i++ )
		{
			m_ciphers[i].generate_r1cs_constraints();
			const libsnark::pb_variable<FieldT>& round_key = (i == 0 ? m_IV : m_outputs[i-1]);

			this->pb.add_r1cs_constraint(
				libsnark::r1cs_constraint<FieldT>(
					round_key + m_ciphers[i].result() + m_messages[i],
					1,
					m_outputs[i]),
				".out = k + E_k(m_i) + m_i");
		}

    // enforce constraint for the output
    m_ciphers[m_ciphers.size()-1].generate_r1cs_constraints();
		const libsnark::pb_variable<FieldT>& round_key = m_outputs[m_ciphers.size()-2];

		this->pb.add_r1cs_constraint(
			libsnark::r1cs_constraint<FieldT>(
				round_key + m_ciphers[m_ciphers.size()-1].result() + m_messages[m_ciphers.size()-1],
				1,
				out),
			".out = k + E_k(m_i) + m_i");

	}

template<typename FieldT>
void MiMC_hash_gadget<FieldT>::generate_r1cs_witness () const {
		for( size_t i = 0; i < m_ciphers.size() - 1; i++ )
		{
			m_ciphers[i].generate_r1cs_witness();

			const FieldT round_key = i == 0 ? this->pb.val(m_IV) : this->pb.val(m_outputs[i-1]);

			this->pb.val( m_outputs[i] ) = round_key + this->pb.val(m_ciphers[i].result()) + this->pb.val(m_messages[i]);
		}

      m_ciphers[m_ciphers.size()-1].generate_r1cs_witness();
	}
}  // libzeth

#endif // __ZETH_MIMC_HASH_TCC__
