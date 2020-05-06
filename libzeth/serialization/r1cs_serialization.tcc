// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SERIALIZATION_R1CS_SERIALIZATION_TCC__
#define __ZETH_SERIALIZATION_R1CS_SERIALIZATION_TCC__

#include "libzeth/serialization/r1cs_serialization.hpp"

namespace libzeth
{

namespace
{

template<typename ppT>
void constraints_write_json(
    const libsnark::linear_combination<libff::Fr<ppT>> &constraints,
    std::ostream &ss)
{
    ss << "[";
    size_t count = 0;
    for (const libsnark::linear_term<libff::Fr<ppT>> &lt : constraints.terms) {
        if (count != 0) {
            ss << ",";
        }

        ss << "{";
        ss << "\"index\":" << lt.index << ",";
        ss << "\"value\":"
           << "\"0x" + bigint_to_hex<libff::Fr<ppT>>(lt.coeff.as_bigint())
           << "\"";
        ss << "}";
        count++;
    }
    ss << "]";
}

} // namespace

template<typename ppT>
std::ostream &r1cs_write_json(
    const libsnark::protoboard<libff::Fr<ppT>> &pb, std::ostream &os)
{
    // output inputs, right now need to compile with debug flag so that the
    // `variable_annotations` exists. Having trouble setting that up so will
    // leave for now.
    libsnark::r1cs_constraint_system<libff::Fr<ppT>> constraints =
        pb.get_constraint_system();

    os << "{\n";
    os << "\"scalar_field_characteristic\":"
       << "\"Not yet supported. Should be bigint in hexadecimal\""
       << ",\n";
    os << "\"num_variables\":" << pb.num_variables() << ",\n";
    os << "\"num_constraints\":" << pb.num_constraints() << ",\n";
    os << "\"num_inputs\": " << pb.num_inputs() << ",\n";
    os << "\"variables_annotations\":[";
    for (size_t i = 0; i < constraints.num_variables(); ++i) {
        os << "{";
        os << "\"index\":" << i << ",";
        os << "\"annotation\":"
           << "\"" << constraints.variable_annotations[i].c_str() << "\"";
        if (i == constraints.num_variables() - 1) {
            os << "}";
        } else {
            os << "},";
        }
    }
    os << "],\n";
    os << "\"constraints\":[";
    for (size_t c = 0; c < constraints.num_constraints(); ++c) {
        os << "{";
        os << "\"constraint_id\": " << c << ",";
        os << "\"constraint_annotation\": "
           << "\"" << constraints.constraint_annotations[c].c_str() << "\",";
        os << "\"linear_combination\":";
        os << "{";
        os << "\"A\":";
        constraints_write_json<ppT>(constraints.constraints[c].a, os);
        os << ",";
        os << "\"B\":";
        constraints_write_json<ppT>(constraints.constraints[c].b, os);
        os << ",";
        os << "\"C\":";
        constraints_write_json<ppT>(constraints.constraints[c].c, os);
        os << "}";
        if (c == constraints.num_constraints() - 1) {
            os << "}";
        } else {
            os << "},";
        }
    }
    os << "]\n";
    os << "}\n";
    return os;
}

} // namespace libzeth

#endif // __ZETH_SERIALIZATION_R1CS_SERIALIZATION_TCC__
