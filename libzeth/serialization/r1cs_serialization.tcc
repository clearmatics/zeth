// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SERIALIZATION_R1CS_SERIALIZATION_TCC__
#define __ZETH_SERIALIZATION_R1CS_SERIALIZATION_TCC__

#include "libzeth/core/field_element_utils.hpp"
#include "libzeth/core/group_element_utils.hpp"
#include "libzeth/serialization/r1cs_serialization.hpp"

namespace libzeth
{

namespace internal
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

} // namespace internal

template<typename ppT>
std::string primary_inputs_to_json(
    const std::vector<libff::Fr<ppT>> &public_inputs)
{
    std::stringstream ss;
    ss << "[";
    for (size_t i = 0; i < public_inputs.size(); ++i) {
        ss << "\"0x"
           << libzeth::bigint_to_hex<libff::Fr<ppT>>(
                  public_inputs[i].as_bigint())
           << "\"";
        if (i < public_inputs.size() - 1) {
            ss << ", ";
        }
    }
    ss << "]";
    std::string inputs_json_str = ss.str();

    return inputs_json_str;
}

template<typename ppT>
std::vector<libff::Fr<ppT>> primary_inputs_from_json(
    const std::string &input_str)
{
    std::vector<libff::Fr<ppT>> res;
    size_t next_hex_pos = input_str.find("0x");
    while (next_hex_pos != std::string::npos) {
        // TODO: avoid the string copy here
        const size_t end_hex = input_str.find("\"", next_hex_pos);
        const std::string next_hex =
            input_str.substr(next_hex_pos, end_hex - next_hex_pos);
        res.push_back(base_field_element_from_hex<libff::Fr<ppT>>(next_hex));
        next_hex_pos = input_str.find("0x", end_hex);
    }
    return res;
}

template<typename ppT>
std::string accumulation_vector_to_json(
    const libsnark::accumulation_vector<libff::G1<ppT>> &acc_vector)
{
    std::stringstream ss;
    unsigned vect_length = acc_vector.rest.indices.size() + 1;
    ss << "[" << point_affine_to_json(acc_vector.first);
    for (size_t i = 0; i < vect_length - 1; ++i) {
        ss << ", " << point_affine_to_json(acc_vector.rest.values[i]);
    }
    ss << "]";
    std::string vect_json_str = ss.str();

    return vect_json_str;
}

template<typename ppT>
libsnark::accumulation_vector<libff::G1<ppT>> accumulation_vector_from_json(
    const std::string &acc_vector_str)
{
    static const char prefix[] = "[\"";
    static const char suffix[] = "\"]";

    if (acc_vector_str.length() < (sizeof(prefix) + sizeof(suffix))) {
        throw std::invalid_argument("invalid accumulation vector string");
    }

    size_t start_idx = acc_vector_str.find(prefix);
    if (start_idx == std::string::npos) {
        throw std::invalid_argument("invalid accumulation vector string");
    }

    // TODO: Remove the temporary string.

    // Allocate once and reuse.
    std::string element_str;

    // Extract first element
    size_t end_idx = acc_vector_str.find(suffix, start_idx);
    if (end_idx == std::string::npos) {
        throw std::invalid_argument("invalid accumulation vector string");
    }

    // Extract the string '["....", "...."]'
    //                     ^             ^
    //                start_idx       end_idx

    element_str = acc_vector_str.substr(start_idx, end_idx + 2 - start_idx);
    libff::G1<ppT> front = point_affine_from_json<libff::G1<ppT>>(element_str);
    start_idx = acc_vector_str.find(prefix, end_idx);

    // Extract remaining elements
    std::vector<libff::G1<ppT>> rest;
    do {
        end_idx = acc_vector_str.find(suffix, start_idx);
        if (end_idx == std::string::npos) {
            throw std::invalid_argument("invalid accumulation vector string");
        }

        element_str = acc_vector_str.substr(start_idx, end_idx + 2 - start_idx);
        rest.push_back(point_affine_from_json<libff::G1<ppT>>(element_str));
        start_idx = acc_vector_str.find(prefix, end_idx);
    } while (start_idx != std::string::npos);

    return libsnark::accumulation_vector<libff::G1<ppT>>(
        std::move(front), std::move(rest));
}

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
        internal::constraints_write_json<ppT>(constraints.constraints[c].a, os);
        os << ",";
        os << "\"B\":";
        internal::constraints_write_json<ppT>(constraints.constraints[c].b, os);
        os << ",";
        os << "\"C\":";
        internal::constraints_write_json<ppT>(constraints.constraints[c].c, os);
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
