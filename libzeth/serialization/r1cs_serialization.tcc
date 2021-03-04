// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
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

template<typename FieldT>
void constraints_write_json(
    const libsnark::linear_combination<FieldT> &constraints,
    std::ostream &out_s)
{
    out_s << "[";
    size_t count = 0;
    for (const libsnark::linear_term<FieldT> &lt : constraints.terms) {
        if (count != 0) {
            out_s << ",";
        }

        out_s << "{";
        out_s << "\"index\":" << lt.index << ",";
        out_s << "\"value\":"
              << "\"" + bigint_to_hex<FieldT>(lt.coeff.as_bigint(), true)
              << "\"";
        out_s << "}";
        count++;
    }
    out_s << "]";
}

} // namespace internal

template<typename FieldT>
std::ostream &primary_inputs_write_json(
    const std::vector<FieldT> &public_inputs, std::ostream &out_s)
{
    out_s << "[";
    for (size_t i = 0; i < public_inputs.size(); ++i) {
        out_s << field_element_to_json(public_inputs[i]);
        if (i < public_inputs.size() - 1) {
            out_s << ",";
        }
    }
    out_s << "]";
    return out_s;
}

template<typename FieldT>
std::istream &primary_inputs_read_json(
    std::vector<FieldT> &public_inputs, std::istream &in_s)
{
    while (true) {
        char separator = 0;
        in_s >> separator;
        if ('[' != separator && ',' != separator) {
            break;
        }

        FieldT element;
        field_element_read_json(element, in_s);
        public_inputs.push_back(element);
    };
    return in_s;
}

template<typename ppT>
std::string accumulation_vector_to_json(
    const libsnark::accumulation_vector<libff::G1<ppT>> &acc_vector)
{
    std::stringstream ss;
    unsigned vect_length = acc_vector.rest.indices.size() + 1;
    ss << "[" << group_element_to_json(acc_vector.first);
    for (size_t i = 0; i < vect_length - 1; ++i) {
        ss << ", " << group_element_to_json(acc_vector.rest.values[i]);
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

    if (acc_vector_str.length() < (sizeof(prefix) - 1 + sizeof(suffix) - 1)) {
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
    libff::G1<ppT> front = group_element_from_json<libff::G1<ppT>>(element_str);
    start_idx = acc_vector_str.find(prefix, end_idx);

    // Extract remaining elements
    std::vector<libff::G1<ppT>> rest;
    do {
        end_idx = acc_vector_str.find(suffix, start_idx);
        if (end_idx == std::string::npos) {
            throw std::invalid_argument("invalid accumulation vector string");
        }

        element_str = acc_vector_str.substr(start_idx, end_idx + 2 - start_idx);
        rest.push_back(group_element_from_json<libff::G1<ppT>>(element_str));
        start_idx = acc_vector_str.find(prefix, end_idx);
    } while (start_idx != std::string::npos);

    return libsnark::accumulation_vector<libff::G1<ppT>>(
        std::move(front), std::move(rest));
}

template<typename FieldT>
std::ostream &r1cs_write_json(
    const libsnark::r1cs_constraint_system<FieldT> &r1cs, std::ostream &out_s)
{
    // output inputs, right now need to compile with debug flag so that the
    // `variable_annotations` exists. Having trouble setting that up so will
    // leave for now.

    out_s << "{\n";
    out_s << "\"scalar_field_characteristic\":"
          << "\"" + bigint_to_hex<FieldT>(FieldT::field_char(), true)
          << "\",\n";
    out_s << "\"num_variables\":" << r1cs.num_variables() << ",\n";
    out_s << "\"num_constraints\":" << r1cs.num_constraints() << ",\n";
    out_s << "\"num_inputs\": " << r1cs.num_inputs() << ",\n";
    out_s << "\"variables_annotations\":[";
    for (size_t i = 0; i < r1cs.num_variables(); ++i) {
        out_s << "{";
        out_s << "\"index\":" << i << ",";
        out_s << "\"annotation\":"
              << "\"" << r1cs.variable_annotations.at(i).c_str() << "\"";
        if (i == r1cs.num_variables() - 1) {
            out_s << "}";
        } else {
            out_s << "},";
        }
    }
    out_s << "],\n";
    out_s << "\"constraints\":[";
    for (size_t c = 0; c < r1cs.num_constraints(); ++c) {
        out_s << "{";
        out_s << "\"constraint_id\": " << c << ",";
        out_s << "\"constraint_annotation\": "
              << "\"" << r1cs.constraint_annotations.at(c).c_str() << "\",";
        out_s << "\"linear_combination\":";
        out_s << "{";
        out_s << "\"A\":";
        internal::constraints_write_json(r1cs.constraints[c].a, out_s);
        out_s << ",";
        out_s << "\"B\":";
        internal::constraints_write_json(r1cs.constraints[c].b, out_s);
        out_s << ",";
        out_s << "\"C\":";
        internal::constraints_write_json(r1cs.constraints[c].c, out_s);
        out_s << "}";
        if (c == r1cs.num_constraints() - 1) {
            out_s << "}";
        } else {
            out_s << "},";
        }
    }
    out_s << "]\n";
    out_s << "}";
    return out_s;
}

} // namespace libzeth

#endif // __ZETH_SERIALIZATION_R1CS_SERIALIZATION_TCC__
