// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_UTIL_API_TCC__
#define __ZETH_UTIL_API_TCC__

#include "libzeth/util_api.hpp"

namespace libzeth
{

template<typename FieldT> FieldT parse_merkle_node(std::string mk_node)
{
    return hexadecimal_str_to_field_element<FieldT>(mk_node);
}

template<typename FieldT, size_t TreeDepth>
joinsplit_input<FieldT, TreeDepth> parse_joinsplit_input(
    const zeth_proto::JoinsplitInput &input)
{
    if (TreeDepth != input.merkle_path_size()) {
        throw std::invalid_argument("Invalid merkle path length");
    }

    zeth_note input_note = parse_zeth_note(input.note());
    size_t inputAddress = input.address();
    bits_addr<TreeDepth> input_address_bits =
        get_bits_addr_from_vector<TreeDepth>(
            address_bits_from_address<TreeDepth>(inputAddress));
    bits256 input_spending_ask = hex_digest_to_bits256(input.spending_ask());
    bits256 input_nullifier = hex_digest_to_bits256(input.nullifier());

    std::vector<FieldT> input_merkle_path;
    for (size_t i = 0; i < TreeDepth; i++) {
        FieldT mk_node = parse_merkle_node<FieldT>(input.merkle_path(i));
        input_merkle_path.push_back(mk_node);
    }

    return joinsplit_input<FieldT, TreeDepth>(
        input_merkle_path,
        input_address_bits,
        input_note,
        input_spending_ask,
        input_nullifier);
}

template<typename ppT>
zeth_proto::HexPointBaseGroup1Affine format_hexPointBaseGroup1Affine(
    const libff::G1<ppT> &point)
{
    libff::G1<ppT> aff = point;
    aff.to_affine_coordinates();
    std::string x_coord =
        "0x" + hex_from_libsnark_bigint<libff::Fq<ppT>>(aff.X.as_bigint());
    std::string y_coord =
        "0x" + hex_from_libsnark_bigint<libff::Fq<ppT>>(aff.Y.as_bigint());

    zeth_proto::HexPointBaseGroup1Affine res;
    res.set_x_coord(x_coord);
    res.set_y_coord(y_coord);

    return res;
}

template<typename ppT>
zeth_proto::HexPointBaseGroup2Affine format_hexPointBaseGroup2Affine(
    const libff::G2<ppT> &point)
{
    libff::G2<ppT> aff = point;
    aff.to_affine_coordinates();
    std::string x_c1_coord =
        "0x" + hex_from_libsnark_bigint<libff::Fq<ppT>>(aff.X.c1.as_bigint());
    std::string x_c0_coord =
        "0x" + hex_from_libsnark_bigint<libff::Fq<ppT>>(aff.X.c0.as_bigint());
    std::string y_c1_coord =
        "0x" + hex_from_libsnark_bigint<libff::Fq<ppT>>(aff.Y.c1.as_bigint());
    std::string y_c0_coord =
        "0x" + hex_from_libsnark_bigint<libff::Fq<ppT>>(aff.Y.c0.as_bigint());

    zeth_proto::HexPointBaseGroup2Affine res;
    res.set_x_c0_coord(x_c0_coord);
    res.set_x_c1_coord(x_c1_coord);
    res.set_y_c0_coord(y_c0_coord);
    res.set_y_c1_coord(y_c1_coord);

    return res;
}

template<typename ppT>
std::string format_primary_inputs(std::vector<libff::Fr<ppT>> public_inputs)
{
    std::stringstream ss;
    ss << "[";
    for (size_t i = 0; i < public_inputs.size(); ++i) {
        ss << "\"0x"
           << libzeth::hex_from_libsnark_bigint<libff::Fr<ppT>>(
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

/// Parse points in affine coordinates
template<typename ppT>
libff::G1<ppT> parse_hexPointBaseGroup1Affine(
    const zeth_proto::HexPointBaseGroup1Affine &point)
{
    libff::Fq<ppT> x_coordinate =
        hexadecimal_str_to_field_element<libff::Fq<ppT>>(point.x_coord());
    libff::Fq<ppT> y_coordinate =
        hexadecimal_str_to_field_element<libff::Fq<ppT>>(point.y_coord());

    libff::G1<ppT> res = libff::G1<ppT>(x_coordinate, y_coordinate);

    return res;
}

/// Parse points in affine coordinates
template<typename ppT>
libff::G2<ppT> parse_hexPointBaseGroup2Affine(
    const zeth_proto::HexPointBaseGroup2Affine &point)
{
    libff::Fq<ppT> x_c1 =
        hexadecimal_str_to_field_element<libff::Fq<ppT>>(point.x_c1_coord());
    libff::Fq<ppT> x_c0 =
        hexadecimal_str_to_field_element<libff::Fq<ppT>>(point.x_c0_coord());
    libff::Fq<ppT> y_c1 =
        hexadecimal_str_to_field_element<libff::Fq<ppT>>(point.y_c1_coord());
    libff::Fq<ppT> y_c0 =
        hexadecimal_str_to_field_element<libff::Fq<ppT>>(point.y_c0_coord());

    // See:
    // https://github.com/scipr-lab/libff/blob/master/libff/algebra/curves/public_params.hpp#L88
    // and:
    // https://github.com/scipr-lab/libff/blob/master/libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp#L33
    //
    // As such, each element of Fqe is assumed to be a vector of 2 coefficients
    // lying in the base field
    libff::Fqe<ppT> x_coordinate(x_c0, x_c1);
    libff::Fqe<ppT> y_coordinate(y_c0, y_c1);

    libff::G2<ppT> res =
        libff::G2<ppT>(x_coordinate, y_coordinate, libff::Fqe<ppT>::one());

    return res;
}

template<typename ppT>
std::vector<libff::Fr<ppT>> parse_str_primary_inputs(std::string input_str)
{
    char *cstr = new char[input_str.length() + 1];
    std::strcpy(cstr, input_str.c_str());
    char *pos;
    printf("Splitting string \"%s\" into tokens:\n", cstr);

    std::vector<libff::Fr<ppT>> res;
    pos = strtok(cstr, "[, ]");

    while (pos != NULL) {
        res.push_back(
            hexadecimal_str_to_field_element<libff::Fr<ppT>>(std::string(pos)));
        pos = strtok(NULL, "[, ]");
    }

    // Free heap memory allocated with the `new` above
    delete[] cstr;

    return res;
}

template<typename ppT>
libzeth::extended_proof<ppT> parse_groth16_extended_proof(
    const zeth_proto::ExtendedProof &ext_proof)
{
    const zeth_proto::ExtendedProofGROTH16 &e_proof =
        ext_proof.groth16_extended_proof();
    // G1
    libff::G1<ppT> a = parse_hexPointBaseGroup1Affine<ppT>(e_proof.a());
    // G2
    libff::G2<ppT> b = parse_hexPointBaseGroup2Affine<ppT>(e_proof.b());
    // G1
    libff::G1<ppT> c = parse_hexPointBaseGroup1Affine<ppT>(e_proof.c());

    std::vector<libff::Fr<ppT>> inputs =
        libsnark::r1cs_primary_input<libff::Fr<ppT>>(
            parse_str_primary_inputs<ppT>(e_proof.inputs()));

    libsnark::r1cs_gg_ppzksnark_proof<ppT> proof(
        std::move(a), std::move(b), std::move(c));
    libzeth::extended_proof<ppT> res(proof, inputs);

    return res;
}

template<typename ppT>
libzeth::extended_proof<ppT> parse_pghr13_extended_proof(
    const zeth_proto::ExtendedProof &ext_proof)
{
    const zeth_proto::ExtendedProofPGHR13 &e_proof =
        ext_proof.pghr13_extended_proof();

    libff::G1<ppT> a = parse_hexPointBaseGroup1Affine<ppT>(e_proof.a());
    libff::G1<ppT> a_p = parse_hexPointBaseGroup1Affine<ppT>(e_proof.a_p());
    libsnark::knowledge_commitment<libff::G1<ppT>, libff::G1<ppT>> g_A(a, a_p);

    libff::G2<ppT> b = parse_hexPointBaseGroup2Affine<ppT>(e_proof.b());
    libff::G1<ppT> b_p = parse_hexPointBaseGroup1Affine<ppT>(e_proof.b_p());
    libsnark::knowledge_commitment<libff::G2<ppT>, libff::G1<ppT>> g_B(b, b_p);

    libff::G1<ppT> c = parse_hexPointBaseGroup1Affine<ppT>(e_proof.c());
    libff::G1<ppT> c_p = parse_hexPointBaseGroup1Affine<ppT>(e_proof.c_p());
    libsnark::knowledge_commitment<libff::G1<ppT>, libff::G1<ppT>> g_C(c, c_p);

    libff::G1<ppT> h = parse_hexPointBaseGroup1Affine<ppT>(e_proof.h());
    libff::G1<ppT> k = parse_hexPointBaseGroup1Affine<ppT>(e_proof.k());

    libsnark::r1cs_ppzksnark_proof<ppT> proof(
        std::move(g_A),
        std::move(g_B),
        std::move(g_C),
        std::move(h),
        std::move(k));
    libsnark::r1cs_primary_input<libff::Fr<ppT>> inputs =
        libsnark::r1cs_primary_input<libff::Fr<ppT>>(
            parse_str_primary_inputs<ppT>(e_proof.inputs()));
    libzeth::extended_proof<ppT> res(proof, inputs);

    return res;
}

template<typename ppT>
libzeth::extended_proof<ppT> parse_extended_proof(
    const zeth_proto::ExtendedProof &ext_proof)
{
#ifdef ZKSNARK_PGHR13
    return parse_pghr13_extended_proof<ppT>(ext_proof);
#elif ZKSNARK_GROTH16
    return parse_groth16_extended_proof<ppT>(ext_proof);
#else
#error You must define one of the SNARK_* symbols indicated into the CMakelists.txt file.
#endif
}

template<typename ppT>
libsnark::accumulation_vector<libff::G1<ppT>> parse_str_accumulation_vector(
    std::string acc_vector_str)
{
    // std::string input_str = "[[one0, one1], [two0, two1], [three0, three1],
    // [four0, four1]]";
    char *cstr = new char[acc_vector_str.length() + 1];
    std::strcpy(cstr, acc_vector_str.c_str());
    char *pos;
    printf("Splitting string \"%s\" into tokens:\n", cstr);

    std::vector<std::string> res;
    pos = strtok(cstr, "[, ]");

    while (pos != NULL) {
        res.push_back(std::string(pos));
        pos = strtok(NULL, "[, ]");
    }

    // Free heap memory allocated with the `new` above
    delete[] cstr;

    // Each element of G1 has 2 coordinates (the points are in the affine form)
    //
    // Messy check that the size of the vector resulting from the string parsing
    // is of the form 2*n meaning that it contains the x and y coordinates of n
    // points
    if (res.size() > 0 && res.size() % 2 != 0) {
        // TODO: Do exception throwing/catching properly
        std::cerr
            << "parse_str_accumulation_vector: Wrong number of coordinates"
            << std::endl;
        exit(1);
    }

    libsnark::accumulation_vector<libff::G1<ppT>> acc_res;
    libff::Fq<ppT> x_coordinate =
        hexadecimal_str_to_field_element<libff::Fq<ppT>>(res[0]);
    libff::Fq<ppT> y_coordinate =
        hexadecimal_str_to_field_element<libff::Fq<ppT>>(res[1]);

    libff::G1<ppT> first_point_g1 = libff::G1<ppT>(x_coordinate, y_coordinate);
    acc_res.first = first_point_g1;

    // Set the `rest` of the accumulation vector
    libsnark::sparse_vector<libff::G1<ppT>> rest;
    libff::G1<ppT> point_g1;
    for (size_t i = 2; i < res.size(); i += 2) {
        // TODO:
        // This is BAD => this code is a duplicate of the function
        // `hexadecimal_str_to_field_element` Let's re-use the content of the
        // function `hexadecimal_str_to_field_element` here. To do this properly
        // this means that we need to modify the type of `abc_g1` in the proto
        // file to be a repeated G1 element (and not a string) Likewise for the
        // inputs which should be changed to repeated field elements
        libff::Fq<ppT> x_coordinate =
            hexadecimal_str_to_field_element<libff::Fq<ppT>>(res[i]);
        libff::Fq<ppT> y_coordinate =
            hexadecimal_str_to_field_element<libff::Fq<ppT>>(res[i + 1]);

        point_g1 = libff::G1<ppT>(x_coordinate, y_coordinate);
        rest[i / 2 - 1] = point_g1;
    }

    acc_res.rest = rest;
    return acc_res;
}

template<typename ppT>
libsnark::r1cs_gg_ppzksnark_verification_key<ppT> parse_groth16_vk(
    const zeth_proto::VerificationKey &verification_key)
{
    const zeth_proto::VerificationKeyGROTH16 &verif_key =
        verification_key.groth16_verification_key();
    // G1
    libff::G1<ppT> alpha_g1 =
        parse_hexPointBaseGroup1Affine<ppT>(verif_key.alpha_g1());
    // G2
    libff::G2<ppT> beta_g2 =
        parse_hexPointBaseGroup2Affine<ppT>(verif_key.beta_g2());
    // G2
    libff::G2<ppT> delta_g2 =
        parse_hexPointBaseGroup2Affine<ppT>(verif_key.delta_g2());

    // Parse the accumulation vector which has been stringyfied
    // and which is in the form:
    // [
    //   [point 1],
    //   [point 2],
    //   ...
    // ]
    libsnark::accumulation_vector<libff::G1<ppT>> abc_g1 =
        parse_str_accumulation_vector<ppT>(verif_key.abc_g1());

    libsnark::r1cs_gg_ppzksnark_verification_key<ppT> vk(
        alpha_g1, beta_g2, delta_g2, abc_g1);

    return vk;
}

template<typename ppT>
libsnark::r1cs_ppzksnark_verification_key<ppT> parse_pghr13_vk(
    const zeth_proto::VerificationKey &verification_key)
{
    const zeth_proto::VerificationKeyPGHR13 &verif_key =
        verification_key.pghr13_verification_key();
    // G2
    libff::G2<ppT> a = parse_hexPointBaseGroup2Affine<ppT>(verif_key.a());
    // G1
    libff::G1<ppT> b = parse_hexPointBaseGroup1Affine<ppT>(verif_key.b());
    // G2
    libff::G2<ppT> c = parse_hexPointBaseGroup2Affine<ppT>(verif_key.c());
    // G2
    libff::G1<ppT> gamma =
        parse_hexPointBaseGroup2Affine<ppT>(verif_key.gamma());
    // G1
    libff::G1<ppT> gamma_beta_g1 =
        parse_hexPointBaseGroup1Affine<ppT>(verif_key.gamma_beta_g1());
    // G2
    libff::G2<ppT> gamma_beta_g2 =
        parse_hexPointBaseGroup2Affine<ppT>(verif_key.gamma_beta_g2());
    // G2
    libff::G2<ppT> z = parse_hexPointBaseGroup2Affine<ppT>(verif_key.z());

    libsnark::accumulation_vector<libff::G1<ppT>> ic =
        parse_str_accumulation_vector<ppT>(verif_key.ic());

    libsnark::r1cs_ppzksnark_verification_key<ppT> vk(
        a, b, c, gamma, gamma_beta_g1, gamma_beta_g2, z, ic);

    return vk;
}

template<typename ppT>
libzeth::verificationKeyT<ppT> parse_verification_key(
    const zeth_proto::VerificationKey &verification_key)
{
#ifdef ZKSNARK_PGHR13
    return parse_pghr13_vk<ppT>(verification_key);
#elif ZKSNARK_GROTH16
    return parse_groth16_vk<ppT>(verification_key);
#else
#error You must define one of the SNARK_* symbols indicated into the CMakelists.txt file.
#endif
}

} // namespace libzeth

#endif // __ZETH_UTIL_API_TCC__
