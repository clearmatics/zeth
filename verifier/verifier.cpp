// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/serialization/r1cs_variable_assignment_serialization.hpp"
#include "libzeth/snarks/groth16/groth16_snark.hpp"
#include "libzeth/snarks/pghr13/pghr13_snark.hpp"

#include <boost/program_options.hpp>
#include <iostream>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>
#include <libff/algebra/curves/bw6_761/bw6_761_pp.hpp>
#include <string>

namespace po = boost::program_options;

static std::ifstream open_file(const std::string &filename)
{
    std::ifstream in_s(
        filename.c_str(), std::ios_base::in | std::ios_base::binary);
    in_s.exceptions(
        std::ios_base::eofbit | std::ios_base::badbit | std::ios_base::failbit);
    return in_s;
}

template<typename ppT, typename snarkT>
int verifier_main(
    const std::string &vk_file,
    const std::string &primary_input_file,
    const std::string &proof_file)
{
    ppT::init_public_params();
    libff::inhibit_profiling_info = true;
    libff::inhibit_profiling_counters = true;

    typename snarkT::verification_key verification_key;
    {
        std::ifstream in_s = open_file(vk_file);
        snarkT::verification_key_read_bytes(verification_key, in_s);
    }

    libsnark::r1cs_primary_input<libff::Fr<ppT>> primary_input;
    {
        std::ifstream in_s = open_file(primary_input_file);
        libzeth::r1cs_variable_assignment_read_bytes(primary_input, in_s);
    }

    typename snarkT::proof proof;
    {
        std::ifstream in_s = open_file(proof_file);
        snarkT::proof_read_bytes(proof, in_s);
    }

    if (!snarkT::verify(primary_input, proof, verification_key)) {
        std::cout << "verification failed.\n";
        return 1;
    }

    return 0;
}

template<typename ppT>
int verifier_resolve_snark(
    const std::string &vk_file,
    const std::string &primary_input_file,
    const std::string &proof_file,
    const std::string &snark)
{
    if (snark == "groth16") {
        return verifier_main<ppT, libzeth::groth16_snark<ppT>>(
            vk_file, primary_input_file, proof_file);
    } else if (snark == "pghr13") {
        return verifier_main<ppT, libzeth::pghr13_snark<ppT>>(
            vk_file, primary_input_file, proof_file);
    }

    throw po::error("unrecognized snark");
}

int verifier_resolve_curve(
    const std::string &vk_file,
    const std::string &primary_input_file,
    const std::string &proof_file,
    const std::string &curve,
    const std::string &snark)
{
    if (curve == "alt-bn128") {
        return verifier_resolve_snark<libff::alt_bn128_pp>(
            vk_file, primary_input_file, proof_file, snark);
    } else if (curve == "bls12-377") {
        return verifier_resolve_snark<libff::bls12_377_pp>(
            vk_file, primary_input_file, proof_file, snark);
    } else if (curve == "bw6-761") {
        return verifier_resolve_snark<libff::bw6_761_pp>(
            vk_file, primary_input_file, proof_file, snark);
    }

    throw po::error("unrecognized curve");
}

int main(int argc, char **argv)
{
    // Options
    po::options_description options("Options");
    options.add_options()(
        "curve,c",
        po::value<std::string>(),
        "Curve: alt-bn128, bls12-377 or bw6-761");
    options.add_options()(
        "snark,s", po::value<std::string>(), "Snark: groth16 or pghr13");

    po::options_description all_options(options);
    all_options.add_options()(
        "vk_file", po::value<std::string>(), "Verification key file");
    all_options.add_options()(
        "primary_input_file", po::value<std::string>(), "Proof file");
    all_options.add_options()(
        "proof_file", po::value<std::string>(), "Proof file");

    po::positional_options_description pos;
    pos.add("vk_file", 1);
    pos.add("primary_input_file", 1);
    pos.add("proof_file", 1);

    try {
        po::parsed_options parsed = po::command_line_parser{argc, argv}
                                        .options(all_options)
                                        .positional(pos)
                                        .run();
        po::variables_map vm;
        po::store(parsed, vm);

        if (0 == vm.count("vk_file")) {
            throw po::error("vk_file not specified");
        }
        if (0 == vm.count("primary_input_file")) {
            throw po::error("primary_input_file not specified");
        }
        if (0 == vm.count("proof_file")) {
            throw po::error("proof_file not specified");
        }
        std::string vk_file = vm["vk_file"].as<std::string>();
        std::string proof_file = vm["proof_file"].as<std::string>();
        std::string primary_input_file =
            vm["primary_input_file"].as<std::string>();
        std::string curve =
            vm.count("curve") ? vm["curve"].as<std::string>() : "alt-bn128";
        std::string snark =
            vm.count("snark") ? vm["snark"].as<std::string>() : "groth16";

        verifier_resolve_curve(
            vk_file, primary_input_file, proof_file, curve, snark);
    } catch (po::error &error) {
        std::cerr << " ERROR: " << error.what() << "\n";
        std::cout
            << "Usage:\n"
            << "  " << argv[0]
            << " [<options>] <vk_file> <primary_input_file> <proof_file>\n\n"
            << options << std::endl;
        return 1;
    }
}
