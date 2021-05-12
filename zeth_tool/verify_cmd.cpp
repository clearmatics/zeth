// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "zeth_tool/verify_cmd.hpp"

#include "libtool/tool_util.hpp"
#include "libzeth/serialization/r1cs_variable_assignment_serialization.hpp"

namespace zethtool
{

namespace commands
{

class verify_cmd : public zeth_subcommand
{
public:
    verify_cmd(
        const std::string &subcommand_name, const std::string &description)
        : zeth_subcommand(subcommand_name, description)
    {
    }

protected:
    /// Given in the form of a class, in order to be used as a parameter to
    /// curve_and_snark_resolver.
    template<typename ppT, typename snarkT> class verify_runner
    {
    public:
        static int execute(
            const std::string &vk_file,
            const std::string &primary_input_file,
            const std::string &proof_file)
        {
            ppT::init_public_params();
            libff::inhibit_profiling_info = true;
            libff::inhibit_profiling_counters = true;

            typename snarkT::verification_key verification_key;
            {
                std::ifstream in_s = libtool::open_input_binary_file(vk_file);
                snarkT::verification_key_read_bytes(verification_key, in_s);
            }

            libsnark::r1cs_primary_input<libff::Fr<ppT>> primary_input;
            {
                std::ifstream in_s =
                    libtool::open_input_binary_file(primary_input_file);
                libzeth::r1cs_variable_assignment_read_bytes(
                    primary_input, in_s);
            }

            typename snarkT::proof proof;
            {
                std::ifstream in_s =
                    libtool::open_input_binary_file(proof_file);
                snarkT::proof_read_bytes(proof, in_s);
            }

            if (!snarkT::verify(primary_input, proof, verification_key)) {
                std::cout << "verification failed.\n";
                return 1;
            }

            return 0;
        }
    };

    void initialize_suboptions(
        boost::program_options::options_description &options,
        boost::program_options::options_description &all_options,
        boost::program_options::positional_options_description &pos) override
    {
        // Options
        options.add_options()(
            "curve,c",
            po::value<std::string>(),
            "Curve: alt-bn128, bls12-377 or bw6-761");
        options.add_options()(
            "snark,s", po::value<std::string>(), "Snark: groth16 or pghr13");

        all_options.add(options).add_options()(
            "vk_file", po::value<std::string>(), "Verification key file");
        all_options.add_options()(
            "primary_input_file",
            po::value<std::string>(),
            "Primary input file");
        all_options.add_options()(
            "proof_file", po::value<std::string>(), "Proof file");

        pos.add("vk_file", 1);
        pos.add("primary_input_file", 1);
        pos.add("proof_file", 1);
    }

    void parse_suboptions(
        const boost::program_options::variables_map &vm) override
    {
        if (vm.count("vk_file") == 0) {
            throw po::error("vk_file not specified");
        }
        if (vm.count("primary_input_file") == 0) {
            throw po::error("primary_input_file not specified");
        }
        if (vm.count("proof_file") == 0) {
            throw po::error("proof_file not specified");
        }

        vk_file = vm["vk_file"].as<std::string>();
        proof_file = vm["proof_file"].as<std::string>();
        primary_input_file = vm["primary_input_file"].as<std::string>();
        curve = vm.count("curve") ? vm["curve"].as<std::string>() : "alt-bn128";
        snark = vm.count("snark") ? vm["snark"].as<std::string>() : "groth16";
    }

    void subcommand_usage(const char *argv0) override
    {
        std::cout << "Usage:\n"
                     "  "
                  << argv0
                  << " verify [vk_file] [primary_input_file] [proof_file]\n";
    }

    int execute_subcommand(const global_options &) override
    {
        return curve_and_snark_resolver<verify_runner>::resolve(
            curve, snark, vk_file, primary_input_file, proof_file);
    }

    std::string vk_file;
    std::string proof_file;
    std::string primary_input_file;
    std::string curve;
    std::string snark;
};

} // namespace commands

zeth_subcommand *verify_cmd = new commands::verify_cmd(
    "verify", "Verify proof against verification key and primary input");

} // namespace zethtool
