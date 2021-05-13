// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "zeth_tool/dump_proof_cmd.hpp"

#include "libtool/tool_util.hpp"
#include "libzeth/serialization/r1cs_variable_assignment_serialization.hpp"
#include "zeth_tool/tool_common.hpp"

namespace zethtool
{

namespace commands
{

class dump_proof_cmd : public zeth_subcommand
{
public:
    dump_proof_cmd(
        const std::string &subcommand_name, const std::string &description)
        : zeth_subcommand(subcommand_name, description)
    {
    }

protected:
    /// Given in the form of a class, in order to be used as a parameter to
    /// curve_and_snark_resolver.
    template<typename ppT, typename snarkT> class prove_runner
    {
    public:
        static int execute(const std::string &proof_file)
        {
            ppT::init_public_params();
            libff::inhibit_profiling_info = true;
            libff::inhibit_profiling_counters = true;

            typename snarkT::proof proof;
            {
                std::ifstream in_s =
                    libtool::open_input_binary_file(proof_file);
                snarkT::proof_read_bytes(proof, in_s);
            }

            snarkT::proof_write_json(proof, std::cout);
            std::cout << "\n";
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
            "proof_file", po::value<std::string>(), "(Output) Proof file");

        pos.add("proof_file", 1);
    }

    void parse_suboptions(
        const boost::program_options::variables_map &vm) override
    {
        if (vm.count("proof_file") == 0) {
            throw po::error("proof_file not specified");
        }
        proof_file = vm["proof_file"].as<std::string>();

        curve = vm.count("curve") ? vm["curve"].as<std::string>() : "alt-bn128";
        snark = vm.count("snark") ? vm["snark"].as<std::string>() : "groth16";
    }

    void subcommand_usage(const char *argv0) override
    {
        std::cout << "Usage:\n  " << argv0 << " dump-proof [proof_file]\n";
    }

    int execute_subcommand(const global_options &) override
    {
        return curve_and_snark_resolver<prove_runner>::resolve(
            curve, snark, proof_file);
    }

    std::string proof_file;
    std::string curve;
    std::string snark;
};

} // namespace commands

zeth_subcommand *dump_proof_cmd =
    new commands::dump_proof_cmd("dump-proof", "Print an existing proof");

} // namespace zethtool
