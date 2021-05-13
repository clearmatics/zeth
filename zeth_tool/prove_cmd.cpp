// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "zeth_tool/prove_cmd.hpp"

#include "libtool/tool_util.hpp"
#include "libzeth/serialization/r1cs_variable_assignment_serialization.hpp"
#include "zeth_tool/tool_common.hpp"

namespace zethtool
{

namespace commands
{

class prove_cmd : public zeth_subcommand
{
public:
    prove_cmd(
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
        static int execute(
            const std::string &pk_file,
            const std::string &assignment_file,
            uint16_t num_primary_inputs,
            const std::string &proof_file)
        {
            ppT::init_public_params();
            libff::inhibit_profiling_info = true;
            libff::inhibit_profiling_counters = true;

            typename snarkT::proving_key proving_key;
            {
                std::ifstream in_s = libtool::open_input_binary_file(pk_file);
                snarkT::proving_key_read_bytes(proving_key, in_s);
            }

            libsnark::r1cs_primary_input<libff::Fr<ppT>> primary;
            libsnark::r1cs_auxiliary_input<libff::Fr<ppT>> auxiliary;
            {
                std::ifstream in_s =
                    libtool::open_input_binary_file(assignment_file);
                libzeth::r1cs_variable_assignment_read_bytes(
                    primary, auxiliary, num_primary_inputs, in_s);
            }

            typename snarkT::proof proof =
                snarkT::generate_proof(proving_key, primary, auxiliary);

            // Write to output file
            std::cout << "Writing proof to file: " << proof_file << "\n";
            {
                std::ofstream out_s =
                    libtool::open_output_binary_file(proof_file);
                snarkT::proof_write_bytes(proof, out_s);
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
        options.add_options()(
            "primary_inputs,p",
            po::value<uint16_t>(),
            "Number of primary inputs (default: 1)");

        all_options.add(options).add_options()(
            "pk_file", po::value<std::string>(), "Proving key file");
        all_options.add_options()(
            "assignment_file", po::value<std::string>(), "Assignment file");
        all_options.add_options()(
            "proof_file", po::value<std::string>(), "(Output) Proof file");

        pos.add("pk_file", 1);
        pos.add("assignment_file", 1);
        pos.add("proof_file", 1);
    }

    void parse_suboptions(
        const boost::program_options::variables_map &vm) override
    {
        if (vm.count("pk_file") == 0) {
            throw po::error("pk_file not specified");
        }
        if (vm.count("assignment_file") == 0) {
            throw po::error("assignment_file not specified");
        }
        if (vm.count("proof_file") == 0) {
            throw po::error("proof_file not specified");
        }

        pk_file = vm["pk_file"].as<std::string>();
        assignment_file = vm["assignment_file"].as<std::string>();
        proof_file = vm["proof_file"].as<std::string>();
        if (vm.count("primary_inputs")) {
            num_primary_inputs = vm["primary_inputs"].as<uint16_t>();
        }
        curve = vm.count("curve") ? vm["curve"].as<std::string>() : "alt-bn128";
        snark = vm.count("snark") ? vm["snark"].as<std::string>() : "groth16";
    }

    void subcommand_usage(const char *argv0) override
    {
        std::cout << "Usage:\n"
                     "  "
                  << argv0
                  << " prove [pk_file] [assignment_file] [proof_file]\n";
    }

    int execute_subcommand(const global_options &) override
    {
        return curve_and_snark_resolver<prove_runner>::resolve(
            curve,
            snark,
            pk_file,
            assignment_file,
            num_primary_inputs,
            proof_file);
    }

    std::string pk_file;
    std::string assignment_file;
    std::string proof_file;
    uint16_t num_primary_inputs;
    std::string curve;
    std::string snark;
};

} // namespace commands

zeth_subcommand *prove_cmd = new commands::prove_cmd(
    "prove", "Generate proof given proving key and assignment");

} // namespace zethtool
