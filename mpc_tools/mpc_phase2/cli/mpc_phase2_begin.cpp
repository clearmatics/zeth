// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/mpc/groth16/mpc_utils.hpp"
#include "libzeth/mpc/groth16/phase2.hpp"
#include "mpc_common.hpp"

#include <boost/program_options.hpp>
#include <fstream>

using namespace libzeth;
using pp = defaults::pp;
namespace po = boost::program_options;

namespace
{

// Usage:
//   $0 phase2-begin [<options>] <linear_combination_file> <challenge_out_file>
//
class mpc_phase2_begin : public mpc_subcommand
{
private:
    std::string lin_comb_file;
    std::string out_file;

public:
    mpc_phase2_begin()
        : mpc_subcommand("phase2-begin", "Create the initial MPC challenge")
        , lin_comb_file()
        , out_file()
    {
    }

private:
    void initialize_suboptions(
        po::options_description &options,
        po::options_description &all_options,
        po::positional_options_description &pos) override
    {
        all_options.add(options).add_options()(
            "linear_combination_file",
            po::value<std::string>(),
            "linear combination file")(
            "challenge_out_file",
            po::value<std::string>(),
            "initial challenge output file");
        pos.add("linear_combination_file", 1).add("challenge_out_file", 1);
    }

    void parse_suboptions(const po::variables_map &vm) override
    {
        if (0 == vm.count("linear_combination_file")) {
            throw po::error("linear_combination_file not specified");
        }
        if (0 == vm.count("challenge_out_file")) {
            throw po::error("challenge_out_file not specified");
        }
        lin_comb_file = vm["linear_combination_file"].as<std::string>();
        out_file = vm["challenge_out_file"].as<std::string>();
    }

    void subcommand_usage(const char *argv0) override
    {
        std::cout << "Usage:\n  " << argv0 << " " << subcommand_name
                  << " [<options>] <linear_combination_file> "
                     "<challenge_out_file>\n\n";
    }

    int execute_subcommand(const global_options &options) override
    {
        if (options.verbose) {
            std::cout << "lin_comb_file: " << lin_comb_file << "\n";
            std::cout << "out: " << out_file << std::endl;
        }

        libff::enter_block("Load linear combination file");
        mpc_hash_t cs_hash;
        srs_mpc_layer_L1<pp> lin_comb =
            read_from_file_and_hash<srs_mpc_layer_L1<pp>>(
                lin_comb_file, cs_hash);
        libff::leave_block("Load linear combination file");

        // Compute circuit
        libff::enter_block("Computing num inputs");
        const size_t num_inputs = [&options]() {
            libsnark::protoboard<Field> pb;
            options.protoboard_init(pb);
            return pb.num_inputs();
        }();
        libff::print_indent();
        std::cout << std::to_string(num_inputs) << std::endl;
        libff::leave_block("Computing num inputs");

        // Initial challenge
        libff::enter_block("Computing initial challenge");
        const srs_mpc_phase2_challenge<pp> initial_challenge =
            srs_mpc_phase2_initial_challenge<pp>(
                srs_mpc_phase2_begin<pp>(cs_hash, lin_comb, num_inputs));
        libff::leave_block("Computing initial challenge");

        libff::enter_block("Writing initial challenge");
        libff::print_indent();
        std::cout << out_file << std::endl;
        {
            std::ofstream out(out_file);
            initial_challenge.write(out);
        }
        libff::leave_block("Writing initial challenge");

        return 0;
    }
};

} // namespace

// Subcommand instance
mpc_subcommand *mpc_phase2_begin_cmd = new mpc_phase2_begin();
