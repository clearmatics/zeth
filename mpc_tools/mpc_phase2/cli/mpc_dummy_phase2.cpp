// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/core/utils.hpp"
#include "libzeth/mpc/groth16/mpc_utils.hpp"
#include "libzeth/mpc/groth16/phase2.hpp"
#include "mpc_common.hpp"

using namespace libzeth;
using pp = defaults::pp;
namespace po = boost::program_options;

namespace
{

// Usage:
//     mpc dummy_phase2 [<option>]
//         <linear_combination_file>
//         <final_challenge_file>
class mpc_dummy_phase2 : public mpc_subcommand
{
    std::string linear_combination_file;
    std::string out_file;

public:
    mpc_dummy_phase2()
        : mpc_subcommand(
              "dummy-phase2", "Run a dummy MPC to generate test data")
        , linear_combination_file()
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
            "Linear combination file")(
            "final_challenge_file",
            po::value<std::string>(),
            "Final challenge file");
        pos.add("linear_combination_file", 1);
        pos.add("final_challenge_file", 1);
    }

    void parse_suboptions(const po::variables_map &vm) override
    {
        if (0 == vm.count("linear_combination_file")) {
            throw po::error("linear_combination file not specified");
        }
        if (0 == vm.count("final_challenge_file")) {
            throw po::error("final_challenge_file not specified");
        }
        linear_combination_file =
            vm["linear_combination_file"].as<std::string>();
        out_file = vm["final_challenge_file"].as<std::string>();
    }

    void subcommand_usage(const char *argv0) override
    {
        std::cout << "Usage:\n  " << argv0 << " " << subcommand_name
                  << " [<options>] <linear_combination_file> "
                     "<final_challenge_file>\n";
    }

    int execute_subcommand(const global_options &options) override
    {
        if (options.verbose) {
            std::cout << "linear_combination_file: " << linear_combination_file
                      << "\n"
                      << "out_file: " << out_file << std::endl;
        }

        // Load the linear_combination output
        libff::enter_block("reading linear combination data");
        srs_mpc_layer_L1<pp> lin_comb =
            read_from_file<srs_mpc_layer_L1<pp>>(linear_combination_file);
        libff::leave_block("reading linear combination data");

        // Generate the zeth circuit (to determine the number of inputs)
        libff::enter_block("computing num_inputs");
        const size_t num_inputs = [&options]() {
            libsnark::protoboard<Field> pb;
            options.protoboard_init(pb);
            return pb.num_inputs();
        }();
        libff::print_indent();
        std::cout << std::to_string(num_inputs) << std::endl;
        libff::leave_block("computing num_inputs");

        // Generate a single delta for dummy phase2
        const Field delta = Field::random_element();

        // Generate and save the dummy phase2 challenge
        const srs_mpc_phase2_challenge<pp> phase2 =
            srs_mpc_dummy_phase2<pp>(lin_comb, delta, num_inputs);
        libff::enter_block("writing phase2 data");
        {
            std::ofstream out(out_file);
            phase2.write(out);
        }
        libff::leave_block("writing phase2 data");

        return 0;
    }
};

} // namespace

mpc_subcommand *mpc_dummy_phase2_cmd = new mpc_dummy_phase2();
