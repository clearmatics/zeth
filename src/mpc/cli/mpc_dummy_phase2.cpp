#include "mpc_common.hpp"
#include "snarks/groth16/mpc/mpc_utils.hpp"
#include "snarks/groth16/mpc/phase2.hpp"
#include "util.hpp"
#include "zeth.h"

using namespace libzeth;
namespace po = boost::program_options;

namespace
{

// Usage:
//     mpc dummy_phase2 [<option>]
//         <linear_combination_file>
//         <final_challenge_file>
class mpc_dummy_phase2 : public subcommand
{
    std::string linear_combination_file;
    std::string out_file;

public:
    mpc_dummy_phase2()
        : subcommand("dummy-phase2"), linear_combination_file(), out_file()
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

    void subcommand_usage() override
    {
        std::cout << "Usage:" << std::endl
                  << "  " << subcommand_name
                  << " [<options>] <linear_combination_file> "
                     "<final_challenge_file>\n";
    }

    int execute_subcommand() override
    {
        if (verbose) {
            std::cout << "linear_combination_file: " << linear_combination_file
                      << "\n"
                      << "out_file: " << out_file << std::endl;
        }

        // Load the linear_combination output
        libff::enter_block("reading linear combination data");
        srs_mpc_layer_L1<ppT> lin_comb =
            read_from_file<srs_mpc_layer_L1<ppT>>(linear_combination_file);
        libff::leave_block("reading linear combination data");

        // Generate the zeth circuit (to determine the number of inputs)
        libff::enter_block("computing num_inputs");
        const size_t num_inputs = [this]() {
            libsnark::protoboard<FieldT> pb;
            init_protoboard(pb);
            return pb.num_inputs();
        }();
        libff::print_indent();
        std::cout << std::to_string(num_inputs) << std::endl;
        libff::leave_block("computing num_inputs");

        // Generate a single delta for dummy phase2
        const FieldT delta = FieldT::random_element();

        // Generate and save the dummy phase2 challenge
        const srs_mpc_phase2_challenge<ppT> phase2 =
            srs_mpc_dummy_phase2<ppT>(lin_comb, delta, num_inputs);
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

subcommand *mpc_dummy_phase2_cmd = new mpc_dummy_phase2();
