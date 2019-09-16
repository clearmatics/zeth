#include "circuits/blake2s/blake2s_comp.hpp"
#include "mpc_common.hpp"
#include "snarks/groth16/mpc_utils.hpp"
#include "util.hpp"
#include "zeth.h"

using namespace libzeth;
namespace po = boost::program_options;

namespace
{

// Usage:
//     mpc dummy_phase2 [<option>] <linear_combination_file>
//
// Options:
//     -h,--help           This message
//     --out <file>        Write phase2 to <file> (mpc-phase2.bin)
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
        boost::program_options::options_description &options,
        boost::program_options::options_description &all_options,
        boost::program_options::positional_options_description &pos) override
    {
        options.add_options()(
            "out,o",
            po::value<std::string>(),
            "phase2 output file (mpc-phase2.bin)");
        all_options.add(options).add_options()(
            "linear_combination_file",
            po::value<std::string>(),
            "Linear combination file");
        pos.add("linear_combination_file", 1);
    }

    void parse_suboptions(
        const boost::program_options::variables_map &vm) override
    {
        if (0 == vm.count("linear_combination_file")) {
            throw po::error("linear_combination file not specified");
        }
        linear_combination_file =
            vm["linear_combination_file"].as<std::string>();

        out_file = vm.count("out") ? vm["out"].as<std::string>()
                                   : trusted_setup_file("mpc-phase2.bin");
    }

    void subcommand_usage() override
    {
        std::cout << "Usage:" << std::endl
                  << "  " << subcommand_name
                  << " [<options>] <linear_combination_file>\n";
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
        const size_t num_inputs = [this]() {
            libsnark::protoboard<FieldT> pb;
            init_protoboard(pb);
            const libsnark::r1cs_constraint_system<FieldT> cs =
                pb.get_constraint_system();
            return cs.num_inputs();
        }();

        // Generate the artifical delta
        const FieldT delta = FieldT::random_element();

        // Generate and save the dummy phase2 data
        const srs_mpc_layer_C2<ppT> phase2 =
            mpc_dummy_layer_C2<ppT>(lin_comb, delta, num_inputs);
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
