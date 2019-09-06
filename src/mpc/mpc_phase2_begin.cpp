#include "mpc_common.hpp"
#include "snarks/groth16/mpc_phase2.hpp"
#include "snarks/groth16/mpc_utils.hpp"

#include <boost/program_options.hpp>
#include <fstream>

using namespace libzeth;
namespace po = boost::program_options;

namespace
{

// Usage:
//   $0 phase2-begin [<options>] <linear_combination_file>
//
// Options:
//   --out <file>    Initial challenge output file (mpc-challenge.bin)
class mpc_phase2_begin : public subcommand
{
private:
    std::string lin_comb_file;
    std::string out_file;

public:
    mpc_phase2_begin() : subcommand("phase2-begin"), lin_comb_file(), out_file()
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
            "Initial challenge output file (mpc-challenge.bin)");
        all_options.add(options).add_options()(
            "linear_combination_file",
            po::value<std::string>(),
            "linear combination file");
        pos.add("linear_combination_file", 1);
    }

    void parse_suboptions(
        const boost::program_options::variables_map &vm) override
    {
        if (0 == vm.count("linear_combination_file")) {
            throw po::error("linear_combination_file not specified");
        }
        lin_comb_file = vm["linear_combination_file"].as<std::string>();
        out_file = vm.count("out") ? vm["out"].as<std::string>()
                                   : trusted_setup_file("mpc-challenge.bin");
    }

    void subcommand_usage() override
    {
        std::cout << "Usage:\n  " << subcommand_name
                  << " [<options>] <linear_combination_file>\n\n";
    }

    int execute_subcommand() override
    {
        if (verbose) {
            std::cout << "lin_comb_file: " << lin_comb_file << "\n";
            std::cout << "out: " << out_file << std::endl;
        }

        libff::enter_block("Load linear combination file");
        srs_mpc_layer_L1<ppT> lin_comb = [&]() {
            std::ifstream in(
                lin_comb_file, std::ios_base::binary | std::ios_base::in);
            return srs_mpc_layer_L1<ppT>::read(in);
        }();
        libff::leave_block("Load linear combination file");

        // Compute circuit
        libff::enter_block("Computing num inputs");
        const size_t num_inputs = [this]() {
            libsnark::protoboard<FieldT> pb;
            init_protoboard(pb);
            return pb.num_inputs();
        }();
        libff::print_indent();
        std::cout << std::to_string(num_inputs) << std::endl;
        libff::leave_block("Computing num inputs");

        // TODO: use the hash of the linear combination as the inital transcript
        // digest?

        // Initial challenge
        libff::enter_block("Computing initial challenge");
        const srs_mpc_phase2_challenge<ppT> initial_challenge =
            srs_mpc_phase2_initial_challenge<ppT>(
                srs_mpc_phase2_begin<ppT>(lin_comb, num_inputs));
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
subcommand *mpc_phase2_begin_cmd = new mpc_phase2_begin();
