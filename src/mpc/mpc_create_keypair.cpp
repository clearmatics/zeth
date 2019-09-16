#include "circuits/blake2s/blake2s_comp.hpp"
#include "mpc_common.hpp"
#include "snarks/groth16/mpc_utils.hpp"
#include "snarks/groth16/powersoftau_utils.hpp"
#include "util.hpp"

#include <vector>

using namespace libzeth;
namespace po = boost::program_options;

namespace
{

// Usage:
//  mpc create-keypair [<option>]
//      <powersoftau_file>
//      <linear_combination_file>
//      <phase2_file>
//
// Options:
//  -h,--help           This message
//  --pot-degree        powersoftau degree (assumed to match linear comb)
//  --out <file>        Write key-pair to <file> (mpc-keypair.bin)
class mpc_create_keypair : public subcommand
{
private:
    std::string powersoftau_file;
    std::string lin_comb_file;
    std::string phase2_file;
    size_t powersoftau_degree;
    std::string out_file;

public:
    mpc_create_keypair()
        : subcommand("create-keypair")
        , powersoftau_file()
        , lin_comb_file()
        , phase2_file()
        , powersoftau_degree(0)
        , out_file()
    {
    }

private:
    void initialize_suboptions(
        boost::program_options::options_description &options,
        boost::program_options::options_description &all_options,
        boost::program_options::positional_options_description &pos) override
    {
        options.add_options()(
            "pot-degree",
            po::value<size_t>(),
            "powersoftau degree (assumed to match linear comb)")(
            "out,o",
            po::value<std::string>(),
            "Write key-pair to file (mpc-keypair.bin)");
        all_options.add(options).add_options()(
            "powersoftau_file", po::value<std::string>(), "powersoftau file")(
            "linear_combination_file",
            po::value<std::string>(),
            "linear combination file")(
            "phase2_file",
            po::value<std::string>(),
            "phase2 final challenge file");
        pos.add("powersoftau_file", 1)
            .add("linear_combination_file", 1)
            .add("phase2_file", 1);
    }

    void parse_suboptions(
        const boost::program_options::variables_map &vm) override
    {
        if (0 == vm.count("powersoftau_file")) {
            throw po::error("powersoftau_file not specified");
        }
        if (0 == vm.count("linear_combination_file")) {
            throw po::error("linear_combination_file not specified");
        }
        if (0 == vm.count("phase2_file")) {
            throw po::error("phase2_file not specified");
        }

        powersoftau_file = vm["powersoftau_file"].as<std::string>();
        lin_comb_file = vm["linear_combination_file"].as<std::string>();
        phase2_file = vm["phase2_file"].as<std::string>();
        powersoftau_degree =
            vm.count("pot-degree") ? vm["pot-degree"].as<size_t>() : 0;
        out_file = vm.count("out") ? vm["out"].as<std::string>()
                                   : trusted_setup_file("mpc-keypair.bin");
    }

    void subcommand_usage() override
    {
        std::cout << "Usage:\n"
                  << "  " << subcommand_name << " [<options>]  \\\n"
                  << "        <powersoftau_file> <linear_combination_file> "
                     "<phase2_file>\n\n";
    }

    int execute_subcommand() override
    {
        if (verbose) {
            std::cout << "powersoftau_file: " << powersoftau_file << "\n"
                      << "lin_comb_file: " << lin_comb_file << "\n"
                      << "phase2_file: " << phase2_file << "\n"
                      << "powersoftau_degree: " << powersoftau_degree << "\n"
                      << "out_file: " << out_file << std::endl;
        }

        // Load all data
        // TODO: Load just degree from lin_comb data, then load everything
        // in parallel.
        libff::enter_block("Load linear combination data");
        libff::print_indent();
        std::cout << lin_comb_file << std::endl;
        srs_mpc_layer_L1<ppT> lin_comb =
            read_from_file<srs_mpc_layer_L1<ppT>>(lin_comb_file);
        libff::leave_block("Load linear combination data");

        libff::enter_block("Load powers of tau");
        libff::print_indent();
        std::cout << powersoftau_file << std::endl;
        srs_powersoftau<ppT> pot = [this, &lin_comb]() {
            std::ifstream in(
                powersoftau_file, std::ios_base::binary | std::ios_base::in);
            const size_t pot_degree =
                powersoftau_degree ? powersoftau_degree : lin_comb.degree();
            return powersoftau_load(in, pot_degree);
        }();
        libff::leave_block("Load powers of tau");

        libff::enter_block("Load phase2 data");
        if (!libff::inhibit_profiling_info) {
            libff::print_indent();
            std::cout << phase2_file << "\n";
        }
        srs_mpc_layer_C2<ppT> phase2 =
            read_from_file<srs_mpc_layer_C2<ppT>>(phase2_file);
        libff::leave_block("Load phase2 data");

        // Compute circuit
        libff::enter_block("Generate QAP");
        libsnark::protoboard<FieldT> pb;
        init_protoboard(pb);
        libsnark::r1cs_constraint_system<FieldT> cs =
            pb.get_constraint_system();
        const libsnark::qap_instance<FieldT> qap =
            libsnark::r1cs_to_qap_instance_map(cs, true);
        libff::leave_block("Generate QAP");

        libsnark::r1cs_gg_ppzksnark_keypair<ppT> keypair = mpc_create_key_pair(
            std::move(pot),
            std::move(lin_comb),
            std::move(phase2),
            std::move(cs),
            qap);

        // Write keypair to a file
        libff::enter_block("Writing keypair file");
        if (!libff::inhibit_profiling_info) {
            libff::print_indent();
            std::cout << out_file << std::endl;
        }
        {
            std::ofstream out(
                out_file, std::ios_base::binary | std::ios_base::out);
            mpc_write_keypair(out, keypair);
        }
        libff::leave_block("Writing keypair file");

        return 0;
    }
};

} // namespace

// Subcommand instance
subcommand *mpc_create_keypair_cmd = new mpc_create_keypair();
