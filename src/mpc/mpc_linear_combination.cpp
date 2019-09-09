#include "circuit-wrapper.hpp"
#include "mpc_common.hpp"
#include "snarks/groth16/mpc_utils.hpp"
#include "snarks/groth16/powersoftau_utils.hpp"
#include "util.hpp"

#include <boost/program_options.hpp>
#include <functional>
#include <vector>

using namespace libzeth;
namespace po = boost::program_options;

namespace
{

using FieldT = libff::Fr<ppT>;
using HashTreeT = MiMC_mp_gadget<FieldT>;
using HashT = sha256_ethereum<FieldT>;

// Usage:
//     mpc linear-combination [<option>] <powersoftau file> <lagrange file>
//
// Options:
//     -h,--help        This message
//     --pot-degree     powersoftau degree (assumed equal to lagrange file)
//     --out <file>     Linear combination output (mpc-linear-combination.bin)
class mpc_linear_combination : public subcommand
{
    std::string powersoftau_file;
    std::string lagrange_file;
    size_t powersoftau_degree;
    std::string out_file;

public:
    mpc_linear_combination()
        : subcommand("linear-combination")
        , powersoftau_file()
        , lagrange_file()
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
            "powersoftau degree (assumed equal to lagrange file)")(
            "out,o",
            po::value<std::string>(),
            "linear combination output (mpc-linear-combination.bin)");
        all_options.add(options).add_options()(
            "powersoftau_file", po::value<std::string>(), "powersoftau file")(
            "lagrange_file", po::value<std::string>(), "lagrange file");
        pos.add("powersoftau_file", 1).add("lagrange_file", 1);
    }

    void parse_suboptions(
        const boost::program_options::variables_map &vm) override
    {
        if (0 == vm.count("powersoftau_file")) {
            throw po::error("powersoftau_file not specified");
        }
        if (0 == vm.count("lagrange_file")) {
            throw po::error("lagrange_file not specified");
        }

        powersoftau_file = vm["powersoftau_file"].as<std::string>();
        lagrange_file = vm["lagrange_file"].as<std::string>();
        powersoftau_degree =
            vm.count("pot-degree") ? vm["pot-degree"].as<size_t>() : 0;
        out_file = vm.count("out")
                       ? vm["out"].as<std::string>()
                       : trusted_setup_file("mpc-linear-combination.bin");
    }

    void subcommand_usage() override
    {
        std::cout << "Usage:\n"
                  << "  " << subcommand_name
                  << " [<options>] <powersoftau file> <lagrange file>\n";
    }

    int execute_subcommand() override
    {
        if (verbose) {
            std::cout << "powersoftau_file: " << powersoftau_file << "\n"
                      << "lagrange_file: " << lagrange_file << "\n"
                      << "powersoftau_degree: " << powersoftau_degree << "\n"
                      << "out_file: " << out_file << std::endl;
        }

        // Load lagrange evaluations to determine n, then load powersoftau
        // TODO: Load just degree from lagrange data, then load the two
        // files in parallel.
        libff::enter_block("Load Lagrange data");
        libff::print_indent();
        std::cout << lagrange_file << std::endl;
        const srs_lagrange_evaluations<ppT> lagrange =
            read_from_file<srs_lagrange_evaluations<ppT>>(lagrange_file);
        libff::leave_block("Load Lagrange data");

        libff::enter_block("Load powers of tau");
        libff::print_indent();
        std::cout << powersoftau_file << std::endl;
        const srs_powersoftau<ppT> pot = [this, &lagrange]() {
            std::ifstream in(
                powersoftau_file, std::ios_base::binary | std::ios_base::in);
            const size_t pot_degree =
                powersoftau_degree ? powersoftau_degree : lagrange.degree;
            return powersoftau_load(in, pot_degree);
        }();
        libff::leave_block("Load powers of tau");

        // Compute circuit
        libff::enter_block("Generate QAP");
        libsnark::protoboard<FieldT> pb;
        joinsplit_gadget<
            FieldT,
            HashT,
            HashTreeT,
            ZETH_NUM_JS_INPUTS,
            ZETH_NUM_JS_OUTPUTS>
            js(pb);
        js.generate_r1cs_constraints();
        const libsnark::r1cs_constraint_system<FieldT> cs =
            pb.get_constraint_system();
        const libsnark::qap_instance<FieldT> qap =
            libsnark::r1cs_to_qap_instance_map(cs, true);
        libff::leave_block("Generate QAP");

        // Compute final step of linear combination
        if (qap.degree() != lagrange.degree) {
            throw std::invalid_argument(
                "Degree of qap " + std::to_string(qap.degree()) + " does not " +
                "match degree of lagrange evaluations. Regenerate with "
                "matching " +
                "degree.");
        }

        // Compute layer1 and write to a file
        const srs_mpc_layer_L1<ppT> lin_comb =
            mpc_compute_linearcombination<ppT>(pot, lagrange, qap);

        libff::enter_block("Writing linear combination file");
        libff::print_indent();
        std::cout << out_file << std::endl;
        {
            std::ofstream out(
                out_file, std::ios_base::binary | std::ios_base::out);
            lin_comb.write(out);
        }
        libff::leave_block("Writing linear combination file");

        return 0;
    }
};

} // namespace

subcommand *mpc_linear_combination_cmd = new mpc_linear_combination();
