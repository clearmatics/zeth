// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/circuits/blake2s/blake2s_comp.hpp"
#include "libzeth/core/utils.hpp"
#include "libzeth/mpc/groth16/mpc_utils.hpp"
#include "libzeth/mpc/groth16/powersoftau_utils.hpp"
#include "mpc_common.hpp"

#include <boost/program_options.hpp>
#include <functional>
#include <vector>

using namespace libzeth;
using pp = defaults::pp;
namespace po = boost::program_options;

namespace
{

// Usage:
//     mpc linear-combination [<option>]
//         <powersoftau file> <lagrange file> <linear_comb_file>
//
// Options:
//     -h,--help        This message
//     --pot-degree     powersoftau degree (assumed equal to lagrange file)
//     --verify         Skip computation.  Load and verify input data.
class mpc_linear_combination : public mpc_subcommand
{
    std::string powersoftau_file;
    std::string lagrange_file;
    size_t powersoftau_degree;
    std::string out_file;
    bool verify;

public:
    mpc_linear_combination()
        : mpc_subcommand(
              "linear-combination", "Create linear combination for our circuit")
        , powersoftau_file()
        , lagrange_file()
        , powersoftau_degree(0)
        , out_file()
        , verify(false)
    {
    }

private:
    void initialize_suboptions(
        po::options_description &options,
        po::options_description &all_options,
        po::positional_options_description &pos) override
    {
        options.add_options()(
            "pot-degree",
            po::value<size_t>(),
            "powersoftau degree (assumed equal to lagrange file)")(
            "verify", "Skip computation. Load and verify input data");
        all_options.add(options).add_options()(
            "powersoftau_file", po::value<std::string>(), "powersoftau file")(
            "lagrange_file", po::value<std::string>(), "lagrange file")(
            "linear_comb_file",
            po::value<std::string>(),
            "linear combination output");
        pos.add("powersoftau_file", 1)
            .add("lagrange_file", 1)
            .add("linear_comb_file", 1);
    }

    void parse_suboptions(const po::variables_map &vm) override
    {
        if (0 == vm.count("powersoftau_file")) {
            throw po::error("powersoftau_file not specified");
        }
        if (0 == vm.count("lagrange_file")) {
            throw po::error("lagrange_file not specified");
        }
        if (0 == vm.count("linear_comb_file")) {
            throw po::error("linear_comb_file not specified");
        }

        powersoftau_file = vm["powersoftau_file"].as<std::string>();
        lagrange_file = vm["lagrange_file"].as<std::string>();
        out_file = vm["linear_comb_file"].as<std::string>();
        powersoftau_degree =
            vm.count("pot-degree") ? vm["pot-degree"].as<size_t>() : 0;
        verify = (bool)vm.count("verify");
    }

    void subcommand_usage(const char *argv0) override
    {
        std::cout << "Usage:\n  " << argv0 << " " << subcommand_name
                  << " [<options>] <powersoftau file> <lagrange file> "
                     "<linear_comb_file>\n";
    }

    int execute_subcommand(const global_options &options) override
    {
        if (options.verbose) {
            std::cout << "powersoftau_file: " << powersoftau_file << "\n"
                      << "lagrange_file: " << lagrange_file << "\n"
                      << "powersoftau_degree: " << powersoftau_degree << "\n"
                      << "out_file: " << out_file << "\n"
                      << "verify: " << std::to_string(verify) << std::endl;
        }

        // Load lagrange evaluations to determine n, then load powersoftau
        // TODO: Load just degree from lagrange data, then load the two
        // files in parallel.
        libff::enter_block("Load Lagrange data");
        libff::print_indent();
        std::cout << lagrange_file << std::endl;
        const srs_lagrange_evaluations<pp> lagrange =
            read_from_file<srs_lagrange_evaluations<pp>>(lagrange_file);
        libff::leave_block("Load Lagrange data");

        libff::enter_block("Load powers of tau");
        libff::print_indent();
        std::cout << powersoftau_file << std::endl;
        const srs_powersoftau<pp> pot = [this, &lagrange]() {
            std::ifstream in(
                powersoftau_file, std::ios_base::binary | std::ios_base::in);
            const size_t pot_degree =
                powersoftau_degree ? powersoftau_degree : lagrange.degree;
            return powersoftau_load<pp>(in, pot_degree);
        }();
        libff::leave_block("Load powers of tau");

        // Compute circuit
        libff::enter_block("Generate QAP");
        libsnark::protoboard<Field> pb;
        options.protoboard_init(pb);
        const libsnark::r1cs_constraint_system<Field> cs =
            pb.get_constraint_system();
        const libsnark::qap_instance<Field> qap =
            libsnark::r1cs_to_qap_instance_map(cs, true);
        libff::leave_block("Generate QAP");

        // Early-out if "--verify" was specified
        if (verify) {
            std::cout << "verify: skipping computation and write.)"
                      << std::endl;
            return 0;
        }

        // Compute final step of linear combination
        if (qap.degree() != lagrange.degree) {
            throw std::invalid_argument(
                "Degree of qap " + std::to_string(qap.degree()) + " does not " +
                "match degree of lagrange evaluations. Regenerate with "
                "matching " +
                "degree.");
        }

        // Compute layer1 and write to a file
        const srs_mpc_layer_L1<pp> lin_comb =
            mpc_compute_linearcombination<pp>(pot, lagrange, qap);

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

mpc_subcommand *mpc_linear_combination_cmd = new mpc_linear_combination();
