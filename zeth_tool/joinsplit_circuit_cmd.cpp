// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "zeth_tool/joinsplit_circuit_cmd.hpp"

#include "libtool/tool_util.hpp"
#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/circuits/circuit_wrapper.hpp"
#include "libzeth/serialization/r1cs_serialization.hpp"

namespace zethtool
{

namespace commands
{

class joinsplit_circuit_cmd : public generic_subcommand<joinsplit_circuit_cmd>
{
public:
    using base_class = generic_subcommand<joinsplit_circuit_cmd>;

    joinsplit_circuit_cmd(
        const std::string &subcommand_name, const std::string &description)
        : base_class(subcommand_name, description)
    {
    }

    template<typename ppT, typename snarkT>
    int execute_generic(const global_options &)
    {
        using Field = libff::Fr<ppT>;
        using circuit_wrapper = libzeth::JoinsplitCircuitT<ppT, snarkT>;

        ppT::init_public_params();
        libff::inhibit_profiling_info = true;
        libff::inhibit_profiling_counters = true;

        circuit_wrapper circuit;
        const libsnark::r1cs_constraint_system<Field> &r1cs =
            circuit.get_constraint_system();

        std::cout << "r1cs: num_variables: " << r1cs.num_variables()
                  << ", num_constraints: " << r1cs.num_constraints() << "\n";

        if (!r1cs_file.empty()) {
            std::cout << "writing r1cs to '" << r1cs_file << "'";
            std::ofstream out_s = libtool::open_binary_output_file(r1cs_file);
            libzeth::r1cs_write_bytes(r1cs, out_s);
            std::cout << "\n";
        }

        return 0;
    };

protected:
    void initialize_suboptions(
        boost::program_options::options_description &options,
        boost::program_options::options_description &all_options,
        boost::program_options::positional_options_description &pos) override
    {
        base_class::initialize_suboptions(options, all_options, pos);
        options.add_options()(
            "r1cs_file", po::value<std::string>(), "R1CS output file");
        all_options.add(options);
    }

    void parse_suboptions(
        const boost::program_options::variables_map &vm) override
    {
        base_class::parse_suboptions(vm);
        if (vm.count("r1cs_file")) {
            r1cs_file = vm["r1cs_file"].as<std::string>();
        }
    }

    void subcommand_usage(const char *argv0) override
    {
        std::cout << "Usage:\n  " << argv0 << "\n";
    }

    std::string r1cs_file;
};

} // namespace commands

zeth_subcommand *joinsplit_circuit_cmd = new commands::joinsplit_circuit_cmd(
    "joinsplit-circuit",
    "Statistics relating to (and export of) the joinsplit circuit");

} // namespace zethtool
