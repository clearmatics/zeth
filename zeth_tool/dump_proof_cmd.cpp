// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "zeth_tool/dump_proof_cmd.hpp"

#include "libtool/tool_util.hpp"
#include "libzeth/serialization/r1cs_variable_assignment_serialization.hpp"
#include "zeth_tool/tool_common.hpp"

namespace zethtool
{

namespace commands
{

class dump_proof_cmd : public generic_subcommand<dump_proof_cmd>
{
public:
    using base_class = generic_subcommand<dump_proof_cmd>;

    dump_proof_cmd(
        const std::string &subcommand_name, const std::string &description)
        : base_class(subcommand_name, description)
    {
    }

    template<typename ppT, typename snarkT>
    int execute_generic(const global_options &)
    {
        ppT::init_public_params();
        libff::inhibit_profiling_info = true;
        libff::inhibit_profiling_counters = true;

        typename snarkT::proof proof;
        {
            std::ifstream in_s = libtool::open_binary_input_file(proof_file);
            snarkT::proof_read_bytes(proof, in_s);
        }

        snarkT::proof_write_json(proof, std::cout);
        std::cout << "\n";
        return 0;
    };

protected:
    void initialize_suboptions(
        boost::program_options::options_description &options,
        boost::program_options::options_description &all_options,
        boost::program_options::positional_options_description &pos) override
    {
        base_class::initialize_suboptions(options, all_options, pos);

        all_options.add(options).add_options()(
            "proof_file", po::value<std::string>(), "(Output) Proof file");
        pos.add("proof_file", 1);
    }

    void parse_suboptions(
        const boost::program_options::variables_map &vm) override
    {
        base_class::parse_suboptions(vm);

        if (vm.count("proof_file") == 0) {
            throw po::error("proof_file not specified");
        }
        proof_file = vm["proof_file"].as<std::string>();
    }

    void subcommand_usage(const char *argv0) override
    {
        std::cout << "Usage:\n  " << argv0 << " dump-proof [proof_file]\n";
    }

    std::string proof_file;
};

} // namespace commands

zeth_subcommand *dump_proof_cmd =
    new commands::dump_proof_cmd("dump-proof", "Print an existing proof");

} // namespace zethtool
