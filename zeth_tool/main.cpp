// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libtool/run.hpp"
#include "zeth_tool/dump_proof_cmd.hpp"
#include "zeth_tool/joinsplit_circuit_cmd.hpp"
#include "zeth_tool/prove_cmd.hpp"
#include "zeth_tool/split_keypair_cmd.hpp"
#include "zeth_tool/tool_common.hpp"
#include "zeth_tool/verify_cmd.hpp"

using namespace zethtool;

class zeth_command : public libtool::command<global_options>
{
public:
    void initialize_global_options(
        boost::program_options::options_description &global,
        boost::program_options::options_description &all_options) override
    {
        global.add_options()("verbose,v", "Verbose output");
        all_options.add(global);
    }

    /// Parse the variables map to update the GlobalOptionsT object.
    void parse_global_options(
        global_options &out_options,
        const boost::program_options::variables_map &vm) override
    {
        out_options = (bool)vm.count("verbose");
    }
};

int main(int argc, char **argv)
{
    // Create command structures
    std::map<std::string, zeth_subcommand *> commands{
        {"verify", verify_cmd},
        {"prove", prove_cmd},
        {"dump-proof", dump_proof_cmd},
        {"joinsplit-circuit", joinsplit_circuit_cmd},
        {"split-keypair", split_keypair_cmd},
    };

    zeth_command cmd;
    bool verbose = false;

    // Execute tool_main
    return libtool::run_command(cmd, verbose, commands, argc, argv);
}
