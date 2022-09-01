// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "mpc_common.hpp"

#include "libtool/run.hpp"

#include <iostream>

namespace
{

/// Instantiation of libtool::command which parses the global options for all
/// mpc subcommands.
class mpc_command : public libtool::command<global_options>
{
public:
    void initialize_global_options(
        boost::program_options::options_description &global,
        boost::program_options::options_description &all_options) override
    {
        global.add_options()("verbose,v", "Verbose output");
        all_options.add(global);
    }

    void parse_global_options(
        global_options &out_options,
        const boost::program_options::variables_map &vm) override
    {
        const bool verbose = (bool)vm.count("verbose");
        if (!verbose) {
            libff::inhibit_profiling_info = true;
            libff::inhibit_profiling_counters = true;
        }

        out_options.verbose = verbose;
    }
};

} // namespace

int mpc_main(
    const std::map<std::string, mpc_subcommand *> &subcommands,
    const ProtoboardInitFn &pb_init,
    int argc,
    char **argv)
{
    libzeth::defaults::pp::init_public_params();

    global_options options{pb_init, false};
    mpc_command cmd;
    return libtool::run_command(cmd, options, subcommands, argc, argv);
}
