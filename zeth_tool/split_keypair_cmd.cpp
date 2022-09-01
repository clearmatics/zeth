// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "zeth_tool/split_keypair_cmd.hpp"

#include "libtool/tool_util.hpp"

namespace zethtool
{

namespace commands
{

class split_keypair_cmd : public generic_subcommand<split_keypair_cmd>
{
public:
    using base_class = generic_subcommand<split_keypair_cmd>;

    split_keypair_cmd(
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

        typename snarkT::keypair keypair;
        {
            std::ifstream in_s = libtool::open_binary_input_file(keypair_file);
            snarkT::keypair_read_bytes(keypair, in_s);
        }

        if (!vk_file.empty()) {
            std::ofstream out_s = libtool::open_binary_output_file(vk_file);
            snarkT::verification_key_write_bytes(keypair.vk, out_s);
        }

        if (!pk_file.empty()) {
            std::ofstream out_s = libtool::open_binary_output_file(pk_file);
            snarkT::proving_key_write_bytes(keypair.pk, out_s);
        }

        return 0;
    }

protected:
    void initialize_suboptions(
        boost::program_options::options_description &options,
        boost::program_options::options_description &all_options,
        boost::program_options::positional_options_description &pos) override
    {
        base_class::initialize_suboptions(options, all_options, pos);

        options.add_options()(
            "vk-file,v",
            po::value<std::string>(),
            "Verification key file (optional)")(
            "pk-file,p",
            po::value<std::string>(),
            "Proving key file (optional)");

        all_options.add(options).add_options()(
            "keypair-file,k", po::value<std::string>(), "Keypair file");
        pos.add("keypair-file", 1);
    }

    void parse_suboptions(
        const boost::program_options::variables_map &vm) override
    {
        base_class::parse_suboptions(vm);

        if (vm.count("keypair-file") == 0) {
            throw po::error("keypair file not specified");
        }

        keypair_file = vm["keypair-file"].as<std::string>();
        vk_file = vm.count("vk-file") ? vm["vk-file"].as<std::string>() : "";
        pk_file = vm.count("pk-file") ? vm["pk-file"].as<std::string>() : "";

        if (vk_file.empty() && pk_file.empty()) {
            throw po::error("no VK or PK file specified");
        }
    }

    void subcommand_usage(const char *argv0) override
    {
        std::cout << "Usage:\n"
                     "  "
                  << argv0 << " split-keypair <options> [keypair_file]\n";
    }

    std::string keypair_file;
    std::string vk_file;
    std::string pk_file;
};

} // namespace commands

zeth_subcommand *split_keypair_cmd = new commands::split_keypair_cmd(
    "split-keypair",
    "Extract the verification key / proving key from a keypair.");

} // namespace zethtool
