// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_MPC_CLI_COMMON_HPP__
#define __ZETH_MPC_CLI_COMMON_HPP__

#include "libzeth/core/include_libsnark.hpp"
#include "libzeth/mpc/groth16/mpc_hash.hpp"
#include "mpc_subcommand.hpp"

#include <boost/program_options.hpp>
#include <fstream>
#include <map>
#include <string>
#include <vector>

// interface for ReadableT types:
// {
//     static ReadableT read(std::istream &in);
// }

// Utility function to load data objects from a file, using a static read
// method. Type must satisfy ReadableT constraints above.
template<typename ReadableT>
inline ReadableT read_from_file(const std::string &file_name)
{
    std::ifstream in(file_name, std::ios_base::binary | std::ios_base::in);
    in.exceptions(
        std::ios_base::eofbit | std::ios_base::badbit | std::ios_base::failbit);
    return ReadableT::read(in);
}

// Load data objects from a file, similarly to read_from_file, while computing
// the hash of the serialized structure. Type must satisfy ReadableT
// constraints above.
template<typename ReadableT>
inline ReadableT read_from_file_and_hash(
    const std::string &file_name, libzeth::mpc_hash_t out_hash)
{
    std::ifstream inf(file_name, std::ios_base::binary | std::ios_base::in);
    libzeth::mpc_hash_istream_wrapper in(inf);
    in.exceptions(
        std::ios_base::eofbit | std::ios_base::badbit | std::ios_base::failbit);
    ReadableT v = ReadableT::read(in);
    in.get_hash(out_hash);
    return v;
}

extern mpc_subcommand *mpc_linear_combination_cmd;
extern mpc_subcommand *mpc_dummy_phase2_cmd;
extern mpc_subcommand *mpc_phase2_begin_cmd;
extern mpc_subcommand *mpc_phase2_contribute_cmd;
extern mpc_subcommand *mpc_phase2_verify_contribution_cmd;
extern mpc_subcommand *mpc_phase2_verify_transcript_cmd;
extern mpc_subcommand *mpc_create_keypair_cmd;

/// Main entry point into the mpc command for a given circuit.
int mpc_main(
    const std::map<std::string, mpc_subcommand *> &commands,
    const ProtoboardInitFn &pb_init,
    int argc,
    char **argv);

#endif // __ZETH_MPC_CLI_COMMON_HPP__
