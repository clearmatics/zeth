// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/tests/circuits/simple_test.hpp"
#include "mpc_common.hpp"

void simple_protoboard(libsnark::protoboard<libzeth::defaults::Field> &pb)
{
    libzeth::tests::simple_circuit<libzeth::defaults::Field>(pb);
}

int main(int argc, char **argv)
{
    const std::map<std::string, mpc_subcommand *> commands{
        {"linear-combination", mpc_linear_combination_cmd},
        {"dummy-phase2", mpc_dummy_phase2_cmd},
        {"phase2-begin", mpc_phase2_begin_cmd},
        {"phase2-contribute", mpc_phase2_contribute_cmd},
        {"phase2-verify-contribution", mpc_phase2_verify_contribution_cmd},
        {"phase2-verify-transcript", mpc_phase2_verify_transcript_cmd},
        {"create-keypair", mpc_create_keypair_cmd},
    };
    return mpc_main(commands, simple_protoboard, argc, argv);
}
