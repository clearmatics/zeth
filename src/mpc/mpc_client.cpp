// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

// Utility for executing operations that are only required by "clients" (that
// is, participants in the MPC that only contribute and potentially validate
// the final transcript.

#include "circuit_wrapper.hpp"
#include "mpc_common.hpp"

void zeth_protoboard(libsnark::protoboard<FieldT> &pb)
{
    joinsplit_gadget<
        FieldT,
        HashT,
        HashTreeT,
        ZETH_NUM_JS_INPUTS,
        ZETH_NUM_JS_OUTPUTS,
        ZETH_MERKLE_TREE_DEPTH>
        js(pb);
    js.generate_r1cs_constraints();
}

int main(int argc, char **argv)
{
    const std::map<std::string, subcommand *> commands{
        {"phase2-contribute", mpc_phase2_contribute_cmd},
        {"phase2-verify-transcript", mpc_phase2_verify_transcript_cmd},
        {"create-keypair", mpc_create_keypair_cmd},
    };
    return mpc_main(argc, argv, commands, zeth_protoboard);
}
