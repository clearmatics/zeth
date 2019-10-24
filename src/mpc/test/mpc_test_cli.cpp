#include "mpc_common.hpp"
#include "test/simple_test.hpp"

void simple_protoboard(libsnark::protoboard<FieldT> &pb)
{
    libzeth::test::simple_circuit<FieldT>(pb);
}

int main(int argc, char **argv)
{
    const std::map<std::string, subcommand *> commands{
        {"linear-combination", mpc_linear_combination_cmd},
        {"dummy-phase2", mpc_dummy_phase2_cmd},
        {"phase2-begin", mpc_phase2_begin_cmd},
        {"phase2-contribute", mpc_phase2_contribute_cmd},
        {"phase2-verify-contribution", mpc_phase2_verify_contribution_cmd},
        {"phase2-verify-transcript", mpc_phase2_verify_transcript_cmd},
        {"create-keypair", mpc_create_keypair_cmd},
    };
    return mpc_main(argc, argv, commands, simple_protoboard);
}
