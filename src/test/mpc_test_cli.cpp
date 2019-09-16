#include "mpc_main.hpp"
#include "test/simple_test.hpp"

void simple_protoboard(libsnark::protoboard<FieldT> &pb)
{
    libzeth::test::simple_circuit<FieldT>(pb);
}

int main(int argc, char **argv) { mpc_main(argc, argv, simple_protoboard); }
