#include "circuit-wrapper.hpp"
#include "mpc_main.hpp"

void zeth_protoboard(libsnark::protoboard<FieldT> &pb)
{
    using HashTreeT = MiMC_mp_gadget<FieldT>;
    using HashT = sha256_ethereum<FieldT>;

    joinsplit_gadget<
        FieldT,
        HashT,
        HashTreeT,
        ZETH_NUM_JS_INPUTS,
        ZETH_NUM_JS_OUTPUTS>
        js(pb);
    js.generate_r1cs_constraints();
}

int main(int argc, char **argv)
{
    return mpc_main(argc, argv, zeth_protoboard);
}
