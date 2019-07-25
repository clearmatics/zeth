
namespace zeth
{
namespace test
{

template <typename ppT>
void simple_circuit(libsnark::protoboard<libff::Fr<ppT>> &pb)
{
    using namespace libsnark;
    using FieldT = libff::Fr<ppT>;

    // x^3 + 4x^2 + 2x + 5 = y

    pb_variable<FieldT> x;
    pb_variable<FieldT> y;
    pb_variable<FieldT> g1;
    pb_variable<FieldT> g2;
    // pb_variable<FieldT> g_out;

    // Statement
    y.allocate(pb, "y");

    // Witness
    x.allocate(pb, "x");
    g1.allocate(pb, "g1");
    g2.allocate(pb, "g2");

    pb.set_input_sizes(1);

    // Constraints

    //   g1
    //  /  \
    //  \  /
    //   x

    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x, x, g1), "g1");

    //   g2
    //  /  \
    // g1   x

    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(g1, x, g2), "g2");

    //                    g_out
    //                   /     \
    //                  /       \
    // g2 + 4.g1 + 2x + 5        1

    pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(g2 + (4*g1) + (2*x) + 5, 1, y), "y");
}

} // namespace test
} // namespace zeth
