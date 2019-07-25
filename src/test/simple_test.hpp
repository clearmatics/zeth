
#include "include_libsnark.hpp"

namespace zeth
{
namespace test
{

/// Generate a simple test circuit with 1 public input 'y' and auxiliary
/// input 'x', for the expression:
///
///   x^3 + 4x^2 + 2x + 5 = y
///
/// Internal auxiliary inputs are:
///
///   g1 = x * x
///   g2 = g1 * x
template <typename ppT>
void simple_circuit(libsnark::protoboard<libff::Fr<ppT>> &pb);

} // namespace test
} // namespace zeth

//
#include "simple_test.tcc"
