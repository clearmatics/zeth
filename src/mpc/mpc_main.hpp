#ifndef __ZETH_MPC_MPC_MAIN_HPP__
#define __ZETH_MPC_MPC_MAIN_HPP__

#include "include_libsnark.hpp"

using ppT = libff::default_ec_pp;
using FieldT = libff::Fr<ppT>;

using ProtoboardInitFn = std::function<void(libsnark::protoboard<FieldT> &)>;

/// Main entry point into the mpc command for a given circuit.
int mpc_main(int argc, char **argv, ProtoboardInitFn pb_init);

#endif // __ZETH_MPC_MPC_COMMON_HPP__
