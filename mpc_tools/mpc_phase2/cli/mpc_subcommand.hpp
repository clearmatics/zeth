// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_MPC_TOOLS_MPC_PHASE2_MPC_SUBCOMMAND_HPP__
#define __ZETH_MPC_TOOLS_MPC_PHASE2_MPC_SUBCOMMAND_HPP__

#include "libtool/subcommand.hpp"
#include "zeth_config.h"

using Field = libzeth::defaults::Field;

using ProtoboardInitFn = std::function<void(libsnark::protoboard<Field> &)>;

class global_options
{
public:
    ProtoboardInitFn protoboard_init;
    bool verbose;
};

using mpc_subcommand = libtool::subcommand<global_options>;

#endif // __ZETH_MPC_TOOLS_MPC_PHASE2_MPC_SUBCOMMAND_HPP__
