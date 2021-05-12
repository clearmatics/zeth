// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_TOOL_TOOL_COMMON_HPP__
#define __ZETH_TOOL_TOOL_COMMON_HPP__

#include "libtool/subcommand.hpp"
#include "libzeth/snarks/groth16/groth16_snark.hpp"
#include "libzeth/snarks/pghr13/pghr13_snark.hpp"

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>
#include <libff/algebra/curves/bw6_761/bw6_761_pp.hpp>

namespace zethtool
{

using global_options = bool;
using zeth_subcommand = libtool::subcommand<global_options>;

/// Given a class of the form:
///
///   template<typename ppT, typename snarkT> class Callee
///   {
///   public:
///       static int execute(std::string &a, ...);
///   };
///
/// this class can be used to invoke the correct instantiation of Callee based
/// on curve_name and snark_name strings. E.g.
///
///   int r = curve_and_snark_resolver<Callee>("alt-bn128", "groth16", a, ....);
template<template<typename, typename> class Callee>
class curve_and_snark_resolver
{
public:
    template<typename... Args>
    static int resolve(
        const std::string &curve_name,
        const std::string &snark_name,
        Args... args)
    {
        if (curve_name == "alt-bn128") {
            return resolve_snark<libff::alt_bn128_pp>(snark_name, args...);
        } else if (curve_name == "bls12-377") {
            return resolve_snark<libff::bls12_377_pp>(snark_name, args...);
        } else if (curve_name == "bw6-761") {
            return resolve_snark<libff::bw6_761_pp>(snark_name, args...);
        }

        throw po::error("unrecognized curve");
    }

protected:
    template<typename ppT, typename... Args>
    static int resolve_snark(const std::string &snark_name, Args... args)
    {
        if (snark_name == "groth16") {
            return Callee<ppT, libzeth::groth16_snark<ppT>>::execute(args...);
        } else if (snark_name == "pghr13") {
            return Callee<ppT, libzeth::pghr13_snark<ppT>>::execute(args...);
        }

        throw po::error("unrecognized snark");
    }
};

} // namespace zethtool

#endif // __ZETH_TOOL_TOOL_COMMON_HPP__
