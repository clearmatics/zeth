// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
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
            // Disabled for now (missing implementation of some functionality)
            // } else if (curve_name == "bw6-761") {
            //     return resolve_snark<libff::bw6_761_pp>(snark_name, args...);
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

/// Base class of subcommands with entry points generic over curve and snark.
/// Implementations are expected to implement a public generic
/// `execute_generic` method of the form:
///
///   class my_cmd : generic_subcommand_base<my_cmd>
///   {
///    public:
///     template<typename ppT, typename snarkT> int execute_generic(
///         const global_options &)
///     {
///       ...
///     }
///   }
///
/// along side the usual parsing entry points `initialize_suboptions` and
/// `parse_suboptions`, which MUST call the equivalent methods on this base
/// class.
template<class CommandT> class generic_subcommand : public zeth_subcommand
{
public:
    generic_subcommand(
        const std::string &subcommand_name, const std::string &description)
        : zeth_subcommand(subcommand_name, description)
    {
    }

protected:
    void initialize_suboptions(
        boost::program_options::options_description &options,
        boost::program_options::options_description &,
        boost::program_options::positional_options_description &) override
    {
        // Options
        options.add_options()(
            "curve,c",
            po::value<std::string>(),
            "Curve: alt-bn128, bls12-377 or bw6-761");
        options.add_options()(
            "snark,s", po::value<std::string>(), "Snark: groth16 or pghr13");
    }

    void parse_suboptions(
        const boost::program_options::variables_map &vm) override
    {
        curve = vm.count("curve") ? vm["curve"].as<std::string>() : "alt-bn128";
        snark = vm.count("snark") ? vm["snark"].as<std::string>() : "groth16";
    }

    int execute_subcommand(const global_options &options) override
    {
        return curve_and_snark_resolver<this_caller>::resolve(
            curve, snark, this, options);
    }

protected:
    template<typename ppT, typename snarkT> class this_caller
    {
    public:
        static int execute(
            generic_subcommand<CommandT> *that, const global_options &o)
        {
            return ((CommandT *)that)->template execute_generic<ppT, snarkT>(o);
        }
    };

    std::string curve;
    std::string snark;
};

} // namespace zethtool

#endif // __ZETH_TOOL_TOOL_COMMON_HPP__
