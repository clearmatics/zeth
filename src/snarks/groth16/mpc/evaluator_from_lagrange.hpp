// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_GROTH16_EVALUATOR_FROM_LAGRANGE_HPP__
#define __ZETH_SNARKS_GROTH16_EVALUATOR_FROM_LAGRANGE_HPP__

#include "include_libsnark.hpp"

#include <map>

namespace libzeth
{

/// Given a sequence of powers of x (with some factor) encoded in
/// GroupT, compute the values of various linear combination of
/// Lagrange polynomials at x. Note that this is not optimal, and
/// primarily intended for testing and validation.
template<typename ppT, typename GroupT> class evaluator_from_lagrange
{
private:
    const std::vector<GroupT> &powers;
    libfqfft::evaluation_domain<libff::Fr<ppT>> &domain;

public:
    evaluator_from_lagrange(
        const std::vector<GroupT> &powers,
        libfqfft::evaluation_domain<libff::Fr<ppT>> &domain);

    GroupT evaluate_from_lagrange_factors(
        const std::map<size_t, libff::Fr<ppT>> lagrange_factors);
};

} // namespace libzeth
#include "evaluator_from_lagrange.tcc"

#endif // __ZETH_SNARKS_GROTH16_EVALUATOR_FROM_LAGRANGE_HPP__
