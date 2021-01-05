// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_EVALUATOR_FROM_LAGRANGE_TCC__
#define __ZETH_CORE_EVALUATOR_FROM_LAGRANGE_TCC__

#include "libzeth/core/evaluator_from_lagrange.hpp"
#include "libzeth/core/multi_exp.hpp"

namespace libzeth
{

template<typename ppT, typename GroupT>
evaluator_from_lagrange<ppT, GroupT>::evaluator_from_lagrange(
    const std::vector<GroupT> &powers,
    libfqfft::evaluation_domain<libff::Fr<ppT>> &domain)
    : powers(powers), domain(domain)
{
    // Lagrange polynomials have order <= m-1, requiring at least m
    // entries in powers (0, ..., m-1) in order to evaluate.
    assert(powers.size() >= domain.m);
}

template<typename ppT, typename GroupT>
GroupT evaluator_from_lagrange<ppT, GroupT>::evaluate_from_lagrange_factors(
    const std::map<size_t, libff::Fr<ppT>> &lagrange_factors)
{
    // libfqfft::evaluation_domain modifies an incoming vector of factors.
    // Write the factors into the vector (it must be large enough to hold
    // domain.m entries), and then run iFFT to transform to coefficients.
    std::vector<libff::Fr<ppT>> coefficients(domain.m, libff::Fr<ppT>::zero());
    for (auto it : lagrange_factors) {
        const size_t lagrange_idx = it.first;
        const libff::Fr<ppT> &lagrange_factor = it.second;

        assert(lagrange_idx < domain.m);
        if (!lagrange_factor.is_zero()) {
            coefficients[lagrange_idx] = lagrange_factor;
        }
    }

    domain.iFFT(coefficients);
    return multi_exp<ppT, GroupT>(powers, coefficients);
}

} // namespace libzeth

#endif // __ZETH_CORE_EVALUATOR_FROM_LAGRANGE_TCC__
