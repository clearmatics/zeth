#pragma once

#include "evaluation_from_lagrange.hpp"
#include "multi_exp.hpp"


template<typename ppT, typename GroupT>
evaluation_from_lagrange<ppT, GroupT>::evaluation_from_lagrange(
    const std::vector<GroupT> &powers,
    libfqfft::evaluation_domain<libff::Fr<ppT>> &domain)
    : powers(powers)
    , domain(domain)
{
    assert(powers.size() >= domain.m - 1);
}

template<typename ppT, typename GroupT>
GroupT evaluation_from_lagrange<ppT, GroupT>::evaluate_from_langrange_factors(
    const std::map<size_t, libff::Fr<ppT>> lagrange_factors)
{
    // libfqfft::evaluation_domain modifies an incoming vector of
    // factors.  Write the factors into the vector (it must be
    // large enough to hold domain.m entries), and then run iFFT
    // to transform to coefficients.

    std::vector<libff::Fr<ppT>> coefficients(domain.m, libff::Fr<ppT>::zero());
    for (auto it : lagrange_factors)
    {
        const size_t lagrange_idx = it.first;
        const libff::Fr<ppT> &lagrange_factor = it.second;

        assert(lagrange_idx < domain.m);
        if (!lagrange_factor.is_zero())
        {
            coefficients[lagrange_idx] = lagrange_factor;
        }
    }

    domain.iFFT(coefficients);
    return multi_exp<ppT, GroupT>(powers, coefficients);
}
