#pragma once

#include "evaluation_from_lagrange.hpp"
#include "multi_exp.hpp"


template<typename ppT>
evaluation_from_lagrange<ppT>::evaluation_from_lagrange(
    const libff::G1_vector<ppT> &powers,
    libfqfft::evaluation_domain<libff::Fr<ppT>> &domain)
    : powers(powers)
    , domain(domain)
{
    assert(powers.size() >= domain.m - 1);
}

template<typename ppT>
libff::G1<ppT> evaluation_from_lagrange<ppT>::evaluate_from_langrange_factors(
    const std::map<size_t, libff::Fr<ppT>> lagrange_factors)
{
    using Fr = libff::Fr<ppT>;

    // libfqfft::evaluation_domain modifies an incoming vector of
    // factors.  Write the factors into the vector (it must be
    // large enough to hold domain.m entries), and then run iFFT
    // to transform to coefficients.

    std::vector<Fr> coefficients(domain.m, Fr::zero());
    for (auto it : lagrange_factors)
    {
        const size_t lagrange_idx = it.first;
        const Fr &lagrange_factor = it.second;

        assert(lagrange_idx < domain.m);
        if (!lagrange_factor.is_zero())
        {
            coefficients[lagrange_idx] = lagrange_factor;
        }
    }

    domain.iFFT(coefficients);
    return multi_exp<ppT>(powers, coefficients);
}
