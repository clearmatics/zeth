#pragma once

#include "include_libsnark.hpp"
#include <map>

/// Given a sequence of powers of x (with some factor) encoded in
/// GroupT, compute the values of various linear combination of
/// Lagrange polynomials at x.
///
/// TODO: Here, we assume that there may be more Lagrange polynomails
/// than variables in the original qap, so we use a map to avoid
/// evaluating those that are unused.  This may not be the optimal approach.
template <typename ppT, typename GroupT>
class evaluation_from_lagrange
{
public:
    evaluation_from_lagrange(
        const std::vector<GroupT> &powers,
        libfqfft::evaluation_domain<libff::Fr<ppT>> &domain);

    GroupT evaluate_from_langrange_factors(
        const std::map<size_t, libff::Fr<ppT>> lagrange_factors);

private:

    const std::vector<GroupT> &powers;
    libfqfft::evaluation_domain<libff::Fr<ppT>> &domain;
};


#include "evaluation_from_lagrange.tcc"
