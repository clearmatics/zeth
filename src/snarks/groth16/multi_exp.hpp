#pragma once

#include "include_libsnark.hpp"

///
template<typename ppT> extern
libff::G1<ppT> multi_exp(
    typename std::vector<libff::G1<ppT>>::const_iterator gs_start,
    typename std::vector<libff::G1<ppT>>::const_iterator gs_end,
    typename std::vector<libff::Fr<ppT>>::const_iterator fs_start,
    typename std::vector<libff::Fr<ppT>>::const_iterator fs_end)
{
    using G1 = libff::G1<ppT>;
    using Fr = libff::Fr<ppT>;
    const libff::multi_exp_method Method = libff::multi_exp_method_BDLO12;
    return
        libff::multi_exp_with_mixed_addition<G1, Fr, Method>(
            gs_start,
            gs_end,
            fs_start,
            fs_end,
            1);
}


///
template<typename ppT> extern
libff::G1<ppT> multi_exp(
    const libff::G1_vector<ppT> &gs,
    const libff::Fr_vector<ppT> &fs)
{
    assert(gs.size() == fs.size());
    assert(gs.size() > 0);

#if 0

    libff::G1<ppT> accum = fs[0] * gs[0];
    for (size_t i = 1 ; i < gs.size() ; ++i)
    {
        accum = accum + fs[i] * gs[i];
    }
    return accum;

#else

    using G1 = libff::G1<ppT>;
    using Fr = libff::Fr<ppT>;
    const libff::multi_exp_method Method = libff::multi_exp_method_BDLO12;
    return
        libff::multi_exp_with_mixed_addition<G1, Fr, Method>(
            gs.begin(),
            gs.end(),
            fs.begin(),
            fs.end(),
            1);

#endif
}
