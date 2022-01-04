// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libtool/tool_util.hpp"

namespace libtool
{

std::ifstream open_binary_input_file(const std::string &filename)
{
    std::ifstream in_s(
        filename.c_str(), std::ios_base::in | std::ios_base::binary);
    in_s.exceptions(
        std::ios_base::eofbit | std::ios_base::badbit | std::ios_base::failbit);
    return in_s;
}

std::ofstream open_binary_output_file(const std::string &filename)
{
    std::ofstream out_s(
        filename.c_str(), std::ios_base::out | std::ios_base::binary);
    return out_s;
}

} // namespace libtool
