// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libsnark_helpers/debug_helpers.hpp"

#include "util.hpp"

namespace libzeth
{

boost::filesystem::path get_path_to_setup_directory()
{
    const char *path = std::getenv("ZETH_TRUSTED_SETUP_DIR");
    if (nullptr == path) {
        // Fallback destination if the ZETH_TRUSTED_SETUP_DIR env var is not set
        return "../trusted_setup";
    }

    return boost::filesystem::path(path);
}

boost::filesystem::path get_path_to_debug_directory()
{
    const char *path_to_debug_directory = std::getenv("ZETH_DEBUG_DIR");
    if (path_to_debug_directory == NULL) {
        // Fallback destination if the ZETH_DEBUG_DIR env var is not set
        path_to_debug_directory = "../debug";
    }

    boost::filesystem::path setup_dir(path_to_debug_directory);
    return setup_dir;
}

bool replace(std::string &str, const std::string &from, const std::string &to)
{
    size_t start_pos = str.find(from);
    if (start_pos == std::string::npos) {
        return false;
    }

    str.replace(start_pos, from.length(), to);
    return true;
}

} // namespace libzeth