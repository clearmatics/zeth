// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/serialization/debug_helpers.hpp"

#include "libzeth/util.hpp"

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

} // namespace libzeth
