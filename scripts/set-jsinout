#!/usr/bin/env bash

# client/zeth/core/constants.py:JS_INPUTS: int = 2
# client/zeth/core/constants.py:JS_OUTPUTS: int = 2
sed -i -e 's/JS_INPUTS: int = 2/JS_INPUTS: int = '$1'/g' client/zeth/core/constants.py
sed -i -e 's/JS_OUTPUTS: int = 2/JS_OUTPUTS: int = '$1'/g' client/zeth/core/constants.py

# libzeth/zeth_constants.hpp:static const size_t ZETH_NUM_JS_INPUTS = 2;
# libzeth/zeth_constants.hpp:static const size_t ZETH_NUM_JS_OUTPUTS = 2;
sed -i -e 's/static const size_t ZETH_NUM_JS_INPUTS = 2/static const size_t ZETH_NUM_JS_INPUTS = '$1'/g' libzeth/zeth_constants.hpp
sed -i -e 's/static const size_t ZETH_NUM_JS_OUTPUTS = 2/static const size_t ZETH_NUM_JS_OUTPUTS = '$1'/g' libzeth/zeth_constants.hpp
