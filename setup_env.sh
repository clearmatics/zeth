#!/bin/bash

export ZETH=`pwd`
export ZETH_KEYSTORE=$ZETH/keystore
export ZETH_COINSTORE=$ZETH/coinstore
export ZETH_TRUSTED_SETUP_DIR=$ZETH/trusted_setup

# Add the zeth executable in the PATH
export PATH=$ZETH/build/src:$PATH
