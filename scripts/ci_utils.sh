# Utility functions for CI tasks.
#
# All functions expect to be executed the root directory of the repository, and
# will exit with this as the current directory.

#
# GANACHE
#

function ganache_setup() {
    if [ "${platform}" == "Linux" ] ; then
        if (which apk) ; then
            apk add --update npm

            # # `py3-virtualenv` depends on `python3`
            # # which installs the latest version of python3
            # # See: https://pkgs.alpinelinux.org/package/edge/main/x86/python3
            # # https://build.alpinelinux.org/buildlogs/build-edge-x86/main/python3/python3-3.8.2-r6.log
            # apk add \
            #     py3-virtualenv \
            #     libffi-dev \
            #     python3-dev

            # # Install openssl for the mpc tests
            # apk add openssl
        # else
        #     sudo apt update
        #     sudo apt install python3-venv
        fi
    fi

    pushd zeth_contracts
    npm config set python python2.7
    npm config set engine-strict true
    npm config set unsafe-perm true
    npm install --unsafe-perm
    popd
}

function ganache_is_active() {
    curl -sf \
         -H "Content-Type: application/json" \
         -X POST \
         --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[]}' \
         http://localhost:8545
}

function ganache_start() {
    pushd zeth_contracts

    npm run testrpc > ganache.stdout &
    echo $! > ganache.pid

    # Wait for ganache to be active
    while ! ganache_is_active ; do
        echo "ganache_start: waiting for ganache ..."
        sleep 1
    done
    echo "ganache_start: ganache is ACTIVE"

    popd
}

function ganache_stop() {
    pushd zeth_contracts
    if ! [ -e ganache.pid ] ; then
        echo "ganache_stop: no PID file"
        return 1
    fi

    pid=`cat ganache.pid`
    while (kill "${pid}") ; do
        sleep 0.5
    done
    rm ganache.pid
    echo "ganache_stop: STOPPED"

    popd
}

#
# PROVER SERVER
#
# These functions assume that the prover_server has been built in the build
# directory.

function prover_server_is_active() {
    # Assume the client env is active
    zeth get-verification-key
}

function prover_server_start() {
    # Requires the client env (for _prover_server_is_active)
    . client/env/bin/activate
    pushd build

    ./prover_server/prover_server > prover_server.stdout &
    echo $! > prover_server.pid

    # Wait for prover_server to be active
    while ! prover_server_is_active ; do
        echo "prover_server_start: waiting for server ..."
        sleep 1
    done
    echo "prover_server_start:: prover_server is ACTIVE"

    popd # build
    deactivate
}

function prover_server_stop() {
    pushd build

    if ! [ -e prover_server.pid ] ; then
        echo "prover_server_stop: no PID file"
        return 1
    fi

    pid=`cat prover_server.pid`
    while (kill "${pid}") ; do
        sleep 0.5
    done
    rm prover_server.pid
    echo "prover_server_stop:: STOPPED"

    popd # build
}

#
# DEPENDENCIES
#

function cpp_build_setup() {
    # Extra deps for native builds

    if [ "${platform}" == "Darwin" ] ; then
        # Some of these commands can fail (if packages are already installed,
        # etc), hence the `|| echo`.
        brew update || echo
        brew install \
             gmp \
             grpc \
             protobuf \
             boost \
             openssl \
             cmake \
             libtool \
             autoconf \
             automake \
             || echo
    fi

    if [ "${platform}" == "Linux" ] ; then
        if (which apk) ; then
            # Packages already available in Docker build
            echo -n             # null op required for syntax
        else
            sudo apt install \
                 libboost-dev \
                 libboost-system-dev \
                 libboost-filesystem-dev \
                 libboost-program-options-dev \
                 libgmp-dev \
                 libprocps-dev \
                 libxslt1-dev \
                 pkg-config
        fi
    fi
}
