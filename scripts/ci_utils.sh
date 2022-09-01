# Utility functions for CI tasks.
#
# All functions expect to be executed the root directory of the repository, and
# will exit with this as the current directory.

. scripts/build_utils.sh

# Launch a server in the background and wait for it to be ready, recording the
# pid in a file.
#
# 1 - server cmd
# 2 - server check cmd
# 3 - pid file
# 4 - stdout file
function server_start() {
    $1 > $4 &
    pid=$!
    echo pid is ${pid}
    echo ${pid} > $3

    # Wait for prover-server to be active
    while ! $2 ; do
        echo "server_start: waiting for $1 ..."
        sleep 1
    done

    echo "server_start: $1 is ACTIVE"
}

# Stop a background server, given a name and pid file
#
# 1 - server name
# 2 - pid file
function server_stop() {
    if ! [ -e $2 ] ; then
        echo "server_stop: no PID file for $1"
        return 1
    fi

    pid=`cat $2`
    while (kill "${pid}") ; do
        sleep 0.5
    done
    rm $2
    echo "server_stop: $1 STOPPED"
}

#
# GANACHE
#

function ganache_setup() {
    # Nothing to do. Just check that the platform vars have been initialized.
    assert_init_platform
}

function ganache_is_active() {
    curl -sf \
         -H "Content-Type: application/json" \
         -X POST \
         --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[]}' \
         http://localhost:8545
}

function ganache_start() {
    server_start \
        scripts/ganache-start \
        ganache_is_active \
        ganache.pid \
        ganache.stdout
}

function ganache_stop() {
    server_stop ganache ganache.pid
}

#
# PROVER SERVER
#
# These functions assume that the prover-server has been built in the build
# directory.

function prover_server_is_active() {
    # Assume the client env is active
    zeth get-verification-key
}

# 1 - prover server flags
function prover_server_start() {
    # Requires the client env (for prover_server_is_active)
    . client/env/bin/activate
    pushd build

    server_start \
        "./prover_server/prover-server $1" \
        prover_server_is_active \
        prover_server.pid \
        prover_server.stdout

    popd # build
    deactivate
}

function prover_server_stop() {
    pushd build
    server_stop prover_server prover_server.pid
    popd # build
}
