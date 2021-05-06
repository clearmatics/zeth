# Values common to mpc server testing scripts

# Enter MPC env, if available
if ! [ -e mpc/env/bin/activate ] ; then
    echo mpy python env not set up correctly, or not run from repo root.
    echo See mpc/README.md.
    return 1
fi

set -e
. mpc/env/bin/activate
set -x

# Directories
TEST_DATA_DIR=`pwd`/testdata
BIN_DIR=`pwd`/build/mpc_tools
PHASE1_SERVER_DIR=`pwd`/_test_server_phase1
PHASE2_SERVER_DIR=`pwd`/_test_server_phase2

# Server files
PHASE1_CONFIG_TEMPLATE=${TEST_DATA_DIR}/mpc_phase1_server_config.json
PHASE2_CONFIG_TEMPLATE=${TEST_DATA_DIR}/mpc_phase2_server_config.json
CHALLENGE_0_FILE=challenge_0.bin
TRANSCRIPT_FILE=transcript
FINAL_OUTPUT_FILE=final_output.bin
FINAL_TRANSCRIPT_FILE=final_transcript.bin

SERVER_KEY=key.pem
SERVER_CERT=cert.pem

# Commands
POT_PROCESS="${BIN_DIR}/pot-process"
MPC="${BIN_DIR}/mpc_phase2/mpc-test-phase2"
POT_DIR=`pwd`"/../powersoftau"
POT_BIN_DIR="${POT_DIR}/target/release"
QAP_DEGREE=8

# Server address (consistent with server config template)
HOST=localhost
PHASE1_PORT=8001
PHASE2_PORT=8002

# Client keys (consistent with server config template)
PRV_KEY_1=${TEST_DATA_DIR}/mpc_key1.bin
PUB_KEY_1=${TEST_DATA_DIR}/mpc_key1.pub
PRV_KEY_2=${TEST_DATA_DIR}/mpc_key2.bin
PUB_KEY_2=${TEST_DATA_DIR}/mpc_key2.pub
PRV_KEY_3=${TEST_DATA_DIR}/mpc_key3.bin
PUB_KEY_3=${TEST_DATA_DIR}/mpc_key3.pub
PRV_KEY_4=${TEST_DATA_DIR}/mpc_key4.bin
PUB_KEY_4=${TEST_DATA_DIR}/mpc_key4.pub

# 1 - server_dir
function prepare_server_common() {

    mkdir -p $1
    pushd $1

    rm -rf server_state.json
    rm -rf server_config.json
    rm -rf ${TRANSCRIPT_FILE} ${FINAL_OUTPUT_FILE} ${FINAL_TRANSCRIPT_FILE} \
       next_challenge.bin phase1_state.json

    # TLS server certs
    if ! [ -e ${SERVER_KEY} ] || ! [ -e ${SERVER_CERT} ] ; then
        echo TLS certificate ...
        KEY_BITS=4096
        cp /etc/ssl/openssl.cnf openssl.tmp.cnf
        echo "[v3_req]" >> openssl.tmp.cnf
        echo "subjectAltName=DNS:localhost" >> openssl.tmp.cnf

        openssl req -x509 \
                -subj "/C=UK/ST=London/L=London/O=ClearmaticsTest/OU=Org/CN=localhost" \
                -reqexts v3_req \
                -extensions v3_req \
                -config openssl.tmp.cnf \
                -nodes \
                -newkey rsa:${KEY_BITS} \
                -keyout ${SERVER_KEY} \
                -out ${SERVER_CERT} \
                -days 365
    fi

    popd
}

# 1 - server dir
# 2 - command
# 3 - get_state function
function start_server_common() {
    pushd $1

    $2 > server.stdout &
    echo $! > server.pid

    x=1
    while ! $3 ; do
        if [ $x == 10 ] ; then
            echo "FAILED TO LAUNCH"
            exit 1
        fi

        echo "TEST: waiting for server to start ..."
        sleep 1

        x=$(( $x + 1 ))
        echo "TEST: retrying ($x)"

    done
    echo "TEST: server up (pid: "`cat server.pid`")"
    popd

}

# 1 - server dir
function stop_server_common() {
    if [ -d $1 ] ; then
        pushd $1
        if [ -e server.pid ] ; then
            pid=`cat server.pid`
            echo "TEST: Stopping server (pid: "${pid}")"
            while (kill "${pid}") ; do
                sleep 0.5
            done
            rm server.pid
            echo "TEST: Server stopped"

            echo "SERVER LOG:"
            cat server.stdout
        fi
        popd
    fi
}

function passed() {
    echo "============================================================"
    echo "==                        PASSED                          =="
    echo "============================================================"
}

set +x
set +e
