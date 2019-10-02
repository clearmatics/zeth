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
BIN_DIR=`pwd`/build/src
SERVER_DIR=`pwd`/_test_server_data

# Server files
SERVER_CONFIG_TEMPLATE=${TEST_DATA_DIR}/mpc_server_config.json
CHALLENGE_0_FILE=${SERVER_DIR}/challenge_0.bin
TRANSCRIPT_FILE=${SERVER_DIR}/transcript.bin
FINAL_OUTPUT_FILE=${SERVER_DIR}/final_output.bin
FINAL_TRANSCRIPT_FILE=${SERVER_DIR}/final_transcript.bin

SERVER_KEY=${SERVER_DIR}/key.pem
SERVER_CERT=${SERVER_DIR}/cert.pem

# Commands
POT="${BIN_DIR}/pot-process"
MPC="${BIN_DIR}/mpc/mpc-test"
QAP_DEGREE=8

# Server address (consistent with server config template)
HOST=localhost
PORT=8001

# Client keys (consistent with server config template)
PRV_KEY_1=${TEST_DATA_DIR}/mpc_key1.bin
PUB_KEY_1=${TEST_DATA_DIR}/mpc_key1.pub
PRV_KEY_2=${TEST_DATA_DIR}/mpc_key2.bin
PUB_KEY_2=${TEST_DATA_DIR}/mpc_key2.pub
PRV_KEY_3=${TEST_DATA_DIR}/mpc_key3.bin
PUB_KEY_3=${TEST_DATA_DIR}/mpc_key3.pub
PRV_KEY_4=${TEST_DATA_DIR}/mpc_key4.bin
PUB_KEY_4=${TEST_DATA_DIR}/mpc_key4.pub

# Get server state
function get_state() {
    curl --cacert ${SERVER_CERT} --fail https://${HOST}:${PORT}/state
}

function prepare_server() {
    rm -rf ${SERVER_DIR}/server_state.json
    rm -rf ${SERVER_DIR}/server_config.json
    rm -rf ${TRANSCRIPT_FILE} ${FINAL_OUTPUT_FILE} ${FINAL_TRANSCRIPT_FILE} \
       ${SERVER_DIR}/next_challenge.bin
    mkdir -p ${SERVER_DIR}
    pushd ${SERVER_DIR}

    # Config
    now=`python -c 'import time; print(time.strftime("%Y-%m-%d %H:%M:%S"))'`
    sed -e "s/TIME/${now}/g" ${SERVER_CONFIG_TEMPLATE} \
        > ${SERVER_DIR}/server_config.json

    # TLS server certs
    if ! [ -e ${SERVER_KEY} ] || ! [ -e ${SERVER_CERT} ] ; then
        echo TLS certificate ...
        KEY_BITS=1024
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

    if ! [ -e ${CHALLENGE_0_FILE} ] ; then
        echo Initial challenge ...
        # Set up phase2
        pot_file=${SERVER_DIR}/_test_pot-${QAP_DEGREE}.bin
        lagrange_file=${SERVER_DIR}/_test_lagrange-${QAP_DEGREE}.bin
        linear_combination_file=${SERVER_DIR}/_test_linear_combination-${QAP_DEGREE}.bin
        # keypair_file=${SERVER_DIR}/_test_keypair-${QAP_DEGREE}.bin

        ${POT} --dummy ${pot_file} ${QAP_DEGREE}
        ${POT} --out ${lagrange_file} ${pot_file} ${QAP_DEGREE}
        ${MPC} linear-combination --out ${linear_combination_file} \
               ${pot_file} ${lagrange_file}
        ${MPC} phase2-begin \
               --out ${CHALLENGE_0_FILE} ${linear_combination_file}
    fi

    popd
}

function start_server() {
    pushd ${SERVER_DIR}

    phase2_server > server.log &
    echo $! > server.pid

    while ! get_state ; do
        echo "TEST: waiting for server to start ..."
        sleep 1
    done
    echo "TEST: server up (pid: "`cat server.pid`")"
    popd
}

function stop_server() {
    if [ -d ${SERVER_DIR} ] ; then
        pushd ${SERVER_DIR}
        if [ -e server.pid ] ; then
            pid=`cat server.pid`
            echo "TEST: Stopping server (pid: "${pid}")"
            while (kill "${pid}") ; do
                sleep 0.5
            done
            rm server.pid
            echo "TEST: Server stopped"
        fi
        popd
    fi
}

set +x
set +e
