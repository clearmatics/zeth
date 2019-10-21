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
PHASE1_SERVER_DIR=`pwd`/_test_server_phase1
PHASE2_SERVER_DIR=`pwd`/_test_server_phase2

# Server files
SERVER_CONFIG_TEMPLATE=${TEST_DATA_DIR}/mpc_server_config.json
CHALLENGE_0_FILE=challenge_0.bin
TRANSCRIPT_FILE=transcript
FINAL_OUTPUT_FILE=final_output.bin
FINAL_TRANSCRIPT_FILE=final_transcript.bin

SERVER_KEY=key.pem
SERVER_CERT=cert.pem

# Commands
POT_PROCESS="${BIN_DIR}/pot-process"
MPC="${BIN_DIR}/mpc/mpc-test"
POT_DIR=`pwd`"/../powersoftau"
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
# 2 - port
function prepare_server_common() {

    mkdir -p $1
    pushd $1

    rm -rf server_state.json
    rm -rf server_config.json
    rm -rf ${TRANSCRIPT_FILE} ${FINAL_OUTPUT_FILE} ${FINAL_TRANSCRIPT_FILE} \
       next_challenge.bin phase1_state.json

    # Config
    now=`python -c 'import time; print(time.strftime("%Y-%m-%d %H:%M:%S"))'`
    sed -e "s/TIME/${now}/g" -e "s/PORT/$2/g" ${SERVER_CONFIG_TEMPLATE} \
        > server_config.json

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

    popd
}

# 1 - server dir
# 2 - command
# 3 - get_state function
function start_server_common() {
    pushd $1

    $2 > server.stdout &
    echo $! > server.pid

    while ! $3 ; do
        echo "TEST: waiting for server to start ..."
        sleep 1
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
        fi
        popd
    fi
}

function get_state_phase1() {
    curl \
        -k \
        --cacert ${PHASE1_SERVER_DIR}/${SERVER_CERT} \
        --fail https://${HOST}:${PHASE1_PORT}/state
}

function get_state_phase2() {
    curl \
        -k \
        --cacert ${PHASE2_SERVER_DIR}/${SERVER_CERT} \
        --fail https://${HOST}:${PHASE2_PORT}/state
}

function prepare_server_phase1() {
    prepare_server_common ${PHASE1_SERVER_DIR} ${PHASE1_PORT}
}

function prepare_server_phase2() {
    prepare_server_common ${PHASE2_SERVER_DIR} ${PHASE2_PORT}

    # Perform the phase2-specific setup based on POT data
    pushd ${PHASE2_SERVER_DIR}
    if ! [ -e ${CHALLENGE_0_FILE} ] ; then

        if [ -e ${PHASE1_SERVER_DIR}/${FINAL_OUTPUT_FILE} ] ; then
            echo "Creating initial challenge (from POT MPC) ..."
           pot_file=${PHASE1_SERVER_DIR}/${FINAL_OUTPUT_FILE}
        else
            echo "Creating initial challenge (from dummy POT) ..."
           pot_file=_test_pot-${QAP_DEGREE}.bin
           ${POT_PROCESS} --dummy ${pot_file} ${QAP_DEGREE}
        fi

        lagrange_file=_test_lagrange-${QAP_DEGREE}.bin
        linear_combination_file=_test_linear_combination-${QAP_DEGREE}.bin

        ${POT_PROCESS} --out ${lagrange_file} ${pot_file} ${QAP_DEGREE}
        ${MPC} linear-combination --out ${linear_combination_file} \
               ${pot_file} ${lagrange_file}
        ${MPC} phase2-begin \
               --out ${CHALLENGE_0_FILE} ${linear_combination_file}
    fi
    popd
}

function start_server_phase1() {
    start_server_common \
        ${PHASE1_SERVER_DIR} \
        "phase1_server -n ${QAP_DEGREE}" \
        get_state_phase1
}

function start_server_phase2() {
    start_server_common ${PHASE2_SERVER_DIR} phase2_server get_state_phase2
}

function stop_server_phase1() {
    stop_server_common ${PHASE1_SERVER_DIR}
}

function stop_server_phase2() {
    stop_server_common ${PHASE2_SERVER_DIR}
}

set +x
set +e
