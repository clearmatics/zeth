# Values common to mpc server testing scripts

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
    curl --fail http://${HOST}:${PORT}/state
}
