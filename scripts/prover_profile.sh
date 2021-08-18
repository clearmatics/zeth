
# Simple script to run the generic prover with some keys and witness data,
# recording the output (including timing information) to separate files.
#
# DATA_DIR and CIRCUIT variables must be set such that the directory
# ${DATA_DIR} contains the following files:
#
#   ${CIRCUIT}_pk.bin
#   ${CIRCUIT}_vk.bin
#   ${CIRCUIT}_assignment.bin
#   ${CIRCUIT}_primary.bin
#
# The zeth-tool binary is expected to be in the path, or at ${ZETH_TOOL}.

if [ "${DATA_DIR}" == "" ] ; then
    echo "DATA_DIR var must be set (see comments in script)"
    exit 1
fi

if [ "${CIRCUIT}" == "" ] ; then
    echo "CIRCUIT var must be set (see comments in script)"
    exit 1
fi

# If not given, use any zeth-tool in the path or a default location.
if [ "${ZETH_TOOL}" == "" ] ; then
    if (which zeth-tool) ; then
        ZETH_TOOL=`which zeth-tool`
    else
        ZETH_TOOL=./zeth_tool/zeth-tool
    fi
fi

PK=${DATA_DIR}/${CIRCUIT}_pk.bin
VK=${DATA_DIR}/${CIRCUIT}_vk.bin
ASSIGNMENT=${DATA_DIR}/${CIRCUIT}_assignment.bin
PRIMARY_INPUT=${DATA_DIR}/${CIRCUIT}_primary.bin

if [ "$1" == "" ] ; then
    echo Usage: $0 '<tag>'
    exit 1
fi
TAG=$1

set -e
set -x

${ZETH_TOOL} prove --profile ${PK} ${ASSIGNMENT} proof.bin > ${CIRCUIT}_${TAG}_proof_1.txt
${ZETH_TOOL} verify ${VK} ${PRIMARY_INPUT} proof.bin
${ZETH_TOOL} prove --profile ${PK} ${ASSIGNMENT} proof.bin > ${CIRCUIT}_${TAG}_proof_2.txt
${ZETH_TOOL} verify ${VK} ${PRIMARY_INPUT} proof.bin
${ZETH_TOOL} prove --profile ${PK} ${ASSIGNMENT} proof.bin > ${CIRCUIT}_${TAG}_proof_3.txt
${ZETH_TOOL} verify ${VK} ${PRIMARY_INPUT} proof.bin
