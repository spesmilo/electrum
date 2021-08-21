#!/usr/bin/env bash

echo "starting electrum"

# environment options
DAEMON=${DAEMON:-"1"}
SERVER_PORT=${SERVER_PORT:-"51001"}
SERVER_PROTOCOL=${SERVER_PROTOCOL:-"t"}

# check if wallet name has been provided
if [ -z "${WALLET_NAME}" ]; then
    echo "environment variable WALLET_NAME must be set"
    exit 1
fi
PARAMS="${PARAMS} -D ${WALLET_DIR}/${WALLET_NAME}"

# add alias if missing
if echo "${WALLET_NAME}" | grep -q ' '; then
    echo "environment variable WALLET_NAME must not contain spaces"
    exit 1
fi
alias ${WALLET_NAME} >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "setting alias '${WALLET_NAME}' to easily launch electrum"
    echo "alias ${WALLET_NAME}=\"electrum ${PARAMS}\"" >> ${APP_DIR}/.bashrc
fi

# add server option if provided
if [ -n "${SERVER_HOST}" ]; then
    if [ "${SERVER_PROTOCOL}" != "t" ] && [ "${SERVER_PROTOCOL}" != "s" ]; then
        echo "invalid server protocol. options: t (insecure) or s (secure)"
    fi
    ELECTRUMX_ADDR=${SERVER_HOST}:${SERVER_PORT}:${SERVER_PROTOCOL}
    PARAMS="${PARAMS} --server ${ELECTRUMX_ADDR}"
fi

# create execution command
MODE="daemon"
[ "${DAEMON}" == "0" ] && MODE="gui"
CMD="${APP_DIR}/.local/bin/electrum ${MODE} ${PARAMS}"

# start service
echo ${CMD}
${CMD}
