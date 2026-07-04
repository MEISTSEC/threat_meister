#!/bin/bash
# Wazuh - YARA active response (Linux)
# Place at: /var/ossec/active-response/bin/yara.sh
# Perms:    chmod 750 ; chown root:wazuh
#
# Triggered by FIM (syscheck) events on the monitored dropzone. Runs the lab
# YARA ruleset against the changed file and writes results to the active
# response log, which the agent forwards to the manager for decoding.
#
# NOTE: unlike the Wazuh Windows sample script, this does NOT delete matched
# files. In an analysis lab you want the sample preserved for further work.

#------------------------- Gather parameters -------------------------#
read INPUT_JSON
YARA_PATH=$(echo "$INPUT_JSON" | jq -r .parameters.extra_args[1])
YARA_RULES=$(echo "$INPUT_JSON" | jq -r .parameters.extra_args[3])
FILENAME=$(echo "$INPUT_JSON" | jq -r .parameters.alert.syscheck.path)

LOG_FILE="logs/active-responses.log"

# Wait for the file to finish being written (size stabilises).
size=0
actual_size=$(stat -c %s "${FILENAME}" 2>/dev/null || echo 0)
while [ "${size}" -ne "${actual_size}" ]; do
    sleep 1
    size=${actual_size}
    actual_size=$(stat -c %s "${FILENAME}" 2>/dev/null || echo 0)
done

#----------------------- Validate parameters -----------------------#
if [[ ! $YARA_PATH ]] || [[ ! $YARA_RULES ]]; then
    echo "wazuh-yara: ERROR - Yara active response error. Yara path and rules parameters are mandatory." >> ${LOG_FILE}
    exit 1
fi

#------------------------- Main workflow --------------------------#
yara_output="$("${YARA_PATH}"/yara -w -r "$YARA_RULES" "$FILENAME")"

if [[ $yara_output != "" ]]; then
    while read -r line; do
        echo "wazuh-yara: INFO - Scan result: $line" >> ${LOG_FILE}
    done <<< "$yara_output"
fi

exit 0;
