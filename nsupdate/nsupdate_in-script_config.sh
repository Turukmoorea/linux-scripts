#!/bin/bash

# Logs the full command used to invoke the script, including all arguments.
invocation_command=$(basename "$0")

set -euo pipefail

# General script configuration ========================================================================================

log_level="NOTICE"                            # Logging level (EMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFO, DEBUG)
verbose=true                                  # true = also print to console
logfile="/var/log/nsupdate_static.log"        # Log file path

# Individual use case configuration
IPV4_ONLY=false
IPV6_ONLY=false
TCP_ONLY=true
PORT=""
PUBLIC_IPV4="$(curl -sS -4 ifconfig.me 2>/dev/null)"

update_file() {
# Temporary nsupdate input file
    UPDATE_TEMP_FILE=$(mktemp /tmp/update_file.XXXXXX)
    chmod 600 "$UPDATE_TEMP_FILE"
    log_message "DEBUG" "Temporary nsupdate file created: $UPDATE_TEMP_FILE"

# Enter after - cat <<EOF > "$UPDATE_TEMP_FILE" - the nsupdate informations =======================
cat <<EOF > "$UPDATE_TEMP_FILE"
server dns.example.ch
zone example.ch.

prereq yxrrset test.example.ch A
update delete test.example.ch A
update add test.example 300 IN A $PUBLIC_IPV4

send
answer
EOF

    # Log the full content of the temp file
    log_message "DEBUG" "nsupdate file content:\n$(cat "$UPDATE_TEMP_FILE")"

}

# Temporary in-script TSIG key
tsig_file() {
    TSIG_TEMP_FILE=$(mktemp /tmp/keyfile.XXXXXX)
    chmod 600 "$TSIG_TEMP_FILE"
    log_message "DEBUG" "Temporary TSIG key file created: $TSIG_TEMP_FILE"

# Enter after - cat <<EOF > "$TSIG_TEMP_FILE" - the TSIG key =======================
cat <<EOF > "$TSIG_TEMP_FILE"
key "sample" {
        algorithm hmac-sha256;
        secret "W63dd/63iP0ZqTRCGyCXg+h5XsVGjJRMEr79CSw997U=";
};

EOF
}

# Logging =============================================================================================================

if [[ ! -w "$(dirname "$logfile")" ]]; then
    echo "ERROR: Cannot write to logfile location: $logfile" >&2
    exit 1
fi

# Logging function with full Syslog severity support
log_message() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%dT%H:%M:%S%z")

    declare -A levels=(
        [EMERGENCY]=0 [ALERT]=1 [CRITICAL]=2 [ERROR]=3
        [WARNING]=4 [NOTICE]=5 [INFO]=6 [DEBUG]=7
    )

    local min_level="${log_level:-NOTICE}"
    local log_file="${logfile:-/var/log/nsupdate_static.log}"
    local is_verbose="${verbose:-false}"
    local function_name="${FUNCNAME[1]:-main}"
    local line_number="${BASH_LINENO[0]}"

    if [[ -z "${levels[$level]+_}" ]]; then
        echo "Invalid log level: $level" >&2
        return 1
    fi
    if [[ -z "${levels[$min_level]+_}" ]]; then
        echo "Invalid configured log level: $min_level" >&2
        return 1
    fi

    if [[ ${levels[$level]} -le ${levels[$min_level]} ]]; then
        local formatted="${timestamp} [${level}] Line:${line_number} (${function_name}) ${message}"
        echo "$formatted" >> "$log_file"
        if [[ "$is_verbose" == true ]]; then
            echo "$formatted"
        fi
    fi
}

log_message "INFO" "Script called: $invocation_command $*"

# Helppage ============================================================================================================

helppage() {
cat <<EOF
================================================================================
 NSUPDATE STATIC – Help Overview
================================================================================

This script is statically configured to perform DNS updates using nsupdate.
All configuration (TSIG key and update instructions) is defined directly in the script.

--------------------------------------------------------------------------------
 TSIG Key Example (insert directly after cat <<EOF > "\$TSIG_TEMP_FILE")
--------------------------------------------------------------------------------

key "sample" {
    algorithm hmac-sha256;
    secret "knAG32FwSKzWZ9CyALGSKU0PiRIb6gHSbZcc6vTjFGo=";
}

Generate with:
  tsig-keygen sample

--------------------------------------------------------------------------------
 Update File Examples (insert directly after cat <<EOF > "\$UPDATE_TEMP_FILE")
--------------------------------------------------------------------------------

➤ Add a record:
---------------------
server dns.example.ch
zone example.ch.

prereq nxrrset test.example.ch A
update add test.example.ch 300 IN A 192.0.2.42

send
answer

➤ Update a record:
-------------------------
server dns.example.ch
zone example.ch.

prereq yxrrset test.example.ch A
update delete test.example.ch A
update add test.example.ch 300 IN A 198.51.100.99

send
answer

➤ Delete a record:
-------------------
server dns.example.ch
zone example.ch.

prereq yxrrset test.example.ch A
update delete test.example.ch A

send
answer

--------------------------------------------------------------------------------
 Dynamic IP Integration (optional)
--------------------------------------------------------------------------------

You can dynamically fetch your current public IPv4 and use it in the update file.

This is useful for:
  ✓ Updating dynamic DNS records with your current IP
  ✓ Adjusting firewall rules dynamically
  ✓ Automating remote access setups

---------------------

server dns.example.ch
zone example.ch.

prereq yxrrset test.example.ch A
update delete test.example.ch A
update add test.example.ch 300 IN A $PUBLIC_IPV4

send
answer

--------------------------------------------------------------------------------
 Notes
--------------------------------------------------------------------------------

⚠ Update files **must not** contain comments or unnecessary lines.
   Only valid "nsupdate" commands are allowed.

✅ The final "answer" keyword is **required** for proper logging output.

================================================================================

EOF
}


for arg in "$@"; do
    if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
        helppage
        exit 0
    fi
done

# cleanup =============================================================================================================

cleanup() {
    log_message "INFO" "Cleanup started"
    rm -f "$TSIG_TEMP_FILE"
    rm -f "$UPDATE_TEMP_FILE"
    log_message "DEBUG" "Temporary files deleted"
}

trap cleanup EXIT

nsupdate_run() {
    log_message "INFO" "Starting nsupdate execution"
    NSUPDATE_OPTS=()

    if [ "${IPV4_ONLY:-}" = "true" ]; then
        NSUPDATE_OPTS+=("-4")
        log_message "DEBUG" "Using IPv4 only"
    elif [ "${IPV6_ONLY:-}" = "true" ]; then
        NSUPDATE_OPTS+=("-6")
        log_message "DEBUG" "Using IPv6 only"
    fi

    if [ "${TCP_ONLY:-true}" = "true" ]; then
        NSUPDATE_OPTS+=("-v")
        log_message "DEBUG" "Forcing TCP usage"
    fi

    if [ -n "${PORT:-}" ]; then
        NSUPDATE_OPTS+=("-p" "$PORT")
        log_message "DEBUG" "Using port: $PORT"
    fi

    NSUPDATE_OPTS+=("-k" "$TSIG_TEMP_FILE")

    log_message "INFO" "Running nsupdate with options: ${NSUPDATE_OPTS[*]}"

    local output
    output=$(nsupdate "${NSUPDATE_OPTS[@]}" < "$UPDATE_TEMP_FILE" 2>&1)
    local status=$?

    if [ $status -eq 0 ]; then
        log_message "INFO" "nsupdate completed successfully"
        log_message "INFO" "nsupdate output:\n$output"
    else
        log_message "ERROR" "nsupdate failed with exit code $status"
        log_message "ERROR" "nsupdate output:\n$output"
    fi


}

# Main Script =========================================================================================================

update_file
tsig_file
nsupdate_run
