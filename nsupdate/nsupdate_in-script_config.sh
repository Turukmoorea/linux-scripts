#!/bin/bash

# Logs the full command used to invoke the script, including all arguments.
INVOCATION_COMMAND=$(basename "$0")

set -euo pipefail

# General script configuration ========================================================================================

umask 077                                     # Ensure newly created files have strict permissions (owner-only access).
log_level="NOTICE"                            # Logging level (EMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFO, DEBUG)
verbose=true                                  # true = also print to console
logfile="/var/log/nsupdate_static.log"        # Log file path

# Individual use case configuration
IPV4_ONLY=true
IPV6_ONLY=false
TCP_ONLY=true
PORT=""
PUBLIC_IPV4="$(curl -sS -4 ifconfig.me 2>/dev/null)"

UPDATE_TEMP_FILE=""
TSIG_TEMP_FILE=""

update_file() {
# Temporary nsupdate input file
    UPDATE_TEMP_FILE=$(mktemp /dev/shm/update_file.XXXXXX)
    chmod 600 "$UPDATE_TEMP_FILE"
    log_message "DEBUG" "Temporary nsupdate file created: $UPDATE_TEMP_FILE"

# Enter after - cat <<EOF > "$UPDATE_TEMP_FILE" - the nsupdate informations =======================
cat <<EOF > "$UPDATE_TEMP_FILE"
server dns.example.ch
zone example.ch.

update delete test.example.ch A
update add test.example 300 IN A $PUBLIC_IPV4

send
answer
EOF

    # Log the full content of the temp file
    log_message "DEBUG" "nsupdate file content:\n$(cat "$UPDATE_TEMP_FILE")"

}

# In-script TSIG key ================================================================================================================================
tsig_file() {
    # Create a temporary file in /dev/shm (a RAM-backed tmpfs mount).
    # This ensures the key is stored only in memory and not written to disk. NOTE: Significantly reduces the possibility of compromising the key
    TSIG_TEMP_FILE=$(mktemp /dev/shm/keyfile.XXXXXX)

    # Write a static TSIG key into the temporary file.
    # NOTE: This is an example key and should be replaced in production environments.
    cat <<EOF > "$TSIG_TEMP_FILE"
key "ddns_TMBB-FW01" {
        algorithm hmac-sha512;
        secret "gd8RsyFLrx10cS+/7dB+BmEoN5JFcx2JSm5TeLgclyIqRnWkHUp796s1ZY/th9x5iAZNGTd2hJzDhVcw0u3Q9g==";
};

EOF

    # Restrict permissions on the temporary key file to owner-only access.
    chmod 600 "$TSIG_TEMP_FILE"

    # Log the location of the temporary key file for debugging.
    log_message "DEBUG" "Temporary TSIG key file created in RAM: $TSIG_TEMP_FILE"

    # Set the global keyfile variable to point to the temporary file.
    keyfile="$TSIG_TEMP_FILE"
}

# Logging ===========================================================================================================================================

source <(curl -s https://raw.githubusercontent.com/Turukmoorea/bashmod_lib/refs/heads/master/log_functions/log_message.sh)

log_message "INFO" "Script called: $INVOCATION_COMMAND $*"

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

update add test.example.ch 300 IN A 192.0.2.42

send
answer

➤ Update a record:
-------------------------
server dns.example.ch
zone example.ch.

update delete test.example.ch A
update add test.example.ch 300 IN A 198.51.100.99

send
answer

➤ Delete a record:
-------------------
server dns.example.ch
zone example.ch.

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

# cleanup ===========================================================================================================================================

# Define a cleanup function that will be executed when the script exits.
# It securely removes sensitive temporary files such as the TSIG key and the nsupdate instruction file.
cleanup() {
    log_message "INFO" "Cleanup started"

    # Securely delete the TSIG key file using 'shred':
    # -u: remove the file after overwriting
    # --force: ignore permissions
    # --zero: overwrite with zeros as final pass
    # --remove=wipesync: ensure syncing file system metadata after deletion
    shred -u --force --zero --remove=wipesync "$keyfile"

    # Delete the temporary nsupdate instruction file
    rm -f "$UPDATE_TEMP_FILE"

    log_message "DEBUG" "Temporary files deleted"
}

# Register the cleanup function to run automatically on script exit (normal or error)
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

    if [ "${TCP_ONLY:-}" = "true" ]; then
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
