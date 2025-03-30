#!/bin/bash

# Logs the full command used to invoke the script, including all arguments.
invocation_command=$(basename "$0")

set -euo pipefail

# General script configuration ======================================================================================================================

log_level="NOTICE"                            # Logging level (EMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFO, DEBUG)
verbose=true                                  # true = also print to console
logfile="/var/log/nsupdate_static.log"        # Log file path

required_packages=(
    bind9-dnsutils
    curl
)

# Individual use case configuration =================================================================================================================
keyfile=""                    # -k, --key <string>

interactive=false             # -i. --interactive (flag)
ipv4_only=false               # -4, --ipv4 (flag)
ipv6_only=false               # -6, --ipv6 (flag)
tcp_only=true                 # -t, --tcp (flag)
port=""                       # --port <integer>

nsupdate_mode="update"        # --mode [add, update, delete]

nsupdate_server=""            # --server <string>
nsupdate_zone=""              # --zone <string>
nsupdate_domain=""            # --domain <string>
nsupdate_ttl=""               # --ttl <integer>
nsupdate_class=""             # --class <string>
nsupdate_type=""              # --type <string>
nsupdate_data=""              # --data <string>

                              # -p, --public (flag für public ipv4) | public_ipv4="$(curl -sS -4 ifconfig.me 2>/dev/null)"

# In-script TSIG key ================================================================================================================================
tsig_file() {
    tsig_temp_file=$(mktemp /tmp/keyfile.XXXXXX)
    chmod 600 "$tsig_temp_file"
    log_message "DEBUG" "Temporary TSIG key file created: $tsig_temp_file"

# Enter after - cat <<EOF > "$tsig_temp_file" - the TSIG key -------------------------------- <
cat <<EOF > "$tsig_temp_file"
key "sample" {
        algorithm hmac-sha256;
        secret "W63dd/63iP0ZqTRCGyCXg+h5XsVGjJRMEr79CSw997U=";
};

EOF

    keyfile="$tsig_temp_file"
}

# Logging ===========================================================================================================================================

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

# Helppage ==========================================================================================================================================

helppage() {
cat <<EOF
================================================================================
 NSUPDATE STATIC – Help Overview
================================================================================

This script is statically configured to perform DNS updates using nsupdate.
All configuration (TSIG key and update instructions) is defined directly in the script.

--------------------------------------------------------------------------------
 TSIG Key Example (insert directly after cat <<EOF > "\$tsig_temp_file")
--------------------------------------------------------------------------------

key "sample" {
    algorithm hmac-sha256;
    secret "knAG32FwSKzWZ9CyALGSKU0PiRIb6gHSbZcc6vTjFGo=";
}

Generate with:
  tsig-keygen sample

--------------------------------------------------------------------------------
 Update File Examples (insert directly after cat <<EOF > "\$update_temp_file")
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
update add test.example.ch 300 IN A $public_ipv4

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

# cleanup ===========================================================================================================================================

cleanup() {
    log_message "INFO" "Cleanup started"
    rm -f "$tsig_temp_file"
    rm -f "$update_temp_file"
    log_message "DEBUG" "Temporary files deleted"
}

trap cleanup EXIT

# requirements ======================================================================================================================================

check_required_packages() {
    local missing_packages=()

    for pkg in "${required_packages[@]}"; do
        if ! dpkg -s "$pkg" &> /dev/null; then
            missing_packages+=("$pkg")
            log_message "WARNING" "Package not installed: $pkg"
        else
            log_message "DEBUG" "Package found: $pkg"
        fi
    done

    if [ ${#missing_packages[@]} -ne 0 ]; then
        log_message "ERROR" "Missing ${#missing_packages[@]} required package(s):"
        for pkg in "${missing_packages[@]}"; do
            log_message "ERROR" "  - $pkg"
        done
        exit 1
    fi

    log_message "INFO" "All required packages are installed."
}

# arguments parser ==================================================================================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                if [[ "$verbose" == "true" ]]; then
                    helppage
                fi
                log_message "DEBUG" "Helppage is called"
                exit 0
                ;;
            # Langoptionen mit Werten
            -k|--key)
                keyfile="$2"
                log_message "DEBUG" "Using keyfile: $keyfile"
                shift 2
                ;;
            --port)
                port="$2"
                log_message "DEBUG" "Using port: $port"
                shift 2
                ;;
            --mode)
                case "$2" in
                    add)
                        nsupdate_mode="add"
                        log_message "DEBUG" "Using nsupdate mode: $nsupdate_mode"
                        ;;
                    update)
                        nsupdate_mode="update"
                        log_message "DEBUG" "Using nsupdate mode: $nsupdate_mode"
                        ;;
                    delete)
                        nsupdate_mode="delete"
                        log_message "DEBUG" "Using nsupdate mode: $nsupdate_mode"
                        ;;
                    *)
                        log_message "ERROR" "Invalid mode: $2"
                        if [[ "$verbose" == "true" ]]; then
                            helppage
                        fi
                        exit 1
                        ;;
                esac
                shift 2
                ;;
            --add)
                nsupdate_mode="add"
                log_message "DEBUG" "Using nsupdate mode: $nsupdate_mode"
                shift
                ;;
            --update)
                nsupdate_mode="update"
                log_message "DEBUG" "Using nsupdate mode: $nsupdate_mode"
                shift
                ;;
            --delete)
                nsupdate_mode="delete"
                log_message "DEBUG" "Using nsupdate mode: $nsupdate_mode"
                shift
                ;;
            --server)
                nsupdate_server="$2"
                shift 2
                ;;
            --zone)
                nsupdate_zone="$2"
                shift 2
                ;;
            --domain)
                nsupdate_domain="$2"
                shift 2
                ;;
            --ttl)
                nsupdate_ttl="$2"
                shift 2
                ;;
            --class)
                nsupdate_class="$2"
                shift 2
                ;;
            --type)
                nsupdate_type="$2"
                shift 2
                ;;
            --data)
                nsupdate_data="$2"
                shift 2
                ;;
            -p|--public)
                nsupdate_data="$(curl -sS -4 ifconfig.me 2>/dev/null)"
                shift
                ;;
            # Kombinierte Einzel-Flags wie -it4p
            -[i46tp]*)
                arg="${1:1}"  # alles nach dem ersten "-"
                for (( i=0; i<${#arg}; i++ )); do
                    flag="${arg:$i:1}"
                    case "$flag" in
                        i) interactive=true ;;
                        4) ipv4_only=true ;;
                        6) ipv6_only=true ;;
                        t) tcp_only=true ;;
                        p) nsupdate_data="$(curl -sS -4 ifconfig.me 2>/dev/null)" ;;
                        *)
                            log_message "ERROR" "Unknown short option: -$flag"
                            if [[ "$verbose" == "true" ]]; then
                                helppage
                            fi
                            exit 1
                            ;;
                    esac
                done
                shift
                ;;
            -*)
                echo "Unknown option: $1" >&2
                if [[ "$verbose" == "true" ]]; then
                    helppage
                fi
                exit 1
                ;;
            *)
                break
                ;;
        esac
    done
}

# variable check ====================================================================================================================================

validate_variables() {
    local invalid_variables=0

    if [[ -n "$keyfile" ]]; then
    tsig_file
    log_message "NOTICE" "No keyfile value defined. Use the in-script tsig key."

        if [[ -f "$keyfile" ]]; then
            if grep -qE 'key\s+"(sample|test|example)"\s*{' "$keyfile"; then
                log_message "WARNING" "The keyfile '$keyfile' uses a placeholder key name (sample/test/example). This should be replaced with a production TSIG key."
            elif ! grep -qE 'key\s+".+"\s*{\s*algorithm\s+hmac-sha(|256|512);\s*secret\s+"[^"]+";\s*};' "$keyfile"; then
                invalid_variables+=1
                log_message "ERROR" "The keyfile '$keyfile' does not contain a valid TSIG key block."
            else
                log_message "DEBUG" "Valid TSIG key detected in keyfile '$keyfile'."
            fi
        else
            invalid_variables+=1
            log_message "ERROR" "Keyfile '$keyfile' does not exist."

        fi
    fi

    if [[ "$nsupdate_mode" != "add" && "$nsupdate_mode" != "update" && "$nsupdate_mode" != "delete" ]]; then
        invalid_variables+=1
        log_message "ERROR" "No valid nsupdate mode defined: $nsupdate_mode"
    fi

    if [[ -n "$nsupdate_zone" || "$nsupdate_zone" != "*.*" ]]
        invalid_variables+=1
        log_message "ERROR" "No valid domain zone defined."
    fi

    if [[ -n "$nsupdate_server" ]]
        invalid_variables+=1
        log_message "ERROR" "No valid domain zone defined."
    fi

    validate_nsupdate_server    # The server validation is too complex and is coded in a separate function.



nsupdate_domain=""            # required
nsupdate_ttl=""               # optional
nsupdate_class=""             # optional
nsupdate_type=""              # required
nsupdate_data=""              # required
}

validate_nsupdate_server() {
    if [[ -z "$nsupdate_server" ]]; then
        invalid_variables+=1
        log_message "ERROR" "No valid server defined in nsupdate_server."
        return 1
    fi

    local resolved_ip=""
    local ip_mode=""
    local ping_cmd="ping -c1"

    # Optionaler Protokoll-Stack erzwingen
    if [[ "${ipv4_only:-false}" == "true" ]]; then
        ip_mode="A"
        ping_cmd+=" -4"
    elif [[ "${ipv6_only:-false}" == "true" ]]; then
        ip_mode="AAAA"
        ping_cmd+=" -6"
    else
        ip_mode="A"
        # Kein -4/-6 → OS entscheidet
    fi

    # Prüfen ob IP oder FQDN
    if [[ "$nsupdate_server" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$nsupdate_server" =~ ^([a-fA-F0-9:]+:+)+[a-fA-F0-9]+$ ]]; then
        resolved_ip="$nsupdate_server"
        log_message "INFO" "Server is an IP address: $resolved_ip"
    else
        # DNS-Auflösung
        resolved_ip=$(dig +short "$nsupdate_server" "$ip_mode" | head -n 1)
        if [[ -z "$resolved_ip" ]]; then
            invalid_variables+=1
            log_message "ERROR" "FQDN '$nsupdate_server' could not be resolved via DNS ($ip_mode)"
            return 1
        fi
        log_message "INFO" "Resolved '$nsupdate_server' to $resolved_ip"
    fi

    # Ping-Test
    if $ping_cmd "$resolved_ip" >/dev/null 2>&1; then
        log_message "INFO" "Ping successful to $resolved_ip"
    else
        log_message "NOTICE" "Ping failed for $resolved_ip – server may be unreachable"
        invalid_variables+=1
        return 1
    fi
}

# functions =========================================================================================================================================
nsupdate_run() {
    log_message "INFO" "Starting nsupdate execution"
    NSUPDATE_OPTS=()

    if [ "${ipv4_only:-}" = "true" ]; then
        NSUPDATE_OPTS+=("-4")
        log_message "DEBUG" "Using IPv4 only"
    elif [ "${ipv6_only:-}" = "true" ]; then
        NSUPDATE_OPTS+=("-6")
        log_message "DEBUG" "Using IPv6 only"
    fi

    if [ "${tcp_only:-true}" = "true" ]; then
        NSUPDATE_OPTS+=("-v")
        log_message "DEBUG" "Forcing TCP usage"
    fi

    if [ -n "${port:-}" ]; then
        NSUPDATE_OPTS+=("-p" "$port")
        log_message "DEBUG" "Using port: $port"
    fi

    NSUPDATE_OPTS+=("-k" "$tsig_temp_file")

    log_message "INFO" "Running nsupdate with options: ${NSUPDATE_OPTS[*]}"

    local output
    output=$(nsupdate "${NSUPDATE_OPTS[@]}" < "$update_temp_file" 2>&1)
    local status=$?

    if [ $status -eq 0 ]; then
        log_message "INFO" "nsupdate completed successfully"
        log_message "INFO" "nsupdate output:\n$output"
    else
        log_message "ERROR" "nsupdate failed with exit code $status"
        log_message "ERROR" "nsupdate output:\n$output"
    fi


}

update_file() {
    # Temporary nsupdate input file
    update_temp_file=$(mktemp /tmp/update_file.XXXXXX)
    chmod 600 "$update_temp_file"
    log_message "DEBUG" "Temporary nsupdate file created: $update_temp_file"

    case $nsupdate_mode in
        add)
            cat <<EOF > "$update_temp_file"
server $nsupdate_server
zone $nsupdate_zone

prereq nxrrset $nsupdate_domain $nsupdate_type
update add $nsupdate_domain $nsupdate_ttl $nsupdate_class $nsupdate_type $nsupdate_data

send
answer
EOF
            ;;
        update)
            cat <<EOF > "$update_temp_file"
server $nsupdate_server
zone $nsupdate_zone

prereq yxrrset $nsupdate_domain $nsupdate_type
update delete $nsupdate_domain $nsupdate_type
update add $nsupdate_domain $nsupdate_ttl $nsupdate_class $nsupdate_type $nsupdate_data

send
answer
EOF
            ;;
        delete)
            cat <<EOF > "$update_temp_file"
server $nsupdate_server
zone $nsupdate_zone

prereq yxrrset $nsupdate_domain $nsupdate_type
update delete $nsupdate_domain $nsupdate_type

send
answer
EOF
            ;;
        *)
            log_message "ERROR" "Unknown nsupdate_mode: $nsupdate_mode"
            exit 1
            ;;
    esac

    # Log the full content of the temp file
    log_message "DEBUG" "nsupdate file content:\n$(cat "$update_temp_file")"
}

interactive_prompt() {

}

# Main Script =======================================================================================================================================

update_file
tsig_file
nsupdate_run
