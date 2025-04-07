#!/bin/bash

################################################################################
# NSUPDATE Dynamic – Secure dynamic DNS update script (RFC 2136)
#
# This script performs authenticated dynamic DNS record updates using `nsupdate`.
# It supports both interactive mode and CLI-based automation and uses a TSIG key
# for secure communication with the DNS server.
#
# Supported update operations:
#   - Add new DNS records (A, AAAA, CNAME, TXT, etc.)
#   - Update existing records
#   - Delete DNS records
#
# Features:
#   ✓ Interactive input wizard (`-i`)
#   ✓ Command-line flags and long options
#   ✓ IPv4-only / IPv6-only / TCP-only support
#   ✓ Auto-fetch public IPv4 address (`--public`)
#   ✓ Writes sensitive temp files only to /dev/shm (RAM)
#   ✓ Secure cleanup (shred + delete) on exit
#   ✓ Extensive logging with configurable verbosity
#
# Requirements:
#   - `bind9-dnsutils` (for nsupdate)
#   - `curl` (for public IP detection)
#
# See `--help` or `-h` for usage examples and full option reference.
################################################################################


# Logs the name of the script as it was invoked (without the path).
invocation_command=$(basename "$0")

# Enables strict error handling:
# -e: Exit immediately on any command returning a non-zero status
# -u: Treat unset variables as an error
# -o pipefail: Return the exit status of the last command in the pipeline that failed
set -euo pipefail

# General script configuration ===============================================================================

umask 077                                     # Ensure newly created files have strict permissions (owner-only access).
log_level="NOTICE"                            # Log verbosity level: EMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFO, DEBUG
verbose=true                                  # If true, log output is also printed to the console
log_file=""                                   # Custom Path to the log file

# List of required system packages. The script will verify they are installed before continuing.
required_packages=(
    bind9-dnsutils                            # Provides the 'nsupdate' tool
    curl                                      # Used to fetch public IP addresses, e.g. via ifconfig.me
)

# Individual use case configuration ==========================================================================

keyfile=""                    # Path to the TSIG key file (argument: -k, --key)

interactive=false             # Enable interactive mode (flag: -i, --interactive)
ipv4_only=false               # Force IPv4 only (flag: -4, --ipv4)
ipv6_only=false               # Force IPv6 only (flag: -6, --ipv6)
tcp_only=true                 # Use TCP instead of UDP for DNS updates (flag: -t, --tcp)
port=""                       # Optional: custom DNS port (argument: --port)

nsupdate_mode="update"        # DNS update mode: add, update, or delete (argument: --mode)

nsupdate_server=""            # Target DNS server for the update (argument: --server)
nsupdate_zone=""              # DNS zone to operate on (argument: --zone)
nsupdate_domain=""            # Fully qualified domain name for the record (argument: --domain)
nsupdate_ttl=""               # Time-To-Live for the DNS record (argument: --ttl)
nsupdate_class=""             # DNS class (e.g. IN, CH, ANY) (argument: --class)
nsupdate_type=""              # Record type (e.g. A, AAAA, TXT) (argument: --type)
nsupdate_data=""              # Record data, e.g. IP address or string (argument: --data)

nsupdate_public=false            # Public IPv4 detection (shortcut flag: -p or --public)
# Example: public_ipv4="$(curl -sS -4 ifconfig.me 2>/dev/null)"


# In-script TSIG key ================================================================================================================================
tsig_file() {
    # Create a temporary file in /dev/shm (a RAM-backed tmpfs mount).
    # This ensures the key is stored only in memory and not written to disk. NOTE: Significantly reduces the possibility of compromising the key
    tsig_temp_file=$(mktemp /dev/shm/keyfile.XXXXXX)

    # Write a static TSIG key into the temporary file.
    # NOTE: This is an example key and should be replaced in production environments.
    cat <<EOF > "$tsig_temp_file"
key "sample" {
        algorithm hmac-sha256;
        secret "W63dd/63iP0ZqTRCGyCXg+h5XsVGjJRMEr79CSw997U=";
};
EOF

    # Restrict permissions on the temporary key file to owner-only access.
    chmod 600 "$tsig_temp_file"

    # Log the location of the temporary key file for debugging.
    log_message "DEBUG" "Temporary TSIG key file created in RAM: $tsig_temp_file"

    # Set the global keyfile variable to point to the temporary file.
    keyfile="$tsig_temp_file"
}


# Logging ===========================================================================================================================================

# Ensure logfile variable is set before continuing
if [[ -z "$logfile" ]]; then
    echo "ERROR: logfile variable is not set." >&2
    exit 1
fi

# Ensure the directory where the logfile should be written is writable.
if [[ ! -w "$(dirname "$logfile")" ]]; then
    echo "ERROR: Cannot write to logfile location: $logfile" >&2
    exit 1
fi

# Logging function with full syslog-style severity level support.
# Parameters:
#   $1 - Log level (e.g. DEBUG, INFO, NOTICE, WARNING, ERROR, etc.)
#   $2 - Log message to output
log_message() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%dT%H:%M:%S%z")  # Generate a timestamp in ISO 8601 format with timezone

    # Define numeric values for log levels (based on syslog standard)
    declare -A levels=(
        [EMERGENCY]=0 [ALERT]=1 [CRITICAL]=2 [ERROR]=3
        [WARNING]=4 [NOTICE]=5 [INFO]=6 [DEBUG]=7
    )

    local min_level="${log_level:-NOTICE}"                                           # Minimum level to log (default: NOTICE)
    local log_file="${logfile:-/var/log/${log_prefix:-$(basename "$0" .sh)}.log}"    # Fallback logfile path if not set
    local is_verbose="${verbose:-false}"                                             # Whether to also print to stdout
    local function_name="${FUNCNAME[1]:-main}"                                       # Calling function's name (fallback: 'main')
    local line_number="${BASH_LINENO[0]}"                                            # Line number where the log_message was called
    local prefix="${log_prefix:-$(basename "$0")}"                                   # Default prefix is script name

    # Check if the requested log level is valid
    if [[ -z "${levels[$level]+_}" ]]; then
        echo "Invalid log level: $level" >&2
        return 1
    fi

    # Check if the configured minimum log level is valid
    if [[ -z "${levels[$min_level]+_}" ]]; then
        echo "Invalid configured log level: $min_level" >&2
        return 1
    fi

    # Only log messages that meet or exceed the configured minimum log level
    if [[ ${levels[$level]} -le ${levels[$min_level]} ]]; then
        local formatted="${timestamp} ${prefix}[${level}]: Line:${line_number} (${function_name}) ${message}"

        # Write to logfile
        echo "$formatted" >> "$log_file"

        # Optionally write to console (stdout) with color
        if [[ "$is_verbose" == true && -t 1 ]]; then
            local color=""
            case "$level" in
                DEBUG) color="\033[0;37m" ;;     # grey
                INFO) color="\033[0;32m" ;;      # green
                NOTICE) color="\033[0;36m" ;;    # cyan
                WARNING) color="\033[0;33m" ;;   # yellow
                ERROR|CRITICAL|ALERT|EMERGENCY) color="\033[0;31m" ;; # red
                *) color="\033[0m" ;;            # reset (default)
            esac
            echo -e "${color}${formatted}\033[0m"
        elif [[ "$is_verbose" == true ]]; then
            echo "$formatted"
        fi

        # Also write to stderr if level is ERROR or more severe
        if [[ ${levels[$level]} -le 3 ]]; then
            echo "$formatted" >&2
        fi
    fi
}

log_message "INFO" "Script called: $invocation_command $*"

# Helppage ==========================================================================================================================================

helppage() {

    log_message "DEBUG" "the helppage is opened"

    cat <<EOF
================================================================================
 NSUPDATE DYNAMIC – Help & Overview / Hilfe & Übersicht
================================================================================

This script performs secure DNS updates using nsupdate (RFC2136).
It can be used interactively or via CLI arguments.
Dieses Skript führt sichere DNS-Updates per RFC2136 durch (nsupdate).
Es kann interaktiv oder via CLI-Argumente gesteuert werden.

--------------------------------------------------------------------------------
 Available Options / Verfügbare Optionen
--------------------------------------------------------------------------------

 -i, --interactive               Start interactive prompt        / Starte interaktiven Modus
 -4                              Force IPv4-only                 / Erzwinge IPv4-only
 -6                              Force IPv6-only                 / Erzwinge IPv6-only
 -t                              Use TCP instead of UDP          / Verwende TCP statt UDP
 -p, --public                    Use public IPv4 (auto-fetch)    / Verwende öffentliche IPv4
 -v                              Verbose console output          / Konsolenausgabe aktivieren

 -k, --key <file>                Path to TSIG key file           / Pfad zur TSIG Key-Datei
     --log <LEVEL>              Set log level (DEBUG..EMERGENCY)/ Log-Level setzen (DEBUG–EMERGENCY)
     --mode <add|update|delete> DNS update mode                 / Modus für DNS-Update
     --server <fqdn/ip>         DNS server (FQDN or IP)         / DNS Server Adresse
     --zone <zone>              DNS zone                        / DNS Zone (z.B. example.ch.)
     --domain <fqdn>            Record FQDN or subdomains       / Vollständiger Domain-Eintrag oder Subdomain
     --ttl <seconds>            TTL (Time-To-Live)              / TTL in Sekunden
     --class <IN|ANY|CH...>     DNS class (optional)            / DNS Klasse (optional)
     --type <A|AAAA|MX...>      DNS record type                 / DNS Record Typ
     --data <value>             Record data (e.g. IP)           / Datenwert (z.B. IP)

Example:
./nsupdate.sh --add -4tp --server dns.example.ch --zone example.ch. \\
              --domain test.example.ch --ttl 3600 --class IN \\
              --type A --data 203.0.113.42 --key /etc/keyfile.key

--------------------------------------------------------------------------------
 Interactive Mode / Interaktiver Modus
--------------------------------------------------------------------------------

  ./nsupdate.sh -i

Step-by-step input of:                     / Schrittweise Eingabe von:
 → TSIG key file path or internal key      / Pfad zur Key-Datei oder interner Key
 → Operation mode (add/update/delete)      / nsupdate-Modus (add/update/delete)
 → DNS server (FQDN or IP)                 / DNS-Server (FQDN oder IP)
 → Zone (e.g. example.ch.)                 / Zone (z.B. example.ch.)
 → Domain (FQDN or Subdomain)              / Domain (FQDN oder Subdomain)
 → TTL (>= 300) (optional)                 / TTL (>= 300) (optional)
 → Class (optional)                        / Klasse (optional)
 → Type (e.g. A, TXT)                      / Typ (z.B. A, MX, TXT)
 → Data (e.g. IP or PUBLIC)                / Daten (z.B. IP oder PUBLIC)

--------------------------------------------------------------------------------
 Public IPv4 Update / Öffentliche IP automatisch setzen
--------------------------------------------------------------------------------

  ./nsupdate.sh --update --public --server dns.example.ch --zone example.ch. \\
                --domain home.example.ch --type A --ttl 600 --key /etc/tsig.key

Auto-fetches public IPv4 from ifconfig.me   / Ermittelt öffentliche IPv4 automatisch

--------------------------------------------------------------------------------
 TSIG Key Example / Beispiel für TSIG Key
--------------------------------------------------------------------------------

key "sample" {
    algorithm hmac-sha256;
    secret "W63dd/63iP0ZqTRCGyCXg+h5XsVGjJRMEr79CSw997U=";
};

Generate with:
  tsig-keygen -a hmac-sha256 sample > /etc/bind/sample.key
Generieren mit: Obigen Befehl nutzen und Keydatei speichern.

⚠ Never expose or store this key on disk unprotected!
⚠ Schlüssel nie ungeschützt speichern – verwende /dev/shm oder RAM-Disk!

--------------------------------------------------------------------------------
 Tips & Best Practices / Hinweise & Best Practices
--------------------------------------------------------------------------------

 ✓ Use fully qualified domains (FQDN)           / Verwende immer FQDNs
 ✓ Zone must end with dot (e.g. example.ch.)    / Zone muss mit Punkt enden
 ✓ TTL ≥ 300 recommended                        / TTL ≥ 300 empfohlen
 ✓ Use 'answer' in nsupdate for logging         / 'answer' aktiviert Antwort-Logging
 ✓ Ensure correct system time (TSIG uses time)  / Zeit muss korrekt sein (TSIG ist zeitbasiert)
 ✓ Use public IPv4 detection if behind NAT      / Öffentliche IP verwenden hinter NAT

--------------------------------------------------------------------------------
 Security / Sicherheit
--------------------------------------------------------------------------------

✔ Sensitive files (key, update) are stored in RAM (/dev/shm)
✔ Temporäre Dateien (Key, Update) werden nur im RAM abgelegt

✔ Automatic secure deletion on script exit
✔ Automatisches, sicheres Löschen beim Skriptende

✔ Optional in-script key usage (fallback)       / Optionaler Key im RAM (Fallback)

✔ Detailed logging with selectable log level    / Ausführliches Logging mit wählbarem Log-Level

Available log levels / Verfügbare Log-Level:

  EMERGENCY   Kritischer Systemfehler – sofortiger Abbruch
  ALERT       Sofortige Aufmerksamkeit erforderlich
  CRITICAL    Kritischer Fehler im Ablauf
  ERROR       Normale Fehler – Skript kann ggf. weiterlaufen
  WARNING     Warnung – Hinweise auf Probleme
  NOTICE      Allgemeine Hinweise auf Aktionen
  INFO        Informationsausgaben über Abläufe
  DEBUG       Detaillierte Debug-Informationen für Entwickler:innen

Logfile: $logfile
Log-Level: $log_level

================================================================================

EOF

    return 0
}

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
    rm -f "$update_temp_file"

    log_message "DEBUG" "Temporary files deleted"
}

# Register the cleanup function to run automatically on script exit (normal or error)
trap cleanup EXIT

# requirements ======================================================================================================================================

# Function to check whether all required system packages are installed.
# If any required package is missing, the script logs an error and exits.
check_required_packages() {
    local missing_packages=()

    # Loop through the list of required packages and check each one
    for pkg in "${required_packages[@]}"; do
        if ! dpkg -s "$pkg" &> /dev/null; then
            # Package not found, add to the missing list
            missing_packages+=("$pkg")
            log_message "WARNING" "Package not installed: $pkg"
        else
            # Package is installed
            log_message "DEBUG" "Package found: $pkg"
        fi
    done

    # If any required packages are missing, log the issue and exit
    if [ ${#missing_packages[@]} -ne 0 ]; then
        log_message "ERROR" "Missing ${#missing_packages[@]} required package(s):"
        for pkg in "${missing_packages[@]}"; do
            log_message "ERROR" "  - $pkg"
        done
        exit 1
    fi

    log_message "INFO" "All required packages are installed."
}

# Run the package check at startup
check_required_packages


# arguments parser ==================================================================================================================================

# Function to parse command-line arguments passed to the script.
# Supports both long and short options, including combined short flags (e.g. -4tp).
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                helppage
                log_message "DEBUG" "Helppage is called"
                exit 0
                ;;

            --log|--level)
                log_level="$2"
                log_message "INFO" "Set logging level to $log_level"
                ;;
            # Options with arguments (key-value style)
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
                # Validate mode value: must be add, update, or delete
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
                            exit 0
                        fi
                        exit 1
                        ;;
                esac
                shift 2
                ;;

            # Alternative flags for setting the mode
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

            # Configuration options
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

            # Automatically retrieve and set the public IPv4 address
            -p|--public)
                nsupdate_public=true
                shift
                ;;

            # Combined short flags (e.g. -4tpiv)
            -[46tpi]*)
                arg="${1:1}"  # Strip leading dash, iterate through each character
                for (( i=0; i<${#arg}; i++ )); do
                    flag="${arg:$i:1}"
                    case "$flag" in
                        v) verbose=true ;;                                       # Enable verbose output
                        4) ipv4_only=true ;;                                     # Force IPv4 only
                        6) ipv6_only=true ;;                                     # Force IPv6 only
                        t) tcp_only=true ;;                                      # Use TCP only
                        p) nsupdate_public=true ;;                              # Set public IP
                        i) interactive=true ;;                                   # Enable interactive mode
                        *)
                            log_message "ERROR" "Unknown short option: -$flag"
                            if [[ "$verbose" == "true" ]]; then
                                helppage
                                exit 0
                            fi
                            exit 1
                            ;;
                    esac
                done
                shift
                ;;

            # Catch any unknown options and exit
            -*)
                echo "Unknown option: $1" >&2
                if [[ "$verbose" == "true" ]]; then
                    helppage
                    exit 0
                fi
                exit 1
                ;;

            # Stop parsing if a non-option argument is encountered
            *)
                break
                ;;
        esac
    done
}

# variable check ====================================================================================================================================

# This function performs validation of all required and optional configuration variables.
# It ensures values are provided, follow the expected formats, and are usable by the script logic.
# If any variable is invalid or missing, the script will log an error and exit.
validate_variables() {
    local invalid_variables=0  # Counter to track number of invalid or missing values

    # ---------------------------------------------------------------------------------------------------------
    # Validate TSIG key file (used for authentication)
    # ---------------------------------------------------------------------------------------------------------
    if [[ -z "$keyfile" ]]; then
        # No keyfile path provided → fallback to built-in key defined in script (in-memory)
        log_message "NOTICE" "No keyfile value defined. Using in-script TSIG key."
    else
        # A keyfile was provided → check if it exists and validate its format
        if [[ -f "$keyfile" ]]; then
            # Warn if the key is a placeholder (commonly used in examples)
            if grep -qE 'key\s+"(sample|test|example)"\s*{' "$keyfile"; then
                log_message "WARNING" "The keyfile '$keyfile' uses a placeholder key name (sample/test/example). This should be replaced with a production TSIG key."
            # Check that the keyfile matches expected format: key name, algorithm, and base64 secret
            elif ! grep -qE 'key\s+".+"\s*{\s*algorithm\s+hmac-sha(|256|512);\s*secret\s+"[^"]+";\s*};' "$keyfile"; then
                invalid_variables+=1
                log_message "ERROR" "The keyfile '$keyfile' does not contain a valid TSIG key block."
            else
                log_message "DEBUG" "Valid TSIG key detected in keyfile '$keyfile'."
            fi
        else
            # Keyfile path does not point to an existing file
            invalid_variables+=1
            log_message "ERROR" "Keyfile '$keyfile' does not exist."
        fi
    fi

    # ---------------------------------------------------------------------------------------------------------
    # Validate nsupdate mode (must be one of: add, update, delete)
    # ---------------------------------------------------------------------------------------------------------
    if [[ "$nsupdate_mode" != "add" && "$nsupdate_mode" != "update" && "$nsupdate_mode" != "delete" ]]; then
        invalid_variables+=1
        log_message "ERROR" "Invalid nsupdate mode: '$nsupdate_mode'. Allowed values are: add, update, delete."
    else
        log_message "DEBUG" "Valid nsupdate mode: '$nsupdate_mode'."
    fi

    # ---------------------------------------------------------------------------------------------------------
    # Validate DNS zone (required, e.g. 'example.ch.')
    # ---------------------------------------------------------------------------------------------------------
    if [[ -z "$nsupdate_zone" || "$nsupdate_zone" == "*.*" ]]; then
        invalid_variables+=1
        log_message "ERROR" "No valid domain zone defined."
    else
        # Ensure the zone ends with a dot (fully-qualified DNS zone format)
        if [[ "$nsupdate_zone" != *"." ]]; then
            nsupdate_zone="${nsupdate_zone}."
            log_message "NOTICE" "Appended trailing dot to domain zone: '$nsupdate_zone'."
        fi
        log_message "DEBUG" "Valid domain zone: '$nsupdate_zone'."
    fi

    # ---------------------------------------------------------------------------------------------------------
    # Validate the DNS server using external helper function (checks reachability and resolves hostname)
    # ---------------------------------------------------------------------------------------------------------
    validate_nsupdate_server || invalid_variables+=1

    # ---------------------------------------------------------------------------------------------------------
    # Validate TTL (Time to Live) – only required for add/update modes
    # ---------------------------------------------------------------------------------------------------------
    if [[ "$nsupdate_mode" == "add" || "$nsupdate_mode" == "update" ]]; then
        if [[ -n "$nsupdate_ttl" ]]; then
            if [[ ! "$nsupdate_ttl" =~ ^[0-9]+$ || "$nsupdate_ttl" -le 0 ]]; then
                invalid_variables+=1
                log_message "ERROR" "Invalid TTL value: '$nsupdate_ttl'. Must be a positive integer."
            else
                log_message "DEBUG" "Valid TTL: '$nsupdate_ttl'."
            fi
        else
            log_message "DEBUG" "No TTL defined. DNS server will use default."
        fi
    else
        log_message "DEBUG" "TTL validation skipped – not required for mode: $nsupdate_mode"
    fi


    # ---------------------------------------------------------------------------------------------------------
    # Validate DNS class (optional – default is usually 'IN')
    # Only check syntax if a class was provided; otherwise, skip validation.
    # ---------------------------------------------------------------------------------------------------------
    if [[ -n "$nsupdate_class" ]]; then
        nsupdate_class="${nsupdate_class^^}"  # Convert to uppercase
        case "$nsupdate_class" in
            IN|CH|HS|NONE|ANY)
                log_message "DEBUG" "Valid DNS class: '$nsupdate_class'."
                ;;
            *)
                invalid_variables+=1
                log_message "ERROR" "Invalid DNS class: '$nsupdate_class'. Allowed values: IN, CH, HS, NONE, ANY."
                ;;
        esac
    else
        log_message "DEBUG" "No DNS class provided – using DNS server default."
    fi


    # ---------------------------------------------------------------------------------------------------------
    # Validate DNS record type – required for add/update, optional but checked if present for delete
    # ---------------------------------------------------------------------------------------------------------
    if [[ -n "$nsupdate_type" ]]; then
        nsupdate_type="${nsupdate_type^^}"  # Normalize to uppercase
        log_message "DEBUG" "Record type defined: '$nsupdate_type'."
    else
        if [[ "$nsupdate_mode" == "add" || "$nsupdate_mode" == "update" ]]; then
            invalid_variables+=1
            log_message "ERROR" "No record type defined. This value is required (e.g., A, MX, TXT...)."
        else
            log_message "DEBUG" "No record type defined – skipping check for mode: $nsupdate_mode"
        fi
    fi


    # ---------------------------------------------------------------------------------------------------------
    # Validate record data (required, e.g. IP address or string)
    # ---------------------------------------------------------------------------------------------------------
    if [[ "$nsupdate_mode" == "add" || "$nsupdate_mode" == "update" ]]; then
        if [[ "${nsupdate_public:-false}" == "true" ]]; then
            nsupdate_data="$(curl -sS -4 ifconfig.me 2>/dev/null)"
            if [[ -n "$nsupdate_data" ]]; then
                log_message "DEBUG" "Public IPv4 address fetched and set as data: $nsupdate_data"
            else
                invalid_variables+=1
                log_message "ERROR" "Failed to retrieve public IPv4 address."
            fi
        elif [[ -n "$nsupdate_data" ]]; then
            log_message "DEBUG" "Record data defined: '$nsupdate_data'."
        else
            invalid_variables+=1
            log_message "ERROR" "No record data value defined. This value is required."
        fi
    else
        log_message "DEBUG" "DNS data validation skipped – not required for mode: $nsupdate_mode"
    fi


    # ---------------------------------------------------------------------------------------------------------
    # Final check: abort if any variable was found invalid
    # ---------------------------------------------------------------------------------------------------------
    if [[ "$invalid_variables" -ne 0 ]]; then
        log_message "ERROR" "One or more variables are invalid. See logfile: $logfile"
        exit 1
    fi
}

# ============================================================================================================
# Helper function: validate the DNS server address or hostname
# Checks if the server is reachable and resolvable (IPv4/IPv6 aware)
# ============================================================================================================
validate_nsupdate_server() {
    # Ensure the DNS server variable is set
    if [[ -z "$nsupdate_server" ]]; then
        invalid_variables+=1
        log_message "ERROR" "No valid server defined in nsupdate_server."
        return 1
    fi

    local resolved_ip=""
    local ip_mode=""
    local ping_cmd="ping -c1"

    # Determine preferred address family based on user options
    if [[ "${ipv4_only:-false}" == "true" ]]; then
        ip_mode="A"          # Request IPv4 address
        ping_cmd+=" -4"      # Force ping to use IPv4
    elif [[ "${ipv6_only:-false}" == "true" ]]; then
        ip_mode="AAAA"       # Request IPv6 address
        ping_cmd+=" -6"      # Force ping to use IPv6
    else
        ip_mode="A"          # Default to IPv4 if unspecified
        # No additional ping options → system default stack
    fi

    # Check if the server is already a literal IP address (IPv4 or IPv6)
    if [[ "$nsupdate_server" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$nsupdate_server" =~ ^([a-fA-F0-9:]+:+)+[a-fA-F0-9]+$ ]]; then
        resolved_ip="$nsupdate_server"
        log_message "INFO" "Server is an IP address: $resolved_ip"
    else
        # Resolve FQDN using dig to get the corresponding IP address (A or AAAA)
        resolved_ip=$(dig +short "$nsupdate_server" "$ip_mode" | head -n 1)
        if [[ -z "$resolved_ip" ]]; then
            invalid_variables+=1
            log_message "ERROR" "FQDN '$nsupdate_server' could not be resolved via DNS ($ip_mode)"
            return 1
        fi
        log_message "INFO" "Resolved '$nsupdate_server' to $resolved_ip"
    fi

    # Attempt to ping the resolved IP to check connectivity
    if $ping_cmd "$resolved_ip" >/dev/null 2>&1; then
        log_message "INFO" "Ping successful to $resolved_ip"
    else
        log_message "NOTICE" "Ping failed for $resolved_ip – server may be unreachable"
        invalid_variables+=1
        return 1
    fi
}

# functions =========================================================================================================================================

# This function runs the `nsupdate` command with all required runtime options.
# It builds the command-line parameters based on user configuration such as IP version, TCP usage, and custom port,
# then securely executes the DNS update using the TSIG key and update instructions from the temporary file.
nsupdate_run() {
    # Log the start of the nsupdate execution
    log_message "INFO" "Starting nsupdate execution"

    # Create an empty array to hold command-line options for nsupdate
    NSUPDATE_OPTS=()

    # If IPv4-only mode is enabled, add the `-4` flag
    if [ "${ipv4_only:-}" = "true" ]; then
        NSUPDATE_OPTS+=("-4")
        log_message "DEBUG" "Using IPv4 only"

    # If IPv6-only mode is enabled, add the `-6` flag
    elif [ "${ipv6_only:-}" = "true" ]; then
        NSUPDATE_OPTS+=("-6")
        log_message "DEBUG" "Using IPv6 only"
    fi

    # Enforce TCP-only transmission with `-v` (verbose mode also forces TCP in `nsupdate`)
    if [ "${tcp_only:-}" = "true" ]; then
        NSUPDATE_OPTS+=("-v")
        log_message "DEBUG" "Forcing TCP usage"
    fi

    # If a custom DNS port is specified, append it with `-p <port>`
    if [ -n "${port:-}" ]; then
        NSUPDATE_OPTS+=("-p" "$port")
        log_message "DEBUG" "Using port: $port"
    fi

    # Always include the TSIG key for authentication via `-k <keyfile>`
    NSUPDATE_OPTS+=("-k" "$keyfile")

    # Log the final constructed nsupdate command for debugging
    log_message "INFO" "Running nsupdate with options: ${NSUPDATE_OPTS[*]}"

    # Execute the nsupdate command with the constructed options and input file
    # Redirect stderr to stdout so both can be captured and logged
    local output
    output=$(nsupdate "${NSUPDATE_OPTS[@]}" < "$update_temp_file" 2>&1)
    local status=$?

    # Check exit code and log results accordingly
    if [ $status -eq 0 ]; then
        log_message "INFO" "nsupdate completed successfully"
        log_message "INFO" "nsupdate output:\n$output"
    else
        log_message "ERROR" "nsupdate failed with exit code $status"
        log_message "ERROR" "nsupdate output:\n$output"
    fi
}


update_file() {
    # Create a temporary file in /dev/shm to hold the nsupdate command instructions.
    # Using /dev/shm (RAM) ensures the file is never written to disk, improving security.
    update_temp_file=$(mktemp /dev/shm/update_file.XXXXXX)

    # Restrict permissions: readable and writable only by the owner.
    chmod 600 "$update_temp_file"

    # Log the creation of the temporary file
    log_message "DEBUG" "Temporary nsupdate file created: $update_temp_file"

    # Generate the content of the nsupdate instruction file based on the selected operation mode
    case $nsupdate_mode in

        # ----------------------------------------------------------------------
        # Mode: add – create a new DNS record if it does not already exist
        # ----------------------------------------------------------------------
        add)
            update_add_line="update add $nsupdate_domain $nsupdate_ttl"
            [[ -n "$nsupdate_class" ]] && update_add_line+=" $nsupdate_class"
            update_add_line+=" $nsupdate_type $nsupdate_data"

            cat <<EOF > "$update_temp_file"
server $nsupdate_server
zone $nsupdate_zone

prereq nxrrset $nsupdate_domain $nsupdate_type
$update_add_line

send
answer
EOF
            ;;


        # ----------------------------------------------------------------------
        # Mode: update – replace an existing DNS record with a new one
        # ----------------------------------------------------------------------
        update)
            update_add_line="update add $nsupdate_domain $nsupdate_ttl"
            [[ -n "$nsupdate_class" ]] && update_add_line+=" $nsupdate_class"
            update_add_line+=" $nsupdate_type $nsupdate_data"

cat <<EOF > "$update_temp_file"
server $nsupdate_server
zone $nsupdate_zone

prereq yxrrset $nsupdate_domain $nsupdate_type
update delete $nsupdate_domain $nsupdate_type
$update_add_line

send
answer
EOF
            ;;

        # ----------------------------------------------------------------------
        # Mode: delete – remove an existing DNS record
        # ----------------------------------------------------------------------
        delete|del)
            if [[ -n "$nsupdate_type" ]]; then
                cat <<EOF > "$update_temp_file"
server $nsupdate_server
zone $nsupdate_zone

prereq yxrrset $nsupdate_domain $nsupdate_type
update delete $nsupdate_domain $nsupdate_type

send
answer
EOF
            else
                cat <<EOF > "$update_temp_file"
server $nsupdate_server
zone $nsupdate_zone

update delete $nsupdate_domain

send
answer
EOF
            fi
            ;;

        # ----------------------------------------------------------------------
        # Invalid mode – log error and exit
        # ----------------------------------------------------------------------
        *)
            log_message "ERROR" "Unknown nsupdate_mode: $nsupdate_mode"
            exit 1
            ;;
    esac

    # Log the full contents of the generated nsupdate file (for debugging)
    log_message "DEBUG" "nsupdate file content:\n$(cat "$update_temp_file")"
}


# This function enables an interactive mode where the user is prompted for all key parameters
# required for an nsupdate DNS modification. It builds a corresponding command-line
# and optionally runs it after confirmation.
interactive_prompt() {

    # ---------------------------------------------------------------------------------------------------------
    # Prompt user for keyfile path or choose to use in-script TSIG key
    # This interactive loop ensures a valid TSIG key is either provided by the user or defaulted to the internal one.
    # ---------------------------------------------------------------------------------------------------------
    while true; do
        # Display a bilingual prompt asking for a path to a TSIG key file.
        # The user can enter a file path or keywords like "IN-SCRIPT" to use the default key embedded in the script.
        echo "DE: Pfad zum Keyfile eingeben oder leer lassen, um den in-script Key zu verwenden:"
        read -p "EN: Enter path to keyfile or leave empty to use the in-script key: [IN-SCRIPT/path_to_keyfile] " keyfile

        # Log the raw user input (for debugging and traceability)
        log_message "DEBUG" "User input for keyfile: '$keyfile'"

        # If the provided input corresponds to a readable file, accept it as the keyfile
        if [ -f "$keyfile" ]; then
            log_message "INFO" "Valid keyfile path provided: '$keyfile'"
            break
        else
            # Normalize input: convert to lowercase and strip all non-alphabetic characters.
            # This makes it more forgiving to typos or different formats like "inSkript", "in_script", etc.
            keyfile=$(echo "$keyfile" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z]//g')

            # Evaluate if the sanitized input matches known variations of "in-script".
            case "$keyfile" in
                inscript*|inskript*|inscrit*|inscrpt*|insript*|"")
                    # If matched, fallback to the in-script TSIG key (set keyfile to empty)
                    log_message "INFO" "Using in-script key (input: '$keyfile')"
                    keyfile=""
                    break
                    ;;
                *)
                    # If input is neither a file nor a recognized keyword, notify the user and repeat the prompt
                    log_message "WARNING" "Invalid keyfile path or unrecognized input ('$keyfile'). Please try again."
                    ;;
            esac
        fi
    done


    # ---------------------------------------------------------------------------------------------------------
    # Prompt for operation mode: add, update, or delete
    # This section asks the user what kind of DNS operation they want to perform.
    # The mode determines how the nsupdate file will be constructed later.
    # ---------------------------------------------------------------------------------------------------------
    valid_modes=("add" "update" "delete")  # List of allowed operation modes

    while true; do
        # Ask the user (in German and English) what action they want to perform
        echo "DE: Den Eintrag neu angelegt, aktualisieren oder löschen?"
        read -p "EN: Create, update or delete the record? Leave empty to use default: $nsupdate_mode [add/update/delete] " nsupdate_mode

        # Convert user input to lowercase to allow case-insensitive input
        nsupdate_mode=$(echo "$nsupdate_mode" | tr '[:upper:]' '[:lower:]')

        # Check if the entered mode is one of the valid modes
        if [[ " ${valid_modes[*]} " == *" $nsupdate_mode "* ]]; then
            log_message "INFO" "Selected mode: $nsupdate_mode"
            break
        else
            # If the input is not valid, show a warning and ask again
            log_message "WARNING" "Invalid input: '$nsupdate_mode'. Expected one of: add, update, delete."
        fi
    done


    # ---------------------------------------------------------------------------------------------------------
    # Prompt for DNS server (FQDN or IP)
    # This input defines the target DNS server that will receive the dynamic update request.
    # The user can enter an IP address (IPv4/IPv6) or a fully qualified domain name (FQDN).
    # If left empty, the previously set value (if any) will be reused.
    # ---------------------------------------------------------------------------------------------------------
    default_nsupdate_server=""
    [[ -n "$nsupdate_server" ]] && default_nsupdate_server="Default: $nsupdate_server"

    echo "DE: FQDN, IPv4 oder IPv6 des gewünschten DNS Servers?"
    read -p "EN: FQDN, IPv4 or IPv6 of the desired DNS server? $default_nsupdate_server [empty for default] " temp_nsupdate_server

    # If the user provided input, override the current value
    if [[ -n "$temp_nsupdate_server" ]]; then
        nsupdate_server="$temp_nsupdate_server"
        log_message "INFO" "Custom DNS server set by user: $nsupdate_server"
    else
        # Otherwise, retain the existing value (if any)
        log_message "INFO" "No DNS server provided – using default: $nsupdate_server"
    fi


    # ---------------------------------------------------------------------------------------------------------
    # Show current technical settings (IP version, TCP, port)
    # This section displays the current configuration options that affect how nsupdate will connect.
    # The user is then asked whether they want to change any of these parameters.
    # ---------------------------------------------------------------------------------------------------------
    echo ""
    printf "%s\n" "---------------------------------------------------------------------------------------"
    printf "%-78s\n" "Overview of current default settings | Übersicht der aktuellen Default-Einstellungen"
    printf "%s\n" "---------------------------------------------------------------------------------------"
    printf "%-29s | %-20s | %-40s\n" "Setting / Einstellung" "Default / Standard" "Transmission description / Beschreibung"
    printf "%s\n" "-----------------------------|--------------------|----------------------------------------"
    printf "%-29s | %-20s | %-40s\n" "IPv4 only / Nur IPv4" "$ipv4_only" "IPv4-only enforce / erzwingen"
    printf "%-29s | %-20s | %-40s\n" "IPv6 only / Nur IPv6" "$ipv6_only" "IPv6-only enforce / erzwingen"
    printf "%-29s | %-20s | %-40s\n" "TCP only / Nur TCP" "$tcp_only" "UDP deactivate / deaktivieren"
    printf "%-29s | %-20s | %-40s\n" "Port" "${port:-(Server default)}" "DNS-Port"
    echo ""

    # Ask user if they want to change any of the above settings
    echo "DE: Möchtest du eine der Einstellungen ändern?"
    read -p "EN: Do you want to change any of the above settings? [y/N] " change_settings

    # Normalize input to lowercase and compare
    if [[ "$(echo "$change_settings" | tr '[:upper:]' '[:lower:]')" == "y" ]]; then
        log_message "INFO" "User confirmed: Settings change requested (input: '$change_settings')"

        while true; do
            # Display available options for modification
            echo ""
            echo "IPv4) Change IPv4-only setting (current: $ipv4_only)"
            echo "IPv6) Change IPv6-only setting (current: $ipv6_only)"
            echo "TCP)  Change TCP-only setting (current: $tcp_only)"
            echo "PORT) Change DNS server port (current: ${port:-(Server default)})"
            echo "EXIT) Leave settings menu."
            echo ""

            # Ask the user which setting they would like to modify
            read -p "DE: Was soll geändert werden? EN: What should be changed? [ipv4/ipv6/tcp/port/exit] " setting_choice
            setting_choice=$(echo "$setting_choice" | tr '[:upper:]' '[:lower:]')

            case "$setting_choice" in
                ipv4)
                    # Toggle the IPv4-only flag (true ↔ false)
                    ipv4_only=$([[ "$ipv4_only" == "true" ]] && echo "false" || echo "true")
                    log_message "INFO" "IPv4-only setting toggled. New value: $ipv4_only"
                    ;;

                ipv6)
                    # Toggle the IPv6-only flag (true ↔ false)
                    ipv6_only=$([[ "$ipv6_only" == "true" ]] && echo "false" || echo "true")
                    log_message "INFO" "IPv6-only setting toggled. New value: $ipv6_only"
                    ;;

                tcp)
                    # Toggle the TCP-only flag (true ↔ false)
                    tcp_only=$([[ "$tcp_only" == "true" ]] && echo "false" || echo "true")
                    log_message "INFO" "TCP-only setting toggled. New value: $tcp_only"
                    ;;

                port)
                    # Prompt user to enter a new DNS port (or leave empty to reset to default)
                    read -p "DE: Gewünschter DNS-Port? EN: Desired DNS port? (empty for default) " input_port
                    if [[ -z "$input_port" ]]; then
                        log_message "INFO" "DNS port reset to default (empty input)."
                    elif [[ "$input_port" =~ ^[0-9]+$ && "$input_port" -gt 0 ]]; then
                        port="$input_port"
                        log_message "INFO" "DNS port set to: $port"
                    else
                        log_message "WARNING" "Invalid input for port: '$input_port'. Must be a positive integer."
                    fi
                    ;;

                exit)
                    # Exit the settings loop
                    log_message "DEBUG" "Leaving settings menu."
                    break
                    ;;

                *)
                    # Catch all: unrecognized input
                    log_message "WARNING" "Unknown choice: '$setting_choice'"
                    ;;
            esac
        done
    else
        log_message "INFO" "User skipped settings change (input: '$change_settings')"
    fi


    # ---------------------------------------------------------------------------------------------------------
    # Zone (required)
    # Prompt the user for the DNS zone (e.g. example.ch.) which defines the domain scope for the update.
    # This value is required for any nsupdate operation.
    # If a value was previously set, it is offered as the default.
    # ---------------------------------------------------------------------------------------------------------
    while true; do
        # Prepare a display string for the current/default value (if available)
        local default_nsupdate_zone=""
        [[ -n "$nsupdate_zone" ]] && default_nsupdate_zone="Default: $nsupdate_zone"

        # Ask the user for input
        read -p "DE: Bitte Zone eingeben. EN: Please enter the zone. $default_nsupdate_zone [string] " input

        if [[ -n "$input" ]]; then
            # If user entered a value, use it as the new zone
            nsupdate_zone="$input"
            log_message "INFO" "Zone set to: $nsupdate_zone"
            break
        elif [[ -n "$nsupdate_zone" ]]; then
            # If user pressed Enter and a previous value exists, reuse it
            log_message "INFO" "Using default zone: $nsupdate_zone"
            break
        else
            # Neither input nor default exists → prompt again
            log_message "WARNING" "Zone is required but not provided."
            echo "DE: Zone ist erforderlich. EN: Zone is required."
        fi
    done

    # ---------------------------------------------------------------------------------------------------------
    # Domain (required)
    # Prompt the user for the fully qualified domain name (FQDN) that will be updated (e.g. host.example.ch).
    # This is the actual DNS record to be added, updated, or deleted.
    # A default is displayed if already set. Input is mandatory.
    # ---------------------------------------------------------------------------------------------------------
    while true; do
        # Prepare the default display text if a previous value exists
        default_nsupdate_domain=""
        [[ -n "$nsupdate_domain" ]] && default_nsupdate_domain="Default: $nsupdate_domain"

        # Ask the user to input the domain name (FQDN)
        read -p "DE: Bitte Domain eingeben. EN: Please enter the domain. $default_nsupdate_domain [string] " input

        if [[ -n "$input" ]]; then
            # Set user input as the new domain
            nsupdate_domain="$input"
            log_message "INFO" "Domain set to: $nsupdate_domain"
            break
        elif [[ -n "$nsupdate_domain" ]]; then
            # If no input provided but a previous value exists, reuse it
            log_message "INFO" "Using default domain: $nsupdate_domain"
            break
        else
            # No input and no default value → user must try again
            log_message "WARNING" "Domain is required but not provided."
            echo "DE: Domain ist erforderlich. EN: Domain is required."
        fi
    done


    # ---------------------------------------------------------------------------------------------------------
    # TTL (optional, with default – only required for add or update modes)
    # Time-To-Live defines how long the DNS record is cached by resolvers.
    # This input is skipped for delete mode.
    # ---------------------------------------------------------------------------------------------------------
    if [[ "$nsupdate_mode" == "add" || "$nsupdate_mode" == "update" ]]; then
        default_nsupdate_ttl=""
        [[ -n "$nsupdate_ttl" ]] && default_nsupdate_ttl="Default: $nsupdate_ttl"

        echo "DE: Bitte TTL (Time to Live) eingeben."
        read -p "EN: Please enter TTL (Time to Live). $default_nsupdate_ttl [>=300] " input

        if [[ -n "$input" ]]; then
            nsupdate_ttl="$input"
            log_message "INFO" "TTL set to: $nsupdate_ttl"
        elif [[ -z "$nsupdate_ttl" ]]; then
            log_message "INFO" "TTL not provided, using the server default"
        else
            log_message "INFO" "Using previously set TTL: $nsupdate_ttl"
        fi
    fi

    # ---------------------------------------------------------------------------------------------------------
    # DNS class (optional)
    # Defines the DNS class (typically 'IN' for Internet).
    # If not provided, the DNS server's default class will be used.
    # ---------------------------------------------------------------------------------------------------------
    default_nsupdate_class="Default: ${nsupdate_class:-Use server default}"
    echo "DE: Bitte DNS Klasse eingeben (z.B. IN). Leer lassen für Standardwert."
    read -p "EN: Please enter DNS class (e.g. IN). Leave empty to use default. $default_nsupdate_class [string]: " input

    if [[ -n "$input" ]]; then
        nsupdate_class="$input"
        log_message "INFO" "DNS class set via user input: $nsupdate_class"
    elif [[ -n "$nsupdate_class" ]]; then
        log_message "INFO" "No input provided – using existing default DNS class: $nsupdate_class"
    else
        log_message "INFO" "No DNS class defined – using server-side default"
    fi


    # ---------------------------------------------------------------------------------------------------------
    # Type (required)
    # Prompt the user to enter the DNS record type, such as A, AAAA, CNAME, TXT, etc.
    # This field is mandatory for all update operations.
    # If previously set, the value will be reused by default.
    # ---------------------------------------------------------------------------------------------------------
    while true; do
        default_nsupdate_type=""
        [[ -n "$nsupdate_type" ]] && default_nsupdate_type="Default: $nsupdate_type"

        # Ask user to input the DNS type (in bilingual format)
        echo "echo DE: Bitte gib den DNS-Typ ein (z. B. A, AAAA, CNAME etc.). Bei Löschvorgängen nur erforderlich, wenn mehrere Typen vorhanden sind."
        read -p "EN: Please enter the DNS record type (e.g. A, AAAA, CNAME, etc.). Required for deletion only if multiple types exist. $default_nsupdate_type [string] " input

        if [[ -n "$input" ]]; then
            # Set the entered value
            nsupdate_type="$input"
            log_message "INFO" "DNS type set to: $nsupdate_type"
            break
        elif [[ -n "$nsupdate_type" ]]; then
            # Use previously defined type if no new input is given
            log_message "INFO" "Using default DNS type: $nsupdate_type"
            break
        else
            if [[ "$nsupdate_mode" == "add" || "$nsupdate_mode" == "update" ]]; then
                # Missing and required → prompt again
                log_message "WARNING" "DNS type is required but not provided."
                echo "DE: DNS Typ ist erforderlich. EN: DNS type is required."
            else
                break
            fi
        fi
    done

    # ---------------------------------------------------------------------------------------------------------
    # Record data (required for add/update)
    # Asks the user to enter the value for the DNS record – e.g., an IP address, a hostname, or a string.
    # Special keyword 'PUBLIC' can be used to auto-fetch the current public IPv4.
    # Skipped entirely for delete mode.
    # ---------------------------------------------------------------------------------------------------------
    input_normalized=""

    if [[ "$nsupdate_mode" == "add" || "$nsupdate_mode" == "update" ]]; then
        while true; do
            default_nsupdate_data=""
            [[ -n "$nsupdate_data" ]] && default_nsupdate_data="Default: $nsupdate_data"

            echo "DE: Bitte IP-Adresse oder Daten eingeben (PUBLIC = öffentliche IPv4 ermitteln)."
            read -p "EN: Enter IP address or data (PUBLIC = fetch public IPv4). $default_nsupdate_data: " input

            input_normalized=$(echo "$input" | tr '[:upper:]' '[:lower:]')

            if [[ -n "$input" ]]; then
                if [[ "$input_normalized" == "public" ]]; then
                    nsupdate_data="$(curl -sS -4 ifconfig.me 2>/dev/null)"
                    if [[ -n "$nsupdate_data" ]]; then
                        log_message "INFO" "Public IPv4 address auto-detected and set: $nsupdate_data"
                        break
                    else
                        log_message "WARNING" "Failed to detect public IPv4 address. Trying again..."
                        echo "DE: Keine gültige öffentliche IP ermittelbar. EN: Could not determine public IP."
                    fi
                else
                    nsupdate_data="$input"
                    log_message "INFO" "DNS data set via user input: $nsupdate_data"
                    break
                fi
            elif [[ -n "$nsupdate_data" ]]; then
                log_message "INFO" "No input provided – using existing DNS data: $nsupdate_data"
                break
            else
                log_message "WARNING" "DNS data is required and not provided. Prompting again..."
                echo "DE: Eingabe erforderlich. EN: Input required."
            fi
        done
    fi

    # ---------------------------------------------------------------------------------------------------------
    # CLI Code composition
    # This section assembles a full command-line string based on the previously gathered parameters.
    # It mimics how the script would be called non-interactively, so the user can review or reuse it.
    # ---------------------------------------------------------------------------------------------------------
    composed_command=""

    # Add the operation mode flag (only one allowed: --add, --update, or --delete)
    case "$nsupdate_mode" in
        add) composed_command+=" --add" ;;
        update) composed_command+=" --update" ;;
        delete) composed_command+=" --delete" ;;
    esac

    # ---------------------------------------------------------------------------------------------------------
    # Compose short flags (combined into a single option like -4tp)
    # These are added based on user selection for IPv4, IPv6, TCP, or public IP mode
    # ---------------------------------------------------------------------------------------------------------
    short_flags=""
    [[ "$ipv4_only" == "true" ]] && short_flags+="4"
    [[ "$ipv6_only" == "true" ]] && short_flags+="6"
    [[ "$tcp_only" == "true" ]] && short_flags+="t"
    [[ "$input_normalized" == "public" ]] && short_flags+="p"
    [[ -n "$short_flags" ]] && composed_command+=" -$short_flags"

    # ---------------------------------------------------------------------------------------------------------
    # Append long options for all DNS-related parameters, if set
    # Each value is wrapped in double quotes to preserve special characters or spaces
    # ---------------------------------------------------------------------------------------------------------
    [[ -n "$nsupdate_server" ]] && composed_command+=" --server $nsupdate_server"
    [[ -n "$nsupdate_zone" ]] && composed_command+=" --zone $nsupdate_zone"
    [[ -n "$nsupdate_domain" ]] && composed_command+=" --domain $nsupdate_domain"
    [[ -n "$nsupdate_ttl" ]] && composed_command+=" --ttl $nsupdate_ttl"
    [[ -n "$nsupdate_class" ]] && composed_command+=" --class $nsupdate_class"
    [[ -n "$nsupdate_type" ]] && composed_command+=" --type $nsupdate_type"
    [[ "$input_normalized" != "public" && -n "$nsupdate_data" ]] && composed_command+=" --data $nsupdate_data"
    [[ -n "$keyfile" ]] && composed_command+=" --key $keyfile"

    # ---------------------------------------------------------------------------------------------------------
    # Display the fully composed command to the user for transparency
    # ---------------------------------------------------------------------------------------------------------
    echo ""
    echo "================================================================================"
    echo " Composed Command Line / Zusammengesetzte Befehlszeile"
    echo "================================================================================"
    echo ""
    echo "$(basename "$0")$composed_command"
    echo ""

    # ---------------------------------------------------------------------------------------------------------
    # Ask for user confirmation before executing the command
    # Default is "no", only explicit "y" triggers execution
    # ---------------------------------------------------------------------------------------------------------
    read -p "Soll der Code ausgeführt werden? Should the code be executed? [y/N] " run_code

    if [[ $(echo "$run_code" | tr '[:upper:]' '[:lower:]') != "y" ]]; then
        log_message "INFO" "User declined to run the generated command: $composed_command"
        exit 1
    fi


    log_message "INFO" "Running generated command: $composed_command"
}

# Main Script =======================================================================================================================================

# ---------------------------------------------------------------------------------------------------------
# Parse all command-line arguments to populate configuration variables.
# This must be called first to ensure all parameters are available for validation or interaction.
# ---------------------------------------------------------------------------------------------------------
parse_args "$@"

# ---------------------------------------------------------------------------------------------------------
# If interactive mode is enabled, launch the interactive input wizard.
# This allows the user to manually input or override values step-by-step.
# ---------------------------------------------------------------------------------------------------------
if [[ "${interactive,,}" == "true" ]]; then
    interactive_prompt
fi

# ---------------------------------------------------------------------------------------------------------
# Validate that all required variables are set correctly.
# This includes checks on TSIG key, domain, zone, record type, data, etc.
# If validation fails, the script will log an error and exit.
# ---------------------------------------------------------------------------------------------------------
validate_variables

# ---------------------------------------------------------------------------------------------------------
# Generate the update file based on selected mode (add, update, delete).
# This file contains the nsupdate instructions that will be passed to the DNS server.
# ---------------------------------------------------------------------------------------------------------
update_file

# ---------------------------------------------------------------------------------------------------------
# If no external keyfile was provided, use the in-script TSIG key.
# The function tsig_file creates a temporary keyfile in memory (/dev/shm).
# ---------------------------------------------------------------------------------------------------------
if [[ -z "$keyfile" ]]; then
    tsig_file
fi

# ---------------------------------------------------------------------------------------------------------
# Run the actual nsupdate command with the prepared update file and options.
# Logs the outcome (success or error) including full output from nsupdate.
# ---------------------------------------------------------------------------------------------------------
nsupdate_run

