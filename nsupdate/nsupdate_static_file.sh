#!/bin/bash

# =================================================================================================

# User defined variables
# Logging
log_file="/etc/bind/log/nsupdate_static_file.log"  # Path to your logfile (required!)
log_level="INFO"                                   # Minimum log level to log (default: NOTICE)
verbose=true

# Static files
static_file="${1:-/etc/bind/static_file/static.zone}"
old_static_file="${static_file}.old"

# Temporary files
temp_file_dir="/dev/shm/nsupdate_static_file"

# DNS Target Server and dig Resolver also TCP and DNSSEC flag
dns_server="localhost"
resolver="9.9.9.9"
dnssec_flag=true
tcp_flag=true
ipv6_flag=""

# ignored record types
allowed_record_types=("A" "AAAA" "CAA" "CNAME" "MX" "PTR" "SRV" "TLSA" "TXT")

# =================================================================================================

# Load external Code snippets
source <(curl -s https://raw.githubusercontent.com/Turukmoorea/bashmod_lib/refs/heads/master/log_functions/log_message.sh)                   # call: log_message "INFO" "Script started"
source <(curl -s https://raw.githubusercontent.com/Turukmoorea/bashmod_lib/refs/heads/master/check_functions/check_ipv4.sh)                  # call: is_valid_ipv4 "$address"
source <(curl -s https://raw.githubusercontent.com/Turukmoorea/bashmod_lib/refs/heads/master/check_functions/check_ipv6.sh)                  # call: is_valid_ipv6 "$address"
source <(curl -s https://raw.githubusercontent.com/Turukmoorea/bashmod_lib/refs/heads/master/check_functions/check_cidr.sh)                  # call: is_valid_cidr "<string>"
source <(curl -s https://raw.githubusercontent.com/Turukmoorea/bashmod_lib/refs/heads/master/normalize_functions/normalize_line.sh)          # call: normalize_line "$original"
source <(curl -s https://raw.githubusercontent.com/Turukmoorea/bashmod_lib/refs/heads/master/check_functions/require_file_contains_any.sh)   # call: require_file_contains_any "/etc/bind/tsig.key" "key" "tsig" "algorithm" "{" "}" ";"
source <(curl -s https://raw.githubusercontent.com/Turukmoorea/bashmod_lib/refs/heads/master/check_functions/check_natural_number.sh)        # call: is_natural_number "$value"

# Logs the name of the script as it was invoked (without the path).
log_message "INFO" "Script called: $(basename "$0") $*"

# Enables strict error handling:
# -e: Exit immediately on any command returning a non-zero status
# -u: Treat unset variables as an error
# -o pipefail: Return the exit status of the last command in the pipeline that failed
set -euo pipefail


# =================================================================================================
# Processing the input file

# --------------------------------------------------------------------------------------------------
# Function: validate_zone
# --------------------------------------------------------------------------------------------------
# Validates a given DNS zone using `dig`. This function ensures:
#   - The zone has a valid SOA record (Start of Authority)
#   - The SOA is returned in the AUTHORITY SECTION
#   - The SOA belongs to the expected zone (not a delegated parent)
#   - If DNSSEC is enabled, a valid RRSIG covering the SOA record must also exist
#
# The function dynamically builds the dig command based on user configuration:
#   - Optional DNS resolver (if $resolver is set)
#   - Optional DNSSEC flag (if $dnssec_flag == "true")
#
# Parameters:
#   $1 - zone_name (the zone to be validated)
#
# Returns:
#   0 if the zone is valid
#   1 if validation fails
# --------------------------------------------------------------------------------------------------
validate_zone() {
    local zone_name="$1"
    local dig_cmd_parts=("dig")

    # If a custom resolver is set, add it to the dig command (e.g. @9.9.9.9)
    if [[ -n "$resolver" ]]; then
        dig_cmd_parts+=("@$resolver")
    fi

    # If DNSSEC validation is enabled, add +dnssec flag to the command
    [[ "$dnssec_flag" == "true" ]] && dig_cmd_parts+=("+dnssec")

    # Add SOA query and the zone name
    dig_cmd_parts+=("SOA" "$zone_name")
    local dig_cmd="${dig_cmd_parts[*]}"

    # Log the complete dig command used
    log_message "INFO" "Validating zone '$zone_name' using: $dig_cmd"

    # Execute the dig command and capture the output
    local dig_output
    dig_output="$(eval "$dig_cmd" 2>/dev/null)"

    # If dig returns no output, the query failed or no response was received
    if [[ -z "$dig_output" ]]; then
        log_message "ERROR" "dig returned no output for zone '$zone_name'"
        return 1
    fi

    # Extract only the AUTHORITY SECTION from the output (excluding the title line)
    local auth_section
    auth_section="$(echo "$dig_output" | awk '/^;; AUTHORITY SECTION:/,/^$/' | tail -n +2)"

    # If no authority section was found, the response is incomplete or non-authoritative
    if [[ -z "$auth_section" ]]; then
        log_message "ERROR" "No AUTHORITY SECTION found in dig output for '$zone_name'"
        return 1
    fi

    # Find the first SOA record in the AUTHORITY SECTION
    local soa_line
    soa_line="$(echo "$auth_section" | grep -Ei 'IN[[:space:]]+SOA' | head -n 1)"

    # If no SOA record was found, the zone is not authoritatively defined
    if [[ -z "$soa_line" ]]; then
        log_message "ERROR" "No SOA record found in AUTHORITY SECTION for '$zone_name'"
        return 1
    fi

    # Extract the zone domain from the SOA line (the first field)
    local soa_domain
    soa_domain="$(echo "$soa_line" | awk '{print $1}' | sed 's/\\.$//')"

    # Check if the SOA domain matches the expected zone
    if [[ "$soa_domain" != "$zone_name" ]]; then
        log_message "ERROR" "SOA record belongs to '$soa_domain', not to requested zone '$zone_name'"
        return 1
    fi

    # Log success: the SOA record matches the zone
    log_message "INFO" "SOA record found and matches zone: $soa_domain"

    # If DNSSEC is enabled, ensure that a valid RRSIG for the SOA exists
    if [[ "$dnssec_flag" == "true" ]]; then
        local rrsig_line
        rrsig_line="$(echo "$dig_output" | grep -Ei "^$soa_domain[.]?[[:space:]]+[0-9]+[[:space:]]+IN[[:space:]]+RRSIG[[:space:]]+SOA")"

        # If no RRSIG is present, DNSSEC validation fails
        if [[ -z "$rrsig_line" ]]; then
            log_message "ERROR" "RRSIG for SOA not found for zone '$soa_domain' — DNSSEC check failed"
            return 1
        fi

        # Log success: RRSIG found for the SOA
        log_message "INFO" "RRSIG for SOA found and valid for zone: $soa_domain"
    fi

    # Final result: the zone is considered valid
    return 0
}

# --------------------------------------------------------------------------------------------------
# Function: parse_record_line
# --------------------------------------------------------------------------------------------------
# Parses a normalized DNS configuration line, validates its components, and writes valid records
# to a zone-specific temporary file.
#
# This function supports common DNS record types and enforces:
#   - Record type must be explicitly allowed (A, AAAA, etc.)
#   - TTL must be a valid natural number or fallback to default
#   - Class must be "IN" or omitted
#   - Domain and value fields are normalized to FQDNs where applicable
#   - Type-specific validation (e.g. valid IPv4 for A, IPv6 for AAAA)
#
# Parameters:
#   $1 - line (normalized DNS record line from config file)
#
# Behavior:
#   - Skips empty or malformed lines
#   - Logs all key operations
#   - Writes valid records to $temp_file_dir/$zone
# --------------------------------------------------------------------------------------------------
parse_record_line() {
    local line="$1"

    # Skip empty lines (redundant check for safety)
    [[ -z "$line" ]] && {
        log_message "DEBUG" "Empty line received by parse_record_line — skipping"
        return 0
    }

    log_message "DEBUG" "Processing normalized line: $line"

    # Initialize parsed record fields
    local record_domain=""
    local record_ttl=""
    local record_type=""
    local record_value=""
    local field_offset=0

    # Split the line into fields (supports up to 5 space-separated fields)
    read -r field1 field2 field3 field4 field5 <<< "$line"

    # The first field is always the record domain (FQDN or relative)
    record_domain="$field1"
    log_message "DEBUG" "Extracted domain: $record_domain"

    # Check if the second field is a valid TTL (natural number)
    if [[ "$field2" =~ ^[0-9]+$ ]]; then
        record_ttl="$field2"
        field_offset=0
        log_message "DEBUG" "Valid TTL found: $record_ttl"
    else
        record_ttl="$default_ttl"
        field_offset=1
        log_message "WARNING" "TTL missing or invalid ('$field2'), using default TTL: $record_ttl"
    fi

    # Determine class and shift fields accordingly
    local possible_class="${!((3 - field_offset))}"
    local possible_type="${!((4 - field_offset))}"
    local possible_value="${!((5 - field_offset))}"

    case "$possible_class" in
        IN|"")
            # Acceptable class — use next fields as type and value
            record_type="$possible_type"
            record_value="$possible_value"
            log_message "DEBUG" "Class: IN or omitted — continuing"
            ;;
        CH|HS|NONE|ANY)
            # Unsupported class — skip line entirely
            log_message "WARNING" "Unsupported record class '$possible_class' found — skipping line"
            return 0
            ;;
        *)
            # Class was omitted — current field is type
            record_type="$possible_class"
            record_value="$possible_type"
            log_message "DEBUG" "No class specified — interpreting '$possible_class' as record type"
            ;;
    esac

    # Ensure that the record type is one of the explicitly allowed types
    if [[ ! " ${allowed_record_types[*]} " =~ " ${record_type} " ]]; then
        log_message "WARNING" "Unsupported record type '$record_type' — skipping line"
        return 0
    fi

    log_message "DEBUG" "Parsed DNS record so far: domain='$record_domain' ttl='$record_ttl' type='$record_type' value='$record_value'"

    # Ensure domain is a valid FQDN (append current zone if needed)
    if [[ "$record_domain" != *"." ]]; then
        record_domain="${record_domain}.${zone}."
        log_message "DEBUG" "Normalized domain to FQDN: $record_domain"
    else
        log_message "DEBUG" "Domain is already FQDN: $record_domain"
    fi

    # Re-validate that TTL is a valid number (defensive double-check)
    if ! [[ "$record_ttl" =~ ^[0-9]+$ ]]; then
        log_message "WARNING" "Re-checked TTL is invalid ('$record_ttl') — skipping line"
        return 0
    fi

    # Type-specific record value validation
    case "$record_type" in
        A)
            # Validate IPv4 address
            if is_valid_ipv4 "$record_value"; then
                log_message "INFO" "Valid A record: $record_domain $record_ttl A $record_value"
            else
                log_message "WARNING" "Invalid IPv4 address for A record: $record_value — skipping line"
                return 0
            fi
            ;;
        AAAA)
            # Validate IPv6 address
            if is_valid_ipv6 "$record_value"; then
                log_message "INFO" "Valid AAAA record: $record_domain $record_ttl AAAA $record_value"
            else
                log_message "WARNING" "Invalid IPv6 address for AAAA record: $record_value — skipping line"
                return 0
            fi
            ;;
        CAA)
            # Placeholder for future CAA record validation
            log_message "DEBUG" "CAA record found — validation placeholder (not yet implemented)"
            ;;
        CNAME|PTR)
            # Normalize value to FQDN if not already
            if [[ "$record_value" != *"." ]]; then
                record_value="${record_value}.${zone}."
                log_message "DEBUG" "Normalized target FQDN for $record_type: $record_value"
            else
                log_message "DEBUG" "Target for $record_type is already FQDN: $record_value"
            fi
            ;;
        MX)
            # Placeholder for future MX record validation
            log_message "DEBUG" "MX record found — validation placeholder (not yet implemented)"
            ;;
        SRV)
            # Placeholder for future SRV record validation
            log_message "DEBUG" "SRV record found — validation placeholder (not yet implemented)"
            ;;
        TLSA)
            # Placeholder for future TLSA record validation
            log_message "DEBUG" "TLSA record found — validation placeholder (not yet implemented)"
            ;;
        TXT)
            # No structural validation — assumed quoted and syntactically correct
            log_message "DEBUG" "TXT record — no validation required (quoted content responsibility of input)"
            ;;
    esac

    # Log that the record has passed all checks
    log_message "INFO" "Record accepted: $record_domain $record_ttl $record_type $record_value"

    # Write record to zone-specific output file
    local zone_file="$temp_file_dir/$zone"
    echo "$record_domain $record_ttl $record_type $record_value" >> "$zone_file"
    log_message "DEBUG" "Record written to file: $zone_file << $record_domain $record_ttl $record_type $record_value"
}

# Ensure temp directory exists
rm -rf "$temp_file_dir"
mkdir -p "$temp_file_dir"

# Runtime variables
zone=""
tsig_key_file=""

# Read the static file line by line
while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
    # Normalize the line (remove comments, collapse whitespace)
    line="$(normalize_line "$raw_line")"

    # Skip empty lines
    [[ -z "$line" ]] && continue

    # Process line by type
    case "$line" in
        zone=*)
            zone="${line#zone=}"
            validate_zone "$zone"
            log_message "INFO" "Zone set to: $zone"
            ;;
        tsig_key_file=*)
            tsig_key_file="${line#tsig_key_file=}"

            if require_file_contains_any "$tsig_key_file" "key" "algorithm" "secret" "{" "}" ";" "};" '==";'; then
                log_message "INFO" "TSIG key file set to: $tsig_key_file"
            else
                log_message "ERROR" "Invalid TSIG key file structure: $tsig_key_file"
                exit 1
            fi
            ;;
        ttl=*)
            default_ttl="${line#ttl=}"

            if is_natural_number "$default_ttl"; then
                log_message "INFO" "Default TTL set to: $default_ttl"
            else
                log_message "ERROR" "Invalid TTL value '$default_ttl' — must be a natural number"
                exit 1
            fi
            ;;
        *)
            log_message "DEBUG" "Line queued for record parsing: $line"
            parse_record_line "$line"
            ;;
    esac
done < "$static_file"

