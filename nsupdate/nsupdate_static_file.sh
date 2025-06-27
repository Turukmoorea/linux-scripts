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
dns_server="localhost" # set: "string" (required)
resolver="9.9.9.9"     # set: "string" or ""
dnssec_flag=true       # set: true or false
tcp_flag=true          # set: true or false
ipv6_flag=""           # set: true, false or "" (if you want to use the default settings of the device)

# ignored record types
allowed_record_types=("A" "AAAA" "CAA" "CNAME" "MX" "PTR" "SRV" "TLSA" "TXT")   # Never set SOA and NS, they are server-critical and should not be set with this script.

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


# --------------------------------------------------------------------------------------------------
# Function: validate_zone
# --------------------------------------------------------------------------------------------------
# Purpose:
#   Validates a given DNS zone using `dig`.
#
# What it does:
#   - Ensures the zone has a valid SOA (Start of Authority) record.
#   - Ensures the SOA is present in the AUTHORITY SECTION.
#   - Confirms the SOA matches the expected zone name.
#   - If DNSSEC is enabled, confirms a valid RRSIG covers the SOA record.
#
# How it works:
#   - Dynamically builds the `dig` command with optional resolver and DNSSEC flags.
#   - Sanitizes the zone name (removes duplicate dots, ensures single trailing dot).
#   - Executes `dig` and parses its output step by step.
#   - Returns 0 if validation passes, 1 otherwise.
#
# Parameters:
#   $1 - zone_name : The zone to validate.
#
# Returns:
#   0 = zone is valid
#   1 = validation failed
# --------------------------------------------------------------------------------------------------
validate_zone() {
    local zone_name="$1"
    local dig_cmd_parts=("dig")

    # ----------------------------------------------------------------------
    # Sanitize zone name: collapse multiple dots, trim trailing dots,
    # then ensure exactly one trailing dot.
    # ----------------------------------------------------------------------
    zone_name="$(echo "$zone_name" | sed -E 's/[.]+/./g' | sed -E 's/[.]$//')"
    zone_name="${zone_name}."

    # ----------------------------------------------------------------------
    # Add custom resolver if configured.
    # E.g., dig @9.9.9.9
    # ----------------------------------------------------------------------
    if [[ -n "$resolver" ]]; then
        dig_cmd_parts+=("@$resolver")
    fi

    # ----------------------------------------------------------------------
    # Add DNSSEC flag if DNSSEC validation is enabled.
    # ----------------------------------------------------------------------
    [[ "$dnssec_flag" == "true" ]] && dig_cmd_parts+=("+dnssec")

    # ----------------------------------------------------------------------
    # Build the final dig command: dig [resolver] [dnssec] SOA zone
    # ----------------------------------------------------------------------
    dig_cmd_parts+=("SOA" "$zone_name")
    local dig_cmd="${dig_cmd_parts[*]}"

    # Log the exact dig command being run
    log_message "INFO" "Validating zone '$zone_name' using: $dig_cmd"

    # ----------------------------------------------------------------------
    # Execute dig and capture output (stderr suppressed)
    # ----------------------------------------------------------------------
    local dig_output
    dig_output="$(eval "$dig_cmd" 2>/dev/null)"

    # ----------------------------------------------------------------------
    # If dig output is empty, the query failed or no response received.
    # ----------------------------------------------------------------------
    if [[ -z "$dig_output" ]]; then
        log_message "ERROR" "dig returned no output for zone '$zone_name'"
        return 1
    fi

    # ----------------------------------------------------------------------
    # Extract AUTHORITY SECTION only, skip the header line.
    # ----------------------------------------------------------------------
    local auth_section
    auth_section="$(echo "$dig_output" | awk '/^;; AUTHORITY SECTION:/,/^$/' | tail -n +2)"

    if [[ -z "$auth_section" ]]; then
        log_message "ERROR" "No AUTHORITY SECTION found in dig output for '$zone_name'"
        return 1
    fi

    # ----------------------------------------------------------------------
    # Find the first SOA record in the AUTHORITY SECTION.
    # ----------------------------------------------------------------------
    local soa_line
    soa_line="$(echo "$auth_section" | grep -Ei 'IN[[:space:]]+SOA' | head -n 1)"

    if [[ -z "$soa_line" ]]; then
        log_message "ERROR" "No SOA record found in AUTHORITY SECTION for '$zone_name'"
        return 1
    fi

    # ----------------------------------------------------------------------
    # Extract the domain from the SOA line and compare with expected zone.
    # ----------------------------------------------------------------------
    local soa_domain
    soa_domain="$(echo "$soa_line" | awk '{print $1}' | sed 's/\.$//')"

    if [[ "$soa_domain" != "$zone_name" ]]; then
        log_message "ERROR" "SOA record belongs to '$soa_domain', not to requested zone '$zone_name'"
        return 1
    fi

    log_message "INFO" "SOA record found and matches zone: $soa_domain"

    # ----------------------------------------------------------------------
    # If DNSSEC is enabled, ensure a valid RRSIG for the SOA exists.
    # ----------------------------------------------------------------------
    if [[ "$dnssec_flag" == "true" ]]; then
        local rrsig_line
        rrsig_line="$(echo "$dig_output" | grep -Ei "^$soa_domain[.]?[[:space:]]+[0-9]+[[:space:]]+IN[[:space:]]+RRSIG[[:space:]]+SOA")"

        if [[ -z "$rrsig_line" ]]; then
            log_message "ERROR" "RRSIG for SOA not found for zone '$soa_domain' — DNSSEC check failed"
            return 1
        fi

        log_message "INFO" "RRSIG for SOA found and valid for zone: $soa_domain"
    fi

    # ----------------------------------------------------------------------
    # All checks passed: zone is valid
    # ----------------------------------------------------------------------
    return 0
}


# --------------------------------------------------------------------------------------------------
# Function: parse_record_line
# --------------------------------------------------------------------------------------------------
# Purpose:
#   Parses a single normalized DNS record line from the static file,
#   validates its structure and content, normalizes domains/values to FQDN,
#   and writes valid records to the corresponding zone-specific tempfile.
#
# Supports:
#   - Record types: A, AAAA, CAA, CNAME, MX, PTR, SRV, TLSA, TXT
#   - TTL validation and fallback
#   - Optional record class (must be IN or empty)
#   - FQDN normalization (single trailing dot, no duplicate dots)
#
# Parameters:
#   $1 - line : the normalized DNS record line
#
# Behavior:
#   1. Skip empty or malformed lines.
#   2. Parse fields: domain, TTL, class, type, value.
#   3. Validate record type and type-specific value.
#   4. Normalize domain and value to valid FQDNs.
#   5. Write the record to the correct zone tempfile.
#
# --------------------------------------------------------------------------------------------------
parse_record_line() {
    local line="$1"

    # ------------------------------------------------------------------------
    # Defensive: Skip if line is empty
    # ------------------------------------------------------------------------
    [[ -z "$line" ]] && {
        log_message "DEBUG" "Empty line received by parse_record_line — skipping"
        return 0
    }

    log_message "DEBUG" "Processing normalized line: $line"

    # ------------------------------------------------------------------------
    # Initialize parsed record fields
    # ------------------------------------------------------------------------
    local record_domain=""
    local record_ttl=""
    local record_type=""
    local record_value=""
    local field_offset=0

    # ------------------------------------------------------------------------
    # Split the line into up to 5 fields (domain, ttl, class, type, value)
    # ------------------------------------------------------------------------
    read -r field1 field2 field3 field4 field5 <<< "$line"

    # The first field is always the record domain
    record_domain="$field1"
    log_message "DEBUG" "Extracted domain: $record_domain"

    # ------------------------------------------------------------------------
    # Check if the second field is a valid TTL (must be numeric)
    # If not, use the default TTL and shift field positions by +1.
    # ------------------------------------------------------------------------
    if [[ "$field2" =~ ^[0-9]+$ ]]; then
        record_ttl="$field2"
        field_offset=0
        log_message "DEBUG" "Valid TTL found: $record_ttl"
    else
        record_ttl="$default_ttl"
        field_offset=1
        log_message "WARNING" "TTL missing or invalid ('$field2'), using default TTL: $record_ttl"
    fi

    # ------------------------------------------------------------------------
    # Determine record class and adjust type/value fields accordingly
    # Only 'IN' or empty class are supported
    # ------------------------------------------------------------------------
    local possible_class="${!((3 - field_offset))}"
    local possible_type="${!((4 - field_offset))}"
    local possible_value="${!((5 - field_offset))}"

    case "$possible_class" in
        IN|"")
            # Valid class → use next fields as type and value
            record_type="$possible_type"
            record_value="$possible_value"
            log_message "DEBUG" "Class: IN or omitted — continuing"
            ;;
        CH|HS|NONE|ANY)
            # Unsupported DNS classes → skip line
            log_message "WARNING" "Unsupported record class '$possible_class' found — skipping line"
            return 0
            ;;
        *)
            # No explicit class → current field must be type
            record_type="$possible_class"
            record_value="$possible_type"
            log_message "DEBUG" "No class specified — interpreting '$possible_class' as record type"
            ;;
    esac

    # ------------------------------------------------------------------------
    # Verify record type is explicitly allowed
    # ------------------------------------------------------------------------
    if [[ ! " ${allowed_record_types[*]} " =~ " ${record_type} " ]]; then
        log_message "WARNING" "Unsupported record type '$record_type' — skipping line"
        return 0
    fi

    log_message "DEBUG" "Parsed record so far: domain='$record_domain' ttl='$record_ttl' type='$record_type' value='$record_value'"

    # ------------------------------------------------------------------------
    # Normalize domain: ensure valid FQDN with single trailing dot
    # Append current zone if not already absolute.
    # ------------------------------------------------------------------------
    if [[ "$record_domain" != *"." ]]; then
        record_domain="${record_domain}.${zone}"
        log_message "DEBUG" "Domain missing dot — appended zone: $record_domain"
    fi

    # Remove multiple consecutive dots, strip trailing, add single trailing dot
    record_domain="$(echo "$record_domain" | sed -E 's/[.]+/./g' | sed -E 's/[.]$//')."
    log_message "DEBUG" "Normalized domain to FQDN: $record_domain"

    # ------------------------------------------------------------------------
    # Defensive: TTL must be valid number
    # ------------------------------------------------------------------------
    if ! [[ "$record_ttl" =~ ^[0-9]+$ ]]; then
        log_message "WARNING" "Re-checked TTL is invalid ('$record_ttl') — skipping line"
        return 0
    fi

    # ------------------------------------------------------------------------
    # Type-specific record value validation and FQDN normalization
    # ------------------------------------------------------------------------
    case "$record_type" in
        A)
            # A record must contain valid IPv4 address
            if is_valid_ipv4 "$record_value"; then
                log_message "INFO" "Valid A record: $record_domain $record_ttl A $record_value"
            else
                log_message "WARNING" "Invalid IPv4 address for A record: $record_value — skipping line"
                return 0
            fi
            ;;
        AAAA)
            # AAAA record must contain valid IPv6 address
            if is_valid_ipv6 "$record_value"; then
                log_message "INFO" "Valid AAAA record: $record_domain $record_ttl AAAA $record_value"
            else
                log_message "WARNING" "Invalid IPv6 address for AAAA record: $record_value — skipping line"
                return 0
            fi
            ;;
        CAA)
            # Placeholder: more detailed validation can be added later
            log_message "DEBUG" "CAA record found — validation placeholder"
            ;;
        CNAME|PTR)
            # CNAME/PTR: normalize value to valid FQDN
            if [[ "$record_value" != *"." ]]; then
                record_value="${record_value}.${zone}"
                log_message "DEBUG" "Target missing dot — appended zone: $record_value"
            else
                log_message "DEBUG" "Target already FQDN: $record_value"
            fi

            # Sanitize value: collapse multiple dots and ensure single trailing dot
            record_value="$(echo "$record_value" | sed -E 's/[.]+/./g' | sed -E 's/[.]$//')."
            log_message "DEBUG" "Sanitized target FQDN for $record_type: $record_value"
            ;;
        MX)
            # MX: add MX-specific checks here if needed
            log_message "DEBUG" "MX record found — validation placeholder"
            ;;
        SRV)
            # SRV: add SRV-specific checks here if needed
            log_message "DEBUG" "SRV record found — validation placeholder"
            ;;
        TLSA)
            # TLSA: add TLSA-specific checks here if needed
            log_message "DEBUG" "TLSA record found — validation placeholder"
            ;;
        TXT)
            # TXT records: assume quoted and valid syntax
            log_message "DEBUG" "TXT record — no structural validation"
            ;;
    esac

    # ------------------------------------------------------------------------
    # Write validated record to zone-specific output file
    # ------------------------------------------------------------------------
    local zone_file="$temp_file_dir/$zone"
    echo "$record_domain $record_ttl $record_type $record_value" >> "$zone_file"
    log_message "INFO" "Record accepted: $record_domain $record_ttl $record_type $record_value"
    log_message "DEBUG" "Record written to file: $zone_file << $record_domain $record_ttl $record_type $record_value"
}

# --------------------------------------------------------------------------------------------------
# Function: write_tempfile_global_variables
# --------------------------------------------------------------------------------------------------
# Purpose:
#   Appends a single global variable declaration (e.g., zone or tsig_key_file)
#   to the current zone-specific tempfile. This ensures that any change
#   to zone or TSIG context is recorded in the correct file.
#
# Usage:
#   write_tempfile_global_variables <var_name> <var_value>
#   Example: write_tempfile_global_variables "zone" "example.com."
#
# Notes:
#   - This function simply appends the variable to the end of the tempfile.
#   - The calling logic must handle when to write updated variables by
#     using change flags (zone_changed, tsig_changed).
#   - No deduplication is done here — the processing logic must handle context correctly.
#
# Parameters:
#   $1 - var_name  : Name of the variable to write (e.g., "zone", "tsig_key_file")
#   $2 - var_value : Value of the variable
#
# Behavior:
#   - Builds the variable line: name="value"
#   - Appends it to the zone-specific tempfile.
#   - Logs the operation for traceability.
# --------------------------------------------------------------------------------------------------
write_tempfile_global_variables() {
    local var_name="$1"         # The name of the variable, e.g. zone or tsig_key_file
    local var_value="$2"        # The new value to write
    local zone_file="$temp_file_dir/$zone"  # Target tempfile for the current zone

    # Write the variable line in the form: var_name="var_value"
    echo "${var_name}=\"${var_value}\"" >> "$zone_file"

    # Log for traceability
    log_message "DEBUG" "Inserted variable '${var_name}=\"${var_value}\"' into tempfile: $zone_file"
}

# =================================================================================================
# First Main Script
# =================================================================================================
#
# This first main block processes the static input file line by line.
# It handles global variables like zone, tsig_key_file and ttl,
# and tracks when these variables change so that updated context headers
# can be written to the zone-specific tempfiles.
#
# The goal is to always keep each record in the correct zone context,
# with the correct TSIG key. This avoids accidentally mixing records
# from different zones or using the wrong TSIG.
#
# --------------------------------------------------------------------------------------------------

# Make sure the temp working directory is fresh for this run.
rm -rf "$temp_file_dir"
mkdir -p "$temp_file_dir"

# Runtime variables:
# Holds the current zone and tsig key file. The flags indicate if they changed.
zone=""
tsig_key_file=""
zone_changed=0   # Flag: set to 1 when the zone changes
tsig_changed=0   # Flag: set to 1 when the TSIG key changes

# Read the static input file line by line
while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
    # Normalize line: strip comments and extra whitespace
    line="$(normalize_line "$raw_line")"

    # Skip empty lines
    [[ -z "$line" ]] && continue

    # Determine the line type
    case "$line" in

        # -----------------------------------------------------------------------------
        # If the line defines a new zone:
        # - Extract the value after 'zone='
        # - Validate the zone (must have valid SOA, etc.)
        # - Set flag so the new zone header gets written before the next record
        # -----------------------------------------------------------------------------
        zone=*)
            zone="${line#zone=}"
            validate_zone "$zone"
            log_message "INFO" "Zone set to: $zone"
            zone_changed=0
            ;;

        # -----------------------------------------------------------------------------
        # If the line defines a new TSIG key file:
        # - Extract the value after 'tsig_key_file='
        # - Validate its structure (must contain key, algorithm, secret, etc.)
        # - Set flag so the new TSIG header gets written before the next record
        # -----------------------------------------------------------------------------
        tsig_key_file=*)
            tsig_key_file="${line#tsig_key_file=}"

            if require_file_contains_any "$tsig_key_file" "key" "algorithm" "secret" "{" "}" ";" "};" '==";'; then
                log_message "INFO" "TSIG key file set to: $tsig_key_file"
                tsig_changed=0
            else
                log_message "ERROR" "Invalid TSIG key file structure: $tsig_key_file"
                exit 1
            fi
            ;;

        # -----------------------------------------------------------------------------
        # If the line defines a new default TTL:
        # - Extract the value after 'ttl='
        # - Validate it is a natural number
        # -----------------------------------------------------------------------------
        ttl=*)
            default_ttl="${line#ttl=}"

            if is_natural_number "$default_ttl"; then
                log_message "INFO" "Default TTL set to: $default_ttl"
            else
                log_message "ERROR" "Invalid TTL value '$default_ttl' — must be a natural number"
                exit 1
            fi
            ;;

        # -----------------------------------------------------------------------------
        # If the line is any other type, treat it as a DNS record.
        #
        # Before parsing the record:
        #   1. Check if the zone or TSIG changed → write updated headers.
        #   2. Verify that both zone and TSIG key are defined.
        # Then parse the record.
        # -----------------------------------------------------------------------------
        *)
            # Write updated zone header if the zone changed
            if [[ $zone_changed -eq 1 ]]; then
                write_tempfile_global_variables "zone" "$zone"
                zone_changed=1
            fi

            # Write updated TSIG header if the TSIG changed
            if [[ $tsig_changed -eq 1 ]]; then
                write_tempfile_global_variables "tsig_key_file" "$tsig_key_file"
                tsig_changed=1
            fi

            # Defensive: do not parse records if zone or TSIG key are missing
            if [[ -z "$zone" || -z "$tsig_key_file" ]]; then
                log_message "ERROR" "Zone and TSIG key file must be defined before parsing records"
                exit 1
            fi

            log_message "DEBUG" "Line queued for record parsing: $line"
            parse_record_line "$line"
            ;;
    esac

done < "$static_file"

# ================================================================================================
# End of the first main loop.
# After processing, each zone-specific tempfile contains:
#   - The correct zone= and tsig_key_file= header lines,
#   - Followed by valid, normalized DNS records.
# ================================================================================================


# Das Static File ist verarbeitet und validiert. Nun müssen die aufbereiteten files auf den Server geladen werden.


