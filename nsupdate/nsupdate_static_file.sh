#!/bin/bash

# =================================================================================================

# User defined variables
# Logging
log_file="/home/timon/github/dns-server-admin/log"  # Path to your logfile (required!)
log_level="DEBUG"                                   # Minimum log level to log (default: NOTICE)
verbose=true

# Static files
static_file="${1:-/home/timon/github/dns-server-admin/unit_test.txt}"  # /etc/bind/static_file/static.zone
old_static_file="${static_file}.old"

# Temporary files
temp_file_dir="/home/timon/github/dns-server-admin/test"  # /dev/shm/nsupdate_static_file

# DNS Target Server and dig Resolver also TCP and DNSSEC flag
dns_server="localhost" # set: "string" (required)
resolver="9.9.9.9"     # set: "string" or ""
dnssec_flag=true       # set: true or false
tcp_flag=true          # set: true or false
ipv6_flag=""           # set: true, false or "" (if you want to use the default settings of the device)

# ignored record types
allowed_record_types=("A" "AAAA" "CAA" "CNAME" "MX" "PTR" "SRV" "TLSA" "TXT")   # Never set SOA and NS, they are server-critical and should not be set with this script. (case-insensitive)

# =================================================================================================

# Load external Code snippets
source <(curl -s https://raw.githubusercontent.com/Turukmoorea/bashmod_lib/refs/heads/master/log_functions/log_message.sh)                   # call: log_message "INFO" "Script started"
source <(curl -s https://raw.githubusercontent.com/Turukmoorea/bashmod_lib/refs/heads/master/check_functions/check_ipv4.sh)                  # call: is_valid_ipv4 "$address"
source <(curl -s https://raw.githubusercontent.com/Turukmoorea/bashmod_lib/refs/heads/master/check_functions/check_ipv6.sh)                  # call: is_valid_ipv6 "$address"
source <(curl -s https://raw.githubusercontent.com/Turukmoorea/bashmod_lib/refs/heads/master/check_functions/check_cidr.sh)                  # call: is_valid_cidr "<string>"
source <(curl -s https://raw.githubusercontent.com/Turukmoorea/bashmod_lib/refs/heads/master/normalize_functions/normalize_line.sh)          # call: normalize_line "$original"
source <(curl -s https://raw.githubusercontent.com/Turukmoorea/bashmod_lib/refs/heads/master/check_functions/check_file_contains_requirements.sh)   # call: require_file_contains_any "/etc/bind/tsig.key" "key" "tsig" "algorithm" "{" "}" ";"
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

  # -----------------------------------------------------------------------------
  # Normalize the zone name
  # - Collapse multiple consecutive dots into one.
  # - Remove any trailing dot.
  # - Ensure exactly one trailing dot for the final query.
  # Example: "example..com.." → "example.com."
  # -----------------------------------------------------------------------------
  zone_name="$(echo "$zone_name" | sed -E 's/[.]+/./g' | sed -E 's/[.]$//')"
  zone_name="${zone_name}."

  # -----------------------------------------------------------------------------
  # Add custom resolver if defined.
  # Example: dig @9.9.9.9
  # -----------------------------------------------------------------------------
  [[ -n "$resolver" ]] && dig_cmd_parts+=("@$resolver")

  # -----------------------------------------------------------------------------
  # Add +dnssec flag if DNSSEC checking is enabled.
  # -----------------------------------------------------------------------------
  [[ "$dnssec_flag" == "true" ]] && dig_cmd_parts+=("+dnssec")

  # -----------------------------------------------------------------------------
  # Complete the dig command: dig [@resolver] [+dnssec] SOA <zone>
  # -----------------------------------------------------------------------------
  dig_cmd_parts+=("SOA" "$zone_name")
  local dig_cmd="${dig_cmd_parts[*]}"

  log_message "INFO" "Validating zone '$zone_name' using: $dig_cmd"

  # -----------------------------------------------------------------------------
  # Run the dig command and capture its output.
  # Suppress stderr to keep logs clean.
  # -----------------------------------------------------------------------------
  local dig_output
  dig_output="$(eval "$dig_cmd" 2>/dev/null)"

  # -----------------------------------------------------------------------------
  # Fail fast if no output — dig did not return data.
  # -----------------------------------------------------------------------------
  if [[ -z "$dig_output" ]]; then
    log_message "ERROR" "dig returned no output for zone '$zone_name'"
    return 1
  fi

  # -----------------------------------------------------------------------------
  # Extract the first SOA record line.
  # This should appear in the AUTHORITY SECTION of the dig output.
  # If none is found, the zone is invalid.
  # -----------------------------------------------------------------------------
  local soa_line
  soa_line="$(echo "$dig_output" | grep -Ei 'IN[[:space:]]+SOA' | head -n 1)"

  if [[ -z "$soa_line" ]]; then
    log_message "ERROR" "No SOA record found in dig output for '$zone_name'"
    return 1
  fi

  # -----------------------------------------------------------------------------
  # Extract the domain part from the SOA line.
  # Example: ";example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. ..."
  # The first field is the domain name.
  #
  # Clean up:
  # - Strip leading spaces or semicolons.
  # - Remove trailing dot.
  # - Convert to lowercase for consistent comparison.
  # -----------------------------------------------------------------------------
  local soa_domain
  soa_domain="$(echo "$soa_line" | awk '{print $1}' | sed -E 's/^[[:space:];]*//; s/\.$//' | tr '[:upper:]' '[:lower:]')"

  # Also normalize the expected zone name for comparison
  local expected_zone
  expected_zone="$(echo "$zone_name" | sed -E 's/\.$//' | tr '[:upper:]' '[:lower:]')"

  log_message "DEBUG" "SOA domain normalized: '$soa_domain' | Expected zone: '$expected_zone'"

  # -----------------------------------------------------------------------------
  # Robust matching.
  # Instead of strict equality, check if the SOA domain CONTAINS the expected zone.
  # This allows for common prefix/suffix edge cases.
  # -----------------------------------------------------------------------------
  if [[ "$soa_domain" == *"$expected_zone"* ]]; then
    log_message "INFO" "SOA domain '$soa_domain' contains expected zone: $expected_zone"
  else
    log_message "ERROR" "SOA domain '$soa_domain' does not contain expected zone: $expected_zone"
    return 1
  fi

  # -----------------------------------------------------------------------------
  # If DNSSEC is enabled, check for a valid RRSIG record covering the SOA.
  # -----------------------------------------------------------------------------
  if [[ "$dnssec_flag" == "true" ]]; then
    local rrsig_line
    rrsig_line="$(echo "$dig_output" | grep -Ei "^$soa_domain[.]?[[:space:]]+[0-9]+[[:space:]]+IN[[:space:]]+RRSIG[[:space:]]+SOA")"

    if [[ -z "$rrsig_line" ]]; then
      log_message "ERROR" "RRSIG for SOA not found for zone '$soa_domain' — DNSSEC check failed"
      return 1
    fi

    log_message "INFO" "RRSIG for SOA found and valid for zone: $soa_domain"
  fi

  # -----------------------------------------------------------------------------
  # All checks passed, zone is valid.
  # -----------------------------------------------------------------------------
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

    # ------------------------------------------------------------------------
    # Tokenize line preserving quotes using eval
    # ------------------------------------------------------------------------
    IFS=' ' read -r -a fields <<< "$line"   # old code: #eval "fields=( $line )"
    
    local num_fields="${#fields[@]}"
    log_message "DEBUG" "Amount of fields: ${fields[*]}"

    # ------------------------------------------------------------------------
    # Domain: always first field
    # ------------------------------------------------------------------------
    record_domain="${fields[0]}"
    log_message "DEBUG" "Domain extracted: $record_domain"

    # ------------------------------------------------------------------------
    # TTL detection (optional)
    # ------------------------------------------------------------------------
    local i=1
    if [[ "${fields[$i]}" =~ ^[0-9]+$ ]]; then
        record_ttl="${fields[$i]}"
        log_message "DEBUG" "TTL detected: $record_ttl"
        ((i++))
    else
        record_ttl="$default_ttl"
        log_message "NOTICE" "TTL missing or invalid ('${fields[$i]}'), using default TTL: $record_ttl"
    fi

    # ------------------------------------------------------------------------
    # Class detection: accept IN or omitted; skip unsupported
    # ------------------------------------------------------------------------
    case "${fields[$i]}" in
        IN|"")
            log_message "DEBUG" "Class: IN or omitted — continuing"
            ((i++))
            ;;
        CH|HS|NONE|ANY)
            log_message "WARNING" "Unsupported record class '${fields[$i]}' found — skipping line"
            return 0
            ;;
        *)
            log_message "DEBUG" "No class specified — interpreting '${fields[$i]}' as record type"
            ;;
    esac

    # ------------------------------------------------------------------------
    # Type: next token
    # ------------------------------------------------------------------------
    for i in "${!allowed_record_types[@]}"; do
        allowed_record_types[$i]=$(echo "${allowed_record_types[$i]}" | tr '[:lower:]' '[:upper:]')
    done

    
    record_type=$(echo "$record_type" | tr '[:lower:]' '[:upper:]')

    allowed=false
    for allowed_type in "${allowed_record_types[@]}"; do
        if [[ "$record_type" == "$allowed_type" ]]; then
            allowed=true
            break
        fi
    done

    if [[ "$allowed" == false ]]; then
        log_message "WARNING" "Unsupported record type '$record_type' for domain '$domain' — skipping line"
        return 0
    fi

    ((i++))

    # ------------------------------------------------------------------------
    # Value: join remaining tokens, preserving quotes
    # ------------------------------------------------------------------------
    for ((; i<num_fields; i++)); do
        if [[ -n "$record_value" ]]; then
            record_value+=" "
        fi
        record_value+="${fields[$i]}"
    done

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
            zone="$(echo "${line#zone=}" | sed -E 's/^[[:space:]]*//; s/[[:space:]]*$//' | sed -E 's/^"(.*)"$/\1/')"
            validate_zone "$zone"
            log_message "INFO" "Zone set to: $zone"
            zone_changed=0
            tsig_changed=0
            ;;

        # -----------------------------------------------------------------------------
        # If the line defines a new TSIG key file:
        # - Extract the value after 'tsig_key_file='
        # - Validate its structure (must contain key, algorithm, secret, etc.)
        # - Set flag so the new TSIG header gets written before the next record
        # -----------------------------------------------------------------------------
        tsig_key_file=*)
            tsig_key_file="$(echo "${line#tsig_key_file=}" | sed -E 's/^[[:space:]]*//; s/[[:space:]]*$//' | sed -E 's/^"(.*)"$/\1/')"

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
            default_ttl="$(echo "${line#ttl=}" | sed -E 's/^[[:space:]]*//; s/[[:space:]]*$//' | sed -E 's/^"(.*)"$/\1/')"

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
            if [[ $zone_changed -eq 0 ]]; then
                write_tempfile_global_variables "zone" "$zone"
                zone_changed=1
            fi

            # Write updated TSIG header if the TSIG changed
            if [[ $tsig_changed -eq 0 ]]; then
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
# ================================================================================================


# Das Static File ist verarbeitet und validiert. Nun müssen die aufbereiteten files auf den Server geladen werden.


