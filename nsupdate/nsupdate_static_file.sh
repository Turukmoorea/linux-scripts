#!/bin/bash

# ============================================================================================================
# DNS Static Zone Update & Management Script
# ------------------------------------------------------------------------------------------------------------
# This script processes static DNS zone files, validates zones and DNS records, generates incremental
# nsupdate commands (add/update/delete), manages a structured debug environment, persists processed data
# versioned in Git, and uploads updates securely using nsupdate with TSIG authentication.
#
# Key Features:
#   - Validates DNS zones using dig, including SOA checks and optional DNSSEC (RRSIG) validation.
#   - Supports IPv4 and IPv6 lookups, TCP mode, and custom resolver configuration.
#   - Processes and normalises record types: A, AAAA, CAA, CNAME, MX, PTR, SRV, TLSA, TXT.
#   - Ignores critical server-side records (e.g., SOA, NS) for safety.
#   - Creates a fully structured debug environment when debug mode is enabled:
#       - Copies RAM-based temp files
#       - Symlinks persistent processed files and logs
#       - Provides full offline traceability
#   - Persists all processed zone data in a Git repository with automated versioned commits.
#   - Generates safe nsupdate files per zone and TSIG key with correct headers and mappings.
#   - Uploads all nsupdate files using nsupdate -v, logs full server responses line by line.
#   - Implements robust error handling (`set -euo pipefail`) and exit traps for safe cleanup.
#
# Requirements:
#   - Bash >= 4
#   - Standard tools: nsupdate, dig, sed, grep, awk, curl, git
#   - Valid TSIG key files for secure DNS updates
#   - Target DNS server must accept TSIG-authenticated updates
#
# Usage:
#   1. Configure your global variables:
#        static_file="/etc/bind/static_file/static.zone"
#        persistent_processed_file_dir="~/.static_file/processed_files"
#        temp_file_dir="/dev/shm/nsupdate_static_file"
#        dns_server="dns.example.com"
#        resolver="dns.example.com" (optional)
#        log_file="/path/to/logfile.log"
#        debug_dir="/path/to/debug_dir"
#        debug_mode=true|false
#
#   2. Load external modules as needed:
#        source <(curl -s https://raw.githubusercontent.com/Turukmoorea/bashmod_lib/refs/heads/master/log_functions/log_message.sh)
#        # Additional check/normalize modules as shown in the script
#
#   3. Run the script:
#        ./nsupdate_static_file.sh /etc/bind/static_file/static.zone
#
#   4. Result:
#        - Valid zones and records will be parsed, validated and grouped by zone & TSIG.
#        - Stale records are detected and removed automatically.
#        - New or changed records are added/updated with correct TTLs.
#        - Processed files are versioned in Git.
#        - nsupdate uploads are run automatically and all responses are logged.
#
# Output:
#   - Logs are written to $log_file and optionally to console if verbose=true.
#   - Debug files are linked/copied under $debug_dir when debug_mode=true.
#   - All processed zone files are versioned under $persistent_processed_file_dir.
#
# Author: Turukmoorea
# Contact: mail@turukmoorea.ch
# Repository: https://github.com/Turukmoorea/linux-scripts
# Last Updated: 2025-07-06
#
# License:
#   This script is free to use, modify, and distribute.
#
# ============================================================================================================

# ------------------------------------------------------------------------------------------------------------
# CONFIGURATION VARIABLES
#   Adjust these to match your local environment.
#   These are NOT commented out so they can be changed directly in this header.
# ------------------------------------------------------------------------------------------------------------

debug_mode=false                                       # true = enable debug mode with full traceability
debug_dir="$HOME/dns-server-admin/debug"  # Debug output directory when debug mode is enabled

# Script metadata
script_name="nsupdate_static_file.sh"                  # Script name used for Git versioning and logging
contact_mail="dns@famtec.ch"                           # Contact email for Git commits

# Logging
log_file="$HOME/dns-server-admin/log/log" # Logfile path (must be writable!)
log_level="INFO"                                       # Logging level: DEBUG, INFO, NOTICE, etc.
verbose=true                                           # true = log output to console as well

# Input and processed files
static_file="${1:-}"                                   # Static input file (can be passed as argument) example static value: "${1:-/etc/bind/static_file/static.zone}"
persistent_processed_file_dir="$HOME/.static_file/processed_files"  # Where processed files are stored/versioned

# Temporary RAM-based workspace
temp_file_dir="/dev/shm/nsupdate_static_file"          # Temp working directory for processing files

# DNS target configuration
dns_server="dns.famtec.ch"                             # Primary DNS server for updates
resolver="dns.famtec.ch"                               # Optional resolver for dig lookups
dnssec_flag=true                                       # true = enable DNSSEC validation
tcp_flag=true                                          # true = force TCP for dig/nsupdate
ipv6_flag=""                                           # true = force IPv6, false = force IPv4, "" = system default

# Allowed record types
allowed_record_types=("A" "AAAA" "CAA" "CNAME" "MX" "PTR" "SRV" "TLSA" "TXT" "LOC") # Supported record types
# NOTE: SOA and NS MUST NOT be included! They are server-critical and handled by authoritative servers.

# ============================================================================================================

# Load external Code snippets
source <(curl -s https://raw.githubusercontent.com/Turukmoorea/bashmod_lib/refs/heads/master/log_functions/log_message.sh)                   # call: log_message "DEBUG" "Script started"
source <(curl -s https://raw.githubusercontent.com/Turukmoorea/bashmod_lib/refs/heads/master/check_functions/check_ipv4.sh)                  # call: is_valid_ipv4 "$address"
source <(curl -s https://raw.githubusercontent.com/Turukmoorea/bashmod_lib/refs/heads/master/check_functions/check_ipv6.sh)                  # call: is_valid_ipv6 "$address"
source <(curl -s https://raw.githubusercontent.com/Turukmoorea/bashmod_lib/refs/heads/master/check_functions/check_cidr.sh)                  # call: is_valid_cidr "<string>"
source <(curl -s https://raw.githubusercontent.com/Turukmoorea/bashmod_lib/refs/heads/master/normalize_functions/normalize_line.sh)          # call: normalize_line "$original"
source <(curl -s https://raw.githubusercontent.com/Turukmoorea/bashmod_lib/refs/heads/master/check_functions/check_file_contains_requirements.sh)   # call: require_file_contains_any "/etc/bind/tsig.key" "key" "tsig" "algorithm" "{" "}" ";"
source <(curl -s https://raw.githubusercontent.com/Turukmoorea/bashmod_lib/refs/heads/master/check_functions/check_natural_number.sh)        # call: is_natural_number "$value"

# Logs the name of the script as it was invoked (without the path).
log_message "NOTICE" "Script called: $(basename "$0") $*"

# Enables strict error handling:
# -e: Exit immediately on any command returning a non-zero status
# -u: Treat unset variables as an error
# -o pipefail: Return the exit status of the last command in the pipeline that failed
set -euo pipefail

# --------------------------------------------------------------------------------------------------
# Function: setup_debug_environment
# --------------------------------------------------------------------------------------------------
# Purpose:
#   Prepares a structured debug directory if debug mode is enabled.
#   Copies volatile RAM-based files and links persistent files for easy offline analysis.
#
# What it does:
#   - Forces the log level to DEBUG when debug mode is on.
#   - Clears and recreates the target debug directory.
#   - Organises the debug folder into separate numbered subfolders for clarity:
#       01_static_file_link/
#       02_processed_ram_file/   (copied)
#       03_nsupdate_files/       (copied)
#       04_persistent_processed/ (symlink)
#       05_log_link/             (symlink)
#   - Ensures safe fallback if files or folders are missing.
#   - Logs every step in detail for maximum traceability.
#
# Parameters:
#   $1 - debug_dir : Absolute path to the debug directory.
#
# Requires:
#   - $debug_mode
#   - $log_level
#   - $static_file
#   - $temp_file_dir
#   - $persistent_processed_file_dir
#   - $log_file
# --------------------------------------------------------------------------------------------------
if [[ "$debug_mode" == "true" ]]; then
  log_level="DEBUG"
  log_message "NOTICE" "Debug mode is enabled — log level forced to DEBUG."
fi

setup_debug_environment() {
  if [[ "$debug_mode" != "true" ]]; then
    log_message "DEBUG" "Debug mode is disabled — skipping debug environment setup."
    return 0
  fi

  # -----------------------------------------------------------------------------------------------
  # Force log level to DEBUG for maximum output when debug mode is enabled
  # -----------------------------------------------------------------------------------------------
  log_level="DEBUG"
  log_message "DEBUG" "Debug mode is enabled — log level forced to DEBUG."

  # -----------------------------------------------------------------------------------------------
  # Prepare target debug directory
  # -----------------------------------------------------------------------------------------------
  local debug_dir="$1"
  if [[ -z "$debug_dir" ]]; then
    echo "ERROR: Debug directory not specified. Exiting."
    exit 1
  fi

  log_message "DEBUG" "Preparing debug directory: $debug_dir"
  rm -rf "$debug_dir"
  mkdir -p "$debug_dir"

  # -----------------------------------------------------------------------------------------------
  # 1. Link the original static file
  # -----------------------------------------------------------------------------------------------
  mkdir -p "$debug_dir/01_static_file_link"
  if [[ -f "$static_file" ]]; then
    ln -sf "$static_file" "$debug_dir/01_static_file_link/static_file.zone"
    log_message "DEBUG" "Linked static_file: $static_file >> $debug_dir/01_static_file_link/"
  else
    log_message "WARNING" "Static file not found: $static_file"
  fi

  # -----------------------------------------------------------------------------------------------
  # 2. Copy processed files from RAM (processing_static_file)
  # -----------------------------------------------------------------------------------------------
  mkdir -p "$debug_dir/02_processed_ram_file"
  if [[ -d "$temp_file_dir/processing_static_file/" ]]; then
    cp -a "$temp_file_dir/processing_static_file/." "$debug_dir/02_processed_ram_file/"
    log_message "DEBUG" "Copied processed RAM files to: $debug_dir/02_processed_ram_file/"
  else
    log_message "WARNING" "No processed RAM files found in: $temp_file_dir/processing_static_file/"
  fi

  # -----------------------------------------------------------------------------------------------
  # 3. Copy nsupdate files from RAM
  # -----------------------------------------------------------------------------------------------
  mkdir -p "$debug_dir/03_nsupdate_files"
  if [[ -d "$temp_file_dir/nsupdate_files/" ]]; then
    cp -a "$temp_file_dir/nsupdate_files/." "$debug_dir/03_nsupdate_files/"
    log_message "DEBUG" "Copied nsupdate RAM files to: $debug_dir/03_nsupdate_files/"
  else
    log_message "WARNING" "No nsupdate RAM files found in: $temp_file_dir/nsupdate_files/"
  fi

  # -----------------------------------------------------------------------------------------------
  # 4. Copy persistent processed files directly
  # -----------------------------------------------------------------------------------------------
  mkdir -p "$debug_dir/04_persistent_processed"
  if [[ -d "$persistent_processed_file_dir" ]]; then
    cp -a "$persistent_processed_file_dir/." "$debug_dir/04_persistent_processed/"
    log_message "DEBUG" "Copied persistent processed files: $persistent_processed_file_dir >> $debug_dir/04_persistent_processed/"
  else
    log_message "WARNING" "Persistent processed directory not found: $persistent_processed_file_dir"
  fi

  # -----------------------------------------------------------------------------------------------
  # 5. Link the log file
  # -----------------------------------------------------------------------------------------------
  mkdir -p "$debug_dir/05_log_link"
  if [[ -f "$log_file" ]]; then
    ln -sf "$log_file" "$debug_dir/05_log_link/log"
    log_message "DEBUG" "Linked log file: $log_file >> $debug_dir/05_log_link/log"
  else
    log_message "WARNING" "Log file not found: $log_file"
  fi

  log_message "DEBUG" "Debug environment fully prepared: $debug_dir"
}

cleanup() {
  local exit_code=$?

  log_message "INFO" "============================================================="
  log_message "DEBUG" "------ Starting debug environment setup before cleanup ------"
  setup_debug_environment "$debug_dir"
  log_message "DEBUG" "------ Debug environment setup finished ------"

  log_message "NOTICE" "------ Starting cleanup of temp files ------"
  log_message "INFO" "Cleaning up temp files in: $temp_file_dir (Exit code: $exit_code)"
  rm -rf "$temp_file_dir"
  log_message "INFO" "Cleanup done. Script exiting with code $exit_code."
  log_message "INFO" "------ Cleanup finished ------"

  exit $exit_code
}


trap cleanup EXIT INT TERM

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
  # Example: "example..com.." >> "example.com."
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
  # Add -4 or -6 if ipv6_flag is set.
  # -----------------------------------------------------------------------------
  if [[ "$ipv6_flag" == "true" ]]; then
    dig_cmd_parts+=("-6")
  elif [[ "$ipv6_flag" == "false" ]]; then
    dig_cmd_parts+=("-4")
  fi

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
  # Check if dig returned status: NOERROR
  # -----------------------------------------------------------------------------
  local dig_status
  dig_status="$(echo "$dig_output" | grep -E '^;; ->>HEADER<<-.*status: [A-Z]+,' | sed -E 's/.*status: ([A-Z]+),.*/\1/')"

  if [[ "$dig_status" != "NOERROR" ]]; then
    log_message "ERROR" "dig for zone '$zone_name' returned status: $dig_status — treating as invalid zone."
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

    log_message "DEBUG" "RRSIG for SOA found and valid for zone: $soa_domain"
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

    log_message "DEBUG" "Processing line: $line"

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
    IFS=' ' read -r -a fields <<< "$line"   # old code: eval "fields=( $line )"
    
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
        log_message "INFO" "TTL missing or invalid ('${fields[$i]}'), using default TTL: $record_ttl"
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
    for idx in "${!allowed_record_types[@]}"; do
       allowed_record_types[$i]=$(echo "${allowed_record_types[$i]}" | tr '[:lower:]' '[:upper:]')
    done
    
    record_type=$(echo "${fields[$i]}" | tr '[:lower:]' '[:upper:]')

    allowed=false
    for allowed_type in "${allowed_record_types[@]}"; do
        if [[ "$record_type" == "$allowed_type" ]]; then
            allowed=true
            break
        fi
    done

    if [[ "$allowed" == false ]]; then
        log_message "WARNING" "Unsupported record type '$record_type' for domain '$record_domain' — skipping line"
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
                log_message "DEBUG" "Valid A record: $record_domain $record_ttl A $record_value"
            else
                log_message "WARNING" "Invalid IPv4 address for A record: $record_value — skipping line"
                return 0
            fi
            ;;
        AAAA)
            # Validate IPv6 address
            if is_valid_ipv6 "$record_value"; then
                log_message "DEBUG" "Valid AAAA record: $record_domain $record_ttl AAAA $record_value"
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
            # Normalize value to valid FQDN:
            if [[ "$record_value" != *"." ]]; then
                record_value="${record_value}.${zone}"
            fi

            # Clean up: collapse multiple dots and ensure single trailing dot
            record_value="$(echo "$record_value" | sed -E 's/[.]+/./g; s/[.]$//')."

            log_message "DEBUG" "Normalized target FQDN for $record_type: $record_value"
            ;;
        MX)
            # MX record must have: priority (number) and target (domain)
            # Example: MX 10 mail.example.com.
            # So record_value must have at least 2 parts.

            local mx_priority mx_target
            IFS=' ' read -r mx_priority mx_target <<< "$record_value"

            if ! [[ "$mx_priority" =~ ^[0-9]+$ ]]; then
                log_message "WARNING" "MX record for '$record_domain' has invalid priority '$mx_priority' — skipping line"
                return 0
            fi

            if [[ -z "$mx_target" ]]; then
                log_message "WARNING" "MX record for '$record_domain' missing target mailserver — skipping line"
                return 0
            fi

            if [[ "$mx_target" != *"." ]]; then
            mx_target="${mx_target}.${zone}"
            fi

            # Collapse multiple consecutive dots and ensure single trailing dot
            mx_target="$(echo "$mx_target" | sed -E 's/[.]+/./g; s/[.]$//')."

            log_message "DEBUG" "Normalized MX target FQDN: $mx_target"

            record_value="${mx_priority} ${mx_target}"
            log_message "DEBUG" "Valid MX record: $record_domain $record_ttl MX $record_value"
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
            # Trim leading/trailing spaces
            record_value="$(echo "$record_value" | sed -E 's/^[[:space:]]*//; s/[[:space:]]*$//')"

            # Remove multiple double quotes at start and end
            record_value="$(echo "$record_value" | sed -E 's/^"+//; s/"+$//')"

            # Ensure exactly one pair of double quotes
            record_value="\"$record_value\""

            log_message "DEBUG" "TXT record value normalized and quoted: $record_value"
            ;;
    esac

    # Log that the record has passed all checks
    log_message "INFO" "Record accepted: $record_domain $record_ttl $record_type $record_value"

    # Write record to zone-specific output file
    local zone_file="$temp_file_dir/processing_static_file/$zone"
    mkdir -p $temp_file_dir/processing_static_file
    echo "$record_domain $record_ttl $record_type $record_value" >> "$zone_file"
    log_message "DEBUG" "Record written to file: $record_domain $record_ttl $record_type $record_value >> $zone_file"
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
    local zone_file="$temp_file_dir/processing_static_file/$zone"  # Target tempfile for the current zone

    # Write the variable line in the form: var_name="var_value"
    mkdir -p "$(dirname "$zone_file")"
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
log_message "NOTICE" "------ Starting static file processing ------"

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
            log_message "NOTICE" "Zone set to: $zone"
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
                log_message "NOTICE" "TSIG key file set to: $tsig_key_file"
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
                log_message "NOTICE" "Default TTL set to: $default_ttl"
            else
                log_message "ERROR" "Invalid TTL value '$default_ttl' — must be a natural number"
                exit 1
            fi
            ;;

        # -----------------------------------------------------------------------------
        # If the line is any other type, treat it as a DNS record.
        #
        # Before parsing the record:
        #   1. Check if the zone or TSIG changed >> write updated headers.
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

            log_message "NOTICE" "Line queued for record parsing: $line"
            parse_record_line "$line"
            ;;
    esac

done < "$static_file"

log_message "INFO" "------ Static file processing finished ------"

# ================================================================================================
# End of the first main loop.
# ================================================================================================
# --------------------------------------------------------------------------------------------------
# Function: write_nsupdate_header
# --------------------------------------------------------------------------------------------------
# Purpose:
#   Writes a standardized nsupdate header for a specific zone/TSIG file
#   if the file does not already exist.
#
# What it does:
#   - Builds the header with:
#       server <dns_server>
#       zone <zone>
#   - Checks if the target file already exists to prevent duplicate headers.
#   - Creates any parent directories as needed.
#
# Parameters:
#   $1 - nsupdate_file : Full path to the nsupdate file.
#   $2 - zone          : The DNS zone for the file.
#
# Uses:
#   - $dns_server : Global DNS server variable.
#
# Behavior:
#   - Logs every action for traceability.
#
# --------------------------------------------------------------------------------------------------
write_nsupdate_header() {
  local nsupdate_file="$1"
  local zone="$2"

  zone="$(echo "$zone" | sed -E 's/[.]+$//')."

  if [[ ! -f "$nsupdate_file" ]]; then
    mkdir -p "$(dirname "$nsupdate_file")"
    {
      echo "server $dns_server"
      echo "zone $zone"
      echo
    } >> "$nsupdate_file"
    log_message "INFO" "Header written to nsupdate file: $nsupdate_file"
  else
    log_message "DEBUG" "nsupdate header already exists: $nsupdate_file"
  fi
}

# --------------------------------------------------------------------------------------------------
# Function: validate_record
# --------------------------------------------------------------------------------------------------
# Purpose:
#   Validates whether a specific DNS record (FQDN and type) already exists on the target DNS server,
#   using the TSIG key file (-k) if defined, and falling back to an unsigned query if needed.
#   Includes a retry mechanism to handle transient resolver failures.
#
# How it works:
#   - Dynamically builds the dig command with optional:
#       - Custom resolver
#       - TCP vs. UDP
#       - DNSSEC flag
#       - IPv4/IPv6 mode
#       - TSIG authentication (-k <keyfile>)
#   - Executes dig with retries and fallback logic.
#   - If the record exists and DNSSEC validation is enabled:
#       - Ensures a valid RRSIG record covers the queried type.
#
# Parameters:
#   $1 - fqdn : Fully Qualified Domain Name to validate.
#   $2 - type : DNS record type (A, AAAA, MX, etc.).
#   $3 - tsig_key_file : Path to TSIG key file for the query.
#
# Uses:
#   - $resolver         : Optional DNS resolver IP.
#   - $dnssec_flag      : If true, verifies RRSIG presence.
#   - $tcp_flag         : If true, forces TCP mode.
#   - $ipv6_flag        : If true or false, forces IPv6 or IPv4.
#
# Returns:
#   0 : Record exists with valid RRSIG (or DNSSEC disabled).
#   1 : Record does not exist or dig query failed (e.g., status != NOERROR) — safe to add.
#   2 : Record exists but missing RRSIG — should be skipped.
#   3 : Record skipped due to dig SERVFAIL — should be skipped.
#
# --------------------------------------------------------------------------------------------------

validate_record() {
  local fqdn="$1"
  local type="$2"
  local tsig_key_file="$3"

  local sleep_time="0.5"
  local max_retries=3
  local attempt=1

  local dig_cmd_parts=()
  local fallback_cmd_parts=()

  # ---------------------------------------------
  # Compose initial dig command
  # ---------------------------------------------
  dig_cmd_parts=("dig")
  [[ -n "$resolver" ]] && dig_cmd_parts+=("@$resolver")
  [[ "$dnssec_flag" == "true" ]] && dig_cmd_parts+=("+dnssec")
  [[ "$tcp_flag" == "true" ]] && dig_cmd_parts+=("+tcp")
  if [[ "$ipv6_flag" == "true" ]]; then
    dig_cmd_parts+=("-6")
  elif [[ "$ipv6_flag" == "false" ]]; then
    dig_cmd_parts+=("-4")
  fi
  if [[ -n "$tsig_key_file" ]]; then
    dig_cmd_parts+=("-k" "$tsig_key_file")
  fi
  dig_cmd_parts+=("$fqdn" "$type")

  local dig_cmd="${dig_cmd_parts[*]}"
  local dig_output=""

  log_message "DEBUG" "Validating record: $fqdn $type with dig command: $dig_cmd"

  while [[ $attempt -le $max_retries ]]; do
    dig_output="$(eval "$dig_cmd" 2>/dev/null)"

    if [[ -n "$dig_output" ]]; then
      log_message "DEBUG" "dig output received on attempt $attempt."
      break
    fi

    # Fallback to unsigned query only once after first failed attempt with TSIG
    if [[ $attempt -eq 1 && -n "$tsig_key_file" ]]; then
      log_message "WARNING" "No response with TSIG — falling back to unsigned query."
      fallback_cmd_parts=()
      local skip_next=0
      for part in "${dig_cmd_parts[@]}"; do
        if [[ "$skip_next" == 1 ]]; then
          skip_next=0
          continue
        elif [[ "$part" == "-k" ]]; then
          skip_next=1
        else
          fallback_cmd_parts+=("$part")
        fi
      done
      dig_cmd="${fallback_cmd_parts[*]}"
      log_message "DEBUG" "Fallback dig command: $dig_cmd"
    else
      log_message "WARNING" "No dig output on attempt $attempt — retrying in ${sleep_time}s..."
      sleep "$sleep_time"
    fi

    ((attempt++))
  done

  # Final outcome after retries
  if [[ -z "$dig_output" ]]; then
    log_message "DEBUG" "No dig output after ${max_retries} attempt(s) — treating as non-existent."
    return 1
  fi


  # ---------------------------------------------
  # Check if dig returned status: NOERROR
  # ---------------------------------------------
  local dig_status
  dig_status="$(echo "$dig_output" | grep -E "^;; ->>HEADER<<-.*status: [A-Z]+," | sed -E 's/.*status: ([A-Z]+),.*/\1/')"

  if [[ "$dig_status" != "NOERROR" ]]; then
    log_message "WARNING" "dig query for '$fqdn' returned status: $dig_status — treating as non-existent or invalid."
    return 3
  fi

  # ---------------------------------------------
  # Check if the ANSWER SECTION contains a real answer
  # ---------------------------------------------
  # Extract only ANSWER SECTION lines (exclude QUESTION, AUTHORITY, ADDITIONAL)
  local answer_section
  answer_section="$(echo "$dig_output" | sed -n '/^;; ANSWER SECTION:/,/^;;/p' | grep -E "IN[[:space:]]+$type")"

  if [[ -z "$answer_section" ]]; then
    log_message "DEBUG" "No $type record found in ANSWER SECTION for '$fqdn' — treating as non-existent."
    return 1
  fi

  # If DNSSEC required, check for RRSIG covering the type in ANSWER SECTION
  if [[ "$dnssec_flag" == "true" ]]; then
    local rrsig_line
    rrsig_line="$(echo "$dig_output" | sed -n '/^;; ANSWER SECTION:/,/^;;/p' | grep -E "IN[[:space:]]+RRSIG[[:space:]]+$type")"
    if [[ -z "$rrsig_line" ]]; then
      log_message "WARNING" "Record '$fqdn $type' exists but missing RRSIG in ANSWER SECTION — skipping due to DNSSEC."
      return 2
    fi
    log_message "DEBUG" "Record '$fqdn $type' exists with valid RRSIG in ANSWER SECTION."
  else
    log_message "DEBUG" "Record '$fqdn $type' exists in ANSWER SECTION."
  fi

  return 0
}

# --------------------------------------------------------------------------------------------------
# Function: write_nsupdate_instruction
# --------------------------------------------------------------------------------------------------
# Purpose:
#   Writes a single nsupdate instruction (e.g., update add / update delete) to the correct nsupdate
#   file for the given zone and TSIG key. Automatically ensures the file has the correct header
#   (server + zone) and updates the TSIG mapping file.
#
# What it does:
#   - Creates or reuses the nsupdate file under $temp_file_dir/nsupdate_files/.
#   - Uses write_nsupdate_header() to ensure header is written once.
#   - Appends the nsupdate instruction to the file.
#   - Updates the TSIG mapping file ($temp_file_dir/tsig_key_mapping.txt).
#
# Parameters:
#   $1 - zone           : The DNS zone (e.g., example.com.)
#   $2 - tsig_key_file  : Path to TSIG key file.
#   $3 - instruction    : The nsupdate instruction (e.g., update add ...).
#
# Uses:
#   - $dns_server
#   - $temp_file_dir
# --------------------------------------------------------------------------------------------------

write_nsupdate_instruction() {
  local zone="$1"
  local tsig_key_file="$2"
  local instruction="$3"

  local nsupdate_dir="$temp_file_dir/nsupdate_files"
  local mapping_file="$nsupdate_dir/tsig_key_mapping.txt"

  # Make sure the target directory exists
  mkdir -p "$nsupdate_dir"

  # Build safe filename: <zone>_<basename of TSIG key file>
  local safe_tsig_name
  safe_tsig_name="$(basename "$tsig_key_file")"
  local nsupdate_file="$nsupdate_dir/${zone}_${safe_tsig_name}"

  # Ensure header exists
  write_nsupdate_header "$nsupdate_file" "$zone"

  # Write the actual instruction
  echo "$instruction" >> "$nsupdate_file"
  log_message "DEBUG" "Instruction appended: $instruction >> $nsupdate_file"

  # Ensure TSIG mapping is tracked
  mkdir -p "$(dirname "$mapping_file")"
  if ! grep -q "^${zone}_${safe_tsig_name}=" "$mapping_file" 2>/dev/null; then
    echo "${zone}_${safe_tsig_name}=$tsig_key_file" >> "$mapping_file"
    log_message "DEBUG" "Mapping added: ${zone}_${safe_tsig_name}=$tsig_key_file"
  else
    log_message "DEBUG" "Mapping already exists for: ${zone}_${safe_tsig_name}"
  fi
}

# --------------------------------------------------------------------------------------------------
# Function: detect_and_prepare_deletes
# --------------------------------------------------------------------------------------------------
# Purpose:
#   Checks for stale DNS records by comparing old processed files in $persistent_processed_file_dir
#   with the new processed files in $nsupdate_dir. Any record that is present in the old file but
#   missing in the new one gets a `update delete` statement prepared.
#
#   - Supports zone and TSIG key switching inside a file.
#   - Skips non-record lines like zone=, tsig_key_file=, ttl=.
#   - Uses write_nsupdate_instruction() to build consistent nsupdate files with correct headers
#     and mappings.
#
# Usage:
#   This is typically run AFTER new files were generated, but BEFORE persisting new static files.
# --------------------------------------------------------------------------------------------------
detect_and_prepare_deletes() {
  # Define directories: old = persistent versioned files, new = RAM temp nsupdate files
  local old_dir="$persistent_processed_file_dir"
  old_dir="${old_dir/#\~/$HOME}"
  local nsupdate_dir="$temp_file_dir/processing_static_file"

  log_message "DEBUG" "Checking for stale records to delete…"
  log_message "DEBUG" "Looking for old files in: $old_dir"

  # -----------------------------------------------------------------------------------------------
  # Find all old files, excluding any files inside .git.
  # -----------------------------------------------------------------------------------------------
  local old_files
  old_files=$(find "$old_dir" -type f ! -path "$old_dir/.git/*" 2>/dev/null || true)

  # If no old files exist, nothing to check >> exit early
  if [[ -z "$old_files" ]]; then
    log_message "DEBUG" "No old files found in $old_dir — nothing to delete."
    return 0
  fi

  # -----------------------------------------------------------------------------------------------
  # Process each old file one by one
  # -----------------------------------------------------------------------------------------------
  while IFS= read -r old_file; do
    local filename
    filename="$(basename "$old_file")"                    # e.g. famtec.zone
    local new_file="$nsupdate_dir/$filename"              # Path to matching new file

    log_message "DEBUG" "Comparing old file: $old_file with new nsupdate file: $new_file"

    # Initialise context for zone and TSIG key file — these can change inside the file
    local zone=""
    local tsig_key_file=""

    # ---------------------------------------------------------------------------------------------
    # Read the old file line by line
    # ---------------------------------------------------------------------------------------------
    while IFS= read -r line || [[ -n "$line" ]]; do
      # Skip empty lines
      [[ -z "$line" ]] && continue

      # -------------------------------------------------------------------------------------------
      # Detect line type: zone= , tsig_key_file= , ttl= or record line
      # -------------------------------------------------------------------------------------------
      case "$line" in
        zone=*)
          # Extract zone name, remove any surrounding quotes
          zone="$(echo "${line#zone=}" | sed -E 's/^"//; s/"$//')"
          log_message "DEBUG" "Zone set to: $zone"
          ;;

        tsig_key_file=*)
          # Extract TSIG key file, remove any surrounding quotes
          tsig_key_file="$(echo "${line#tsig_key_file=}" | sed -E 's/^"//; s/"$//')"
          log_message "DEBUG" "TSIG key switched to: $tsig_key_file"
          ;;

        *)
          # ---------------------------------------------------------------------------------------
          # Defensive: do not continue if context is missing
          # ---------------------------------------------------------------------------------------
          if [[ -z "$zone" || -z "$tsig_key_file" ]]; then
            log_message "ERROR" "Missing zone or TSIG for record: $line"
            continue
          fi

          # Normalise record for consistent comparison:
          #   Collapse multiple spaces into a single space
          local record_normalized
          record_normalized="$(echo "$line" | sed -E 's/[[:space:]]+/ /g')"

          # ---------------------------------------------------------------------------------------
          # Load new records once (per file)
          # ---------------------------------------------------------------------------------------
          local new_records=""
          if [[ -f "$new_file" ]]; then
            new_records=$(grep -Ev '^(zone=|tsig_key_file=|ttl=|#|$)' "$new_file" | sed -E 's/[[:space:]]+/ /g')
          fi

          # ---------------------------------------------------------------------------------------
          # Check if record exists in new file — if not, prepare DELETE
          # ---------------------------------------------------------------------------------------
          if [[ -z "$new_records" ]] || ! grep -Fq "$record_normalized" <<< "$new_records"; then
            # Parse domain and type only for the delete statement
            local domain type
            read -r domain _ type _ <<< "$record_normalized"

            # Build nsupdate delete instruction
            local instruction="update delete $domain $type"

            # Write delete to nsupdate file with correct header and mapping
            write_nsupdate_instruction "$zone" "$tsig_key_file" "$instruction"
            log_message "INFO" "Prepared DELETE: $instruction"
          else
            log_message "DEBUG" "Record still valid: $record_normalized"
          fi
          ;;
      esac

    done < "$old_file"    # End of inner while: per line in old file

  done <<< "$old_files"   # End of outer while: per old file

  log_message "DEBUG" "Stale record detection completed."
}

# --------------------------------------------------------------------------------------------------
# Function: process_nsupdate_adds_and_updates
# --------------------------------------------------------------------------------------------------
# Purpose:
#   Goes through each prepared nsupdate file in $temp_file_dir/nsupdate_files, line by line.
#   Uses validate_record() to check if each DNS record already exists on the DNS server (via TSIG key).
#   Decides whether to:
#     - Simply add (update add)
#     - Or update existing (update delete + update add)
#
# How it works:
#   - Uses the context of zone and tsig_key_file which can change dynamically in the file.
#   - Each record line is parsed with shell pattern matching.
#   - Calls write_nsupdate_instruction() to create correct nsupdate statements with header + mapping.
#
# Inputs:
#   - $temp_file_dir/nsupdate_files: Prepared nsupdate input files.
#   - validate_record(): Must be defined and usable.
# --------------------------------------------------------------------------------------------------

process_nsupdate_adds_and_updates() {
  local processing_static_dir="$temp_file_dir/processing_static_file"
  local nsupdate_dir="$temp_file_dir/nsupdate_files"

  log_message "DEBUG" "Processing input files in $processing_static_dir >> generating $nsupdate_dir ..."

  # Loop over all files in processing_static_dir
  local processing_files
  processing_files=$(find "$processing_static_dir" -type f 2>/dev/null || true)

   if [[ -z "$processing_files" ]]; then
    log_message "DEBUG" "No processing files found in $processing_static_dir — nothing to process."
    return 0
  fi

  while IFS= read -r processing_file; do
    log_message "DEBUG" "Processing nsupdate file: $processing_file"

    # Init context for zone and tsig_key
    local zone=""
    local tsig_key_file=""

    while IFS= read -r line || [[ -n "$line" ]]; do
      [[ -z "$line" ]] && continue

      case "$line" in
        zone=*)
          zone="$(echo "${line#zone=}" | sed -E 's/^"//; s/"$//')"
          log_message "DEBUG" "Zone set to: $zone"
          ;;

        tsig_key_file=*)
          tsig_key_file="$(echo "${line#tsig_key_file=}" | sed -E 's/^"//; s/"$//')"
          log_message "DEBUG" "TSIG key switched to: $tsig_key_file"
          ;;

        *)
          # Defensive: do not continue if zone or TSIG missing
          if [[ -z "$zone" || -z "$tsig_key_file" ]]; then
            log_message "ERROR" "Missing zone or TSIG for record: $line"
            continue
          fi

          # Parse DNS record: expect format -> domain ttl type value...
          local domain ttl type value
          read -r domain ttl type value <<< "$line"

          # Compose value: get all fields after the 3rd
          value="$(echo "$line" | cut -d' ' -f4-)"

          # Validate whether record exists already (calls dig with TSIG)
          validate_record "$domain" "$type" "$tsig_key_file"
          local status=$?

          if [[ $status -eq 1 ]]; then
            # Record does not exist >> simple add
            local instruction="update add $domain $ttl $type $value"
            write_nsupdate_instruction "$zone" "$tsig_key_file" "$instruction"
            log_message "DEBUG" "Prepared ADD: $instruction"

          elif [[ $status -eq 0 ]]; then
            # Record exists but may be outdated >> prepare delete/add instructions
            local instruction_delete="update delete $domain $type"
            local instruction_add="update add $domain $ttl $type $value"

            # Prepare safe file name
            local safe_tsig_name
            safe_tsig_name="$(basename "$tsig_key_file")"
            local nsupdate_file_target="$nsupdate_dir/${zone}_${safe_tsig_name}"

            # Check and add delete only if not already present
            if [[ ! -f "$nsupdate_file_target" ]] || ! grep -Fxq "$instruction_delete" "$nsupdate_file_target"; then
              write_nsupdate_instruction "$zone" "$tsig_key_file" "$instruction_delete"
              log_message "INFO" "Delete statement added: $instruction_delete"
            else
              log_message "DEBUG" "Delete statement already exists >> skipping: $instruction_delete"
            fi

            # Always add the updated record
            write_nsupdate_instruction "$zone" "$tsig_key_file" "$instruction_add"
            log_message "INFO" "update statement added: $instruction_delete + $instruction_add"

          elif [[ $status -eq 2 ]]; then
            # Record exists but fails DNSSEC (or other reason) >> skip
            log_message "WARNING" "Skipped record due to failed validation: $domain $type"

          elif [[ $status -eq 3 ]]; then
            # dig request status SERVFAIL >> skip
            log_message "WARNING" "Skipping record '$domain $type' due to SERVFAIL status — DNS query validation failed."
          fi

          ;;
      esac

    done < "$processing_file"

  done <<< "$processing_files"

  log_message "DEBUG" "Processing of nsupdate files completed."
}

# --------------------------------------------------------------------------------------------------
# Function: finalize_nsupdate_files
# --------------------------------------------------------------------------------------------------
# Purpose:
#   Ensures that each nsupdate file under $temp_file_dir/nsupdate_files ends with
#   'send' and 'answer' statements. This guarantees that nsupdate will process all
#   instructions and return results for logging.
#
# How it works:
#   - Loops over all files in the nsupdate output directory.
#   - Checks if 'send' and 'answer' exist at the end.
#   - Appends them only if missing.
#
# Uses:
#   - $temp_file_dir/nsupdate_files
# --------------------------------------------------------------------------------------------------

finalize_nsupdate_files() {
  local nsupdate_dir="$temp_file_dir/nsupdate_files"

  log_message "DEBUG" "Finalizing nsupdate files with 'send' and 'answer'..."

  # Find all files
  local nsupdate_files
  nsupdate_files=$(find "$nsupdate_dir" -type f ! -name "tsig_key_mapping.txt" 2>/dev/null || true)

  if [[ -z "$nsupdate_files" ]]; then
    log_message "DEBUG" "No nsupdate files found in $nsupdate_dir — nothing to finalize."
    return 0
  fi

  while IFS= read -r nsupdate_file; do
    local need_send=true
    local need_answer=true

    # Defensive: read last few lines for both checks
    if tail -n 5 "$nsupdate_file" | grep -Fxq "send"; then
      need_send=false
    fi

    if tail -n 5 "$nsupdate_file" | grep -Fxq "answer"; then
      need_answer=false
    fi

    # Append if needed
    if [[ "$need_send" == true ]]; then
      echo "send" >> "$nsupdate_file"
      log_message "DEBUG" "Appended 'send' >> $nsupdate_file"
    fi

    if [[ "$need_answer" == true ]]; then
      echo "answer" >> "$nsupdate_file"
      log_message "DEBUG" "Appended 'answer' >> $nsupdate_file"
    fi

    log_message "DEBUG" "Finalized: $nsupdate_file"

  done <<< "$nsupdate_files"

  log_message "INFO" "All nsupdate files finalized."
}

log_message "NOTICE" "------ Starting DNS Update Workflow ------"

if detect_and_prepare_deletes && process_nsupdate_adds_and_updates && finalize_nsupdate_files; then
  log_message "INFO" "------ DNS Update Workflow finished ------"
else
  log_message "ERROR" "DNS Update Workflow failed — check previous logs for details."
  exit 1
fi


# --------------------------------------------------------------------------------------------------
# Function: persist_and_version_processed_files
# --------------------------------------------------------------------------------------------------
# Purpose:
#   Persists all processed static DNS files to a persistent storage directory and
#   automatically versions them using Git. This ensures that all changes are tracked,
#   auditable, and recoverable.
#
# What it does:
#   - Expands any leading tilde (~) in the persistent directory path to an absolute path.
#   - Ensures the target directory exists; creates it if necessary.
#   - Checks whether any previously processed files exist (excluding the .git directory).
#   - Initializes a Git repository in the persistent directory if none exists.
#   - Copies all newly processed files from the temporary working directory to the persistent one.
#   - Stages and commits any changes to Git, but only if there are actual differences.
#
# How it works:
#   - Uses `mkdir -p` to safely create missing directories.
#   - Uses `find` to detect any existing files, ignoring `.git`.
#   - Uses `git -C` to run Git commands in the target directory without changing $PWD.
#   - Uses `cp -a` to preserve file attributes and structure.
#   - Commits are timestamped for traceability.
#
# Required variables (global):
#   - $persistent_processed_file_dir : Absolute path to the target persistent directory.
#   - $temp_file_dir                : Source directory containing newly processed files.
#   - $script_name                  : Used for Git user.name.
#   - $contact_mail                 : Used for Git user.email.
#
# Return value:
#   - Returns nothing explicitly; logs all actions.
#   - Exits with a non-zero code if an error occurs to ensure the caller knows to abort.
# --------------------------------------------------------------------------------------------------
persist_and_version_processed_files() {
  # -----------------------------------------------------------------------------
  # Step 0: Expand tilde (~) to absolute $HOME path if present.
  # -----------------------------------------------------------------------------
  persistent_processed_file_dir="${persistent_processed_file_dir/#\~/$HOME}"

  log_message "DEBUG" "Persisting processed files to: $persistent_processed_file_dir"

  # -----------------------------------------------------------------------------
  # Step 1: Ensure the target persistent directory exists.
  # -----------------------------------------------------------------------------
  if [[ ! -d "$persistent_processed_file_dir" ]]; then
    log_message "DEBUG" "Persistent directory does not exist — creating it: $persistent_processed_file_dir"
    mkdir -p "$persistent_processed_file_dir"
  fi

  # -----------------------------------------------------------------------------
  # Step 2: Check if any old files already exist (excluding .git).
  # -----------------------------------------------------------------------------
  local old_files
  old_files=$(find "$persistent_processed_file_dir" -type f ! -path "$persistent_processed_file_dir/.git/*" 2>/dev/null || true)

  if [[ -z "$old_files" ]]; then
    log_message "NOTICE" "No previous processed files found — first run or empty state."
  else
    log_message "DEBUG" "Found existing processed files — will overwrite where needed."
  fi

  # -----------------------------------------------------------------------------
  # Step 3: Initialize Git repository if it does not exist.
  # Ensures that the repository always uses 'master' as the default branch.
  # -----------------------------------------------------------------------------
  if [[ ! -d "$persistent_processed_file_dir/.git" ]]; then
    log_message "INFO" "No Git repository found — initializing new Git repository."

    # Initialise the Git repository
    git -C "$persistent_processed_file_dir" init

    # Force the branch name to 'master' robustly:
    # This works even if the default branch is different globally.
    # '-M' renames the current branch or creates it if needed.
    git -C "$persistent_processed_file_dir" branch -M master

    # Configure Git user details
    git -C "$persistent_processed_file_dir" config user.name "$script_name"
    git -C "$persistent_processed_file_dir" config user.email "$contact_mail"

    log_message "INFO" "Git repository initialized and forced to branch 'master'."
  else
    log_message "DEBUG" "Git repository already initialized."
    # Defensive: force branch name just in case someone renamed it.
    git -C "$persistent_processed_file_dir" branch -M master
    log_message "DEBUG" "Verified branch name: forced to 'master'."
  fi

  # -----------------------------------------------------------------------------
  # Step 4: Copy new processed files from temporary directory to persistent storage.
  # -----------------------------------------------------------------------------
  # Copy any other files in temp_file_dir that are NOT inside processing_static_file/
  # Example: zone files that are on top-level (like sandboxed.ch)
  find "$temp_file_dir/processing_static_file" -type f -exec cp -a {} "$persistent_processed_file_dir/" \;

  # -----------------------------------------------------------------------------
  # Step 5: Stage and commit all changes, but only if there are actual differences.
  # -----------------------------------------------------------------------------
  git -C "$persistent_processed_file_dir" add .

  if ! git -C "$persistent_processed_file_dir" diff --cached --quiet; then
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    git -C "$persistent_processed_file_dir" commit -m "Automated commit: Processed static files @ $timestamp"
    log_message "INFO" "Changes committed to Git."
  else
    log_message "INFO" "No changes detected — nothing to commit."
  fi
}

# -----------------------------------------------------------------------------
# Execute and handle errors
# -----------------------------------------------------------------------------
log_message "NOTICE" "------ Starting save new processed files persistent ------"
if persist_and_version_processed_files; then
  log_message "INFO" "------ Save new processed files persistent finished ------"
else
  log_message "ERROR" "Saving processed files failed — aborting."
  exit 1
fi

# ------------------------------------------------------------------------------------------------
  # Purpose:
  #   Iterates over all nsupdate instruction files in $temp_file_dir/nsupdate_files,
  #   finds the correct TSIG key for each file (from tsig_key_mapping.txt),
  #   executes nsupdate in verbose mode (-v) with TCP,
  #   and logs the entire output line by line.
  #
  # Requirements:
  #   - Each nsupdate file must contain proper 'server', 'zone', 'update', 'send', 'answer' statements.
  #   - The mapping file must have the format: <zonefile_basename>=<tsig_key_path>
  #
  # What it does:
  #   1. Loops through all files in nsupdate_files/ (except tsig_key_mapping.txt).
  #   2. Extracts the matching TSIG key for each file.
  #   3. Runs nsupdate -v -k <tsig_key_file> <nsupdate_file>.
  #   4. Captures and logs the complete output for auditing.
  #
  # Returns:
  #   0 on success, non-zero if any error occurs.
  #
  # ------------------------------------------------------------------------------------------------

upload_nsupdate_files() {
    log_message "NOTICE" "------ nsupdate upload started ------"

  local nsupdate_dir="$temp_file_dir/nsupdate_files"
  local mapping_file="$nsupdate_dir/tsig_key_mapping.txt"

  log_message "INFO" "Starting upload of all nsupdate files in: $nsupdate_dir"

  # Defensive check: the TSIG key mapping file must exist
  if [[ ! -f "$mapping_file" ]]; then
    log_message "ERROR" "TSIG key mapping file not found: $mapping_file"
    return 1
  fi

  # Loop over all nsupdate files except the mapping file
  while IFS= read -r ns_file; do
    # Skip the mapping file itself
    [[ "$(basename "$ns_file")" == "tsig_key_mapping.txt" ]] && continue

    local base_name
    base_name="$(basename "$ns_file")"

    # Extract the TSIG key file path for this file from the mapping
    local tsig_key_file
    tsig_key_file="$(grep "^${base_name}=" "$mapping_file" | cut -d'=' -f2)"

    if [[ -z "$tsig_key_file" ]]; then
      log_message "ERROR" "No TSIG key found for file: $base_name — skipping this file"
      continue
    fi

    log_message "INFO" "Uploading zone file with the command: nsupdate -v -k $tsig_key_file $ns_file"

    # Run nsupdate in verbose mode (-v) with the specified TSIG key
    # Note: nsupdate will use TCP automatically if needed due to '-v'
    local nsupdate_output
    nsupdate_output="$(nsupdate -v -k "$tsig_key_file" "$ns_file" 2>&1)"

    # Log each line of the output separately for clear log readability
    log_message "DEBUG" "nsupdate output for $base_name:"
    while IFS= read -r line; do
      log_message "DEBUG" "$line"
    done <<< "$nsupdate_output"

  done < <(find "$nsupdate_dir" -type f ! -name "tsig_key_mapping.txt")

  log_message "DEBUG" "All nsupdate uploads completed."
}

if upload_nsupdate_files; then
  log_message "INFO" "------ nsupdate upload finished ------"
else
  log_message "ERROR" "nsupdate upload failed!"
  exit 1
fi
