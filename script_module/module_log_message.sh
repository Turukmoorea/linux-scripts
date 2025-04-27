#!/bin/bash

# ============================================================================================================
# Central Logging Module for Bash Scripts
# ------------------------------------------------------------------------------------------------------------
# This module provides a centralized and reusable logging function for Bash scripts. It enables consistent,
# structured log output with log levels (based on syslog), optional console color output, and script-specific
# configuration – ideal for use in personal tools or team-wide scripts.
#
# Usage:
# 1. Source this module in your script:
#      source /path/to/logging.sh
#    OR load it dynamically:
#      source <(curl -s source <(curl -s https://raw.githubusercontent.com/Turukmoorea/linux-scripts/refs/heads/master/script_module/module_log_message.sh))
#
# 2. In your main script, define the following optional variables:
#      logfile="/var/log/my_script.log"              # Path to your logfile (required!)
#      log_level="INFO"                              # Minimum log level to log (default: NOTICE)
#      verbose=true                                  # Also print logs to console (stdout)
#      log_prefix="MyScript"                           # Optional name prefix in log lines (default: script name)
#
# 3. Call the logger like this:
#      log_message "INFO" "Script started"
#      log_message "ERROR" "Something went wrong"
#
# Output format:
#   2025-04-06T14:22:33+0200 MyTool[INFO]: Line:23 (main) Something happened
#
# Console output (if verbose=true) is colorized when running interactively.
#    Red for errors, yellow for warnings, green for info, etc.
#
# Log levels (based on syslog):
#   EMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFO, DEBUG
#
# License:
#   This snippet is free to use, modify, and distribute.
#
#
# Logging ===========================================================================================================================================

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

    # Ensure logfile variable is set before continuing
    if [[ -z "$log_file" ]]; then
        echo "ERROR: logfile variable is not set." >&2
        exit 1
    fi

    # Ensure the directory where the logfile should be written is writable.
    if [[ ! -w "$(dirname "$logfile")" ]]; then
        echo "ERROR: Cannot write to logfile location: $logfile" >&2
        exit 1
    fi

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
