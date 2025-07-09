# Bash Script Conventions

## 1. Script Header

A Bash script must always include a detailed header block before the actual code. This should include:

* **Script Name:** Unique name of the script.
* **Author:** Responsible person(s). (usually Turukmoorea)
* **Contact:** Email address or other contact option. (usually [mail@turukmoorea.ch](mailto:mail@turukmoorea.ch))
* **Repository Link:** Link to a public repository. (usually [https://github.com/Turukmoorea/](https://github.com/Turukmoorea/)...)
* **Last Update Date:** Date of the last modification.
* **License and Terms of Use:** Legal notes on usage. (usually unlicense license)
* **Detailed Function Description:** Purpose, features, requirements.
* **Usage:** Examples for calls, options, parameters.
* **Global Variables:** List and explain all global variables with example values and recommended defaults.
* **Dependencies:** List all external tools, modules, or files required.

The header may be multilingual, but all further comments must be written in English only.

---

## 2. Inline Comments

* Each relevant block must have single or multi-line English block comments:

  ```bash
  # ------------------------------------------------------------
  # This block performs input validation for user arguments.
  # It ensures no empty values are passed to the main logic.
  # Edge cases are handled by rejecting invalid inputs.
  # ------------------------------------------------------------
  ```

* Non-trivial single lines should be commented inline:

  ```bash
  echo "$result"  # Output the computed result to stdout
  ```

* Comments should always explain:

  * What the block does.
  * Why it is implemented this way.
  * Possible side effects or constraints.

---

## 3. Function Header

Each function must have a detailed English docstring block and should be kept as granular as possible to improve code clarity, even if each function is only slightly separated.

```bash
# ------------------------------------------------------------
# Function: cleanup
# Purpose : Remove temporary files and restore system state.
#
# Description:
#   Called automatically on script exit or interruption.
#   Deletes debug artefacts and closes open file descriptors.
#
# Parameters:
#   None
#
# Returns:
#   None
#
# Globals:
#   TMP_DIR - Location of temporary debug files.
#
# Notes:
#   Must be robust to handle partial execution states.
# ------------------------------------------------------------
```

---

## 4. Logging Principle

* Logging must use a consistent `log_message` function.
* Supported log levels: DEBUG, INFO, NOTICE, WARNING, ERROR.
* Debug mode raises logging level to DEBUG.
* Logging output can go only to a logfile or optionally be mirrored live to the console using a `verbose` flag.
* Failing commands must be logged with the exact command, exit status, and debug information.

---

## 5. Error Handling

* Strict safety setup:

  ```bash
  set -euo pipefail
  ```

  * `-e`: Exit script on any error.
  * `-u`: Treat unset variables as errors.
  * `pipefail`: Failures in pipelines are correctly propagated.

* Cleanup using trap:

  ```bash
  trap cleanup EXIT INT TERM
  ```

* `cleanup` safely stores debug artefacts such as RAM files, logs, and symlinks.

---

## 6. Debug Environment

* Reproducible debug folders must include:

  * Linked original files
  * Temporary copies
  * Persistent directories as symlinks or copies
  * Complete log files

* Always use a numerically sorted structure (`01_`, `02_`, ...) for clarity.

---

## 7. Use of External Modules

* Reusable functions like `log_message` should be included modularly using `source`:

  ```bash
  source <(curl -s https://example.org/bash-modules/logging.sh)
  ```

* This keeps the main script readable and modularly maintainable.
