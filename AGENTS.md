## Shell Script Development Standards (v2.0)

The following standards are non-negotiable for `dev-harden`.

### 1. The Header: No More `sh` From the 80s
Use `bash` via `env` for portability. We need modern features like arrays and local scoping.
```bash
#!/usr/bin/env bash
set -o errexit   # -e: Abort on nonzero exitstatus
set -o nounset   # -u: Abort on unbound variable
set -o pipefail  # Don't hide errors within pipes
IFS=$'\n\t'      # Stop splitting on spaces like a maniac
```

### 2. Scoping & Immutability (Functional-ish)
- **Global Constants:** Always `readonly`. Use `UPPER_CASE`.
- **Functions:** Every variable MUST be `local`. No global state soup.
- **Returns:** Use `return` for status codes, `echo` to "return" data via command substitution.
- **Early Returns:** Guard clauses are your friend. Flatten the control flow. If I see more than 3 levels of indentation, I'm quitting.

### 3. Syntax & Safety
- **Conditionals:** Always use `[[ ... ]]`, not `[ ... ]`. It's safer and less likely to blow up on empty strings.
- **Arithmetic:** Use `(( ... ))` for numeric comparisons and math.
- **Subshells:** Use `$(...)`, never backticks. It's not 1985.
- **Quoting:** Quote EVERYTHING. `"${var}"`, not `$var`. No exceptions.
- **Tool Checks:** Use `command -v tool_name` to check for dependencies. `which` is for people who don't care about portability.

### 4. Logging & Error Handling
- **Die Early:** Use a `die()` function for fatal errors.
- **Stderr:** All logging (info, warn, error) goes to `stderr` (`>&2`). `stdout` is reserved for data/results.
- **XDG Compliance:** Respect `${XDG_CONFIG_HOME:-$HOME/.config}`. Don't just dump files in `$HOME`.
- **Temp Files:** Use `mktemp -t` or `mktemp -d`. Clean them up using a `trap`.

### 5. Portability (The macOS/Linux Divide)
- Avoid `sed -i` (it's different on macOS and Linux). Use a temporary file and `mv`.
- Use `printf` instead of `echo -e` or `echo -n`.
- Test on both `bash` 3.2 (macOS default) and 5.x (modern Linux).

### 6. Verification
- All scripts MUST pass `shellcheck`. If it's yellow or red, fix it.
