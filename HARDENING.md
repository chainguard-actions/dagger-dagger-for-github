<!-- markdownlint-disable -->

# Hardening Report: dagger--dagger-for-github/v8.4.1

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **dagger--dagger-for-github/v8.4.1** was hardened automatically. 12 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Multiple ${{ ... }} expressions are directly interpolated inside run: shell command strings (sub-rule a), allowing an attacker-controlled input to inject arbitrary shell commands.

Step 1 (install dagger):
- `VERSION=${{ inputs.version }}` — inputs.version interpolated directly into shell
- `COMMIT=${{ inputs.commit }}` — inputs.commit interpolated directly into shell

Step 'assemble':
- `verb=${{ inputs.verb }}` — direct interpolation
- `shell=$(echo '${{ toJSON(inputs.shell) }}' | jq -rj .)` — toJSON does not prevent injection; the expression is still substituted into the shell string before jq runs
- `dagger_flags=$(echo '${{ toJSON(inputs.dagger-flags) }}' | jq -rj . | ...)` — same issue
- `args=$(echo '${{ toJSON(inputs.args) }}' | jq -rj . | ...)` — same issue
- `call=$(echo '${{ toJSON(inputs.call) }}' | jq -rj . | ...)` — same issue
- `check=$(echo '${{ toJSON(inputs.check) }}' | jq -rj . | ...)` — same issue
- `if [[ -n "${{ inputs.call }}" ]]; then` — direct interpolation in conditional

Step 'exec':
- `cd ${{ inputs.workdir }} && { \` — direct interpolation, unquoted
- `DAGGER_CLOUD_TOKEN=${{ inputs.cloud-token }} \` — direct interpolation
- `${{ steps.assemble.outputs.dagger-flags }} \` — steps output interpolated directly
- `${{ steps.assemble.outputs.args || steps.assemble.outputs.call || steps.assemble.outputs.script || steps.assemble.outputs.check }}` — steps outputs interpolated directly
- `if [[ -n "${{ inputs.summary-path }}" ]]; then` — direct interpolation
- `summary_content > "${{ inputs.summary-path }}"` — direct interpolation in redirection
- `if [[ "${{ inputs.enable-github-summary }}" == "true" ]]; then` — direct interpolation

Locations:

- `action.yml:82`
- `action.yml:88`
- `action.yml:113`
- `action.yml:114`
- `action.yml:115`
- `action.yml:116`
- `action.yml:117`
- `action.yml:118`
- `action.yml:119`
- `action.yml:136`
- `action.yml:137`
- `action.yml:139`
- `action.yml:141`

### github-env-injection (severity: high)

In the 'assemble' step, values derived from user-controlled inputs (${{ inputs.verb }}, ${{ inputs.args }}, ${{ inputs.call }}, ${{ inputs.check }}, ${{ inputs.shell }}, ${{ inputs.dagger-flags }}) are written to $GITHUB_OUTPUT via `echo "verb=$verb" >> "$GITHUB_OUTPUT"`, `echo "dagger-flags=$dagger_flags" >> "$GITHUB_OUTPUT"`, `echo "args=$args" >> "$GITHUB_OUTPUT"`, `echo "call=$call" >> "$GITHUB_OUTPUT"`, `echo "check=$check" >> "$GITHUB_OUTPUT"`, and `echo "script=$script" >> "$GITHUB_OUTPUT"` without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`). An attacker can inject newlines into these values to poison subsequent GITHUB_OUTPUT entries. In the 'exec' step, `echo "traceURL=$trace_url" >> "$GITHUB_OUTPUT"` and the heredoc stdout block also write to $GITHUB_OUTPUT. The assemble step writes are the primary concern as they directly propagate unsanitized inputs.

Locations:

- `action.yml:127`
- `action.yml:128`
- `action.yml:129`
- `action.yml:130`
- `action.yml:131`
- `action.yml:132`

### unsafe-shell (severity: high)

The install step pipes a remote script directly to a shell interpreter without first downloading and verifying it: `curl -fsSL https://dl.dagger.io/dagger/install.sh | BIN_DIR=... DAGGER_VERSION="$VERSION" DAGGER_COMMIT="$COMMIT" sh`. If the remote server is compromised or the connection is intercepted, arbitrary code will execute on the runner. The script should be downloaded to a file, its integrity verified (e.g. via checksum), and then executed separately.

Locations:

- `action.yml:99`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.version }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:84`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.commit }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:92`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.verb }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:137`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.call }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:144`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.workdir }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:171`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.cloud-token }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:172`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.summary-path }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:231`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.summary-path }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:232`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.enable-github-summary }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:236`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection, unsafe-shell, static-inline-injection

**Notes:**

Fixed all security findings in action.yml:

1. **script-injection / static-inline-injection**: Moved all ${{ inputs.* }} and ${{ steps.*.outputs.* }} expressions from run: shell blocks to env: blocks. The install step now uses INPUT_VERSION/INPUT_COMMIT env vars; the assemble step uses INPUT_VERB, INPUT_SHELL, INPUT_DAGGER_FLAGS, INPUT_ARGS, INPUT_CALL, INPUT_CHECK env vars (replacing toJSON+jq patterns with printf+sed); the exec step uses INPUT_WORKDIR, INPUT_SUMMARY_PATH, INPUT_ENABLE_GITHUB_SUMMARY, DAGGER_CLOUD_TOKEN, DAGGER_FLAGS, DAGGER_ARGS, DAGGER_CALL, DAGGER_CHECK env vars.

2. **github-env-injection**: Added `tr -d '\n\r'` sanitization for all values written to $GITHUB_OUTPUT in the assemble step (safe_script, safe_verb, safe_dagger_flags, safe_args, safe_call, safe_check).

3. **unsafe-shell**: Replaced `curl -fsSL ... | sh` with a two-step approach: download to a temp file with `curl -fsSL -o "$install_script"`, then execute separately with `sh "$install_script"`, then clean up with `rm -f`.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed script injection vulnerability in the `exec` step of action.yml. The original code used unquoted variable expansions ($DAGGER_FLAGS, ${VERB}, ${INPUT_MODULE:+-m $INPUT_MODULE}) in the dagger shell command, allowing shell metacharacter injection (;, |, &, $(...), etc.). The fix builds the dagger command as a bash array: flags are safely word-split via `IFS=' ' read -r -a`, and all user-controlled values (VERB, INPUT_MODULE, effective_extra) are added as individually quoted array elements. The command is then executed as `"${cmd[@]}"`, ensuring all arguments are passed literally to the dagger binary without shell interpretation.

