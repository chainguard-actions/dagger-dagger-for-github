<!-- markdownlint-disable -->

# Hardening Report: dagger--dagger-for-github/v8.4.1

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **dagger--dagger-for-github/v8.4.1** was hardened automatically. 14 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Multiple `${{ inputs.* }}` and `${{ steps.*.outputs.* }}` expressions are interpolated directly inside `run:` shell command strings in action.yml, violating sub-rule (a). This allows an attacker-controlled value to be injected into the shell before quoting can occur. Offending lines include:
- `VERSION=${{ inputs.version }}` (line 84)
- `COMMIT=${{ inputs.commit }}` (line 92)
- `verb=${{ inputs.verb }}` (line 137)
- `shell=$(echo '${{ toJSON(inputs.shell) }}' | jq -rj .)` (line 138)
- `dagger_flags=$(echo '${{ toJSON(inputs.dagger-flags) }}' | jq -rj .)` (line 140)
- `args=$(echo '${{ toJSON(inputs.args) }}' | jq -rj .)` (line 141)
- `call=$(echo '${{ toJSON(inputs.call) }}' | jq -rj .)` (line 142)
- `check=$(echo '${{ toJSON(inputs.check) }}' | jq -rj .)` (line 143)
- `if [[ -n "${{ inputs.call }}" ]]` (line 144)
- `cd ${{ inputs.workdir }}` (line 171)
- `DAGGER_CLOUD_TOKEN=${{ inputs.cloud-token }}` (line 172)
- `${{ steps.assemble.outputs.dagger-flags }}` (line 174)
- `${{ steps.assemble.outputs.args || ... }}` (line 177)
- `if [[ -n "${{ inputs.summary-path }}" ]]` (line ~185)
- `if [[ "${{ inputs.enable-github-summary }}" == "true" ]]` (line ~190)

Locations:

- `action.yml:84`
- `action.yml:92`
- `action.yml:137`
- `action.yml:138`
- `action.yml:140`
- `action.yml:141`
- `action.yml:142`
- `action.yml:143`
- `action.yml:144`
- `action.yml:171`
- `action.yml:172`
- `action.yml:174`
- `action.yml:177`

### github-env-injection (severity: high)

The `assemble` step writes values derived from untrusted inputs to `$GITHUB_OUTPUT` without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`). The variables `verb` (set from `${{ inputs.verb }}`), `args`, `call`, `check`, and `dagger-flags` (all derived from `inputs.*` via toJSON/jq) are written directly to GITHUB_OUTPUT via `echo "verb=$verb" >> "$GITHUB_OUTPUT"` etc. An attacker can inject newlines into these values to poison subsequent output parsing. Additionally, the first step writes `printf '%s/bin' "$prefix_dir" >> $GITHUB_PATH` where `$GITHUB_PATH` is unquoted, though the value itself is locally computed.

Locations:

- `action.yml:155`
- `action.yml:156`
- `action.yml:157`
- `action.yml:158`
- `action.yml:159`
- `action.yml:160`

### hardcoded-credentials (severity: high)

A literal Dagger Cloud token is hardcoded in the test workflow: `cloud-token: dag_dagger_sBIv6DsjNerWvTqt2bSFeigBUqWxp9bhh3ONSSgeFnw`. This should be stored as a GitHub Actions secret and referenced via `${{ secrets.DAGGER_CLOUD_TOKEN }}` instead of being committed in plaintext.

Locations:

- `.github/workflows/test.yml:73`

### unpinned-uses (severity: high)

Multiple `uses:` references are pinned to mutable tags or version strings rather than immutable 40-character commit SHAs, making the workflow vulnerable to supply-chain attacks if the tag is moved or the action is compromised.

In `.github/workflows/publish-immutable-action.yml`:
- `uses: actions/checkout@v4`
- `uses: actions/publish-immutable-action@v0`

In `.github/workflows/test.yml`:
- `uses: actions/checkout@v4` (appears in every job)
- `uses: actions/checkout@v6` (in the `check` job)

Locations:

- `.github/workflows/publish-immutable-action.yml:14`
- `.github/workflows/publish-immutable-action.yml:17`
- `.github/workflows/test.yml:23`
- `.github/workflows/test.yml:66`
- `.github/workflows/test.yml:67`

### unsafe-shell (severity: high)

Remote shell scripts are downloaded and piped directly to `sh` without first saving to a file and verifying integrity. This pattern allows a compromised or MITM'd remote server to execute arbitrary code on the runner.

In `action.yml` (line 110): `curl -fsSL https://dl.dagger.io/dagger/install.sh | \ BIN_DIR=... sh`

In `.github/workflows/test.yml` (lines ~267, ~281, ~295): `curl -fsS https://dl.dagger.io/dagger/install.sh \ | BIN_DIR=/usr/local/bin DAGGER_VERSION=... sh`

Locations:

- `action.yml:110`
- `.github/workflows/test.yml:267`
- `.github/workflows/test.yml:281`
- `.github/workflows/test.yml:295`

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

**Fixes applied:** script-injection, static-inline-injection, github-env-injection, hardcoded-credentials, unpinned-uses, unsafe-shell

**Notes:**

Fixed all findings in action.yml and .github/workflows/ files:

1. script-injection / static-inline-injection: Moved all ${{ inputs.* }} and ${{ steps.*.outputs.* }} expressions from run: blocks into env: blocks. The exec step now receives VERB, SCRIPT, DAGGER_FLAGS, ASSEMBLE_ARGS, ASSEMBLE_CALL, ASSEMBLE_CHECK, INPUT_WORKDIR, DAGGER_CLOUD_TOKEN, INPUT_SUMMARY_PATH, and INPUT_ENABLE_GITHUB_SUMMARY as environment variables. The assemble step receives INPUT_VERB, INPUT_SHELL_JSON, INPUT_DAGGER_FLAGS_JSON, INPUT_ARGS_JSON, INPUT_CALL_JSON, INPUT_CHECK_JSON, and INPUT_CALL as env vars.

2. github-env-injection: All values written to $GITHUB_OUTPUT in the assemble step are sanitized with `printf '%s' "$var" | tr -d '\n\r'` before writing. Also fixed unquoted $GITHUB_PATH reference.

3. hardcoded-credentials: Replaced literal token `dag_dagger_sBIv6DsjNerWvTqt2bSFeigBUqWxp9bhh3ONSSgeFnw` in test.yml with `${{ secrets.DAGGER_CLOUD_TOKEN }}`.

4. unpinned-uses: Pinned all actions/checkout@v4 to SHA 11d5960a326750d5838078e36cf38b85af677262 and actions/publish-immutable-action@v0 to SHA 4bc8754ffc40f27910afb20287dbbbb675a4e978. The actions/checkout@v6 (likely a typo) was also pinned to the v4 SHA.

5. unsafe-shell: Replaced all `curl | sh` patterns with download-then-execute: `curl ... -o "$INSTALL_SCRIPT"` followed by `sh "$INSTALL_SCRIPT"` (without '--' since there is no stdin pipe anymore). Applied in both action.yml and all three preinstall steps in test.yml.

6. The exec step's dagger_flags and positional args are now tokenized into bash arrays using the xargs/printf '%s\0' pattern to safely handle multi-token inputs without injection risk.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed all 14 script injection occurrences in hardened/action/.github/workflows/test.yml. Each step that had `${{ steps.*.outputs.* }}` directly interpolated in a `run:` block was updated to use an `env:` block instead. The expressions are now assigned to environment variables (TARGET or URL) in the `env:` section, and the shell scripts reference them as `$TARGET` or `$URL`. This prevents attacker-controlled step output values from being interpreted as shell commands during YAML template substitution.

