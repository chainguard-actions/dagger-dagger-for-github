<!-- markdownlint-disable -->

# Hardening Report: dagger--dagger-for-github/v8.4.1

> This file was generated automatically by the hardening agent.

**Policy SHA:** `374911c4be584df24e6da57af2d990570ef0f859`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **dagger--dagger-for-github/v8.4.1** was hardened automatically. 16 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Install step (composite step 1). Rule (a): expressions are put straight into the run: script with no quotes. Offending lines: `VERSION=${{ inputs.version }}` (line 83) and `COMMIT=${{ inputs.commit }}` (line 91). Rule (b): `BIN_DIR=${prefix_dir}/bin` (line 110) expands the inherited RUNNER_TEMP value without quotes.

Locations:

- `action.yml:83`
- `action.yml:91`
- `action.yml:110`

### script-injection (severity: high)

Step 'assemble'. Rule (a): input expressions are put straight into the run: script. Offending lines: `verb=${{ inputs.verb }}` (line 136); `shell=$(echo '${{ toJSON(inputs.shell) }}' | jq -rj .)` (line 137); the same `echo '${{ toJSON(inputs.dagger-flags|args|call|check) }}'` pattern on lines 139-142; and `if [[ -n "${{ inputs.call }}" ]]` (line 143). toJSON output inside single quotes can still break out of the quotes if the value contains a single quote. Rule (b): `printf '%s' "$shell" > $script` (line 152) leaves $script unquoted.

Locations:

- `action.yml:136`
- `action.yml:137`
- `action.yml:139`
- `action.yml:140`
- `action.yml:141`
- `action.yml:142`
- `action.yml:143`

### script-injection (severity: high)

Step 'exec'. Rule (a): `cd ${{ inputs.workdir }}` (line 170); `DAGGER_CLOUD_TOKEN=${{ inputs.cloud-token }}` (line 171); `${{ steps.assemble.outputs.dagger-flags }}` (line 173); `${{ steps.assemble.outputs.args || ...call || ...script || ...check }}` (lines 176 and 199); `if [[ -n "${{ inputs.summary-path }}" ]]` / `summary_content > "${{ inputs.summary-path }}"` (lines 230-231); `if [[ "${{ inputs.enable-github-summary }}" == "true" ]]` (line 235). Rule (b): `${VERB}` (line 174) is unquoted, and `${INPUT_MODULE:+-m $INPUT_MODULE}` (line 175) expands $INPUT_MODULE unquoted inside the guard. The safe guarded form would be `${INPUT_MODULE:+-m "$INPUT_MODULE"}`.

Locations:

- `action.yml:170`
- `action.yml:171`
- `action.yml:173`
- `action.yml:174`
- `action.yml:175`
- `action.yml:176`
- `action.yml:199`
- `action.yml:230`
- `action.yml:231`
- `action.yml:235`

### github-env-injection (severity: high)

Step 'assemble' writes values derived from inputs to $GITHUB_OUTPUT without the `printf '%s' ... | tr -d '\n\r'` step: `echo "script=$script"`, `echo "verb=$verb"` (verb comes from inputs.verb and nothing is stripped), and `echo "dagger-flags=$dagger_flags"`, `echo "args=$args"`, `echo "call=$call"`, `echo "check=$check"` (lines 154-159). Those last values only go through `sed -z 's/\n/ /g'`, which does not remove carriage returns (\r) and is not the required pipeline.

Locations:

- `action.yml:155`
- `action.yml:156`
- `action.yml:157`
- `action.yml:158`
- `action.yml:159`

### github-env-injection (severity: high)

Step 'exec' writes dagger stdout, which depends on the inputs, to $GITHUB_OUTPUT as a multi-line heredoc. The delimiter is `delim="$(sha256sum $tmpout | cut -d " " -f1)"` (line 182): a hash of the output itself, not a value from a cryptographically secure random source (/dev/urandom, openssl rand, uuidgen). It is deterministic, so it does not meet the random-delimiter exception. The delimiter should come from e.g. `od -An -N16 -tx1 /dev/urandom`.

Locations:

- `action.yml:182`
- `action.yml:187`

### unsafe-shell (severity: high)

The remote install script is piped straight into a shell: `curl -fsSL https://dl.dagger.io/dagger/install.sh | \ BIN_DIR=... sh` (lines 109-110). The script should be downloaded to a file, ideally checksum-verified, and then run as a separate step.

Locations:

- `action.yml:109`

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

### prior-fix (severity: high)

Carried forward from this version's previous harden, which fixed it; fix it again unless the code no longer has the problem. The previous harden changed action.yml without recording a finding for it, and this analysis reported nothing there. Re-apply its security changes unless the code no longer needs them. The previous patch:
```diff
diff --git a/action.yml b/action.yml
index a77955c..425daca 100644
--- a/action.yml
+++ b/action.yml
@@ -67,7 +67,27 @@ outputs:
 runs:
   using: "composite"
   steps:
     - shell: bash
+      env:
+        INPUT_VERSION: ${{ inputs.version }}
+        INPUT_COMMIT: ${{ inputs.commit }}
       run: |
         set -o pipefail
         # Fallback to /usr/local for backwards compatability
@@ -76,12 +96,12 @@ runs:
         if [[ ! -d "$prefix_dir" ]] || [[ ! -w "$prefix_dir" ]]; then
             prefix_dir="$(mktemp -d)"
         fi
-        printf '%s/bin' "$prefix_dir" >> $GITHUB_PATH
+        printf '%s/bin' "$prefix_dir" >> "$GITHUB_PATH"
 
         # If the dagger version is 'latest', set the version back to an empty
         # string. This allows the install script to detect and install the latest
         # version itself
-        VERSION=${{ inputs.version }}
+        VERSION="$INPUT_VERSION"
         if [[ "$VERSION" == "latest" ]]; then
           VERSION=
         elif [[ -n "$VERSION" && "$VERSION" != v* ]]; then
@@ -89,7 +109,7 @@ runs:
           VERSION="v$VERSION"
         fi
 
-        COMMIT=${{ inputs.commit }}
+        COMMIT="$INPUT_COMMIT"
 
         if [[ -x "$(command -v dagger)" ]]; then
           echo "::group::Checking dagger"
@@ -107,10 +127,10 @@ runs:
         fi
 
         echo "::group::Installing dagger"
-        curl -fsSL https://dl.dagger.io/dagger/install.sh | \
-        BIN_DIR=${prefix_dir}/bin DAGGER_VERSION="$VERSION" DAGGER_COMMIT="$COMMIT" sh
+        INSTALL_SCRIPT="$(mktemp)"
+        curl -fsSL https://dl.dagger.io/dagger/install.sh -o "$INSTALL_SCRIPT"
+        BIN_DIR="${prefix_dir}/bin" DAGGER_VERSION="$VERSION" DAGGER_COMMIT="$COMMIT" sh "$INSTALL_SCRIPT"
         echo "::endgroup::"
-
     - id: should-exec
       shell: bash
       env:
@@ -133,15 +153,22 @@ runs:
       shell: bash
       env:
         INPUT_MODULE: ${{ inputs.module }}
+        INPUT_VERB: ${{ inputs.verb }}
+        INPUT_SHELL_JSON: ${{ toJSON(inputs.shell) }}
+        INPUT_DAGGER_FLAGS_JSON: ${{ toJSON(inputs.dagger-flags) }}
+        INPUT_ARGS_JSON: ${{ toJSON(inputs.args) }}
+        INPUT_CALL_JSON: ${{ toJSON(inputs.call) }}
+        INPUT_CHECK_JSON: ${{ toJSON(inputs.check) }}
+        INPUT_CALL: ${{ inputs.call }}
       run: |
-        verb=${{ inputs.verb }}
-        shell=$(echo '${{ toJSON(inputs.shell) }}' | jq -rj .)
+        verb="$INPUT_VERB"
+        shell=$(printf '%s' "$INPUT_SHELL_JSON" | jq -rj .)
         # Collapse backslash-continuations and newlines into spaces for CLI args
-        dagger_flags=$(echo '${{ toJSON(inputs.dagger-flags) }}' | jq -rj . | sed -z 's/\\\n/ /g; s/\n/ /g')
-        args=$(echo '${{ toJSON(inputs.args) }}' | jq -rj . | sed -z 's/\\\n/ /g; s/\n/ /g')
-        call=$(echo '${{ toJSON(inputs.call) }}' | jq -rj . | sed -z 's/\\\n/ /g; s/\n/ /g')
-        check=$(echo '${{ toJSON(inputs.check) }}' | jq -rj . | sed -z 's/\\\n/ /g; s/\n/ /g')
-        if [[ -n "${{ inputs.call }}" ]]; then
+        dagger_flags=$(printf '%s' "$INPUT_DAGGER_FLAGS_JSON" | jq -rj . | sed -z 's/\\\n/ /g; s/\n/ /g')
+        args=$(printf '%s' "$INPUT_ARGS_JSON" | jq -rj . | sed -z 's/\\\n/ /g; s/\n/ /g')
+        call=$(printf '%s' "$INPUT_CALL_JSON" | jq -rj . | sed -z 's/\\\n/ /g; s/\n/ /g')
+        check=$(printf '%s' "$INPUT_CHECK_JSON" | jq -rj . | sed -z 's/\\\n/ /g; s/\n/ /g')
+        if [[ -n "$INPUT_CALL" ]]; then
           verb="call"
         elif [[ -n "$check" ]]; then
           verb="check"
@@ -152,12 +179,18 @@ runs:
           script=$(mktemp)
           printf '%s' "$shell" > $script
         fi
-        echo "script=$script" >> "$GITHUB_OUTPUT"
-        echo "verb=$verb" >> "$GITHUB_OUTPUT"
-        echo "dagger-flags=$dagger_flags" >> "$GITHUB_OUTPUT"
-        echo "args=$args" >> "$GITHUB_OUTPUT"
-        echo "call=$call" >> "$GITHUB_OUTPUT"
-        echo "check=$check" >> "$GITHUB_OUTPUT"
+        safe_script=$(printf '%s' "$script" | tr -d '\n\r')
+        safe_verb=$(printf '%s' "$verb" | tr -d '\n\r')
+        safe_dagger_flags=$(printf '%s' "$da
... (truncated)
```

Locations:

- `action.yml`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection, unsafe-shell, static-inline-injection, prior-fix

**Notes:**

Changes to action.yml, step by step:

- Install step: inputs.version and inputs.commit now come in through env: (INPUT_VERSION, INPUT_COMMIT) and are assigned quoted. The GITHUB_PATH write is quoted and has newlines stripped. BIN_DIR is quoted. install.sh is downloaded to a mktemp file with curl -o, run with `sh "$INSTALL_SCRIPT"` (it takes no arguments, so there is no -s or -- to drop), then deleted.

- Assemble step: verb, the toJSON values for shell, dagger-flags, args, call and check, and call itself now come in through env:. The JSON values are piped to jq with `printf '%s' "$VAR"`, which removes the single-quote breakout. $script is quoted. Every GITHUB_OUTPUT value goes through `printf '%s' ... | tr -d '\n\r'` before it is written.

- Exec step: workdir, cloud-token, dagger-flags, the combined args/call/script/check value, summary-path and enable-github-summary all come in through env:. Upstream pasted dagger-flags and the combined args value straight into the script, so the shell split them and honored quotes. They are now split the same way with the quote-aware xargs method (guarded by an empty check, with `xargs -r true` to catch an unmatched quote, and the built-in printf run through sh -c), and passed to dagger as arrays. VERB is passed as `${VERB:+"$VERB"}` and the module as `${INPUT_MODULE:+-m "$INPUT_MODULE"}`. The cloud token is still set only for the dagger command, as upstream did. The stdout heredoc delimiter, previously a sha256 of the output, is now random from /dev/urandom.

One behaviour change: if dagger-flags or args contain shell syntax such as $VAR or $(...), it is now passed to dagger as literal text instead of being expanded. That is the injection being closed, but anyone who relied on that expansion will see a difference. I made no test runs.

