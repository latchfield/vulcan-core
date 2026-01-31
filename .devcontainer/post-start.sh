#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Latchfield Technologies http://latchfield.com

set -o errexit
set -o nounset

log() {
    echo "(${0##*/}) $*"
}

sudo service cron start

# Configure automatic git commit signing using SSH agent key if available
if [ -z "$(git config gpg.format)" ]; then
    key_count=$(ssh-add -L | wc -l || true)
    signing_key=""

    if [ "$key_count" -eq 1 ]; then
        signing_key="$(ssh-add -L)"
    elif [ "$key_count" -gt 1 ]; then
        gsks=$(ssh-add -L | awk '{print $3}' | grep -E "^.*-gsk$" | head -n 1)
        gsks_count=$(echo "$gsks" | wc -l || true)
        if [ "$gsks_count" -eq 1 ]; then
            signing_key=$(ssh-add -L | awk -v key="$gsks" '$3 == key')
        else
            log "WARNING: More than one SSH key found in SSH agent. Ensure only one key is loaded or suffixed with '-gsk' for git signing. Skipping git commit signing configuration."
        fi
    else
        log "No SSH agent keys found. Skipping git commit signing configuration."
    fi

    if [ -n "$signing_key" ]; then
        set -o xtrace
        git config --global gpg.format ssh
        git config --global user.signingkey "$signing_key"
        git config --global commit.gpgsign true
        git config --global core.pager cat
        set +o xtrace
        log "INFO: Git commit signing configured with the SSH key from SSH agent."
    fi
else
    log "INFO: Git signing already configured, skipping SSH signing configuration."
fi

# Configure uv if installed and pyproject.toml exists
if command -v uv >/dev/null 2>&1 && [ -f pyproject.toml ]; then
    set -o xtrace
    uv sync --all-extras
    set +o xtrace    
else
    log "WARNING: uv command not found or pyproject.toml not present. This may be expected depending on the project type."
fi