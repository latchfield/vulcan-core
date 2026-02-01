#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Latchfield Technologies http://latchfield.com

set -o errexit
set -o nounset

log() {
    echo "(${0##*/}) $*"
}

if [ -f template-configuration-needed ]; then
    log "WARNING: This repo was created from a template. \nAfter configuring the pyproject.toml, remove the 'template-configuration-needed' file project root and rebuild the devcontainer.\n"
    exit 1
fi

# Ensure shared cache is owned by vscode user
set +e
if mountpoint -q "${WORKSPACE}/../.cache"; then
    sudo chown vscode:vscode "${WORKSPACE}/../.cache"
else
    log "WARNING: Shared cache mount not found: ${WORKSPACE}/../.cache. Creating local .cache directory."
    sudo mkdir -p ${WORKSPACE}/../.cache
    sudo chown vscode:vscode ${WORKSPACE}/../.cache
fi
chown_rc=$?
set -e

if [ "$chown_rc" -ne 0 ]; then
    log "WARNING: failed to set ownership of shared cache directory; continuing."
fi

log "INFO: Installing 'uv' package manager..."
UV_VERSION=$(grep -Po 'required-version\s*=\s*"\K[^"]*' pyproject.toml 2>/dev/null || echo "==0.9.*")
pipx install -f "uv${UV_VERSION}"