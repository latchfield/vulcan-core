#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Latchfield Technologies

set -o errexit
set -o nounset

if [ -f template-configuration-needed ]; then
    echo "WARNING: This repo was created from a template. \nAfter configuring the pyproject.toml, remove the 'template-configuration-needed' file project root and rebuild the devcontainer.\n"
    exit 1
fi

# Configure poetry if installed and pyproject.toml exists
if command -v poetry >/dev/null 2>&1 && [ -f pyproject.toml ]; then
    set -o xtrace
    poetry install --all-extras
    set +o xtrace    
else
    echo "Poetry not found or pyproject.toml not present."
fi