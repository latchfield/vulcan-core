# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Latchfield Technologies http://latchfield.com

default:
    @just --list --justfile {{justfile()}}

# Python versions from pyvers.py script
py_vers_all := `python3 utils/pyvers.py -a`
py_vers_lowest := `python3 utils/pyvers.py -m`

warm_uv_cache:
    @echo 'Warming package cache for Python versions: {{py_vers_all}}\n'
    @for version in {{py_vers_all}}; do \
        echo '{{BOLD + CYAN}}UV sync with Python'" $version"'{{NORMAL}}'; \
        uv run --isolated --python $version --all-extras python3 --version; \
        echo ; \
    done

    @echo '{{BOLD + CYAN}}UV sync with lowest-supported versions with Python'" {{py_vers_lowest}}"'{{NORMAL}}'
    @uv run --isolated --python {{py_vers_lowest}} --resolution lowest-direct --all-extras python3 --version

test *args:
    @pytest "$@"

test_pyvers *args:
    @echo 'Testing with Python versions: {{py_vers_all}}\n'
    @for version in {{py_vers_all}}; do \
        echo '{{BOLD + CYAN}}Testing with Python'" $version"'{{NORMAL}}'; \
        uv run --isolated --python $version --all-extras pytest -q --no-cov -o addopts="" "$@"; \
        echo ; \
    done

    @echo '{{BOLD + CYAN}}Testing lowest-supported versions with Python'" {{py_vers_lowest}}"'{{NORMAL}}'
    @uv run --isolated --python {{py_vers_lowest}} --resolution lowest-direct --all-extras pytest -q --no-cov -o addopts=""

check:
    ruff check src/
    pyright src/
    deptry src/
    bandit src/

clean_all:
    rm -rf "${WORKSPACE}/dist"
    rm -rf "${HOME}/.cache/actcache/cache/"