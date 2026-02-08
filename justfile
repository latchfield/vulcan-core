# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Latchfield Technologies http://latchfield.com

default:
    @just --list --justfile {{justfile()}}

# Calculate the list of minor available Python versions that also satisfy the pyproject.toml
# UV will use the latest patch version available for each minor version.
# just --evaluate py_versions
py_versions := ```
    uv python list --output-format json | uv run --no-project --with packaging python3 -c "
    import sys, json, tomllib, pathlib
    from packaging.specifiers import SpecifierSet
    from packaging.version import Version
    spec = SpecifierSet(tomllib.loads(pathlib.Path('pyproject.toml').read_text())['project']['requires-python'])
    available = sorted({e['version_parts']['minor'] for e in json.load(sys.stdin) if e['implementation'] == 'cpython' and e['variant'] == 'default'})
    print(' '.join(f'3.{m}' for m in available if Version(f'3.{m}.0') in spec))
    "
    ```

# Determine the current Python version, versions other than the current, and the lowest
py_version := `python -c "from sys import version_info as v; print(f'{v.major}.{v.minor}')"`
py_other_vers := replace(py_versions, py_version, '')
py_lowest_ver := replace_regex(py_versions, ' .*', '')

warm_uv_cache:
    @echo 'Warming package cache for Python versions: {{py_versions}}\n'
    @for version in {{py_versions}}; do \
        echo '{{BOLD + CYAN}}UV sync with Python'" $version"'{{NORMAL}}'; \
        uv run --isolated --python $version --all-extras python3 --version; \
        echo ; \
    done

    @echo '{{BOLD + CYAN}}UV sync with lowest-supported versions with Python'" {{py_lowest_ver}}"'{{NORMAL}}'
    @uv run --isolated --python {{py_lowest_ver}} --resolution lowest-direct --all-extras python3 --version

test *args:
    @pytest "$@"

test_pyvers *args:
    @echo 'Testing with Python versions: {{py_versions}}\n'
    @for version in {{py_versions}}; do \
        echo '{{BOLD + CYAN}}Testing with Python'" $version"'{{NORMAL}}'; \
        uv run --isolated --python $version --all-extras pytest -q --no-cov -o addopts="" "$@"; \
        echo ; \
    done

    @echo '{{BOLD + CYAN}}Testing lowest-supported versions with Python'" {{py_lowest_ver}}"'{{NORMAL}}'
    @uv run --isolated --python {{py_lowest_ver}} --resolution lowest-direct --all-extras pytest -q --no-cov -o addopts=""

check:
    ruff check src/
    pyright src/
    deptry src/
    bandit src/