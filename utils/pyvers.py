# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Latchfield Technologies http://latchfield.com
import argparse
import json
import platform
import sys
import tomllib
import urllib.request


def _validate_version_string(version: str, context: str) -> None:
    """Validate that a version string only contains digits and dots.
    
    Raises ValueError if the version contains wildcards or other non-numeric characters.
    """
    if not version or not all(c.isdigit() or c == "." for c in version):
        msg = f"Invalid version string {version!r} in {context}: must only contain digits and dots"
        raise ValueError(msg)
    if ".." in version or version.startswith(".") or version.endswith("."):
        msg = f"Invalid version string {version!r} in {context}: malformed version"
        raise ValueError(msg)


def parse_version_spec(spec_str: str) -> list[tuple[str, str]]:
    """Parse a PEP 440 version specifier string and return constraints.

    Parses constraints like ">=3.10,<3.13" into a list of (operator, version) tuples.
    Raises ValueError if an unknown or unsupported specifier is encountered.
    """
    conditions: list[tuple[str, str]] = []
    operators = [">=", "<=", "==", "!=", ">", "<"]
    
    for part in spec_str.split(","):
        part = part.strip()
        
        for operator in operators:
            if part.startswith(operator):
                version = part[len(operator):].strip()
                _validate_version_string(version, spec_str)
                conditions.append((operator, version))
                break
        else:
            msg = f"Unsupported version specifier: {part!r} in {spec_str!r}"
            raise ValueError(msg)
    
    return conditions


def version_matches(version_str: str, conditions: list[tuple[str, str]]) -> bool:
    """Check if a version string satisfies all the given constraints."""
    # Convert version strings to tuples of integers for lexicographic comparison
    v_parts = tuple(int(p) for p in version_str.split("."))
    for op, spec_ver in conditions:
        s_parts = tuple(int(p) for p in spec_ver.split("."))
        # Pad shorter version to same length (e.g., "3.10" becomes "3.10.0" when compared to "3.10.1")
        max_len = max(len(v_parts), len(s_parts))
        v_padded = v_parts + (0,) * (max_len - len(v_parts))
        s_padded = s_parts + (0,) * (max_len - len(s_parts))

        # Check if version fails this constraint
        if (
            (op == ">=" and v_padded < s_padded)
            or (op == ">" and v_padded <= s_padded)
            or (op == "<=" and v_padded > s_padded)
            or (op == "<" and v_padded >= s_padded)
            or (op == "==" and v_padded != s_padded)
            or (op == "!=" and v_padded == s_padded)
        ):
            return False
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Get the project's Python version information")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-c", "--current", action="store_true", help="Print only the current version")
    group.add_argument("-o", "--other", action="store_true", help="Print only other valid versions")
    group.add_argument("-m", "--min", action="store_true", help="Print only the minimum valid version")
    group.add_argument("-a", "--all", action="store_true", help="Print all valid versions")
    group.add_argument("-M", "--max", action="store_true", help="Print only the maximum valid version")
    group.add_argument("-l", "--lesser", action="store_true", help="Print all valid versions except the highest")
    parser.add_argument("-j", "--json", action="store_true", help="Output in JSON format")

    args = parser.parse_args()

    current_version = f"{sys.version_info.major}.{sys.version_info.minor}"

    os_name = platform.system().lower()
    arch = platform.machine()

    url = "https://raw.githubusercontent.com/astral-sh/uv/refs/heads/main/crates/uv-python/download-metadata.json"
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310
        metadata = json.loads(response.read())

    # Extract major.minor versions from metadata, filtering for current OS/arch
    available_versions: set[str] = {
        f"{entry['major']}.{entry['minor']}"
        for entry in metadata.values()
        if (entry.get("os") == os_name and entry.get("arch", {}).get("family") == arch and not entry.get("prerelease"))
    }

    with open("pyproject.toml", "rb") as f:
        requires_python: str = tomllib.load(f)["project"]["requires-python"]

    conditions = parse_version_spec(requires_python)
    valid_versions = sorted(
        (v for v in available_versions if version_matches(f"{v}.0", conditions)),
        key=lambda v: tuple(map(int, v.split('.'))),
    )

    other_versions = [v for v in valid_versions if v != current_version]
    lesser_versions = valid_versions[:-1] if valid_versions else []
    min_version = valid_versions[0] if valid_versions else ""
    max_version = valid_versions[-1] if valid_versions else ""

    if args.current:
        print(current_version)
    elif args.other:
        if args.json:
            print(json.dumps(other_versions))
        else:
            print(" ".join(other_versions))
    elif args.min:
        print(min_version)
    elif args.max:
        print(max_version)
    elif args.lesser:
        if args.json:
            print(json.dumps(lesser_versions))
        else:
            print(" ".join(lesser_versions))
    elif args.all:
        if args.json:
            print(json.dumps(valid_versions))
        else:
            print(" ".join(valid_versions))
    else:
        # Default output (no arguments)
        print(f"py_vers_current={current_version}")
        print(f"py_vers_min={min_version}")
        print(f"py_vers_max={max_version}")
        print(f"py_vers_other={json.dumps(other_versions)}")
        print(f"py_vers_lesser={json.dumps(lesser_versions)}")


if __name__ == "__main__":
    main()
