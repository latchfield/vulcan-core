# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Latchfield Technologies http://latchfield.com

import pytest
from pytest import Config, Directory, Item, Session  # noqa: PT013

# TODO: Clean up and document this code


class VirtualDirectory(Directory):
    """A virtual directory collector that preserves its children's hierarchy."""

    def collect(self):
        """Return the collected test items."""
        return self.collected

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.collected = []
        self.children = {}  # Track child collectors by path

    def get_or_create_child(self, path_parts, parent_path=None):
        """Get or create a child collector maintaining the hierarchy."""
        if not path_parts:
            return self

        current_part = path_parts[0]
        current_path = parent_path / current_part if parent_path else self.path / current_part

        if current_path not in self.children:
            child = VirtualDirectory.from_parent(parent=self, path=current_path)
            self.children[current_path] = child
            self.collected.append(child)

        collector = self.children[current_path]
        if len(path_parts) > 1:
            return collector.get_or_create_child(path_parts[1:], current_path)
        return collector


def pytest_configure(config):
    config.addinivalue_line("markers", "integration: mark test as integration test")


def pytest_addoption(parser):
    parser.addoption(
        "--plus_integration", action="store_true", help="includes tests marked with @pytest.mark.integration"
    )


def mark_integration_tests(config: Config, items: list[Item]):
    """
    Dynamically skips tests marked as integration. By default, if the items to test include any marked as
    integration, all integration tests within are skipped. However, if only integration tests are selected, then they
    are allowed to run. This can be overriden by using the --integration flag, causing all tests to run even if marked
    as integration.

    The purpose of this is to overcome current limitations in VSCode Explorer where it is not possible to configure test
    suites to run separately. With this behavior, individual integration tests can still be run from within VSCode, but
    will not run by default improving test performance.
    """

    # TODO: Consider allowing integration tests to run if running with coverage
    if len(items) > 1 and not (config.getoption("--plus_integration") or "integration" in str(config.getoption("-m"))):
        i_count = sum(1 for item in items if item.get_closest_marker("integration"))
        if i_count < len(items):
            for item in items:
                if item.get_closest_marker("integration"):
                    item.add_marker(
                        pytest.mark.skip("Integration test. Include with `--plus_integration` or  `-m integration`")
                    )


def organize_hierarchy(items: list[Item]):
    """
    Injects virtual directories for integration and unit tests
    """
    if not items:
        return

    # Find the 'tests' directory collector
    test_parent = None
    for item in items:
        if test_parent is None:
            current = item.parent
            while current and current.parent:
                if current.name == "tests":
                    test_parent = current
                    break
                current = current.parent
        if test_parent:
            break

    if not test_parent:
        return

    # Create our virtual directory collectors
    integration_collector = VirtualDirectory.from_parent(parent=test_parent, path=test_parent.path / "integration")
    unit_collector = VirtualDirectory.from_parent(parent=test_parent, path=test_parent.path / "unit")

    for item in items:
        # Determine the virtual collector to use
        is_integration = bool(item.get_closest_marker("integration"))
        collector = integration_collector if is_integration else unit_collector

        # Get the path parts for creating the hierarchy
        original_nodeid = item.nodeid
        if "::" in original_nodeid:
            path, _ = original_nodeid.split("::", 1)
            path = path.removeprefix("tests/")
            path_parts = path.split("/")

            # Create/get the proper parent in the hierarchy
            item.parent = collector.get_or_create_child(path_parts)
            item.parent.collected.append(item)


def pytest_collection_modifyitems(session: Session, config: Config, items: list[Item]):
    """
    Modifies the test hierarchy to inject virtual 'integration' and 'unit' nodes
    under the tests folder while preserving the original hierarchy.
    """
    mark_integration_tests(config, items)
    organize_hierarchy(items)
