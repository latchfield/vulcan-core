This is a Python-based repository that provides a library and CLI tools for building, running, and managing business rules. Please follow these guidelines when contributing:

## Coding Standards

### Environment Setup
- The working environment is configured and ready to use. Do not perform initial project setup steps, such as package installation.

### Required Before Each Commit
1. Run `deptry ./src` to check for dependency issues. Fix all issues using `uv add` or `uv remove`.
2. Run `ruff check --fix --unsafe-fixes --output-format=grouped` to check and fix linting issues.
3. Run `pyright ./src` to check for type errors. Fix all reported issues.
4. Run `pytest --plus_integration` to ensure all tests pass. Fix all reported issues.

### Development Flow
1. Formulate a high-level plan by breaking down major goals into groups of related changes. Prioritize simple changes first.
2. For each change group, use test-driven development (TDD):
    - Update the design of the Vulcan codebase, focusing on method/function contracts, signatures, and types. Skip implementation at this stage. Ensure backward compatibility where possible.
    - Write or modify tests to cover new or changed contracts. Use assertions to validate expected output behavior (not internal state). Run tests to ensure they initially fail.
    - Implement or modify code to satisfy the test criteria.
    - Repeat until all unit and relevant integration tests pass.
3. Perform 1-5 incremental optimization and code-cleanup passes to improve code quality, readability, and maintainability. Refactor, simplify logic, and remove unnecessary complexity. Run unit tests after each change.

### Testing Considerations
- Only run integration tests when working on integration tests, or preparing to commit. When doing so, run only the relevant test.
- When working on an integration test, run only the test(s) you are working on.
- Always run the full unit test suite with `pytest` (this does not run integration tests). Run after each change.
- Each test should cover a single expected behavior, use concise and readable code, minimal comments, and ideally fewer than 3 assertions. Use pytest fixtures to set up common test scenarios.
- Use integration tests sparingly, only for end-to-end scenarios involving multiple components.
- Avoid overlapping tests, tests of internal or private implementation details, or tests of only native Python/third-party library behavior.

## Repository Structure
For coding tasks, these are the only filesystem paths you need to know:
- `README.md`: Main documentation file for the Vulcan project.
- `src/`: Main Vulcan Python module code.
- `tests/`: Unit and integration tests for the Vulcan library.

## Vulcan Python Module Overview (`src/vulcan_core/`)
- `__init__.py`: Lists entities considered part of Vulcan's public API.
- `actions.py`: Defines the `Action` class and `action` helper for rule `then` and `inverse` consequences.
- `ast_utils.py`: Internal utilities for analyzing and transforming rule conditions and actions. Uses AST processing to extract lambda expressions, discover referenced Facts, and validate the Vulcan API contract.
- `conditions.py`: Defines the `Condition` class and `condition` helper for rule `when` expressions.
- `engine.py`: Main entry point to the Vulcan rules engine (`RuleEngine`). The `evaluation()` loop coordinates fact-rule matching, rule evaluation, action execution, fact state, reporting, and error handling.
- `models.py`: Defines Vulcan's public API for Fact data models. Uses immutable dataclasses for data integrity and consistency.
- `reporting.py`: Internal models/utilities for capturing, serializing, and explaining Vulcan rule processing.
- `util.py`: Internal general-purpose utilities and decorators (context management, not-implemented stubs, function wrapping, etc.).

## Important Vulcan Implementation Details
- Conditions and Actions are deferred execution containers: they capture fact dependencies at construction, but do not execute their logic until called with Fact instances during rule evaluation.
- The RulesEngine only evaluates rules relevant when their referenced facts change. By design, rules can add or change the state of Facts, triggering other rules for evaluation.
- In f-strings, Vulcan Fact classes render their attributes as `{Class.attribute}` (e.g., `f"{Foo.bar}"` renders to `{Foo.bar}`), enabling IDE type inspection and deferring value substitution until rule evaluation.
- The `condition` helper transforms parameterless lambdas (e.g., `lambda: Foo.bar and Bar.baz`) into parameterized functions (e.g., `lambda p0, p1: p0.bar and p1.baz`) during AST processing.
- The `condition` helper can also be used as a decorator to create custom conditions from functions that take Fact instances as parameters.
- Lambdas wrapped with `condition` must be parameterless and may only directly reference Fact class attributes, not Fact instances.
- Condition objects support composition using Python's bitwise operators (`&`, `|`, `^`, `~`) for logical expressions.
- Due to Python's limitations in inspecting lambda source code, Vulcan uses several non-obvious workarounds to perform reliable inspection. Be sure to carefully understand the AST processing code when making AST-related changes.

## Key Guidelines
- Follow Python best practices and idiomatic patterns, but be consistent with the existing codebase.
- Maintain existing code structure and organization unless explicitly asked to refactor or change it.
- Use manual dependency injection patterns where appropriate (not a framework).
- Document all APIs and complex logic with comments and docstrings, but avoid excessive comments that clutter the code.