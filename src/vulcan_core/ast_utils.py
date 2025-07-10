# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Latchfield Technologies http://latchfield.com

import ast
import inspect
import io
import logging
import re
import textwrap
import tokenize
from ast import Attribute, Module, Name, NodeTransformer, NodeVisitor
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cached_property
from types import MappingProxyType
from typing import Any, ClassVar, TypeAliasType, get_type_hints

from vulcan_core.models import Fact, HasSource

logger = logging.getLogger(__name__)


class ASTProcessingError(RuntimeError):
    """Internal error encountered while processing AST."""


class ContractError(Exception):
    """Base exception for callable contract violations."""


class ScopeAccessError(ContractError):
    """Raised when a callable attempts to access instances not passed as parameters or when decorated functions attempt
    to access class attributes instead of parameter instance attributes."""


class NotAFactError(ContractError):
    """Raised when a callable parameter, or accessed attribute is not a subclass of Fact."""

    def __init__(self, type_obj: type) -> None:
        message = f"'{type_obj.__name__}' is not a Fact subclass"
        super().__init__(message)


class CallableSignatureError(ContractError):
    """Raised when a decorated function has any missing type hints, an incorrect return type, or if a lambda that
    requires arguments is provided."""


class _AttributeVisitor(NodeVisitor):
    """Visitor to collect attribute accesses from the AST."""

    def __init__(self):
        self.attributes = []

    def visit_Attribute(self, node):  # noqa: N802
        if isinstance(node.value, Name):
            self.attributes.append((node.value.id, node.attr))
        self.generic_visit(node)  # Continue traversing the AST


class _NestedAttributeVisitor(NodeVisitor):
    """Visitor to detect nested attribute access."""

    def __init__(self):
        self.has_nested = False

    def visit_Attribute(self, node):  # noqa: N802
        if isinstance(node.value, Attribute):
            self.has_nested = True
        self.generic_visit(node)


class AttributeTransformer(NodeTransformer):
    """Transformer to replace static class attribute access with parameterized instances."""

    def __init__(self, class_to_param):
        self.class_to_param = class_to_param

    def visit_Attribute(self, node: Attribute):  # noqa: N802
        node = self.generic_visit(node)  # type: ignore

        if isinstance(node.value, Name) and node.value.id in self.class_to_param:
            return Attribute(
                value=Name(id=self.class_to_param[node.value.id], ctx=node.value.ctx),
                attr=node.attr,
                ctx=node.ctx,
            )
        return node


@dataclass(slots=True)
class LambdaTracker:
    """Index entry for tracking the parsing position of lambda functions in source lines.

    Attributes:
        source (str): The source code string containing lambda functions
        positions (list[int]): Positions where lambda functions are found in the source
        index (int): The lambda being parsed within the source string.
        in_use (bool): Whether this source is currently being processed or not, making it eligible for cache deletion.
    """

    source: str
    positions: list[int]
    index: int = field(default=0)
    in_use: bool = field(default=True)


@dataclass
class ASTProcessor[T: Callable]:
    """
    This class extracts source code from functions or lambda expressions, parses them into
    Abstract Syntax Trees (AST), and performs various validations and transformations.

    The processor validates that:
    - Functions have proper type hints for parameters and return types
    - All parameters are subclasses of Fact
    - No nested attribute access (e.g., X.y.z) is used
    - No async functions are processed
    - Lambda expressions do not contain parameters
    - No duplicate parameter types in function signatures

    For lambda expressions, it automatically transforms attribute access patterns
    (e.g., ClassName.attribute) into parameterized functions for easier execution.

    Note: This class is not thread-safe and should not be used concurrently across multiple threads.

    Type Parameters:
        T: The type signature the processor is working with, this varies based on a condition or action being processed.

    Attributes:
        func: The callable to process, a lambda or a function
        decorator: The decorator type that initiated the processing (e.g., `condition` or `action`)
        return_type: Expected return type for the callable
        source: Extracted source code of func (set during post-init)
        tree: Parsed AST of the source code (set during post-init)
        facts: Tuple of fact strings discovered in the callable (set during post-init)

    Properties:
        is_lambda: True if the callable is a lambda expression

    Raises:
        OSError: When source code cannot be extracted
        ScopeAccessError: When accessing undefined classes or using nested attributes
        CallableSignatureError: When function signature doesn't meet requirements
        NotAFactError: When parameter types are not Fact subclasses
        ASTProcessingError: When AST processing encounters internal errors
    """

    func: T
    decorator: Callable
    return_type: type | TypeAliasType
    source: str = field(init=False)
    tree: Module = field(init=False)
    facts: tuple[str, ...] = field(init=False)

    # Class-level tracking of lambdas across parsing calls to handle multiple lambdas on the same line
    _lambda_cache: ClassVar[OrderedDict[str, LambdaTracker]] = OrderedDict()
    _MAX_LAMBDA_CACHE_SIZE: ClassVar[int] = 1024

    @cached_property
    def is_lambda(self) -> bool:
        return isinstance(self.func, type(lambda: None)) and self.func.__name__ == "<lambda>"

    def __post_init__(self):
        # Extract source code and parse AST
        if isinstance(self.func, HasSource):
            self.source = self.func.__source__
        else:
            try:
                if self.is_lambda:
                    # As of Python 3.12, there is no way to determine to which lambda self.func refers in an
                    # expression containing multiple lambdas. Therefore we use a dict to track the index of each
                    # lambda function encountered, as the order will correspond to the order of ASTProcessor
                    # invocations for that line. An additional benefit is that we can also use this as a cache to
                    # avoid re-reading and parsing the source code for lambda functions sharing the same line.
                    source_line = f"{self.func.__code__.co_filename}:{self.func.__code__.co_firstlineno}"
                    tracker = self._lambda_cache.get(source_line)

                    if tracker is None:
                        self.source = self._get_lambda_source()
                        positions = self._find_lambdas(self.source)

                        tracker = LambdaTracker(self.source, positions)
                        self._lambda_cache[source_line] = tracker
                        self._trim_lambda_cache()
                    else:
                        tracker.index += 1

                        # Reset the position if it exceeds the count of lambda expressions
                        if tracker.index >= len(tracker.positions):
                            tracker.index = 0

                    # Extract the next lambda source based on the current tracking state
                    self.source = self._extract_next_lambda(tracker)

                    # If all found lambdas have been processed, mark the tracker as not in use
                    if tracker.index >= len(tracker.positions) - 1:
                        tracker.in_use = False

                else:
                    self.source = textwrap.dedent(inspect.getsource(self.func))
            except OSError as e:
                if str(e) == "could not get source code":
                    msg = "could not get source code. Try recursively deleting all __pycache__ folders in your project."
                    raise OSError(msg) from e
                else:
                    raise
            self.func.__source__ = self.source

        # Parse the AST with minimal error handling
        self.tree = ast.parse(self.source)

        # Perform basic AST checks and attribute discovery
        self._validate_ast()
        attributes = self._discover_attributes()

        if self.is_lambda:
            # Process attributes and create a transformed lambda
            caller_globals = self._get_caller_globals()
            facts, class_to_param = self._resolve_facts(attributes, caller_globals)

            self.facts = tuple(facts)
            self.func = self._transform_lambda(class_to_param, caller_globals)

        else:
            # Get function metadata and validate signature
            hints = get_type_hints(self.func)
            params = inspect.signature(self.func).parameters  # type: ignore
            self._validate_signature(hints, params)

            # Process attributes
            facts: list[str] = []
            param_names = list(params)

            # Create the list of accessed facts and verify they are in the correct scope
            for class_name, attr in attributes:
                if class_name not in param_names:
                    msg = f"Accessing class '{class_name}' not passed as parameter"
                    raise ScopeAccessError(msg)
                facts.append(f"{hints[class_name].__name__}.{attr}")

            self.facts = tuple(facts)

    def _trim_lambda_cache(self) -> None:
        """Clean up lambda cache by removing oldest unused entries when cache size exceeds limit."""
        if len(self._lambda_cache) <= self._MAX_LAMBDA_CACHE_SIZE:
            return

        # Calculate how many entries to remove (excess + 20% buffer to avoid thrashing)
        excess_count = len(self._lambda_cache) - self._MAX_LAMBDA_CACHE_SIZE
        buffer_count = int(self._MAX_LAMBDA_CACHE_SIZE * 0.2)
        target_count = excess_count + buffer_count

        # Find and remove unused entries
        removed_count = 0
        for key in list(self._lambda_cache):
            if removed_count >= target_count:
                break
            if not self._lambda_cache[key].in_use:
                del self._lambda_cache[key]
                removed_count += 1

    def _find_lambdas(self, source: str) -> list[int]:
        """Find all lambda expressions in the source code and return their starting positions."""
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        lambda_positions = [
            token.start[1] for token in tokens if token.type == tokenize.NAME and token.string == "lambda"
        ]

        return lambda_positions

    def _get_lambda_source(self) -> str:
        """Get single and multiline lambda source using AST parsing of the source file."""
        source = None

        try:
            # Get the source file and line number
            # Avoid reading source from files directly, as it may fail in some cases (e.g., lambdas in REPL)
            file_content = "".join(inspect.findsource(self.func)[0])
            lambda_lineno = self.func.__code__.co_firstlineno

            # Parse the AST of the source file
            file_ast = ast.parse(file_content)

            # Find the lambda expression at the specific line number
            class LambdaFinder(ast.NodeVisitor):
                def __init__(self, target_lineno):
                    self.target_lineno = target_lineno
                    self.found_lambda = None

                def visit_Lambda(self, node):  # noqa: N802 - Case sensitive for AST
                    if node.lineno == self.target_lineno:
                        self.found_lambda = node
                    self.generic_visit(node)

            finder = LambdaFinder(lambda_lineno)
            finder.visit(file_ast)

            if finder.found_lambda:
                # Get the source lines that contain this lambda
                lines = file_content.split("\n")
                start_line = finder.found_lambda.lineno - 1

                # Find the end of the lambda expression
                end_line = start_line
                if hasattr(finder.found_lambda, "end_lineno") and finder.found_lambda.end_lineno:
                    end_line = finder.found_lambda.end_lineno - 1
                else:
                    # Fallback: find the closing parenthesis
                    paren_count = 0
                    for i in range(start_line, len(lines)):
                        line = lines[i]
                        paren_count += line.count("(") - line.count(")")
                        if paren_count <= 0 and ")" in line:
                            end_line = i
                            break

                source = "\n".join(lines[start_line : end_line + 1])

        except (OSError, SyntaxError, AttributeError):
            logger.exception("Failed to extract lambda source, attempting fallback.")
            source = inspect.getsource(self.func).strip()

        if source is None or source == "":
            msg = "Could not extract lambda source code"
            raise ASTProcessingError(msg)

        # Normalize the source: convert line breaks to spaces, collapse whitespace, and dedent
        source = re.sub(r"\r\n|\r|\n", " ", source)
        source = re.sub(r"\s+", " ", source)
        source = textwrap.dedent(source)

        return source

    def _extract_next_lambda(self, src: LambdaTracker) -> str:
        """Extracts the next lambda expression from source code."""
        source = src.source
        index = src.index
        lambda_start = src.positions[index]

        # The source may include unrelated code (e.g., assignment and condition() call)
        # So we need to extract just the lambda expression, handling nested structures correctly
        source = source[lambda_start:]

        # Track depth of various brackets to ensure we don't split inside valid nested structures apart from trailing
        # arguments within the condition() call
        paren_level = 0
        bracket_level = 0
        brace_level = 0

        for i, char in enumerate(source):
            if char == "(":
                paren_level += 1
            elif char == ")":
                if paren_level > 0:
                    paren_level -= 1
                elif paren_level == 0:  # End of expression in a function call
                    return source[:i]
            elif char == "[":
                bracket_level += 1
            elif char == "]":
                if bracket_level > 0:
                    bracket_level -= 1
            elif char == "{":
                brace_level += 1
            elif char == "}":
                if brace_level > 0:
                    brace_level -= 1
            # Only consider comma as a separator when not inside any brackets
            elif char == "," and paren_level == 0 and bracket_level == 0 and brace_level == 0:
                return source[:i]

        return source

    def _get_caller_globals(self) -> dict[str, Any]:
        """Find the globals of the caller of the decorator in order to validate accessed types."""
        try:
            decorator_name = self.decorator.__name__
            frame = inspect.currentframe()
            while frame.f_code.co_name != decorator_name:  # type: ignore
                frame = frame.f_back  # type: ignore
            return frame.f_back.f_globals  # type: ignore  # noqa: TRY300

        except AttributeError as err:  # pragma: no cover - internal AST error
            msg = f"Unable to locate caller ('{decorator_name}') globals"
            raise ASTProcessingError(msg) from err

    def _validate_ast(self) -> None:
        # Check for nested attribute access
        visitor = _NestedAttributeVisitor()
        visitor.visit(self.tree)
        if visitor.has_nested:
            msg = "Nested attribute access (X.y.z) is not allowed"
            raise ScopeAccessError(msg)

        # Checks for async functions
        if isinstance(self.tree.body[0], ast.AsyncFunctionDef):
            msg = "Async functions are not supported"
            raise CallableSignatureError(msg)

        # Lambda-specific checks
        if self.is_lambda:
            if not isinstance(self.tree, ast.Module) or not isinstance(
                self.tree.body[0], ast.Expr
            ):  # pragma: no cover - internal AST error
                msg = "Expected an expression in AST body"
                raise ASTProcessingError(msg)

            lambda_node = self.tree.body[0].value
            if not isinstance(lambda_node, ast.Lambda):  # pragma: no cover - internal AST error
                msg = "Expected a lambda expression"
                raise ASTProcessingError(msg)

            if lambda_node.args.args:
                msg = "Lambda expressions must not have parameters"
                raise CallableSignatureError(msg)

    def _discover_attributes(self) -> list[tuple[str, str]]:
        """Discover attributes accessed within the AST."""
        visitor = _AttributeVisitor()
        visitor.visit(self.tree)
        return visitor.attributes

    def _resolve_facts(self, attributes: list[tuple[str, str]], globals_dict: dict) -> tuple[list[str], dict[str, str]]:
        """Validate attribute accesses and return normalized fact strings."""
        facts = []
        class_to_param = {}
        param_counter = 0

        for class_name, attr in attributes:
            # Verify the name refers to a class type
            if class_name not in globals_dict or not isinstance(globals_dict[class_name], type):
                msg = f"Accessing undefined class '{class_name}'"
                raise ScopeAccessError(msg)

            # Verify it's a Fact subclass
            class_obj = globals_dict[class_name]
            if not issubclass(class_obj, Fact):
                raise NotAFactError(class_obj)

            facts.append(f"{class_name}.{attr}")
            if class_name not in class_to_param:
                class_to_param[class_name] = f"p{param_counter}"
                param_counter += 1

        # Deduplicate facts while preserving order
        seen = set()
        facts = [fact for fact in facts if not (fact in seen or seen.add(fact))]

        return facts, class_to_param

    def _validate_signature(self, hints: dict, params: MappingProxyType[str, inspect.Parameter]) -> None:
        """Validate function signature requirements."""

        # Validate return type
        if "return" not in hints or hints["return"] is not self.return_type:
            msg = f"Return type hint is required and must be {self.return_type!r}"
            raise CallableSignatureError(msg)

        # Track parameter types to check for duplicates
        param_types = []

        # Validate parameters
        for param in params.values():
            if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
                msg = "Variable arguments (*args, **kwargs) are not supported"
                raise CallableSignatureError(msg)

            if param.name not in hints:
                msg = "All parameters must have type hints"
                raise CallableSignatureError(msg)

            if param.name != "return":
                param_type = hints[param.name]
                if not isinstance(param_type, type) or not issubclass(param_type, Fact):
                    raise NotAFactError(param_type)
                param_types.append(param_type)

        # Check for duplicate parameter types
        seen_types = set()
        for param_type in param_types:
            if param_type in seen_types:
                msg = f"Duplicate parameter type '{param_type.__name__}' is not allowed"
                raise CallableSignatureError(msg)
            seen_types.add(param_type)

    def _transform_lambda(self, class_to_param: dict[str, str], caller_globals: dict[str, Any]) -> T:
        # Transform and create new lambda
        transformer = AttributeTransformer(class_to_param)
        new_tree = transformer.visit(self.tree)
        lambda_body = ast.unparse(new_tree.body[0].value)

        # The AST unparsing creates a full lambda expression, but we only want its body. This handles edge cases where
        # the transformed AST might generate different lambda syntax than the original source code, ensuring we only
        # get the expression part.
        if lambda_body.startswith("lambda"):
            lambda_body = lambda_body[lambda_body.find(":") + 1 :].strip()

        # Create a new lambda object with the transformed body
        # TODO: Find a way to avoid using exec or eval here
        lambda_code = f"lambda {', '.join(class_to_param.values())}: {lambda_body}"
        new_func = eval(lambda_code, caller_globals)  # noqa: S307 # nosec B307
        new_func.__source__ = self.source

        return new_func
