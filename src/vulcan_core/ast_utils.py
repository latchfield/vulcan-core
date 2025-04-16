# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Latchfield Technologies http://latchfield.com

import ast
import inspect
import textwrap
from ast import Attribute, Module, Name, NodeTransformer, NodeVisitor
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cached_property
from types import MappingProxyType
from typing import Any, TypeAliasType, get_type_hints

from vulcan_core.models import Fact, HasSource


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


@dataclass
class ASTProcessor[T: Callable]:
    func: T
    decorator: Callable
    return_type: type | TypeAliasType
    source: str = field(init=False)
    tree: Module = field(init=False)
    facts: tuple[str, ...] = field(init=False)

    @cached_property
    def is_lambda(self) -> bool:
        return isinstance(self.func, type(lambda: None)) and self.func.__name__ == "<lambda>"

    def __post_init__(self):
        # Extract source code and parse AST
        if isinstance(self.func, HasSource):
            self.source = self.func.__source__
        else:
            try:
                self.source = textwrap.dedent(inspect.getsource(self.func))
            except OSError as e:
                if str(e) == "could not get source code":
                    msg = "could not get source code. Try recursively deleting all __pycache__ folders in your project."
                    raise OSError(msg) from e
                else:
                    raise
            self.func.__source__ = self.source

        self.source = self._extract_lambda_source() if self.is_lambda else self.source
        self.tree = ast.parse(self.source)

        # Peform basic AST checks and attribute discovery
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
            params = inspect.signature(self.func).parameters
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

    def _extract_lambda_source(self) -> str:
        """Extracts just the lambda expression from source code."""
        lambda_start = self.source.find("lambda")
        if lambda_start == -1:  # pragma: no cover - internal AST error
            msg = "Could not find lambda expression in source"
            raise ASTProcessingError(msg)

        # The source includes the entire line of code (e.g., assignment and condition() call)
        # We need to extract just the lambda expression, handling nested structures correctly
        source = self.source[lambda_start:]

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
        """Discover attribute accessed within the AST."""
        visitor = _AttributeVisitor()
        visitor.visit(self.tree)
        return visitor.attributes

    def _resolve_facts(self, attributes: list[tuple[str, str]], globals_dict: dict) -> tuple[list[str], dict[str, str]]:
        """Validate attribute accesses and return normalized fact strings."""
        facts = []
        class_to_param = {}
        param_counter = 0

        for class_name, attr in attributes:
            # Verify name refers to a class type
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
        # the transformed AST might generate different lambda syntax. than the original source code, ensuring we only
        # get the expression part.
        if lambda_body.startswith("lambda"):
            lambda_body = lambda_body[lambda_body.find(":") + 1 :].strip()

        # TODO: Find a way to avoid using exec or eval here
        lambda_code = f"lambda {', '.join(class_to_param.values())}: {lambda_body}"
        new_func = eval(lambda_code, caller_globals)  # noqa: S307 # nosec B307
        return new_func
