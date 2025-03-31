# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Latchfield Technologies http://latchfield.com

from collections.abc import Callable
from dataclasses import field

import pytest

from vulcan_core import CallableSignatureError, Fact, NotAFactError, ScopeAccessError
from vulcan_core.ast_utils import ASTProcessor


class Foo(Fact):
    baz: bool = True
    bol: bool = True


class Bar(Fact):
    biz: bool = False


class Biff(Fact):
    bez: bool = False


class Fuzz(Fact):
    fizz: str = "fizz"
    fazz: list[str] = field(default_factory=list)


class NotAFact:
    value: bool = True


@pytest.fixture
def biff_instance():
    return Biff()


type ReturnType = bool | Fact


def process_ast(func: Callable[..., ReturnType]):
    return ASTProcessor(func=func, decorator=process_ast, return_type=ReturnType)


def test_prohibited_scope_lambda(biff_instance):
    with pytest.raises(ScopeAccessError):
        process_ast(lambda: Foo.baz and biff_instance.bez)


def test_prohibited_scope_decorator(biff_instance):
    with pytest.raises(ScopeAccessError):

        @process_ast
        def test_func(first: Foo) -> ReturnType:
            return first.baz and biff_instance.bez


def test_missing_type_hints_decorator():
    with pytest.raises(CallableSignatureError):

        @process_ast
        def test_func(first, second: Bar) -> bool:
            return first.baz and second.biz


def test_non_fact_class_lambda():
    with pytest.raises(NotAFactError):
        process_ast(lambda: NotAFact.value)


def test_non_fact_parameter_decorator():
    with pytest.raises(NotAFactError):

        @process_ast
        def test_func(first: NotAFact) -> ReturnType:
            return first.value


def test_missing_return_type_decorator():
    with pytest.raises(CallableSignatureError):

        @process_ast
        def test_func(first: Foo):
            return first.baz


def test_nested_attribute_lambda():
    with pytest.raises(ScopeAccessError):
        process_ast(lambda: Foo.baz.nested)  # type: ignore


def test_nested_attribute_decorator():
    with pytest.raises(ScopeAccessError):

        @process_ast
        def test_func(first: Foo) -> ReturnType:
            return first.baz.nested  # type: ignore


def test_lambda_with_parameters():
    with pytest.raises(CallableSignatureError):
        process_ast(lambda x: Foo.baz)


def test_variable_args():
    with pytest.raises(CallableSignatureError):

        @process_ast
        def test_func(*args: Fact) -> ReturnType:
            return True


def test_variable_kwargs():
    with pytest.raises(CallableSignatureError):

        @process_ast
        def test_func(**kwargs: Foo) -> ReturnType:
            return True


def test_async_function():
    with pytest.raises(CallableSignatureError):

        @process_ast  # type: ignore
        async def test_func(first: Foo) -> ReturnType:
            return first.baz


def test_duplicate_params_decorator():
    with pytest.raises(CallableSignatureError):

        @process_ast
        def cond(foo: Foo, faz: Foo) -> ReturnType:
            return foo.baz or faz.bol


def test_fact_discovery_lambda():
    processor = process_ast(lambda: Foo.baz and Bar.biz)
    assert len(processor.facts) == 2
    assert "Foo.baz" in processor.facts
    assert "Bar.biz" in processor.facts


def test_operator_fact_discovery_lambda():
    processor = process_ast(lambda: (Fuzz.fizz + Fuzz.fizz).count("z") == 2)
    fuzz = Fuzz(fizz="fiz")

    assert processor.func(fuzz)
    assert len(processor.facts) == 1
    assert "Fuzz.fizz" in processor.facts


def test_array_unpack_discovery_lambda():
    processor = process_ast(lambda: Fuzz(fazz=[*Fuzz.fazz, "Appended"]))
    result = processor.func(Fuzz())

    assert isinstance(result, Fuzz)
    assert result.fazz == ["Appended"]
    assert len(processor.facts) == 1
    assert "Fuzz.fazz" in processor.facts


def test_fact_discovery_decorator():
    @process_ast
    def test_func(first: Foo, second: Bar) -> ReturnType:
        return first.baz and second.biz

    assert len(test_func.facts) == 2
    assert "Foo.baz" in test_func.facts
    assert "Bar.biz" in test_func.facts


def test_transformed_lambda_execution():
    processor = process_ast(lambda: Foo.baz and Bar.biz)
    foo = Foo()
    bar = Bar()

    result = processor.func(foo, bar)
    assert result == (foo.baz and bar.biz)


def test_transformed_function_execution():
    @process_ast
    def test_func(first: Foo, second: Bar) -> ReturnType:
        return first.baz and second.biz

    foo = Foo()
    bar = Bar()

    result = test_func.func(foo, bar)
    assert result == (foo.baz and bar.biz)
