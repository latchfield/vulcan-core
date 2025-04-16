# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Latchfield Technologies http://latchfield.com

from functools import partial
from unittest.mock import Mock

import pytest
from langchain_core.language_models import BaseChatModel
from langchain_openai import ChatOpenAI

from vulcan_core import Condition, Fact, MissingFactError, condition
from vulcan_core.ast_utils import CallableSignatureError
from vulcan_core.conditions import ai_condition


class Foo(Fact):
    baz: bool = True
    bol: bool = True


class Bar(Fact):
    biz: bool = False


class FactA(Fact):
    feature: str = "Kilauea"


class FactB(Fact):
    feature: str = "Olypus Mons"


class FactC(Fact):
    feature: str = "Pacific"


@pytest.fixture
def foo_instance():
    return Foo()


@pytest.fixture
def bar_instance():
    return Bar()


@pytest.fixture
def fact_a_instance():
    return FactA()


@pytest.fixture
def fact_b_instance():
    return FactB()


@pytest.fixture
def model():
    return ChatOpenAI(model="gpt-4o-mini", temperature=0, max_tokens=100)


def test_condition_lambda(foo_instance: Foo, bar_instance: Bar):
    cond = condition(lambda: Foo.baz and Bar.biz)
    assert isinstance(cond, Condition)
    assert len(cond.facts) == 2
    assert "Foo.baz" in cond.facts
    assert "Bar.biz" in cond.facts

    assert cond(foo_instance, bar_instance) == (foo_instance.baz and bar_instance.biz)


def test_condition_decorator(foo_instance: Foo, bar_instance: Bar):
    @condition
    def test_func(first: Foo, second: Bar) -> bool:
        return first.baz and second.biz

    assert isinstance(test_func, Condition)
    assert len(test_func.facts) == 2
    assert "Foo.baz" in test_func.facts
    assert "Bar.biz" in test_func.facts

    assert test_func(foo_instance, bar_instance) == (foo_instance.baz and bar_instance.biz)


def test_complex_lambda():
    cond = condition(lambda: (Foo.baz and (Bar.biz or Foo.bol)))
    assert len(cond.facts) == 3
    assert set(cond.facts) == {"Foo.baz", "Bar.biz", "Foo.bol"}


def test_invert_condition(foo_instance: Foo):
    cond = condition(lambda: Foo.baz)
    inverted = ~cond

    assert inverted.facts == cond.facts
    assert inverted(foo_instance) == (not cond(foo_instance))


@pytest.mark.integration
def test_ai_simple_condition_false(model: BaseChatModel, fact_a_instance: FactA, fact_b_instance: FactB):
    cond = ai_condition(model, f"Are {FactA.feature} and {FactB.feature} both on the same planet?")

    assert set(cond.facts) == {"FactA.feature", "FactB.feature"}
    assert cond(fact_a_instance, fact_b_instance) is False


@pytest.mark.integration
def test_ai_simple_condition_true(model: BaseChatModel, fact_a_instance: FactA, fact_b_instance: FactB):
    cond = ai_condition(model, f"Are {FactA.feature} and {FactB.feature} loosely similiar in concept?")

    assert set(cond.facts) == {"FactA.feature", "FactB.feature"}
    assert cond(fact_a_instance, fact_b_instance) is True


@pytest.mark.integration
def test_ai_missing_fact(model: BaseChatModel):
    # TODO: Determine the difference between tool calls and non-tool calls
    # We shouldn't raise an exception if tools are being used
    with pytest.raises(MissingFactError):
        ai_condition(model, "Is the sky blue?")


@pytest.mark.integration
def test_aicondition_with_custom_model(model: BaseChatModel, fact_a_instance: FactA, fact_b_instance: FactB):
    cond = condition(f"Are {FactA.feature} and {FactB.feature} both on the same planet?", model=model)

    assert set(cond.facts) == {"FactA.feature", "FactB.feature"}
    assert cond(fact_a_instance, fact_b_instance) is False


def test_condition_with_custom_model(foo_instance: Foo, bar_instance: Bar):
    model = Mock()
    condition(lambda: Foo.baz and Bar.biz, model=model)


def test_aicondition_model_override():
    model1 = Mock()
    model2 = Mock()

    custom_condition = partial(condition, model=model1)

    cond1 = custom_condition(f"Are {FactA.feature} and {FactB.feature} both on the same planet?")
    cond2 = custom_condition(f"Are {FactA.feature} and {FactB.feature} both on the same planet?", model=model2)

    assert cond1.model != cond2.model  # type: ignore


def test_lambda_param_check():
    with pytest.raises(CallableSignatureError):
        condition(lambda x: Foo.baz)