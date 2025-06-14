# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Latchfield Technologies http://latchfield.com

from dataclasses import dataclass
from functools import partial

import pytest
from langchain.schema import AIMessage, BaseMessage, ChatGeneration, ChatResult
from langchain_core.language_models import BaseChatModel, LanguageModelInput
from langchain_core.messages.tool import tool_call
from langchain_core.runnables import Runnable

from tests.core.fixtures.rule_loading import load_simple_rule
from vulcan_core import Fact, InternalStateError, RecursionLimitError, RuleEngine, action, condition
from vulcan_core.ast_utils import NotAFactError


class Foo(Fact):
    baz: bool = True
    bol: bool = True


class Bar(Fact):
    biz: bool = False
    bul: int = 0


class Biff(Fact):
    bez: bool = False
    bil: int


class LocationA(Fact):
    name: str = "Kilauea"


class LocationB(Fact):
    name: str = "Olypus Mons"


class Material(Fact):
    name: str = "Pumice"


class LocationAnalysis(Fact):
    commonality: str


class LocationResult(Fact):
    all_related: bool = False


class RuleFired(Fact):
    status: bool = True


@pytest.fixture
def engine() -> RuleEngine:
    engine = RuleEngine()
    engine.fact(Foo())
    engine.fact(Bar())
    engine.fact(LocationA())
    engine.fact(LocationB())
    engine.fact(Material())
    return engine


def test_simple_rule(engine: RuleEngine):
    engine.rule(
        name="test_rule",
        when=condition(lambda: Foo.baz or Bar.biz),
        then=action(partial(Foo, bol=False)),
    )

    engine.evaluate()
    assert engine[Foo].bol is False


# https://github.com/latchfield/vulcan-core/issues/44
def test_lambda_reparsing(engine: RuleEngine):
    load_simple_rule(engine)
    load_simple_rule(engine)


def test_same_fact_multiple_attributes_lambda(engine: RuleEngine):
    engine.rule(
        when=condition(lambda: Foo.baz or Foo.bol or Foo.baz),
        then=action(partial(Bar, biz=True)),
    )

    engine.evaluate()
    assert engine[Bar].biz is True


def test_same_fact_multiple_attributes_decorator(engine: RuleEngine):
    @condition
    def cond(foo: Foo) -> bool:
        return foo.baz or foo.bol

    engine.rule(
        when=cond,
        then=action(partial(Bar, biz=True)),
    )

    engine.evaluate()
    assert engine[Bar].biz is True


def test_skipped_condition(engine: RuleEngine):
    engine.rule(
        when=condition(lambda: False),
        then=action(partial(Foo, bol=False)),
    )

    engine.evaluate()
    assert engine[Foo].bol is True


def test_cascade_rules(engine: RuleEngine):
    engine.rule(
        when=condition(lambda: Foo.baz),
        then=action(partial(Bar, biz=True)),
    )

    engine.rule(
        when=condition(lambda: Bar.biz),
        then=action(partial(Foo, bol=False)),
    )

    engine.evaluate()
    assert engine[Bar].biz is True
    assert engine[Foo].bol is False


def test_inverse_action(engine: RuleEngine):
    engine.rule(
        when=condition(lambda: Foo.baz),
        then=action(partial(Bar, bul=5)),
        inverse=action(partial(Bar, bul=10)),
    )

    # First evaluate with condition true
    engine.evaluate()
    assert engine[Bar].bul == 5

    # Update fact to make condition false
    engine.fact(Foo(baz=False))
    engine.evaluate()
    assert engine[Bar].bul == 10


def test_recursion_limit(engine: RuleEngine):
    # Create two rules that keep toggling each other
    engine.rule(
        when=condition(lambda: Foo.baz),
        then=action((partial(Foo, baz=False), partial(Bar, biz=True))),
    )
    engine.rule(
        when=condition(lambda: Bar.biz),
        then=action((partial(Bar, biz=False), partial(Foo, baz=True))),
    )

    with pytest.raises(RecursionLimitError):
        engine.evaluate()


def test_automatic_fact_create():
    engine = RuleEngine()
    engine.fact(Foo())

    engine.rule(
        when=condition(lambda: Foo.baz),
        then=action(partial(Bar, bul=10)),
    )

    engine.evaluate()
    assert engine[Bar].biz is False
    assert engine[Bar].bul == 10


def test_missing_fact():
    engine = RuleEngine()
    engine.fact(Foo())

    engine.rule(
        when=condition(lambda: Foo.baz),
        then=action(partial(Biff, bez=False)),
    )

    with pytest.raises(InternalStateError):
        engine.evaluate()


def test_multiple_fact_updates(engine: RuleEngine):
    engine.rule(
        when=condition(lambda: Foo.baz),
        then=action((partial(Foo, bol=False), partial(Bar, biz=True))),
    )

    engine.evaluate()
    assert engine[Foo].bol is False
    assert engine[Bar].biz is True


def test_initialize_fact_merge(engine: RuleEngine):
    engine.fact(Foo(baz=True, bol=False))
    engine.fact(partial(Foo, baz=False))

    result = engine[Foo]
    assert result.baz is False
    assert result.bol is False


def test_initialize_fact_autocreate():
    engine = RuleEngine()
    engine.fact(partial(Foo, baz=False))

    result = engine[Foo]
    assert result.baz is False
    assert result.bol is True


def test_not_a_fact():
    @dataclass()
    class NotAFact:
        some_value: int = 0

    engine = RuleEngine()

    with pytest.raises(NotAFactError):
        engine.fact(NotAFact())  # type: ignore


@pytest.mark.integration
def test_ai_simple_rule(engine: RuleEngine):
    # TODO: This test is firing the second rule twice for some reason

    engine.rule(
        when=condition(f"Are {LocationA.name} and {LocationB.name} volcanos?"),
        then=action(partial(LocationAnalysis, commonality="volcano")),
    )

    engine.rule(
        when=condition(f"Is {LocationAnalysis.commonality} and {Material.name} related?"),
        then=action(partial(LocationResult, all_related=True)),
    )

    engine.evaluate()
    assert engine[LocationAnalysis].commonality == "volcano"
    assert engine[LocationResult].all_related is True


# Test case for https://github.com/latchfield/vulcan-core/issues/31
def test_ai_rule_retry(engine: RuleEngine):
    call_count = 1
    failure_count = 3

    class MockModel(BaseChatModel):
        """Mock model to simulate failing AI response"""

        @property
        def _llm_type(self) -> str:
            return "mock_model"

        def bind_tools(self, *args, **kwargs) -> Runnable[LanguageModelInput, BaseMessage]:
            return self

        def _generate(self, *args, **kwargs) -> ChatResult:
            nonlocal call_count
            call_count += 1
            if call_count <= failure_count:
                msg = f"Simulated failure on attempt {call_count}"
                raise ValueError(msg)

            tool = tool_call(
                id="call_1",
                name="BooleanDecision",
                args={"justification": "Something", "result": True, "invalid_inquiry": False},
            )

            message = AIMessage(content="", tool_calls=[tool])
            generation = ChatGeneration(message=message)
            return ChatResult(generations=[generation])

    engine.rule(
        when=condition(f"Are {LocationA.name} and {LocationB.name} volcanos?", model=MockModel()),
        then=action(partial(LocationAnalysis, commonality="volcano")),
    )

    # Simulate successful retry
    engine.evaluate()
    assert engine[LocationAnalysis].commonality == "volcano"

    # Simulate failure when exceeding max retries
    call_count = 1
    failure_count = 4
    with pytest.raises(ValueError, match="Simulated failure on attempt 4"):
        engine.evaluate()


# TODO: Simplify and clarify test fixtures throughout tests
@pytest.mark.integration
def test_rag_simple_rule(engine: RuleEngine):
    pass
    # Thoughts:
    # * 2 phase, AI to review prompt and determine best rag search
    # * Allow user to specifiy search terms as key
    # * Use prompt as-is for RAG lookup

    # engine.rule(
    #     when=condition(f"Does {NewsPaper.pages} speak favorably about {Team.name}?"),
    #     then=action(RuleFired()),
    # )

    # TODO: Add engine listeners/callbacks?
    # engine.rule(
    #     when=decision(lambda: Fact.value == "volcano"),
    #     then=invoke(some_function),
    # )
