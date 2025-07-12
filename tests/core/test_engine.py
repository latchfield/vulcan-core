# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Latchfield Technologies http://latchfield.com

from dataclasses import dataclass
from functools import partial

import pytest
import yaml
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
# Updated for https://github.com/latchfield/vulcan-core/issues/46
def test_lambda_reparsing(engine: RuleEngine):
    for _ in range(2):
        load_simple_rule(engine)


def test_same_fact_multiple_attributes_lambda(engine: RuleEngine):
    engine.rule(
        when=condition(lambda: Foo.baz or Foo.bol or Foo.baz),
        then=action(partial(Bar, biz=True)),
    )

    engine.evaluate()
    assert engine[Bar].biz is True


# https://github.com/latchfield/vulcan-core/issues/65
def test_multiline_rule(engine: RuleEngine):
    cond1 = condition(lambda: Foo.baz)
    cond2 = condition(lambda: Foo.bol)

    # fmt: off
    engine.rule(
        when=cond1
        & cond2
        & condition(lambda: Foo.baz or Foo.bol or Foo.baz),
        then=action(partial(Bar, biz=True)),
    )
    # fmt: on

    engine.evaluate()
    assert engine[Bar].biz is True


# https://github.com/latchfield/vulcan-core/issues/65
def test_rule_with_reserved_literals(engine: RuleEngine):
    # fmt: off
    engine.rule(
        when=condition(lambda: Foo.bol)
        & condition(lambda: "lambda:" != None) & condition(lambda: Foo.baz),
        then=action(partial(Bar, biz=True)),
    )
    # fmt: on

    engine.evaluate()
    assert engine[Bar].biz is True


# https://github.com/latchfield/vulcan-core/issues/66
def test_same_fact_multiple_attributes_compound_conditions(engine: RuleEngine):
    # Suspect there may be a random component somewhere - sometimes this test passes when expected to fail
    engine.rule(
        when=condition(lambda: Foo.baz) & condition(lambda: Foo.bol),
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


# Test case for https://github.com/latchfield/vulcan-core/issues/61
def test_skip_rule_missing_facts():
    engine = RuleEngine()

    engine.rule(
        when=condition(lambda: Foo.baz and Bar.biz),
        then=action(partial(Biff, bez=True)),
        inverse=action(partial(Biff, bez=False)),
    )

    engine.evaluate(Foo())
    assert Biff.__name__ not in engine.facts


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
                args={"comments": "Something", "result": True, "processing_failed": False},
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


# Test case for https://github.com/latchfield/vulcan-core/issues/76
def test_fact_insertion_iteration_matching():
    # Test that rules that previously did not match are not fired in the same
    # iteration if another fact satisfies the match criteria
    engine = RuleEngine()
    engine.fact(Foo())

    engine.rule(
        name="First rule",
        when=condition(lambda: Foo.baz),
        then=action(partial(Bar, biz=True)),
    )

    engine.rule(
        name="Second rule",
        when=condition(lambda: Bar.biz),
        then=action(partial(Biff, bez=False, bil=42)),
    )

    engine.rule(
        name="Third rule",
        when=condition(lambda: Bar.biz and Biff.bez),
        then=action(partial(Foo, bol=False)),
    )

    engine.evaluate(audit=True)
    report = yaml.safe_load(engine.yaml_report())
    matches = report["report"]["iterations"][1]["matches"]
    assert len(matches) == 1


# Test case for https://github.com/latchfield/vulcan-core/issues/76
def test_rule_iteration_interactions():
    # Test that rules that match in the same iteration do not interfere with each other
    engine = RuleEngine()
    engine.fact(Foo())
    engine.fact(Bar(bul=0))

    engine.rule(
        name="First rule",
        when=condition(lambda: Foo.baz),
        then=action(partial(Bar, bul=10)),
    )

    engine.rule(
        name="Second rule",
        when=condition(lambda: Bar.bul > 5),
        then=action(partial(Biff, bez=True, bil=0)),
    )

    engine.evaluate(audit=True)
    report = yaml.safe_load(engine.yaml_report())

    # The second rule should fire twice, but with different values
    # The first evaluation should use the initial value of Bar.bul
    # The second evaluation should use the updated value from the first rule
    evaluation1 = report["report"]["iterations"][0]["matches"][1]["evaluation"]
    evaluation2 = report["report"]["iterations"][1]["matches"][0]["evaluation"]
    assert evaluation1 == "False = (Bar.bul|0| > 5)"
    assert evaluation2 == "True = (Bar.bul|10| > 5)"


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
