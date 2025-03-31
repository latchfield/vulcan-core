# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Latchfield Technologies http://latchfield.com

from functools import partial

import pytest

from vulcan_core import Fact, InternalStateError, RecursionLimitError, RuleEngine, action, condition


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
