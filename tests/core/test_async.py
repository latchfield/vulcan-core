# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Latchfield Technologies http://latchfield.com

import asyncio
from functools import partial
from unittest.mock import AsyncMock, MagicMock

import pytest
import yaml
from langchain_core.language_models import BaseChatModel

from vulcan_core import condition
from vulcan_core.actions import action
from vulcan_core.conditions import BooleanDecision
from vulcan_core.engine import RuleEngine
from vulcan_core.models import Fact

RULE_COUNT = 5
BARRIER_TIMEOUT = 0.25


class Subject(Fact):
    name: str = "test"


class Outcome(Fact):
    triggered: int = 0


@pytest.fixture
def chain() -> MagicMock:
    def invoke(*_) -> BooleanDecision:
        return BooleanDecision(comments="sync call", result=True, processing_failed=False)

    async def ainvoke(*_) -> BooleanDecision:
        if barrier := getattr(structured, "barrier", None):
            async with asyncio.timeout(BARRIER_TIMEOUT):
                await barrier.wait()
        return BooleanDecision(comments="async call", result=True, processing_failed=False)

    mock = MagicMock(spec=BaseChatModel)
    structured = MagicMock(spec=BaseChatModel)
    structured.invoke.side_effect = invoke
    structured.ainvoke = AsyncMock(side_effect=ainvoke)
    mock.with_structured_output.return_value = structured
    return mock


@pytest.fixture
def engine(chain: MagicMock) -> RuleEngine:
    # Build engine with RULE_COUNT independent AI conditions
    eng = RuleEngine()
    eng.fact(Subject(name="test"))

    for i in range(RULE_COUNT):
        eng.rule(
            name=f"rule_{i}",
            when=condition(f"Is {Subject.name} valid?", model=chain),
            then=action(partial(Outcome, triggered=i)),
        )

    return eng


@pytest.fixture
def compound_engine(chain: MagicMock) -> RuleEngine:
    # Build engine with (A & B) | (C & D) for compound condition hierarchy tests
    eng = RuleEngine()
    eng.fact(Subject(name="test"))

    cond_a = condition(f"Is {Subject.name} condition A?", model=chain)
    cond_b = condition(f"Is {Subject.name} condition B?", model=chain)
    cond_c = condition(f"Is {Subject.name} condition C?", model=chain)
    cond_d = condition(f"Is {Subject.name} condition D?", model=chain)
    eng.rule(
        name="compound_rule",
        when=(cond_a & cond_b) | (cond_c & cond_d),
        then=action(partial(Outcome, triggered=0)),
    )

    return eng


def test_evaluate_uses_sync(engine: RuleEngine, chain: MagicMock) -> None:
    engine.evaluate()

    structured = chain.with_structured_output.return_value
    assert structured.invoke.call_count == RULE_COUNT
    assert structured.ainvoke.call_count == 0


@pytest.mark.asyncio
async def test_aevaluate_uses_async(engine: RuleEngine, chain: MagicMock) -> None:
    structured = chain.with_structured_output.return_value

    # Barrier gates all RULE_COUNT ainvoke calls simultaneously; sequential
    # execution would deadlock, proving parallel gather is used.
    structured.barrier = asyncio.Barrier(RULE_COUNT)
    await engine.aevaluate()

    assert structured.ainvoke.call_count == RULE_COUNT
    assert structured.invoke.call_count == 0


@pytest.mark.asyncio
async def test_aevaluate_audit_integrity(engine: RuleEngine) -> None:
    await engine.aevaluate(audit=True)

    report = yaml.safe_load(engine.yaml_report())
    iterations = report["report"]["iterations"]
    assert len(iterations) == 1

    matches = iterations[0]["matches"]
    assert len(matches) == RULE_COUNT
    assert all(match["elapsed"] >= 0 for match in matches)


@pytest.mark.asyncio
async def test_aevaluate_speculative_parallel(compound_engine: RuleEngine, chain: MagicMock) -> None:
    structured = chain.with_structured_output.return_value

    # Barrier requires all 4 AI terms across both compound levels to be active
    # simultaneously. If any level evaluates sequentially, the barrier never
    # fills and the test deadlocks, catching the regression.
    structured.barrier = asyncio.Barrier(4)
    await compound_engine.aevaluate(speculative=True)

    assert structured.ainvoke.call_count == 4


def test_evaluate_compound_short_circuits(compound_engine: RuleEngine, chain: MagicMock) -> None:
    compound_engine.evaluate()

    # (A & B) | (C & D): A=True, B=True → True, OR short-circuits, C and D are skipped
    structured = chain.with_structured_output.return_value
    assert structured.invoke.call_count == 2
    assert structured.ainvoke.call_count == 0
