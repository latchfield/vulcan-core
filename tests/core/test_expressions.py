# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Latchfield Technologies http://latchfield.com

import pytest

from vulcan_core import Condition, Fact


class FactA(Fact):
    value: bool


class FactB(Fact):
    value: int


class FactC(Fact):
    value: str


@pytest.fixture
def facts() -> dict[str, Fact]:
    return {
        "FactA.value": FactA(value=True),
        "FactB.value": FactB(value=1),
        "FactC.value": FactC(value="test"),
    }


@pytest.fixture
def cond_a() -> Condition:
    return Condition(facts=("FactA.value",), func=lambda fact: fact.value)


@pytest.fixture
def cond_b() -> Condition:
    return Condition(facts=("FactB.value",), func=lambda fact: fact.value > 10)


@pytest.fixture
def cond_c() -> Condition:
    return Condition(facts=("FactC.value",), func=lambda fact: fact.value == "test")


def resolve_args(facts, needed_facts) -> list[Fact]:
    return [facts[key] for key in needed_facts if key in facts]


class TestCondition:
    def test_condition_evaluation(self, cond_a: Condition, cond_b: Condition, facts: dict[str, Fact]):
        assert cond_a(facts["FactA.value"]) is True
        assert cond_b(facts["FactB.value"]) is False

    def test_condition_inversion(self, cond_a: Condition, facts: dict[str, Fact]):
        inverse_condition = ~cond_a
        assert inverse_condition(facts["FactA.value"]) is False
        assert inverse_condition.inverted is True

    def test_condition_facts_tracking(self, cond_a: Condition, cond_b: Condition):
        assert cond_a.facts == ("FactA.value",)
        assert cond_b.facts == ("FactB.value",)


class TestCompoundCondition:
    def test_and_operation_true(self, cond_a: Condition, cond_c: Condition, facts: dict[str, Fact]):
        compound = cond_a & cond_c
        args = resolve_args(facts, compound.facts)
        assert compound(*args) is True

    def test_and_operation_false(self, cond_a: Condition, cond_b: Condition, facts: dict[str, Fact]):
        compound = cond_a & cond_b
        args = resolve_args(facts, compound.facts)
        assert compound(*args) is False

    def test_or_operation_true(self, cond_a: Condition, cond_b: Condition, facts: dict[str, Fact]):
        compound = cond_a | cond_b
        args = resolve_args(facts, compound.facts)
        assert compound(*args) is True

    def test_or_operation_false(self, cond_a: Condition, cond_b: Condition, facts: dict[str, Fact]):
        compound = ~cond_a | cond_b
        args = resolve_args(facts, compound.facts)
        assert compound(*args) is False

    def test_xor_operation_true(self, cond_a: Condition, cond_b: Condition, facts: dict[str, Fact]):
        compound = cond_a ^ cond_b
        args = resolve_args(facts, compound.facts)
        assert compound(*args) is True

    def test_xor_operation_false(self, cond_a: Condition, cond_c: Condition, facts: dict[str, Fact]):
        compound = cond_a ^ cond_c
        args = resolve_args(facts, compound.facts)
        assert compound(*args) is False

    def test_compound_inversion(self, cond_a: Condition, cond_b: Condition, facts: dict[str, Fact]):
        compound = ~(cond_a | cond_b)
        args = resolve_args(facts, compound.facts)
        assert compound(*args) is False
        assert compound.inverted is True

    def test_compound_facts_tracking(self, cond_a: Condition, cond_b: Condition, cond_c: Condition):
        compound = cond_a & cond_c | cond_b
        assert compound.facts == ("FactA.value", "FactC.value", "FactB.value")

    def test_compound_facts_tracking_duplicates(self, cond_a: Condition, cond_b: Condition):
        compound = cond_a & cond_b | cond_b
        assert compound.facts == ("FactA.value", "FactB.value")

    def test_complex_combination(self, cond_a: Condition, cond_b: Condition, cond_c: Condition, facts: dict[str, Fact]):
        complex_expr = (cond_c & cond_b) | ~cond_b
        args = resolve_args(facts, complex_expr.facts)
        assert complex_expr(*args) is True
