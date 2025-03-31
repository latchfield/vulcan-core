# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Latchfield Technologies http://latchfield.com

from functools import partial

import pytest

from vulcan_core import Action, ActionReturn, Fact, action


class Foo(Fact):
    baz: int = 10
    buz: bool = False


class Bar(Fact):
    biz: int = 5


@pytest.fixture
def foo_instance():
    return Foo()


@pytest.fixture
def bar_instance():
    return Bar()


def test_action_lambda(foo_instance: Foo, bar_instance: Bar):
    act = action(lambda: Bar(biz=Foo.baz + Bar.biz + 7))

    assert isinstance(act, Action)
    assert "Foo.baz" in act.facts
    assert "Bar.biz" in act.facts

    result = act(foo_instance, bar_instance)
    assert isinstance(result, Bar)
    assert result.biz == foo_instance.baz + bar_instance.biz + 7


def test_action_decorator(foo_instance: Foo, bar_instance: Bar):
    @action
    def act(first: Foo, second: Bar) -> ActionReturn:
        return Bar(biz=first.baz - second.biz - 7)

    assert isinstance(act, Action)
    assert "Foo.baz" in act.facts
    assert "Bar.biz" in act.facts

    result = act(foo_instance, bar_instance)
    assert isinstance(result, Bar)
    assert result.biz == foo_instance.baz - bar_instance.biz - 7


def test_partial_return_lambda(bar_instance: Bar):
    act = action(lambda: partial(Foo, baz=Bar.biz + 7))
    assert "Bar.biz" in act.facts

    result = act(bar_instance)
    assert isinstance(result, partial)
    foo = result()

    assert isinstance(foo, Foo)
    assert foo.baz == bar_instance.biz + 7


def test_multiple_returns_lambda(foo_instance: Foo, bar_instance: Bar):
    act = action(lambda: (Bar(biz=Foo.baz + 7), partial(Foo, baz=Bar.biz + 9)))
    result = act(foo_instance, bar_instance)

    assert isinstance(result, tuple)
    assert len(result) == 2
    assert isinstance(result[0], Bar)
    assert isinstance(result[1], partial)

    assert result[0].biz == foo_instance.baz + 7
    foo = result[1]()
    assert isinstance(foo, Foo)
    assert foo.baz == bar_instance.biz + 9


def test_multiple_returns_decorator(foo_instance: Foo, bar_instance: Bar):
    @action
    def act(first: Foo, second: Bar) -> ActionReturn:
        return Bar(biz=first.baz), partial(Foo, baz=second.biz + 9)

    result = act(foo_instance, bar_instance)
    assert isinstance(result, tuple)
    assert len(result) == 2
    assert isinstance(result[0], Bar)
    assert isinstance(result[1], partial)

    foo = result[1]()
    assert isinstance(foo, Foo)
    assert foo.baz == bar_instance.biz + 9
