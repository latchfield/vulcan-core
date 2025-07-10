# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Latchfield Technologies http://latchfield.com

from __future__ import annotations

from dataclasses import dataclass
from functools import partial

from vulcan_core.ast_utils import ASTProcessor
from vulcan_core.models import ActionCallable, ActionReturn, DeclaresFacts, Fact, FactHandler


@dataclass(frozen=True, slots=True)
class Action(FactHandler[ActionCallable, ActionReturn], DeclaresFacts):
    """
    Represents a deferred result calculation of a rule.
    """

    def __call__(self, *args: Fact) -> ActionReturn:
        return self._evaluate(*args)

    def _evaluate(self, *args: Fact) -> ActionReturn:
        return self.func(*args)


def action(value: ActionCallable | ActionReturn) -> Action:
    if not isinstance(value, partial) and callable(value):
        processed = ASTProcessor[ActionCallable](value, action, ActionReturn)
        return Action(processed.facts, processed.func)
    else:
        return Action((), lambda: value)
