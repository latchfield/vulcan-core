# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Latchfield Technologies http://latchfield.com

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from functools import cached_property, partial
from types import MappingProxyType
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from vulcan_core.ast_utils import NotAFactError
from vulcan_core.models import DeclaresFacts, Fact
from vulcan_core.reporting import Auditor

if TYPE_CHECKING:  # pragma: no cover - not used at runtime
    from collections.abc import Mapping

    from vulcan_core.actions import Action
    from vulcan_core.conditions import Expression

logger = logging.getLogger(__name__)


class InternalStateError(RuntimeError):
    """Raised when the internal state of the RuleEngine is invalid."""


class RecursionLimitError(RuntimeError):
    """Raised when the recursion limit is reached during rule evaluation."""


@dataclass(frozen=True)
class Rule:
    """
    Represents a rule with a condition and corresponding actions.

    Attributes:
        - id (UUID): A unique identifier for the rule, automatically generated.
        - name (Optional[str]): The name of the rule.
        - when (Expression): The condition that triggers the rule.
        - then (Action): The action to be executed when the condition is met.
        - inverse (Optional[Action]): An optional action to be executed when the condition is not met.
    """

    id: UUID = field(default_factory=uuid4, init=False)
    name: str | None
    when: Expression
    then: Action
    inverse: Action | None


# TODO: Look into support for langchain operators and lang graph integration


@dataclass(kw_only=True)
class RuleEngine:
    """
    RuleEngine is a class that manages the evaluation of rules based on a set of facts. It allows for the addition of rules,
    updating of facts, and cascading evaluation of rules.

    Attributes:
        enabled (bool): Indicates whether the rule engine is enabled.
        recusion_limit (int): The maximum number of recursive evaluations allowed.
        facts (dict[type[Fact], Fact]): A dictionary to store facts with their types as keys.
        rules (dict[str, list[Rule]]): A dictionary to store rules associated with fact strings.

    Methods:
        rule(self, *, name: str | None = None, when: LogicEvaluator, then: BaseAction, inverse: BaseAction | None = None): Adds a rule to the rule engine.
        update_facts(self, fact: tuple[Fact | partial[Fact], ...] | partial[Fact] | Fact) -> Iterator[str]: Updates the facts in the working memory.
        evaluate(self, trace: bool = False): Evaluates the rules based on the current facts in working memory.
        yaml_report(self): Returns the YAML report of the last evaluation (if tracing was enabled).
    """

    enabled: bool = False
    recusion_limit: int = 10
    _facts: dict[str, Fact] = field(default_factory=dict, init=False)
    _rules: dict[str, list[Rule]] = field(default_factory=dict, init=False)
    _audit: Auditor = field(default_factory=Auditor, init=False)

    @cached_property
    def facts(self) -> Mapping[str, Fact]:
        return MappingProxyType(self._facts)

    @cached_property
    def rules(self) -> Mapping[str, list[Rule]]:
        return MappingProxyType(self._rules)

    def __getitem__[T: Fact](self, key: type[T]) -> T:
        """
        Retrieves a fact from the working memory.

        Args:
            key (type[Fact]): The type of the fact to retrieve.

        Returns:
            T: The fact instance of the specified type.
        """
        return self._facts[key.__name__]  # type: ignore

    def fact(self, fact: Fact | partial[Fact]):
        """
        Updates the working memory with a new fact or merges a partial fact.

        Args:
            fact (Union[Fact, partial[Fact]]): The fact instance or partial fact to update the working memory with.

        Raises:
            InternalStateError: If a partial fact cannot be instantiated due to missing required fields
        """
        # TODO: Figure out how to track only fact attributes that have changed, and fire on affected rules

        if isinstance(fact, partial):
            fact_name = fact.func.__name__
            fact_class = fact.func
            if not issubclass(fact_class, Fact):  # type: ignore
                raise NotAFactError(fact_class)

            if fact_name in self._facts:
                self._facts[fact_name] |= fact
            else:
                try:
                    self._facts[fact_name] = fact()
                except TypeError as err:
                    msg = f"Fact '{fact_name}' is missing and lacks sufficient defaults to create from partial: {fact}"
                    raise InternalStateError(msg) from err
        else:
            fact_class = type(fact)
            if not issubclass(fact_class, Fact):
                raise NotAFactError(fact_class)

            self._facts[type(fact).__name__] = fact

    def rule[T: Fact](
        self, *, name: str | None = None, when: Expression, then: Action, inverse: Action | None = None
    ) -> None:
        """
        Convenience method for adding a rule to the rule engine.

        Args:
            name (Optional[str]): The name of the rule. Defaults to None.
            when (Expression): The condition that triggers the rule.
            then (Action): The action to be executed when the condition is met.
            inverse (Optional[Action]): The action to be executed when the condition is not met. Defaults to None.

        Returns:
            None
        """
        rule = Rule(name, when, then, inverse)

        # TODO: Add automatic inverse option?

        # Update the facts to rule mapping
        for fact_str in when.facts:
            if fact_str in self._rules:
                self._rules[fact_str].append(rule)
            else:
                self._rules[fact_str] = [rule]

    def _update_facts(self, fact: tuple[Fact | partial[Fact], ...] | partial[Fact] | Fact) -> list[str]:
        """
        Updates the fact in the facts dictionary. If the provided fact is an instance of Fact, it updates the dictionary
        with the type of the fact as the key. If the provided fact is a partial function, it updates the dictionary with
        the function of the partial as the key.

        Args:
            fact (tuple[Fact | partial[Fact], ...] | partial[Fact] | Fact): The fact(s) to be updated, either as an instance of Fact, a partial function, or a tuple of either.

        Returns:
            Iterator[str]: An iterator over the fact strings of the updated facts.
        """
        facts = fact if isinstance(fact, tuple) else (fact,)
        updated = []

        for f in facts:
            self.fact(f)

            # Track which attributes were updated
            if isinstance(f, partial):
                fact_name = f.func.__name__
                attrs = f.keywords
            else:
                fact_name = f.__class__.__name__
                attrs = vars(f)

            updated.extend([f"{fact_name}.{attr}" for attr in attrs])

        return updated

    def _resolve_facts(self, declared: DeclaresFacts, facts: dict[str, Fact]) -> list[Fact]:
        # Deduplicate the fact strings and retrieve unique fact instances
        keys = {key.split(".")[0]: key for key in declared.facts}.values()
        return [facts[key.split(".")[0]] for key in keys]

    def evaluate(self, fact: Fact | partial[Fact] | None = None, *, audit: bool = False):
        """
        Cascading evaluation of rules based on the facts in working memory.

        If provided a fact, will update and evaluate immediately. Otherwise all rules will be evaluated.

        Args:
            fact: Optional fact to update and evaluate immediately
            audit: Enables tracing for explanbility report generation
        """
        evaluated_rules: set[UUID] = set()
        consequence: set[str] = set()

        # TODO: Create an internal consistency check to determine if all referenced Facts are present?

        # TODO: detect cycles in graph before executing
        # Move to a separate lifecycle step?
        # Provide option for handling

        # TODO: Check whether fact attributes have actually changed, and only fire rules that are affected
        if fact:
            scope = self._update_facts(fact)
        else:
            # By default, evaluate all facts
            fact_list = self._facts.values()
            scope = {f"{fact.__class__.__name__}.{attr}" for fact in fact_list for attr in vars(fact)}

        if audit:
            self._audit.evaluation_reset()

        # Iterate over the rules until the recusion limit is reached or no new rules are fired
        for iteration in range(self.recusion_limit + 1):
            if iteration == self.recusion_limit:
                msg = f"Recursion limit of {self.recusion_limit} reached"
                raise RecursionLimitError(msg)

            # Ensure that rules do not interfere with one another in the same iteration
            facts_snapshot = self._facts.copy()

            if audit:
                self._audit.iteration_start()

            # Evaluate matching rules
            for fact_str, rules in self._rules.items():
                if fact_str in scope:
                    for rule in rules:
                        # Skip the rule if it was already evaluated in this iteration (due to matching on another Fact)
                        if rule.id in evaluated_rules:
                            continue
                        evaluated_rules.add(rule.id)

                        # Skip if not all facts required by the rule are present
                        try:
                            resolved_facts = self._resolve_facts(rule.when, facts_snapshot)
                        except KeyError as e:
                            logger.debug("Rule %s (%s) skipped due to missing fact: %s", rule.name, rule.id, str(e))
                            continue

                        if audit:
                            self._audit.rule_start()

                        # Evaluate the rule and prepare the aciton
                        action = None
                        condition_result = rule.when(*resolved_facts)
                        if condition_result:
                            action = rule.then
                        elif rule.inverse:
                            action = rule.inverse

                        # Evaluate the action and update the consequences
                        action_result = None
                        if action:
                            action_result = action(*self._resolve_facts(action, facts_snapshot))
                            facts = self._update_facts(action_result)
                            consequence.update(facts)

                        if audit:
                            self._audit.rule_end(rule, action_result, facts_snapshot, condition_result=condition_result)

            if audit:
                self._audit.iteration_end()

            # Check for next iteration
            if consequence:
                scope = consequence
                consequence = set()
                evaluated_rules.clear()
            else:
                break

    def yaml_report(self) -> str:
        return self._audit.generate_yaml_report()
