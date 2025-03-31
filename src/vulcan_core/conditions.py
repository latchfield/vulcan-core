# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Latchfield Technologies http://latchfield.com

from __future__ import annotations

import _string  # type: ignore
import re
from abc import abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from string import Formatter
from typing import TYPE_CHECKING

from langchain.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from vulcan_core.actions import ASTProcessor
from vulcan_core.models import ConditionCallable, DeclaresFacts, Fact, FactHandler, Similarity

if TYPE_CHECKING:  # pragma: no cover - not used at runtime
    from langchain_core.language_models import BaseChatModel
    from langchain_core.runnables import RunnableSerializable


@dataclass(frozen=True, slots=True)
class Expression(DeclaresFacts):
    """
    Abstract base class for defining deferred logical expressions. It captures the assosciation of logic with Facts so
    that upon a Fact update, the logical expression can be selectively evaluated. It also provides a set of logical
    operators for combining conditions, resulting in a new CompoundCondition.
    """

    inverted: bool = field(kw_only=True, default=False)

    def _compound(self, other: Expression, operator: Operator) -> Expression:
        # Be sure to preserve the order of facts while removing duplicates
        combined_facts = tuple(dict.fromkeys(self.facts + other.facts))
        return CompoundCondition(combined_facts, self, operator, other)

    def __and__(self, other: Expression) -> Expression:
        return self._compound(other, Operator.AND)

    def __or__(self, other: Expression) -> Expression:
        return self._compound(other, Operator.OR)

    def __xor__(self, other: Expression) -> Expression:
        return self._compound(other, Operator.XOR)

    @abstractmethod
    def __call__(self, *args: Fact) -> bool: ...

    @abstractmethod
    def __invert__(self) -> Expression: ...


# TODO: Investigate cached condition and deadline parameters, useful for expensive calls like AI/DB conditions
@dataclass(frozen=True, slots=True)
class Condition(FactHandler[ConditionCallable, bool], Expression):
    """
    A Condition is a container to defer logical epxressions against a supplied Fact. The expression can be inverted
    using the `~` operator. Conditions also support the '&',  '|', and '^' operators for combinatorial logic.

    Attributes:
        facts (tuple[str, ...]): A tuple of strings representing the facts/attributes this condition
            depends upon. Each string should be in the format "ClassName.attribute" without nesting.
        func (Callable[..., bool]): A callable that implements the actual condition logic. It should
            return a boolean value indicating whether the condition is satisfied.
        is_inverted (bool): Flag indicating whether the condition result should be inverted.
    """

    def __call__(self, *args: Fact) -> bool:
        result = self.func(*args)
        return not result if self.inverted else result

    def __invert__(self) -> Condition:
        return Condition(self.facts, self.func, inverted=not self.inverted)


class Operator(Enum):
    """Represents the logical operation of a CompoundCondition"""

    AND = auto()
    OR = auto()
    XOR = auto()


@dataclass(frozen=True, slots=True)
class CompoundCondition(Expression):
    """
    Represents a compound logical condition composed of two sub-conditions, an operator, and an negation flag. This
    class allows for the deferred evaluation of complex logical expressions by combining simpler conditions using
    logical operators such as `&`, `|`, and `^`.

    CompoundConditions are chain evaluated from left to right. For example, `a | b | c` is equivalent to: `(a | b) | c`
    but ordering can be overriden with parenthesis: `a | (b | c)` which is equivalent to: `(a) | (b | c)`.

    This clas should not be used directly in favor of the logical operators.
    """

    left: Expression
    operator: Operator
    right: Expression

    # TODO: Add a compile method that generates a lambda function with AST for faster evaluation

    def _pick_args(self, expr: Expression, args) -> list[Fact]:
        """Returns the arg values passed to this CompoundCondition that are needed by the given expression."""
        return [arg for fact, arg in zip(self.facts, args, strict=False) if fact in expr.facts]

    def __call__(self, *args: Fact) -> bool:
        """
        Upon evaluation, each sub-condition is evaluated and combined using the operator. If the CompoundCondition is
        negated, the result is inverted before being returned.
        """

        left_args = self._pick_args(self.left, args)
        right_args = self._pick_args(self.right, args)

        left_result = self.left(*left_args)
        right_result = self.right(*right_args)

        if self.operator == Operator.AND:
            result = left_result and right_result
        elif self.operator == Operator.OR:
            result = left_result or right_result
        elif self.operator == Operator.XOR:
            result = left_result ^ right_result
        else:
            msg = (
                f"Operator {self.operator} not implemented"  # pragma: no cover - Saftey check for future enum additions
            )
            raise NotImplementedError(msg)

        return not result if self.inverted else result

    def __invert__(self) -> CompoundCondition:
        return CompoundCondition(self.facts, self.left, self.operator, self.right, inverted=not self.inverted)


class MissingFactError(Exception):
    """Raised when and AI condition has no declared facts for context."""


class AIDecisionError(Exception):
    """Raised when an AI detrmines an error with the inquiry during evaluation."""


# TODO: Move this to models module?
class BooleanDecision(BaseModel):
    rationale: str = Field(description="A short explanation for the decision or error.")
    answer: bool = Field(description="The answer to the inquiry.")
    error: bool = Field(description="'True' if any error was encountered with the inquiry and/or response.")


class DeferredFormatter(Formatter):
    """Formatter that defers the evaluation of value searches."""

    def __init__(self):
        super().__init__()
        self.found_lookups: dict[str, Similarity] = {}

    def get_field(self, field_name, args, kwargs):
        first, rest = _string.formatter_field_name_split(field_name)
        obj = self.get_value(first, args, kwargs)

        for is_attr, i in rest:
            obj = getattr(obj, i) if is_attr else obj[i]
            if isinstance(obj, Similarity):
                self.found_lookups[field_name] = obj
                return (f"{{{field_name}}}", field_name)
        return obj, first


class LiteralFormatter(Formatter):
    """A formatter that does not inspect attributes of the object being formatted."""

    def get_field(self, field_name, args, kwargs):
        return (self.get_value(field_name, args, kwargs), field_name)


@dataclass(frozen=True, slots=True)
class AICondition(Condition):
    chain: RunnableSerializable
    system_template: str
    inquiry_template: str
    func: None = field(init=False, default=None)

    def __call__(self, *args: Fact) -> bool:
        # Use just the fact names to format the system message
        keys = {key.split(".")[0]: key for key in self.facts}.keys()

        # Format everything except any LazyLookup objects
        formatter = DeferredFormatter()
        system_msg = formatter.vformat(self.system_template, [], dict(zip(keys, args, strict=False)))
        rag_lookup = formatter.vformat(self.inquiry_template, [], dict(zip(keys, args, strict=False)))
        rag_lookup = rag_lookup.translate(str.maketrans("{}", "<>"))

        values = {}
        for f_name, lookup in formatter.found_lookups.items():
            values[f_name] = lookup[rag_lookup]

        system_msg = LiteralFormatter().vformat(system_msg, [], values)

        # Invoke the LLM and get the result
        inquiry = self.inquiry_template.translate(str.maketrans("{}", "<>"))
        result: BooleanDecision = self.chain.invoke({"system_msg": system_msg, "inquiry": inquiry})
        if result.error:
            raise AIDecisionError(result.rationale)

        return not result.answer if self.inverted else result.answer


# TODO: Investigate how best to register tools for specific consitions
def ai_condition(model: BaseChatModel, inquiry: str) -> AICondition:
    # TODO: Optimize by precompiling regex and storing translation table globally
    # Find and referenced facts and replace braces with angle brackets
    facts = tuple(re.findall(r"\{([^}]+)\}", inquiry))
    # inquiry = inquiry.translate(str.maketrans("{}", "<>"))

    # TODO: Determine if this should be kept, especially with LLMs calling tools
    if not facts:
        msg = "An AI condition requires at least one referenced fact."
        raise MissingFactError(msg)

    # TODO: Move these rules to a validation rule set for ai conditions
    system = "Answer the <inquiry> by referencing the following information tags:\n\n"

    for fact in facts:
        system += f"<{fact}>\n{{{fact}}}\n<{fact}/>\n\n"
    system += "</instructions>"

    prompt_template = ChatPromptTemplate.from_messages(
        [
            ("system", "{system_msg}"),
            ("user", "<inquiry>{inquiry}</inquiry>"),
        ]
    )
    structured_model = model.with_structured_output(BooleanDecision)
    chain = prompt_template | structured_model
    return AICondition(chain=chain, system_template=system, inquiry_template=inquiry, facts=facts)


default_model = ChatOpenAI(model="gpt-4o-mini", temperature=0, max_tokens=100)  # type: ignore[call-arg] - pyright can't see the args for some reason


def condition(func: ConditionCallable | str) -> Condition:
    """
    Creates a Condition object from a lambda or function. It performs limited static analysis of the code to ensure
    proper usage and discover the facts/attributes accessed by the condition. This allows the rule engine to track
    dependencies between conditions and facts with minimal boilerplate code.

    Lambda usage requires Fact access via accessing static class attributes (e.g., User.age). Whereas functions are not
    allowed to access class attributes statically, and must only access attributes via parameter instances. Neither
    lambdas or functions are allowed to access instances outside of their scope.

    Args:
        func (Callable[..., bool]): A lambda or function that returns a boolean value.
            For regular functions, parameters must be properly type-hinted with Fact subclasses. For lambdas, no
            parameters are allowed.

    Returns:
        Condition: A Condition object containing:
            - facts: A tuple of fact identifiers in the form "FactClass.attribute"
            - func: The transformed callable that will evaluate the condition

    Raises:
        - ASTProcessingError: If unable to retrieve caller globals or process the AST.
        - CallableSignatureError: If async functions are used or signature validation fails
        - ScopeAccessError: If attributes are accessed from classes not passed as parameters

    Example:
        # Will be transformed to accept instances of User:
        is_user_adult = condition(lambda: User.age >= User.max_age)

        # As with the lambda, decorated functions will be analyzed for which Facts attributes are accessed:
        @condition
        def is_user_adult(user: User) -> bool:
            return user.age >= user.max_age

    Notes:
        - Async functions are not supported
        - Nested attribute access (e.g., a.b.c) is not allowed
    """

    if not isinstance(func, str):
        processed = ASTProcessor[ConditionCallable](func, condition, bool)
        return Condition(processed.facts, processed.func)
    else:
        return ai_condition(default_model, func)


# TODO: Create a convenience function for creating OnFactChanged conditions
@dataclass(frozen=True, slots=True)
class OnFactChanged(Condition):
    """
    A condition that always returns True. It is used to trigger rules when a Fact is updated. It is useful for rules
    that need to simply update a Fact when another fact is updated.
    """

    def __call__(self, *args: Fact) -> bool:
        return True
