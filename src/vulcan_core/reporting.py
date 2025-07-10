# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Latchfield Technologies http://latchfield.com

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial
from typing import TYPE_CHECKING, Any

import yaml

from vulcan_core.conditions import AICondition, CompoundCondition, Condition

if TYPE_CHECKING:  # pragma: no cover - not used at runtime
    from collections.abc import Mapping
    from vulcan_core.conditions import Expression
    from vulcan_core.engine import Rule
    from vulcan_core.models import ActionReturn, Fact

Primitive = int | float | bool | str | bytes | complex


class ReportGenerationError(RuntimeError):
    """Raised when there is an error generating a report from the rule engine."""


class StopWatchError(RuntimeError):
    """Raised when there is an error with the stopwatch operations."""


@dataclass(slots=True)
class StopWatch:
    """A simple stopwatch for timing operations."""

    _duration: float | None = field(default=None, init=False)
    _timestamp: datetime | None = field(default=None, init=False)
    _start_time: float | None = field(default=None, init=False)

    @property
    def duration(self) -> float:
        """Get the duration between start and stopwatch in seconds."""
        if self._duration is None:
            msg = "No stopwatch measurement. Call start() then stop() before accessing duration."
            raise StopWatchError(msg)

        return self._duration

    @property
    def timestamp(self) -> datetime:
        """Get the timestamp of when the stopwatch was started."""
        if self._timestamp is None:
            msg = "Stopwatch not started. Call start() first."
            raise StopWatchError(msg)

        return self._timestamp

    def start(self) -> None:
        """Start or restart the stopwatch."""
        self._start_time = time.time()
        self._timestamp = datetime.now(UTC)
        self._duration = None

    def stop(self) -> None:
        """Stop the stopwatch and calculate duration."""
        if self._start_time is None:
            msg = "Stopwatch not started. Call start() first."
            raise StopWatchError(msg)

        self._duration = time.time() - self._start_time
        self._start_time = None


@dataclass(frozen=True, slots=True)
class RuleMatch:
    """Represents a single rule match within an iteration."""

    rule: str  # Format: "id:name"
    timestamp: datetime
    elapsed: float  # seconds with millisecond precision
    evaluation: str  # String representation of the evaluation
    consequences: tuple[RuleConsequence, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)
    context: tuple[RuleContext, ...] = field(default_factory=tuple)
    rationale: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for YAML serialization."""
        # Format timestamp as 'YYYY-MM-DDTHH:MM:SS(.ffffff)Z' (no offset)
        ts = self.timestamp
        if ts.tzinfo is not None:
            ts = ts.astimezone(UTC).replace(tzinfo=None)
        result = {
            "rule": self.rule,
            "timestamp": ts.isoformat() + "Z",
            "elapsed": round(self.elapsed, 3),
            "evaluation": self.evaluation,
        }

        # Handle consequences
        if self.consequences:
            consequences_dict = {}
            for consequence in self.consequences:
                consequences_dict.update(consequence.to_dict())
            result["consequences"] = consequences_dict
        else:
            result["consequences"] = None

        # Add optional fields only if they have content
        if self.warnings:
            result["warnings"] = list(self.warnings)

        if self.context:
            context_list = [ctx.to_dict() for ctx in self.context]
            result["context"] = context_list

        if self.rationale:
            result["rationale"] = self.rationale

        return result


@dataclass(frozen=True, slots=True)
class FactRecord:
    """Tracks fact attribute changes within an iteration."""

    rule_id: str
    rule_name: str
    value: Any


@dataclass(frozen=True, slots=True)
class Iteration:
    """Tracks iteration data during execution and provides serialization for reporting."""

    id: int = field(default=-1)
    stopwatch: StopWatch = field(default_factory=StopWatch, init=False)
    matched_rules: list[RuleMatch] = field(default_factory=list, init=False)
    updated_facts: dict[str, FactRecord] = field(default_factory=dict, init=False)

    def __post_init__(self):
        self.stopwatch.start()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for YAML serialization."""
        # Format timestamp as 'YYYY-MM-DDTHH:MM:SS(.ffffff)Z' (no offset)
        ts = self.stopwatch.timestamp
        if ts.tzinfo is not None:
            ts = ts.astimezone(UTC).replace(tzinfo=None)
        return {
            "id": self.id,
            "timestamp": ts.isoformat() + "Z",
            "elapsed": round(self.stopwatch.duration, 3),
            "matches": [match.to_dict() for match in self.matched_rules],
        }


@dataclass(frozen=True, slots=True)
class RuleConsequence:
    """Represents a consequences of a rule action."""

    fact_name: str
    attribute_name: str
    value: Primitive | None = None

    def to_dict(self) -> dict[str, Primitive | None]:
        """Convert to dictionary for YAML serialization."""

        if self.attribute_name:
            return {f"{self.fact_name}.{self.attribute_name}": self.value}
        else:
            return {self.fact_name: self.value}


@dataclass(frozen=True, slots=True)
class RuleContext:
    """Represents context information for values referenced in conditions."""

    fact_attribute: str
    value: str

    def to_dict(self) -> dict[str, str]:
        """Convert to dictionary for YAML serialization."""
        return {self.fact_attribute: self.value}


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    """Represents the complete evaluation report."""

    iterations: list[Iteration] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for YAML serialization."""
        return {"report": {"iterations": [iteration.to_dict() for iteration in self.iterations]}}

    def to_yaml(self) -> str:
        """Convert the report to YAML format."""

        # Create a custom representer for None values
        def represent_none(dumper: yaml.SafeDumper, data: None) -> yaml.ScalarNode:
            return dumper.represent_scalar("tag:yaml.org,2002:str", "None")

        # Create a custom dumper to avoid global state issues
        class CustomDumper(yaml.SafeDumper):
            pass

        # Add the custom representer to our custom dumper
        CustomDumper.add_representer(type(None), represent_none)

        # Also prevent hard-line wrapping by setting a high width
        return yaml.dump(
            self.to_dict(),
            Dumper=CustomDumper,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
            width=1000000,  # Very large width to prevent wrapping
        )


@dataclass(slots=True)
class ActionReporter:
    """Determines the consequences of an rule's action."""

    action_result: ActionReturn | None
    facts_dict: Mapping[str, Fact]
    consequences: list[RuleConsequence] = field(default_factory=list, init=False)

    def __post_init__(self):
        self._transform()

    def _transform(self):
        """Transform the action result(s) into consequences."""
        if self.action_result is None:
            return

        if isinstance(self.action_result, tuple):
            # Handle multiple action results
            for item in self.action_result:
                self.consequences.extend(self._fact_to_consequence(item))
        else:
            self.consequences.extend(self._fact_to_consequence(self.action_result))

    def _fact_to_consequence(self, fact: Fact | partial[Fact]) -> list[RuleConsequence]:
        """Extract consequences from a single fact or a partial."""
        consequences = []

        if isinstance(fact, partial):
            # Iterate over a partial's keywords to resolve attributes
            fact_name = fact.func.__name__
            attributes = fact.keywords.items()
        else:
            # For complete fact updates, report all attributes include default values
            fact_name = fact.__class__.__name__
            attributes = [(attr_name, getattr(fact, attr_name)) for attr_name in fact.__annotations__]

        # Dereference values and append to the consequences list
        for attr_name, value in attributes:
            attr_value = self._dereference(value) if isinstance(fact, partial) else value
            consequences.append(RuleConsequence(fact_name, attr_name, attr_value))

        return consequences

    def _dereference(self, value: Any) -> Primitive:
        """Detects whether the value is reference and resolves it to the actual value."""

        # FIXME: This needs to be replaced with a better typed solution. This will catch unintended str value cases.
        if isinstance(value, str) and value.startswith("{") and value.endswith("}"):
            # Assume this is a reference, such as "{FactName.attribute}"
            template_content = value[1:-1]  # Remove curly braces

            if "." in template_content:
                fact_name, attr_name = template_content.split(".", 1)
                if fact_name in self.facts_dict:
                    fact_instance = self.facts_dict[fact_name]
                    return getattr(fact_instance, attr_name)

        # If the value is not a primitive type, convert it to string
        if not isinstance(value, Primitive):
            value = str(value)

        return value


@dataclass(frozen=True, slots=True)
class RuleFormatter:
    """Formats rule data as strings for reporting."""

    condition: Expression
    fact_map: Mapping[str, Fact]
    result: bool | None = None

    _expression: str = field(default="", init=False)
    _ai_rationale: str | None = field(default=None, init=False)
    _context: tuple[RuleContext, ...] = field(default_factory=tuple, init=False)

    @property
    def expression(self) -> str:
        """Return the formatted rule evaluation expression."""
        return self._expression

    @property
    def ai_rationale(self) -> str | None:
        """Return the AI rationale for the condition, if applicable."""
        return self._ai_rationale

    @property
    def context(self) -> tuple[RuleContext, ...]:
        """Return the context for long strings or multiline values."""
        return self._context

    def __post_init__(self):
        expression = self._format_expression(self.condition, result=self.result)
        ai_rationale = self._format_ai_rationale(self.condition)
        context = self._format_context()

        object.__setattr__(self, "_expression", expression)
        object.__setattr__(self, "_ai_rationale", ai_rationale)
        object.__setattr__(self, "_context", context)

    def _format_context(self) -> tuple[RuleContext, ...]:
        """Extract context for long strings (>25 chars or multiline) from evaluation - input data only."""
        context = []

        # Check condition facts for long strings - only extract input data for conditions
        for fact_ref in self.condition.facts:
            class_name, attr_name = fact_ref.split(".", 1)
            if class_name in self.fact_map:
                fact_instance = self.fact_map[class_name]
                actual_value = getattr(fact_instance, attr_name)

                if self._should_extract_to_context(actual_value):
                    context.append(RuleContext(fact_ref, actual_value))

        return tuple(context)

    def _should_extract_to_context(self, value) -> bool:
        """Determine if a value should be extracted to context."""
        if isinstance(value, str):
            return len(value) > 25 or "\n" in value
        return False

    def _format_expression(self, condition: Expression, *, result: bool | None) -> str:
        """Format the evaluation string showing the condition with fact values."""

        # Format based on condition type
        if isinstance(condition, AICondition):
            expr = self._format_ai_condition(condition)
        elif isinstance(condition, CompoundCondition):
            expr = self._format_compound_condition(condition)
        elif isinstance(condition, Condition):
            expr = self._format_simple_condition(condition)
        else:
            msg = f"Unsupported expression type: {type(condition).__name__}"
            raise ReportGenerationError(msg)

        # Apply inversion if needed
        if condition.inverted:
            expr = f"not({expr})"

        return f"{result} = {expr}"

    def _format_ai_condition(self, condition: AICondition) -> str:
        """Format an AI condition with its template."""
        # For AI conditions, show the inquiry with fact values substituted
        inquiry = condition.inquiry
        for fact_ref in condition.facts:
            class_name, attr_name = fact_ref.split(".", 1)
            if class_name in self.fact_map:
                fact_instance = self.fact_map[class_name]
                actual_value = getattr(fact_instance, attr_name)

                # Show the value inline if it is not a long string or multiline
                if not self._should_extract_to_context(actual_value):
                    placeholder = f"{{{class_name}.{attr_name}}}"
                    inquiry = inquiry.replace(placeholder, f"{{{class_name}.{attr_name}|{actual_value}|}}")

        return f"{inquiry}"

    def _format_ai_rationale(self, condition: Expression) -> str | None:
        """Extract rationale from AI conditions after evaluation."""

        if isinstance(condition, AICondition):
            return condition.last_rationale()
        elif isinstance(condition, CompoundCondition):
            # Check left and right sides for AI conditions
            left_rationale = self._format_ai_rationale(condition.left)
            right_rationale = self._format_ai_rationale(condition.right)

            # Combine rationales if both exist
            if left_rationale and right_rationale:
                return f"{left_rationale}; {right_rationale}"
            elif left_rationale:
                return left_rationale
            elif right_rationale:
                return right_rationale

        return None

    def _format_simple_condition(self, condition: Condition) -> str:
        """Format a simple lambda-based condition."""

        expression = ""

        if condition.func.__name__ != "<lambda>":
            # Format decoratored function expressions
            expression = f"{condition.func.__name__}()"

            if condition.evaluated():
                expression += f"|{condition.last_result()}|"
            else:
                expression += "|-|"

        else:
            # Format lambda expressions
            source = condition.func.__source__
            expression = source.split("lambda:")[1].strip()

            # Replace fact references with values
            for fact_ref in condition.facts:
                class_name, attr_name = fact_ref.split(".", 1)
                if class_name in self.fact_map:
                    fact_instance = self.fact_map[class_name]
                    actual_value = getattr(fact_instance, attr_name)
                    replacement = f"{class_name}.{attr_name}"

                    # Append the value if it is not a long string or multiline
                    if not self._should_extract_to_context(actual_value):
                        replacement += f"|{actual_value}|"

                    expression = expression.replace(f"{class_name}.{attr_name}", replacement)

            # Wrap lambda expressions in parentheses
            expression = f"({expression})"

        return expression

    def _format_compound_condition(self, condition: CompoundCondition) -> str:
        """Format a compound condition with operators."""

        # Evaluate each side to get the actual boolean results
        left_result = condition.left.last_result()
        right_result = condition.right.last_result()

        # Format each side with their actual results
        left_str = self._format_expression(condition.left, result=left_result)
        right_str = self._format_expression(condition.right, result=right_result)

        # Keep just the expression part (after the "= ")
        left_expr, right_expr = [
            value.split(" = ", 1)[1] if " = " in value else value for value in (left_str, right_str)
        ]

        # Format and return the compound expression
        return f"{left_expr} {condition.operator.name.lower()} {right_expr}"


@dataclass(slots=True)
class Auditor:
    """
    Facility to capture runtime iteration and rule state information.
    """

    _iteration: Iteration = field(default_factory=Iteration, init=False)
    _evaluation_report: EvaluationReport | None = field(default=None, init=False)
    _rule_stopwatch: StopWatch = field(default_factory=StopWatch, init=False)

    def evaluation_reset(self) -> None:
        """Reset the reporter to start a new evaluation report."""
        self._evaluation_report = EvaluationReport()

    def generate_yaml_report(self) -> str:
        """Generate YAML report of the tracked evaluation."""
        if not self._evaluation_report:
            msg = "No evaluation report available. Use evaluate(audit=True) to enable tracing."
            raise RuntimeError(msg)

        return self._evaluation_report.to_yaml()

    def iteration_start(self) -> None:
        """Start timing and auditing for a new iteration."""
        self._iteration = Iteration(id=self._iteration.id + 1)

    def iteration_end(self) -> None:
        """End iteration timing and create report iteration."""
        self._iteration.stopwatch.stop()

        if self._iteration.matched_rules and self._evaluation_report is not None:
            self._evaluation_report.iterations.append(self._iteration)

    def rule_start(self) -> None:
        """Start timing and auditing for rule execution."""
        self._rule_stopwatch.start()

    def rule_end(
        self,
        rule: Rule,
        result: ActionReturn | None,
        working_memory: Mapping[str, Fact],
        *,
        condition_result: bool,
    ) -> None:
        """
        Create a RuleMatch from pre-evaluated rule data.

        Args:
            rule: The rule that was executed
            resolved_facts: Facts that were resolved for the rule
            result: The result of executing the action (or None if no action)
            working_memory: Current facts dictionary for context
            condition_result: The boolean result of the rule condition evaluation
        """

        self._rule_stopwatch.stop()
        rule_name = rule.name or "None"
        rule_id = str(rule.id)[:8]

        # Process action results and track consequences
        action = ActionReporter(result, working_memory)
        warnings = ()

        # If there was an action, generate warnings and update changed attribute tracking
        if result is not None:
            warnings = self._generate_warnings(result, rule_id)
            self._update_fact_tracking(action.consequences, rule)

        # Format various report components
        formatter = RuleFormatter(rule.when, working_memory, result=condition_result)

        # Add tne rule match to the report
        self._iteration.matched_rules.append(
            RuleMatch(
                rule=f"{rule_id}:{rule_name}",
                timestamp=self._rule_stopwatch.timestamp,
                elapsed=self._rule_stopwatch.duration,
                evaluation=formatter.expression,
                consequences=tuple(action.consequences),
                warnings=warnings,
                context=formatter.context,
                rationale=formatter.ai_rationale,
            )
        )

    def _generate_warnings(self, action_result: ActionReturn | None, rule_id: str) -> tuple[str, ...]:
        """Check for and report rule warnings"""
        if action_result is None:
            return ()

        # Handle tuple of results (multiple actions)
        warnings = []
        results = action_result if isinstance(action_result, tuple) else (action_result,)

        for result in results:
            # Complete Fact replacement: not a partial
            if not isinstance(result, partial):
                fact_name = result.__class__.__name__
                warning_msg = (
                    f"Fact Replacement | Rule:{rule_id} consequence replaces "
                    f"({fact_name}), potentially altering unintended attributes. "
                    f"Consider using a partial update to ensure only intended changes."
                )
                warnings.append(warning_msg)
            else:
                # Partial update: check for attribute overrides
                fact_name = result.func.__name__
                for attr_name, value in result.keywords.items():
                    fact_attr = f"{fact_name}.{attr_name}"
                    if fact_attr in self._iteration.updated_facts:
                        prev_fact_tracker = self._iteration.updated_facts[fact_attr]
                        warning_msg = (
                            f"Rule Ordering | Rule:{prev_fact_tracker.rule_id} consequence "
                            f"({fact_name}.{attr_name}|{prev_fact_tracker.value}|) "
                            f"was overridden by Rule:{rule_id} "
                            f"({fact_name}.{attr_name}|{value}|) "
                            f"within the same iteration"
                        )
                        warnings.append(warning_msg)
        return tuple(warnings)

    def _update_fact_tracking(
        self,
        consequences: list[RuleConsequence],
        current_rule: Rule,
    ) -> None:
        """Update the attribute changes tracker with new consequences."""
        rule_id = str(current_rule.id)[:8]
        rule_name = current_rule.name or "None"

        for consequence in consequences:
            if consequence.attribute_name:
                # This is a partial attribute update
                fact_attr = f"{consequence.fact_name}.{consequence.attribute_name}"
                self._iteration.updated_facts[fact_attr] = FactRecord(rule_id, rule_name, consequence.value)
