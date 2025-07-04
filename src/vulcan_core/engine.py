# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Latchfield Technologies http://latchfield.com

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from functools import cached_property, partial
from types import MappingProxyType
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from vulcan_core.ast_utils import NotAFactError
from vulcan_core.models import DeclaresFacts, Fact

if TYPE_CHECKING:  # pragma: no cover - not used at runtime
    from vulcan_core.actions import Action
    from vulcan_core.conditions import Expression
    from vulcan_core.reporting import EvaluationReport

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
    _evaluation_report: EvaluationReport | None = field(default=None, init=False)

    @cached_property
    def facts(self) -> MappingProxyType[str, Fact]:
        return MappingProxyType(self._facts)

    @cached_property
    def rules(self) -> MappingProxyType[str, list[Rule]]:
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

    def _resolve_facts(self, declared: DeclaresFacts) -> list[Fact]:
        # Deduplicate the fact strings and retrieve unique fact instances
        keys = {key.split(".")[0]: key for key in declared.facts}.values()
        return [self._facts[key.split(".")[0]] for key in keys]

    def evaluate(self, fact: Fact | partial[Fact] | None = None, trace: bool = False):
        """
        Cascading evaluation of rules based on the facts in working memory.

        If provided a fact, will update and evaluate immediately. Otherwise all rules will be evaluated.
        
        Args:
            fact: Optional fact to update and evaluate immediately
            trace: Whether to track evaluation details for reporting
        """
        # Reset tracking data on each evaluate() call
        if trace:
            from vulcan_core.reporting import EvaluationReport
            self._evaluation_report = EvaluationReport()
        else:
            self._evaluation_report = None
            
        fired_rules: set[UUID] = set()
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

        # Iterate over the rules until the recusion limit is reached or no new rules are fired
        for iteration in range(self.recusion_limit + 1):
            if iteration == self.recusion_limit:
                msg = f"Recursion limit of {self.recusion_limit} reached"
                raise RecursionLimitError(msg)

            # Start timing the iteration
            iteration_start = time.time()
            iteration_timestamp = datetime.now()
            
            # Track matches for this iteration
            iteration_matches = []
            
            # Track attribute changes within this iteration for warnings
            iteration_attribute_changes = {}  # {fact_attr: (rule_id, rule_name, value)}
            
            for fact_str, rules in self._rules.items():
                if fact_str in scope:
                    for rule in rules:
                        # Skip if we already evaluated the rule this iteration
                        if rule.id in fired_rules:
                            continue

                        # Skip if not all facts required by the rule are present
                        try:
                            resolved_facts = self._resolve_facts(rule.when)
                        except KeyError as e:
                            logger.debug("Rule %s (%s) skipped due to missing fact: %s", rule.name, rule.id, str(e))
                            continue

                        fired_rules.add(rule.id)

                        # Track rule evaluation if tracing
                        if trace:
                            rule_start = time.time()
                            rule_timestamp = datetime.now()
                            
                            # Evaluate the rule and track result
                            rule_result = rule.when(*resolved_facts)
                            
                            # Determine which action to use
                            action = None
                            if rule_result:
                                action = rule.then
                            elif rule.inverse:
                                action = rule.inverse
                            
                            # Execute action and capture consequences
                            consequences = []
                            warnings = []
                            if action:
                                # Execute the action to get the result and consequences
                                result = action(*self._resolve_facts(action))
                                consequences = self._extract_action_consequences_from_result(result)
                                
                                # Check for attribute conflicts and generate warnings
                                warnings = self._check_for_rule_ordering_warnings(
                                    consequences, iteration_attribute_changes, rule
                                )
                                
                                # Update the attribute changes tracker
                                self._update_attribute_changes_tracker(
                                    consequences, iteration_attribute_changes, rule
                                )
                                
                                # Update facts
                                facts = self._update_facts(result)
                                consequence.update(facts)
                            
                            # Create match data
                            match_data = self._trace_rule_evaluation(
                                rule, resolved_facts, rule_result, action, 
                                rule_timestamp, time.time() - rule_start, consequences, warnings
                            )
                            iteration_matches.append(match_data)
                        else:
                            # Original evaluation logic
                            action = None
                            # Evaluate the rule's 'when' and determine which action to invoke
                            if rule.when(*resolved_facts):
                                action = rule.then
                            elif rule.inverse:
                                action = rule.inverse

                        if action and not trace:  # Only execute if not already done in tracing
                            # Update the facts and track consequences to fire subsequent rules
                            result = action(*self._resolve_facts(action))
                            facts = self._update_facts(result)
                            consequence.update(facts)

            # Record iteration if tracing and there were matches
            if trace and iteration_matches:
                from vulcan_core.reporting import ReportIteration
                iteration_elapsed = time.time() - iteration_start
                report_iteration = ReportIteration(
                    id=iteration + 1,
                    timestamp=iteration_timestamp,
                    elapsed=iteration_elapsed,
                    matches=iteration_matches
                )
                self._evaluation_report.iterations.append(report_iteration)

            # If rules updated some facts, prepare for the next iteration
            if consequence:
                scope = consequence
                consequence = set()
                fired_rules.clear()
            else:
                break

    def yaml_report(self) -> str:
        """
        Returns the YAML report of the last evaluation (if tracing was enabled).
        
        Returns:
            str: YAML-formatted report
            
        Raises:
            RuntimeError: If no report is available (tracing not enabled)
        """
        if not self._evaluation_report:
            msg = "No evaluation report available. Use evaluate(trace=True) to enable tracing."
            raise RuntimeError(msg)
        
        return self._evaluation_report.to_yaml()
    
    def _trace_rule_evaluation(self, rule: Rule, resolved_facts: list[Fact], 
                               rule_result: bool, action, rule_timestamp: datetime, 
                               elapsed: float, consequences: list, warnings: list = None) -> object:
        """
        Trace the evaluation of a rule for reporting purposes.
        
        Args:
            rule: The rule being evaluated
            resolved_facts: The resolved facts for the rule
            rule_result: The boolean result of the rule evaluation
            action: The action that will be executed (if any)
            rule_timestamp: When the rule evaluation started
            elapsed: How long the rule evaluation took
            consequences: Already computed consequences from action execution
            warnings: Any warnings generated during rule execution
            
        Returns:
            RuleMatch object with evaluation details
        """
        from vulcan_core.reporting import RuleMatch
        
        rule_name = rule.name or "None"
        rule_id = str(rule.id)[:8]  # Use first 8 chars of UUID for readability
        
        # Create evaluation string representation
        evaluation_str = self._format_evaluation_string(rule.when, resolved_facts, rule_result)
        
        # Extract context for long strings (>25 chars or multiline)
        context = self._extract_context_from_evaluation_and_consequences(
            rule.when, resolved_facts, consequences
        )
        
        return RuleMatch(
            rule=f"{rule_id}:{rule_name}",
            timestamp=rule_timestamp,
            elapsed=elapsed,
            evaluation=evaluation_str,
            consequences=consequences,
            warnings=warnings or [],
            context=context,
        )
    
    def _format_evaluation_string(self, condition, resolved_facts: list[Fact], result: bool) -> str:
        """
        Format the evaluation string showing the condition with fact values.
        """
        from vulcan_core.conditions import Condition, CompoundCondition, AICondition
        
        # Create a mapping of fact class names to actual instances for value lookup
        fact_map = {fact.__class__.__name__: fact for fact in resolved_facts}
        
        # Format based on condition type
        if isinstance(condition, AICondition):
            return self._format_ai_condition(condition, fact_map, result)
        elif isinstance(condition, CompoundCondition):
            return self._format_compound_condition(condition, fact_map, result)
        elif isinstance(condition, Condition):
            return self._format_simple_condition(condition, fact_map, result)
        else:
            # Fallback for unknown condition types
            return f"{result} = unknown_condition_type"
    
    def _format_simple_condition(self, condition, fact_map: dict, result: bool) -> str:
        """Format a simple lambda-based condition."""
        # Try to parse the condition function to understand the expression
        import inspect
        
        try:
            # Get the source code of the lambda function
            source = inspect.getsource(condition.func)
            # Extract the lambda expression (simplified parsing)
            if "lambda:" in source:
                expr_part = source.split("lambda:")[1].strip()
                # Remove any trailing punctuation
                expr_part = expr_part.rstrip(")\n,")
                
                # Replace fact references with values
                formatted_expr = expr_part
                for fact_ref in condition.facts:
                    class_name, attr_name = fact_ref.split(".", 1)
                    if class_name in fact_map:
                        fact_instance = fact_map[class_name]
                        actual_value = getattr(fact_instance, attr_name)
                        # Replace the fact reference with the inline value format
                        formatted_expr = formatted_expr.replace(
                            f"{class_name}.{attr_name}", 
                            f"{class_name}.{attr_name}|{actual_value}|"
                        )
                
                # Apply inversion if needed
                if condition.inverted:
                    formatted_expr = f"not({formatted_expr})"
                
                return f"{result} = {formatted_expr}"
                
        except Exception:
            # Fallback to basic formatting if source parsing fails
            pass
        
        # Fallback: basic format with fact values
        fact_parts = []
        for fact_ref in condition.facts:
            class_name, attr_name = fact_ref.split(".", 1)
            if class_name in fact_map:
                fact_instance = fact_map[class_name]
                actual_value = getattr(fact_instance, attr_name)
                fact_parts.append(f"{fact_ref}|{actual_value}|")
            else:
                fact_parts.append(f"{fact_ref}|?|")
        
        # Simple joining for multiple facts
        if len(fact_parts) == 1:
            evaluation_expr = fact_parts[0]
        else:
            evaluation_expr = " and ".join(fact_parts)
            
        if condition.inverted:
            evaluation_expr = f"not({evaluation_expr})"
        
        return f"{result} = {evaluation_expr}"
    
    def _format_compound_condition(self, condition, fact_map: dict, result: bool) -> str:
        """Format a compound condition with operators."""
        from vulcan_core.conditions import Operator
        
        operator_map = {
            Operator.AND: "and",
            Operator.OR: "or", 
            Operator.XOR: "xor"
        }
        
        operator_str = operator_map.get(condition.operator, "unknown_op")
        
        # Recursively format left and right parts
        left_result = condition.left(*self._resolve_facts(condition.left))
        right_result = condition.right(*self._resolve_facts(condition.right))
        
        left_str = self._format_evaluation_string(condition.left, self._resolve_facts(condition.left), left_result)
        right_str = self._format_evaluation_string(condition.right, self._resolve_facts(condition.right), right_result)
        
        # Extract just the expression part (after the "= ")
        left_expr = left_str.split(" = ", 1)[1] if " = " in left_str else left_str
        right_expr = right_str.split(" = ", 1)[1] if " = " in right_str else right_str
        
        compound_expr = f"{left_expr} {operator_str} {right_expr}"
        
        if condition.inverted:
            compound_expr = f"not({compound_expr})"
        
        return f"{result} = {compound_expr}"
    
    def _format_ai_condition(self, condition, fact_map: dict, result: bool) -> str:
        """Format an AI condition with its template."""
        # For AI conditions, show the template with fact values substituted
        template = condition.inquiry_template
        
        # Simple substitution for now - replace fact references with values
        for fact_ref in condition.facts:
            class_name, attr_name = fact_ref.split(".", 1)
            if class_name in fact_map:
                fact_instance = fact_map[class_name]
                actual_value = getattr(fact_instance, attr_name)
                # Replace placeholders in template
                template = template.replace(f"{{{class_name}.{attr_name}}}", f"{{{class_name}.{attr_name}|{actual_value}|}}")
        
        # Handle negation if condition is inverted
        if condition.inverted:
            return f"{result} = not({template})"
        else:
            return f"{result} = {template}"
    
    def _extract_action_consequences_from_result(self, result) -> list:
        """
        Extract consequences from an already-executed action result.
        """
        from vulcan_core.reporting import RuleMatchConsequence
        
        consequences = []
        
        # Handle different result types
        if isinstance(result, tuple):
            # Multiple facts/partials returned
            for item in result:
                consequences.extend(self._extract_fact_consequences(item))
        else:
            # Single fact/partial returned
            consequences.extend(self._extract_fact_consequences(result))
                
        return consequences
    
    def _extract_fact_consequences(self, fact_or_partial) -> list:
        """Extract consequences from a single fact or partial."""
        from vulcan_core.reporting import RuleMatchConsequence
        
        consequences = []
        
        if isinstance(fact_or_partial, partial):
            # It's a partial fact update
            fact_class = fact_or_partial.func
            fact_name = fact_class.__name__
            
            # Get the keyword arguments (the attributes being set)
            keywords = fact_or_partial.keywords
            for attr_name, value in keywords.items():
                # Resolve fact references if the value is a reference
                resolved_value = self._resolve_fact_reference(value)
                consequences.append(RuleMatchConsequence(fact_name, attr_name, resolved_value))
                
        else:
            # It's a full fact instance
            fact_name = fact_or_partial.__class__.__name__
            
            # For full facts, we need to show all non-default attributes
            # This is simplified - we'll capture all attributes for now
            fact_dict = {}
            for attr_name in fact_or_partial.__annotations__:
                if not attr_name.startswith("_"):  # Skip private attributes
                    value = getattr(fact_or_partial, attr_name)
                    fact_dict[attr_name] = value
            
            consequences.append(RuleMatchConsequence(fact_name, None, fact_dict))
        
        return consequences
    
    def _resolve_fact_reference(self, value):
        """Resolve a fact reference (like AnotherFact.value) to its actual value."""
        # Check if this looks like a fact reference
        if hasattr(value, '__class__') and hasattr(value.__class__, '__name__'):
            if hasattr(value.__class__, '__module__') and 'vulcan_core' in value.__class__.__module__:
                # This is likely a Fact class - check if it's being used as a reference
                pass
        
        # For now, if the value is a string and looks like a fact reference, try to resolve it
        if isinstance(value, str) and '.' in value and '{' in value and '}' in value:
            # This looks like an unresolved template string
            return value
            
        # Otherwise try to get the actual value from our fact store
        # This is a simplified implementation - in reality we'd need more sophisticated parsing
        try:
            # Check if this is a Fact attribute reference  
            value_str = str(value)
            if '.' in value_str and not value_str.startswith('{'):
                # Might be a fact reference like "AnotherFact.value"
                parts = value_str.split('.')
                if len(parts) == 2:
                    fact_name, attr_name = parts
                    if fact_name in self._facts:
                        fact_instance = self._facts[fact_name]
                        return getattr(fact_instance, attr_name)
        except Exception:
            pass
        
        return value
    
    def _check_for_rule_ordering_warnings(self, consequences: list, 
                                         attribute_changes: dict, current_rule: Rule) -> list[str]:
        """
        Check for rule ordering warnings when consequences override previous attributes.
        """
        warnings = []
        
        for consequence in consequences:
            if consequence.attribute_name:
                # This is a partial attribute update
                fact_attr = f"{consequence.fact_name}.{consequence.attribute_name}"
                
                if fact_attr in attribute_changes:
                    # This attribute was already set by another rule in this iteration
                    prev_rule_id, prev_rule_name, prev_value = attribute_changes[fact_attr]
                    current_rule_id = str(current_rule.id)[:8]
                    current_rule_name = current_rule.name or "None"
                    
                    warning_msg = (
                        f"Rule Ordering | Rule:{prev_rule_id} consequence "
                        f"({consequence.fact_name}.{consequence.attribute_name}|{prev_value}|) "
                        f"was overridden by Rule:{current_rule_id} "
                        f"({consequence.fact_name}.{consequence.attribute_name}|{consequence.value}|) "
                        f"within the same iteration"
                    )
                    warnings.append(warning_msg)
        
        return warnings
    
    def _update_attribute_changes_tracker(self, consequences: list, 
                                        attribute_changes: dict, current_rule: Rule):
        """
        Update the attribute changes tracker with new consequences.
        """
        rule_id = str(current_rule.id)[:8]
        rule_name = current_rule.name or "None"
        
        for consequence in consequences:
            if consequence.attribute_name:
                # This is a partial attribute update
                fact_attr = f"{consequence.fact_name}.{consequence.attribute_name}"
                attribute_changes[fact_attr] = (rule_id, rule_name, consequence.value)
    
    def _extract_context_from_evaluation_and_consequences(self, condition, resolved_facts: list[Fact], 
                                                         consequences: list) -> list:
        """
        Extract context for long strings (>25 chars or multiline) from evaluation and consequences.
        """
        from vulcan_core.reporting import RuleMatchContext
        
        context = []
        
        # Create a mapping of fact class names to actual instances for value lookup
        fact_map = {fact.__class__.__name__: fact for fact in resolved_facts}
        
        # Check condition facts for long strings
        for fact_ref in condition.facts:
            class_name, attr_name = fact_ref.split(".", 1)
            if class_name in fact_map:
                fact_instance = fact_map[class_name]
                actual_value = getattr(fact_instance, attr_name)
                
                if self._should_extract_to_context(actual_value):
                    is_multiline = isinstance(actual_value, str) and '\n' in actual_value
                    context.append(RuleMatchContext(fact_ref, actual_value, is_multiline))
        
        # Check consequences for long strings
        for consequence in consequences:
            if self._should_extract_to_context(consequence.value):
                if consequence.attribute_name:
                    fact_attr = f"{consequence.fact_name}.{consequence.attribute_name}"
                else:
                    fact_attr = consequence.fact_name
                
                is_multiline = isinstance(consequence.value, str) and '\n' in consequence.value
                context.append(RuleMatchContext(fact_attr, consequence.value, is_multiline))
        
        return context
    
    def _should_extract_to_context(self, value) -> bool:
        """
        Determine if a value should be extracted to context.
        Returns True for strings longer than 25 characters or multiline strings.
        """
        if isinstance(value, str):
            return len(value) > 25 or '\n' in value
        return False
