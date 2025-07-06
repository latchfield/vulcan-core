# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Latchfield Technologies http://latchfield.com

from datetime import datetime
from functools import partial
from unittest.mock import Mock

import pytest
import yaml

from vulcan_core import Fact, RuleEngine, action, condition
from vulcan_core.reporting import (
    EvaluationReport,
    ReportIteration,
    RuleMatch,
    RuleMatchConsequence,
    RuleMatchContext,
)


class Foo(Fact):
    bar: bool = True
    biz: bool = False


class Bar(Fact):
    baz: int = 0
    biff: str = ""


class AnotherFact(Fact):
    value: int = 23


class YetAnotherFact(Fact):
    value: str = "some_value"


class MySummaryFact(Fact):
    value: bool = False


class MyTestFact(Fact):
    short_value: str = "short"
    long_value: str = "This is a very long string that exceeds twenty-five characters"
    multiline_value: str = "Line 1\nLine 2\nLine 3"


class ResultTestFact(Fact):
    status: str = ""


class MyNonPartialFact(Fact):
    value: int = 0
    another_attribute: int = 50


def test_rule_match_consequence_to_dict():
    """Test RuleMatchConsequence serialization."""
    # Test with attribute
    consequence = RuleMatchConsequence("Bar", "baz", 23)
    assert consequence.to_dict() == {"Bar.baz": 23}

    # Test without attribute (full fact)
    consequence = RuleMatchConsequence("MyFact", None, {"value": 42, "another": 100})
    assert consequence.to_dict() == {"MyFact": {"value": 42, "another": 100}}


def test_rule_match_context_to_dict():
    """Test RuleMatchContext serialization."""
    context = RuleMatchContext("Foo.bar", True)
    assert context.to_dict() == {"Foo.bar": True}


def test_rule_match_to_dict():
    """Test RuleMatch serialization."""
    timestamp = datetime(2025, 7, 1, 23, 35, 13, 10000)
    match = RuleMatch(
        rule="1:Update biz if either bar or biz are True",
        timestamp=timestamp,
        elapsed=0.010,
        evaluation="True = Foo.bar|True| or Foo.biz|False|",
        consequences=[RuleMatchConsequence("Bar", "baz", 23)],
        warnings=["Test warning"],
        context=[RuleMatchContext("Foo.bar", True)],
        rationale="Test rationale",
    )

    result = match.to_dict()
    expected = {
        "rule": "1:Update biz if either bar or biz are True",
        "timestamp": "2025-07-01T23:35:13.010000Z",
        "elapsed": 0.010,
        "evaluation": "True = Foo.bar|True| or Foo.biz|False|",
        "consequences": {"Bar.baz": 23},
        "warnings": ["Test warning"],
        "context": [{"Foo.bar": True}],
        "rationale": "Test rationale",
    }
    assert result == expected


def test_rule_match_to_dict_minimal():
    """Test RuleMatch serialization with minimal data."""
    timestamp = datetime(2025, 7, 1, 23, 35, 13, 30000)
    match = RuleMatch(
        rule="3:None",
        timestamp=timestamp,
        elapsed=0.010,
        evaluation="False = Foo.biz|False|",
    )

    result = match.to_dict()
    expected = {
        "rule": "3:None",
        "timestamp": "2025-07-01T23:35:13.030000Z",
        "elapsed": 0.010,
        "evaluation": "False = Foo.biz|False|",
        "consequences": None,
    }
    assert result == expected


def test_report_iteration_to_dict():
    """Test ReportIteration serialization."""
    timestamp = datetime(2025, 7, 1, 23, 35, 13, 0)
    match = RuleMatch(
        rule="1:Test Rule",
        timestamp=timestamp,
        elapsed=0.010,
        evaluation="True = Foo.bar|True|",
        consequences=[RuleMatchConsequence("Bar", "baz", 23)],
    )

    iteration = ReportIteration(id=1, timestamp=timestamp, elapsed=0.030, matches=[match])

    result = iteration.to_dict()
    assert result["id"] == 1
    assert result["timestamp"] == "2025-07-01T23:35:13Z"
    assert result["elapsed"] == 0.030
    assert len(result["matches"]) == 1


def test_evaluation_report_to_dict():
    """Test EvaluationReport serialization."""
    timestamp = datetime(2025, 7, 1, 23, 35, 13, 0)
    match = RuleMatch(
        rule="1:Test Rule",
        timestamp=timestamp,
        elapsed=0.010,
        evaluation="True = Foo.bar|True|",
    )

    iteration = ReportIteration(id=1, timestamp=timestamp, elapsed=0.030, matches=[match])

    report = EvaluationReport(iterations=[iteration])

    result = report.to_dict()
    assert "report" in result
    assert "iterations" in result["report"]
    assert len(result["report"]["iterations"]) == 1


def test_evaluation_report_to_yaml():
    """Test EvaluationReport YAML serialization."""
    timestamp = datetime(2025, 7, 1, 23, 35, 13, 0)
    match = RuleMatch(
        rule="1:Test Rule",
        timestamp=timestamp,
        elapsed=0.010,
        evaluation="True = Foo.bar|True|",
        consequences=[RuleMatchConsequence("Bar", "baz", 23)],
    )

    iteration = ReportIteration(id=1, timestamp=timestamp, elapsed=0.030, matches=[match])

    report = EvaluationReport(iterations=[iteration])
    yaml_output = report.to_yaml()

    # Verify it's valid YAML
    parsed = yaml.safe_load(yaml_output)
    assert "report" in parsed
    assert "iterations" in parsed["report"]

    # Verify structure
    iteration_data = parsed["report"]["iterations"][0]
    assert iteration_data["id"] == 1
    assert iteration_data["elapsed"] == 0.030
    assert len(iteration_data["matches"]) == 1

    match_data = iteration_data["matches"][0]
    assert match_data["rule"] == "1:Test Rule"
    assert match_data["consequences"]["Bar.baz"] == 23


def test_rule_engine_tracing_basic():
    """Test basic tracing functionality in RuleEngine."""
    engine = RuleEngine()
    engine.fact(Foo())
    engine.fact(Bar())

    engine.rule(
        name="test_rule",
        when=condition(lambda: Foo.bar),
        then=action(partial(Bar, baz=42)),
    )

    # Test without tracing
    engine.evaluate()

    # Test that yaml_report raises error when tracing not enabled
    with pytest.raises(RuntimeError, match="No evaluation report available"):
        engine.yaml_report()

    # Test with tracing
    engine.evaluate(trace=True)

    # Test that yaml_report works
    yaml_output = engine.yaml_report()
    assert isinstance(yaml_output, str)
    assert "report:" in yaml_output
    assert "iterations:" in yaml_output

    # Verify structure
    parsed = yaml.safe_load(yaml_output)
    assert "report" in parsed
    assert "iterations" in parsed["report"]
    assert len(parsed["report"]["iterations"]) >= 1


def test_rule_engine_tracing_multiple_iterations():
    """Test tracing with multiple iterations."""
    engine = RuleEngine()
    engine.fact(Foo())
    engine.fact(Bar())

    # Rule that will trigger in first iteration
    engine.rule(
        name="first_rule",
        when=condition(lambda: Foo.bar),
        then=action(partial(Bar, baz=42)),
    )

    # Rule that will trigger in second iteration (after Bar.baz is set)
    engine.rule(
        name="second_rule",
        when=condition(lambda: Bar.baz > 0),
        then=action(partial(Foo, biz=True)),
    )

    engine.evaluate(trace=True)

    yaml_output = engine.yaml_report()
    parsed = yaml.safe_load(yaml_output)

    # Should have multiple iterations
    iterations = parsed["report"]["iterations"]
    assert len(iterations) >= 2


def test_rule_engine_detailed_evaluation_format():
    """Test that evaluation strings and consequences are properly formatted."""
    engine = RuleEngine()
    engine.fact(Foo(bar=True, biz=False))
    engine.fact(Bar(baz=0))

    engine.rule(
        name="test_condition_formatting",
        when=condition(lambda: Foo.bar and not Foo.biz),
        then=action(partial(Bar, baz=23)),
    )

    engine.evaluate(trace=True)

    yaml_output = engine.yaml_report()
    parsed = yaml.safe_load(yaml_output)

    # Verify structure exists
    assert "report" in parsed
    assert "iterations" in parsed["report"]
    assert len(parsed["report"]["iterations"]) >= 1

    iteration = parsed["report"]["iterations"][0]
    assert "matches" in iteration
    assert len(iteration["matches"]) >= 1

    match = iteration["matches"][0]

    # Verify rule information
    assert "rule" in match
    assert "test_condition_formatting" in match["rule"]

    # Verify evaluation string contains fact values
    assert "evaluation" in match
    evaluation = match["evaluation"]
    assert "True" in evaluation or "False" in evaluation

    # Verify consequences are captured
    assert "consequences" in match
    if match["consequences"]:  # Only check if there are consequences
        assert "Bar.baz" in match["consequences"]
        assert match["consequences"]["Bar.baz"] == 23


def test_rule_engine_warnings_detection():
    """Test that rule ordering warnings are detected when attributes are overridden."""
    engine = RuleEngine()

    # Starting facts
    engine.fact(Foo(bar=True, biz=False))
    engine.fact(Bar(baz=0, biff=""))

    # Rule 1 - Sets Bar.baz to 23
    engine.rule(
        name="First Rule",
        when=condition(lambda: Foo.bar),
        then=action(partial(Bar, baz=23)),
    )

    # Rule 2 - Also sets Bar.baz to 42, creating a conflict
    engine.rule(
        name="Second Rule",
        when=condition(lambda: Foo.bar),  # Same condition, will fire in same iteration
        then=action(partial(Bar, baz=42)),
    )

    engine.evaluate(trace=True)

    yaml_output = engine.yaml_report()
    parsed = yaml.safe_load(yaml_output)

    # Find the match that should have warnings
    iterations = parsed["report"]["iterations"]
    assert len(iterations) >= 1

    iteration = iterations[0]
    matches = iteration["matches"]
    assert len(matches) >= 2

    # The second match should have a warning about overriding the first
    second_match = matches[1]
    assert "warnings" in second_match
    assert len(second_match["warnings"]) > 0

    warning = second_match["warnings"][0]
    assert "Rule Ordering" in warning
    assert "was overridden by" in warning
    assert "Bar.baz" in warning


def test_rule_engine_context_handling():
    """Test that long strings and multiline content are extracted to context."""

    engine = RuleEngine()
    engine.fact(
        MyTestFact(
            short_value="short",
            long_value="This is a very long string that exceeds twenty-five characters",
            multiline_value="Line 1\nLine 2\nLine 3",
        )
    )
    engine.fact(ResultTestFact())

    # Rule that uses long/multiline values
    engine.rule(
        name="Test Context Rule",
        when=condition(lambda: MyTestFact.long_value and MyTestFact.multiline_value),
        then=action(partial(ResultTestFact, status="This is another very long string that should go to context")),
    )

    engine.evaluate(trace=True)

    yaml_output = engine.yaml_report()
    parsed = yaml.safe_load(yaml_output)

    # Check that context was extracted
    iterations = parsed["report"]["iterations"]
    assert len(iterations) >= 1

    iteration = iterations[0]
    matches = iteration["matches"]
    assert len(matches) >= 1

    match = matches[0]

    # Should have context due to long strings
    assert "context" in match
    assert len(match["context"]) > 0

    # Verify context contains the long values
    context_dict = {}
    for ctx_item in match["context"]:
        context_dict.update(ctx_item)

    # Should contain references to long values used in condition or consequences
    long_value_found = any("This is a very long string" in str(v) for v in context_dict.values())
    assert long_value_found


def test_rule_engine_ai_rationale_extraction():
    """Test that AI condition rationale extraction works."""
    from vulcan_core.conditions import AICondition

    # Test the rationale extraction method directly
    engine = RuleEngine()

    # Mock AI condition with rationale
    mock_chain = Mock()
    mock_model = Mock()

    ai_condition = AICondition(
        facts=("MyTestFact.long_value",),
        chain=mock_chain,
        model=mock_model,
        system_template="You are a helpful assistant",
        attachments_template='<attachments>\n<attachment id="fact:MyTestFact.long_value">\n{MyTestFact.long_value}\n</attachment>\n</attachments>',
        inquiry="Is {MyTestFact.long_value} an example?",
    )

    # Set the rationale using the post_init approach
    object.__setattr__(ai_condition, "_rationale", "This is a test rationale for AI decision")

    # Test the rationale extraction
    rationale = engine._extract_ai_rationale(ai_condition)
    assert rationale == "This is a test rationale for AI decision"

    # Test with a regular condition (should return None)
    regular_condition = condition(lambda: True)
    rationale = engine._extract_ai_rationale(regular_condition)
    assert rationale is None


def test_rule_engine_example_scenario():
    """Test scenario similar to the example_rules.py to demonstrate functionality."""
    engine = RuleEngine()

    # Starting facts similar to example
    engine.fact(Foo(bar=True, biz=False))
    engine.fact(Bar(baz=0, biff=""))

    # Rule 1 - Simple or condition
    engine.rule(
        name="Update if either bar or biz are True",
        when=condition(lambda: Foo.bar or Foo.biz),
        then=action(partial(Bar, baz=23)),
    )

    # Rule 2 - Compound condition with inverse
    engine.rule(
        name="Update Bar if both bar and biz are True",
        when=condition(lambda: Foo.bar and Foo.biz),
        then=action(partial(Bar, biff="then_action")),
        inverse=action(partial(Bar, biff="inverse_action")),
    )

    # Rule 3 - Condition that evaluates False with no inverse
    engine.rule(
        when=condition(lambda: Foo.biz),
        then=action(partial(Foo, bar=False)),
    )

    engine.evaluate(trace=True)

    yaml_output = engine.yaml_report()
    parsed = yaml.safe_load(yaml_output)

    # Validate structure
    assert "report" in parsed
    assert "iterations" in parsed["report"]

    iterations = parsed["report"]["iterations"]
    assert len(iterations) >= 1

    # Check first iteration
    iteration = iterations[0]
    assert iteration["id"] == 1
    assert "matches" in iteration
    assert len(iteration["matches"]) >= 2  # Should have at least 2 rule matches

    # Validate matches have required fields
    for match in iteration["matches"]:
        assert "rule" in match
        assert "timestamp" in match
        assert "elapsed" in match
        assert "evaluation" in match
        assert "consequences" in match


def test_fact_reference_resolution_in_consequences():
    """Test that fact references in consequences are properly resolved."""
    engine = RuleEngine()

    # Setup facts
    engine.fact(Foo(bar=True, biz=False))
    engine.fact(Bar(baz=0, biff=""))
    engine.fact(AnotherFact(value=23))
    engine.fact(YetAnotherFact(value="resolved_value"))

    # Rule that uses fact references in consequences
    engine.rule(
        name="Test fact reference resolution",
        when=condition(lambda: Foo.bar),
        then=action(partial(Bar, baz=AnotherFact.value, biff=YetAnotherFact.value)),
    )

    engine.evaluate(trace=True)
    yaml_output = engine.yaml_report()
    parsed = yaml.safe_load(yaml_output)

    # Check that consequences have resolved values, not template strings
    match = parsed["report"]["iterations"][0]["matches"][0]
    consequences = match["consequences"]

    assert consequences["Bar.baz"] == 23  # Should be resolved, not "{AnotherFact.value}"
    assert consequences["Bar.biff"] == "resolved_value"  # Should be resolved


def test_rule_ordering_warnings_with_fact_references():
    """Test rule ordering warnings show resolved fact references."""
    engine = RuleEngine()

    # Setup facts
    engine.fact(Foo(bar=True, biz=False))
    engine.fact(Bar(baz=0, biff=""))
    engine.fact(AnotherFact(value=23))

    # Two rules that both modify the same attribute with fact references
    engine.rule(
        name="First Rule",
        when=condition(lambda: Foo.bar),
        then=action(partial(Bar, baz=AnotherFact.value)),
    )

    engine.rule(
        name="Second Rule",
        when=condition(lambda: Foo.bar),  # Same condition, fires in same iteration
        then=action(partial(Bar, baz=42)),
    )

    engine.evaluate(trace=True)
    yaml_output = engine.yaml_report()
    parsed = yaml.safe_load(yaml_output)

    # Find the match with warnings
    second_match = parsed["report"]["iterations"][0]["matches"][1]
    assert "warnings" in second_match
    assert len(second_match["warnings"]) > 0

    warning = second_match["warnings"][0]
    assert "Rule Ordering" in warning
    assert "(Bar.baz|23|)" in warning  # Should show resolved value, not template
    assert "(Bar.baz|42|)" in warning


def test_yaml_none_representation():
    """Test that None values are represented as 'None' not 'null' in YAML."""
    engine = RuleEngine()

    engine.fact(Foo(bar=True, biz=False))
    engine.fact(Bar(baz=0, biff=""))

    # Rule that evaluates to False and has no consequences
    engine.rule(
        name="No consequences rule",
        when=condition(lambda: Foo.biz),  # False
        then=action(partial(Bar, baz=99)),
    )

    engine.evaluate(trace=True)
    yaml_output = engine.yaml_report()

    # Check that None is represented as 'None' not 'null'
    assert "consequences: None" in yaml_output
    assert "consequences: null" not in yaml_output
    assert "!!null" not in yaml_output


def test_long_string_context_extraction():
    """Test that long strings are extracted to context and not shown inline."""
    engine = RuleEngine()

    engine.fact(
        MyTestFact(
            short_value="short",
            long_value="This is a very long string that exceeds twenty-five characters and should be extracted",
            multiline_value="Line 1\nLine 2\nLine 3",
        )
    )
    engine.fact(ResultTestFact(status=""))

    # Rule using long string
    engine.rule(
        name="Long string test",
        when=condition(lambda: MyTestFact.long_value and MyTestFact.multiline_value),
        then=action(partial(ResultTestFact, status="updated")),
    )

    engine.evaluate(trace=True)
    yaml_output = engine.yaml_report()
    parsed = yaml.safe_load(yaml_output)

    match = parsed["report"]["iterations"][0]["matches"][0]

    # Long strings should not appear inline in evaluation
    evaluation = match["evaluation"]
    assert "MyTestFact.long_value" in evaluation  # Reference should be present
    assert "This is a very long string" not in evaluation  # Long value should not be inline

    # Long strings should appear in context
    assert "context" in match
    context_values = [next(iter(ctx.values())) for ctx in match["context"]]
    assert any("This is a very long string" in str(val) for val in context_values)


def test_compound_conditions_with_empty_parts():
    """Test compound conditions that might have empty or no-fact parts."""
    engine = RuleEngine()

    engine.fact(Foo(bar=True, biz=False))
    engine.fact(MySummaryFact(value=False))

    # Create a compound condition with a part that has no fact references
    fact_cond = condition(lambda: Foo.bar)
    empty_cond = condition(lambda: True)  # No fact references
    compound = fact_cond & empty_cond

    engine.rule(
        name="Compound with empty part",
        when=compound,
        then=action(partial(MySummaryFact, value=True)),
    )

    engine.evaluate(trace=True)
    yaml_output = engine.yaml_report()
    parsed = yaml.safe_load(yaml_output)

    match = parsed["report"]["iterations"][0]["matches"][0]
    evaluation = match["evaluation"]

    # Should handle empty condition parts gracefully
    assert "condition()" in evaluation  # Empty part should be represented
    assert " and " in evaluation  # Should have proper operator
    assert "Foo.bar|True|" in evaluation  # Fact part should be present


def test_no_hard_line_wrapping():
    """Test that YAML output doesn't contain hard line wrapping."""
    engine = RuleEngine()

    engine.fact(Foo(bar=True, biz=False))
    engine.fact(Bar(baz=0, biff=""))
    engine.fact(AnotherFact(value=23))

    # Create a rule with long warning messages
    engine.rule(
        name="Very long rule name that could potentially cause line wrapping issues in YAML output",
        when=condition(lambda: Foo.bar),
        then=action(partial(Bar, baz=AnotherFact.value)),
    )

    engine.rule(
        name="Another very long rule name that should also trigger warnings",
        when=condition(lambda: Foo.bar),
        then=action(partial(Bar, baz=42)),
    )

    engine.evaluate(trace=True)
    yaml_output = engine.yaml_report()

    # Check that warning messages aren't hard-wrapped
    lines = yaml_output.split("\n")
    for line in lines:
        if "Rule Ordering" in line:
            # The warning should be on a single line (after the '- ')
            assert line.strip().startswith("- Rule Ordering")
            # Should not have continuation on next line
            break


def test_fact_replacement_warnings():
    """Test that fact replacement warnings are generated for complete fact objects."""
    engine = RuleEngine()

    # Set up initial facts
    engine.fact(MySummaryFact(value=True))

    # Add a rule that uses a complete fact object (not partial)
    engine.rule(
        name="Complete fact replacement rule",
        when=condition(lambda: MySummaryFact.value),
        then=action(MyNonPartialFact(value=42, another_attribute=100)),
    )

    engine.evaluate(trace=True)
    yaml_output = engine.yaml_report()

    # Parse the YAML to check the structure
    report_data = yaml.safe_load(yaml_output)

    # Find the rule match that should have the warning
    matches = report_data["report"]["iterations"][0]["matches"]
    assert len(matches) == 1

    match = matches[0]
    assert "warnings" in match
    assert len(match["warnings"]) == 1

    warning = match["warnings"][0]
    assert "Fact Replacement" in warning
    assert "MyNonPartialFact" in warning
    assert "potentially altering unintended attributes" in warning
    assert "Consider using a partial update" in warning

    # Check that the consequences show the complete fact
    consequences = match["consequences"]
    assert "MyNonPartialFact" in consequences
    assert consequences["MyNonPartialFact"]["value"] == 42
    assert consequences["MyNonPartialFact"]["another_attribute"] == 100


def test_custom_condition_formatting():
    """Test that custom conditions (created with @condition decorator) are properly formatted with names and return values."""

    @condition
    def my_cond() -> bool:
        return True

    @condition
    def another_cond() -> bool:
        return False

    engine = RuleEngine()
    engine.fact(MySummaryFact(value=True))

    # Test compound condition with custom conditions and lambda
    engine.rule(
        name="Custom condition test",
        when=~my_cond & another_cond | condition(lambda: not (MySummaryFact.value)),
        then=action(partial(MySummaryFact, value=False)),
    )

    engine.evaluate(trace=True)
    yaml_output = engine.yaml_report()
    report_data = yaml.safe_load(yaml_output)

    # Find the rule match
    matches = report_data["report"]["iterations"][0]["matches"]
    assert len(matches) == 1

    match = matches[0]
    evaluation = match["evaluation"]

    # Check that custom conditions show function names and return values
    assert "not(my_cond()|True|)" in evaluation
    assert "another_cond()|False|" in evaluation
    assert "(not (MySummaryFact.value|True|))" in evaluation

    # Check the complete evaluation format
    expected_evaluation = "False = not(my_cond()|True|) and another_cond()|False| or (not (MySummaryFact.value|True|))"
    assert evaluation == expected_evaluation


def test_lambda_not_operator_preservation():
    """Test that the 'not' operator is preserved in lambda condition evaluation strings."""

    engine = RuleEngine()
    engine.fact(Foo(bar=True, biz=False))

    # Test lambda with 'not' operator
    engine.rule(when=condition(lambda: Foo.bar and not Foo.biz), then=action(partial(Bar, baz=1)))

    engine.evaluate(trace=True)
    yaml_output = engine.yaml_report()
    report_data = yaml.safe_load(yaml_output)

    # Check the evaluation string preserves the 'not' operator and wraps lambda in parentheses
    matches = report_data["report"]["iterations"][0]["matches"]
    assert len(matches) == 1

    evaluation = matches[0]["evaluation"]
    assert evaluation == "True = (Foo.bar|True| and not Foo.biz|False|)"


def test_compound_condition_with_lambda_parentheses():
    """Test that lambda conditions in compound expressions are wrapped in parentheses."""

    @condition
    def simple_true() -> bool:
        return True

    @condition
    def simple_false() -> bool:
        return False

    engine = RuleEngine()
    engine.fact(MySummaryFact(value=True))

    # Create lambda condition separately to avoid multi-lambda issues
    lambda_cond = condition(lambda: not MySummaryFact.value)

    # Test compound condition with both custom conditions and lambda
    engine.rule(when=~simple_true & simple_false | lambda_cond, then=action(partial(Bar, baz=1)))

    engine.evaluate(trace=True)
    yaml_output = engine.yaml_report()
    report_data = yaml.safe_load(yaml_output)

    # Check the evaluation string
    matches = report_data["report"]["iterations"][0]["matches"]
    assert len(matches) == 1

    evaluation = matches[0]["evaluation"]
    # Lambda conditions should be wrapped in parentheses, custom conditions should not
    assert "not(simple_true()|True|)" in evaluation
    assert "simple_false()|False|" in evaluation
    assert "(not MySummaryFact.value|True|)" in evaluation

    expected = "False = not(simple_true()|True|) and simple_false()|False| or (not MySummaryFact.value|True|)"
    assert evaluation == expected


def test_simple_custom_condition_formatting():
    """Test formatting of simple custom conditions (not compound)."""

    @condition
    def simple_true_cond() -> bool:
        return True

    @condition
    def simple_false_cond() -> bool:
        return False

    engine = RuleEngine()
    engine.fact(MySummaryFact(value=True))

    # Test simple custom condition combined with a fact-based condition (don't modify facts)
    engine.rule(
        name="Simple true condition",
        when=simple_true_cond & condition(lambda: MySummaryFact.value),
        then=action(partial(ResultTestFact, status="fired")),
    )

    # Test inverted custom condition
    engine.rule(
        name="Inverted false condition",
        when=~simple_false_cond & condition(lambda: MySummaryFact.value),
        then=action(partial(ResultTestFact, status="also_fired")),
    )

    engine.evaluate(trace=True)
    yaml_output = engine.yaml_report()
    report_data = yaml.safe_load(yaml_output)

    matches = report_data["report"]["iterations"][0]["matches"]
    assert len(matches) == 2

    # Check first match (simple custom condition)
    first_match = matches[0]
    assert "simple_true_cond()|True|" in first_match["evaluation"]
    assert "MySummaryFact.value|True|" in first_match["evaluation"]

    # Check second match (inverted custom condition)
    second_match = matches[1]
    assert "not(simple_false_cond()|False|)" in second_match["evaluation"]
    assert "MySummaryFact.value|True|" in second_match["evaluation"]
