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
        rationale="Test rationale"
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
        "rationale": "Test rationale"
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
        consequences=[RuleMatchConsequence("Bar", "baz", 23)]
    )
    
    iteration = ReportIteration(
        id=1,
        timestamp=timestamp,
        elapsed=0.030,
        matches=[match]
    )
    
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
    
    iteration = ReportIteration(
        id=1,
        timestamp=timestamp,
        elapsed=0.030,
        matches=[match]
    )
    
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
        consequences=[RuleMatchConsequence("Bar", "baz", 23)]
    )
    
    iteration = ReportIteration(
        id=1,
        timestamp=timestamp,
        elapsed=0.030,
        matches=[match]
    )
    
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