# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Latchfield Technologies http://latchfield.com

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import yaml


@dataclass
class RuleMatchConsequence:
    """Represents the consequences of a rule match."""
    fact_name: str
    attribute_name: str | None = None
    value: Any = None
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for YAML serialization."""
        if self.attribute_name:
            return {f"{self.fact_name}.{self.attribute_name}": self.value}
        else:
            return {self.fact_name: self.value}


@dataclass
class RuleMatchContext:
    """Represents context information for values referenced in conditions."""
    fact_attribute: str
    value: Any
    is_multiline: bool = False
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for YAML serialization."""
        if self.is_multiline and isinstance(self.value, str):
            # Use YAML literal scalar format for multiline strings
            return {self.fact_attribute: self.value}
        else:
            return {self.fact_attribute: self.value}


@dataclass
class RuleMatch:
    """Represents a single rule match within an iteration."""
    rule: str  # Format: "id:name"
    timestamp: datetime
    elapsed: float  # seconds with millisecond precision
    evaluation: str  # String representation of the evaluation
    consequences: list[RuleMatchConsequence] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    context: list[RuleMatchContext] = field(default_factory=list)
    rationale: str | None = None
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for YAML serialization."""
        result = {
            "rule": self.rule,
            "timestamp": self.timestamp.isoformat() + "Z",
            "elapsed": round(self.elapsed, 3),
            "evaluation": self._format_evaluation_for_yaml(),
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
            result["warnings"] = self.warnings
            
        if self.context:
            context_list = []
            for ctx in self.context:
                context_list.append(ctx.to_dict())
            result["context"] = context_list
            
        if self.rationale:
            result["rationale"] = self.rationale
            
        return result
    
    def _format_evaluation_for_yaml(self) -> str:
        """Format the evaluation string, extracting long strings to context if needed."""
        # For now, return as-is. We'll enhance this to extract long strings to context
        return self.evaluation


@dataclass
class ReportIteration:
    """Represents a single iteration of rule evaluation."""
    id: int
    timestamp: datetime
    elapsed: float  # seconds with millisecond precision
    matches: list[RuleMatch] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for YAML serialization."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() + "Z",
            "elapsed": round(self.elapsed, 3),
            "matches": [match.to_dict() for match in self.matches],
        }


@dataclass
class EvaluationReport:
    """Represents the complete evaluation report."""
    iterations: list[ReportIteration] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for YAML serialization."""
        return {
            "report": {
                "iterations": [iteration.to_dict() for iteration in self.iterations]
            }
        }
    
    def to_yaml(self) -> str:
        """Convert the report to YAML format."""
        # Create a custom representer for None values
        def represent_none(dumper, data):
            return dumper.represent_scalar('tag:yaml.org,2002:str', 'None')
        
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
            width=1000000  # Very large width to prevent wrapping
        )