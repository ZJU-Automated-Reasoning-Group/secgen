"""Utilities and data models for SecGen vulnerability reporting."""

import json
from typing import NamedTuple, List


class Vulnerability(NamedTuple):
    """Vulnerability information."""
    type: str
    description: str
    file: str
    line: int
    severity: str


def parse_sarif(content: str) -> List[Vulnerability]:
    """Parse SARIF and extract vulnerabilities."""
    data = json.loads(content)
    vulnerabilities = []
    
    for run in data.get("runs", []):
        rules = {rule["id"]: rule for rule in run.get("tool", {}).get("driver", {}).get("rules", [])}
        
        for result in run.get("results", []):
            rule_id = result.get("ruleId")
            if rule_id in rules:
                rule = rules[rule_id]
                severity = str(rule.get("properties", {}).get("security-severity", 
                             rule.get("properties", {}).get("problem.severity", "unknown")))
                
                for loc in result.get("locations", []):
                    phys = loc.get("physicalLocation", {})
                    vulnerabilities.append(Vulnerability(
                        type=rule_id,
                        description=rule.get("fullDescription", {}).get("text", "No description"),
                        file=phys.get("artifactLocation", {}).get("uri", "unknown"),
                        line=phys.get("region", {}).get("startLine", 0),
                        severity=severity
                    ))
    
    return vulnerabilities
