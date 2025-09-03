import json
from typing import List
from secgen.checker.vulnerability_detector import VulnerabilityDetector, AnalysisReport
from secgen.core.models import Severity, VulnerabilityType


def convert_severity(severity_str: str) -> Severity:
    """Convert string severity to Severity enum."""
    return getattr(Severity, severity_str.upper())


def convert_vuln_types(type_strings: List[str]) -> set:
    """Convert string vulnerability types to VulnerabilityType set."""
    return {vt for type_str in type_strings for vt in VulnerabilityType if vt.value == type_str}


def format_output(report: AnalysisReport, detector: VulnerabilityDetector, format_type: str) -> str:
    """Format analysis report based on format type."""
    if format_type == "json":
        return json.dumps(detector.export_json_report(report), indent=2)
    elif format_type == "sarif":
        return format_sarif_output(report, detector)
    else:  # text
        return detector.generate_summary_report(report)


def format_sarif_output(report: AnalysisReport, detector: VulnerabilityDetector) -> str:
    """Format analysis report as SARIF."""
    sarif_report = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "SecGen Code Audit Agent", "version": "1.0.0", "rules": []}}, "results": []}]
    }
    
    # Add rules and results
    seen_rules = set()
    for vuln in report.vulnerabilities:
        rule_id = vuln.vuln_type.value
        if rule_id not in seen_rules:
            rule = {
                "id": rule_id,
                "name": vuln.vuln_type.value.replace('_', ' ').title(),
                "shortDescription": {"text": vuln.description},
                "defaultConfiguration": {"level": "warning" if vuln.severity in [Severity.LOW, Severity.MEDIUM] else "error"}
            }
            if vuln.cwe_id:
                rule["properties"] = {"cwe": vuln.cwe_id}
            sarif_report["runs"][0]["tool"]["driver"]["rules"].append(rule)
            seen_rules.add(rule_id)
        
        result = {
            "ruleId": rule_id,
            "message": {"text": vuln.description},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": vuln.location.file_path}, "region": {"startLine": vuln.location.line_start, "endLine": vuln.location.line_end}}}],
            "level": "warning" if vuln.severity in [Severity.LOW, Severity.MEDIUM] else "error"
        }
        if vuln.recommendation:
            result["fixes"] = [{"description": {"text": vuln.recommendation}}]
        sarif_report["runs"][0]["results"].append(result)
    
    return json.dumps(sarif_report, indent=2)


def list_vulnerability_types():
    """List all available vulnerability types."""
    print("Available vulnerability types:")
    for vt in VulnerabilityType:
        print(f"  {vt.value:30} - {vt.value.replace('_', ' ').title()}")
