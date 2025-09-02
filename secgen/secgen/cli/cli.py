"""Command-line interface for the code quality audit agent."""

import argparse
import json
import sys
import time
from pathlib import Path
from typing import List, Optional

from secgen.checker.vulnerability_detector import VulnerabilityDetector, AnalysisReport
from secgen.core.analyzer import Severity, VulnerabilityType
from secgen.agent.models import OpenAIServerModel

try:
    from secgen.agent.minotor import AgentLogger, LogLevel
except ImportError:
    import logging
    from enum import IntEnum
    
    class LogLevel(IntEnum):
        OFF, ERROR, INFO, DEBUG = -1, 0, 1, 2
    
    class AgentLogger:
        def __init__(self, level=LogLevel.INFO):
            self.level = level
            self.logger = logging.getLogger(__name__)
            
        def log(self, message, level=LogLevel.INFO):
            if level <= self.level:
                getattr(self.logger, {LogLevel.ERROR: 'error', LogLevel.DEBUG: 'debug'}.get(level, 'info'))(message)


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser."""
    parser = argparse.ArgumentParser(
        description="Code Quality Audit Agent - Comprehensive security vulnerability scanner",
        epilog="""Examples:
  secgen-audit .                                    # Analyze current directory
  secgen-audit /path/to/project --min-severity high # High severity only
  secgen-audit /path/to/project -o report.json -f json # Export to JSON
  secgen-audit /path/to/project --extensions .c .cpp .h # C/C++ only
  secgen-audit /path/to/project --model gpt-4 --api-key KEY # Use LLM"""
    )
    
    # Core arguments
    parser.add_argument("project_path", help="Path to the project directory to analyze")
    parser.add_argument("--extensions", nargs="+", default=[".py", ".c", ".cpp", ".h", ".hpp", ".java", ".js", ".ts"], help="File extensions to analyze")
    parser.add_argument("--exclude", nargs="+", default=["test", "tests", "__pycache__", ".git", "node_modules", "vendor"], help="Patterns to exclude")
    parser.add_argument("--min-severity", choices=["info", "low", "medium", "high", "critical"], default="low", help="Minimum severity level")
    parser.add_argument("--min-confidence", type=float, default=0.0, metavar="0.0-1.0", help="Minimum confidence threshold")
    parser.add_argument("--vuln-types", nargs="+", choices=[vt.value for vt in VulnerabilityType], help="Specific vulnerability types")
    
    # Output options
    parser.add_argument("--output", "-o", help="Output file path (default: stdout)")
    parser.add_argument("--format", "-f", choices=["text", "json", "sarif"], default="text", help="Output format")
    
    # LLM options
    parser.add_argument("--model", help="LLM model (e.g., gpt-4, gpt-3.5-turbo)")
    parser.add_argument("--api-key", help="API key for the LLM service")
    parser.add_argument("--api-base", help="Base URL for the LLM API")
    parser.add_argument("--temperature", type=float, default=0.1, help="LLM temperature")
    
    # Analysis control
    parser.add_argument("--disable-interprocedural", action="store_true", help="Disable interprocedural analysis")
    parser.add_argument("--disable-taint", action="store_true", help="Disable taint analysis")
    parser.add_argument("--disable-memory", action="store_true", help="Disable memory safety analysis")
    parser.add_argument("--enable-llm-enhancement", action="store_true", help="Enable LLM-based enhancement")
    
    # Logging and utility
    parser.add_argument("--verbose", "-v", action="count", default=0, help="Increase verbosity")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress all output except results")
    parser.add_argument("--log-file", help="Write logs to file")
    parser.add_argument("--version", action="version", version="SecGen Code Audit Agent 1.0.0")
    parser.add_argument("--list-vuln-types", action="store_true", help="List all available vulnerability types and exit")
    
    return parser


def setup_logging(args) -> AgentLogger:
    """Setup logging based on command line arguments."""
    level = LogLevel.OFF if args.quiet else (LogLevel.DEBUG if args.verbose > 0 else LogLevel.INFO)
    return AgentLogger(level=level)


def setup_model(args, logger) -> Optional[OpenAIServerModel]:
    """Setup LLM model if specified."""
    if not args.model:
        return None
    
    if not args.api_key:
        logger.log("Warning: Model specified but no API key provided", level=LogLevel.ERROR)
        return None
    
    try:
        model = OpenAIServerModel(model_id=args.model, api_key=args.api_key, api_base=args.api_base, temperature=args.temperature)
        logger.log(f"Initialized model: {args.model}")
        return model
    except Exception as e:
        logger.log(f"Error initializing model: {e}", level=LogLevel.ERROR)
        return None


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


async def main():
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Handle utility options
    if args.list_vuln_types:
        list_vulnerability_types()
        return 0
    
    # Setup logging
    logger = setup_logging(args)
    
    # Validate project path
    project_path = Path(args.project_path)
    if not project_path.exists():
        logger.log(f"Error: Project path does not exist: {project_path}", level=LogLevel.ERROR)
        return 1
    
    if not project_path.is_dir():
        logger.log(f"Error: Project path is not a directory: {project_path}", level=LogLevel.ERROR)
        return 1
    
    # Setup model if requested
    model = setup_model(args, logger)
    
    # Create detector
    config = {
        'disable_interprocedural': args.disable_interprocedural,
        'disable_taint': args.disable_taint,
        'disable_memory': args.disable_memory,
        'enable_llm_enhancement': args.enable_llm_enhancement
    }
    
    detector = VulnerabilityDetector(model=model, logger=logger, config=config)
    
    try:
        # Perform analysis
        logger.log(f"Starting analysis of {project_path}")
        start_time = time.time()
        
        report = detector.analyze_project(
            str(project_path),
            file_extensions=args.extensions,
            exclude_patterns=args.exclude
        )
        
        # Apply filters
        min_severity = convert_severity(args.min_severity)
        vuln_types = convert_vuln_types(args.vuln_types) if args.vuln_types else None
        
        filtered_vulnerabilities = detector.filter_vulnerabilities(
            report.vulnerabilities,
            min_severity=min_severity,
            min_confidence=args.min_confidence,
            vuln_types=vuln_types
        )
        
        # Update report with filtered vulnerabilities
        report.vulnerabilities = filtered_vulnerabilities
        report.total_vulnerabilities = len(filtered_vulnerabilities)
        
        # Enhance with LLM if requested
        if args.enable_llm_enhancement and model:
            logger.log("Enhancing analysis with LLM...")
            enhanced_vulns = await detector.enhance_with_llm_analysis(filtered_vulnerabilities)
            report.vulnerabilities = enhanced_vulns
        
        # Format output
        output = format_output(report, detector, args.format)
        
        # Write output
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            logger.log(f"Results written to {args.output}")
        else:
            print(output)
        
        # Exit with appropriate code
        if report.total_vulnerabilities > 0:
            critical_count = report.vulnerabilities_by_severity.get('critical', 0)
            high_count = report.vulnerabilities_by_severity.get('high', 0)
            return 2 if critical_count > 0 else (1 if high_count > 0 else 0)
        return 0
        
    except KeyboardInterrupt:
        logger.log("Analysis interrupted by user", level=LogLevel.ERROR)
        return 130
    except Exception as e:
        logger.log(f"Error during analysis: {e}", level=LogLevel.ERROR)
        if args.verbose > 1:
            import traceback
            logger.log(traceback.format_exc(), level=LogLevel.ERROR)
        return 1


def cli_main():
    """Synchronous entry point for CLI."""
    import asyncio
    try:
        return asyncio.run(main())
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(cli_main())
