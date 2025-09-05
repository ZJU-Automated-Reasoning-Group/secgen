"""Command-line interface for the code quality audit agent."""

import argparse
import sys
import time
from pathlib import Path
from typing import List, Optional

from secgen.core.models import VulnerabilityType
from secgen.agent.models import OpenAIServerModel
from secgen.checker import AnalysisReport
from secgen.checker.report_generator import ReportGenerator
from secgen.agent.minotor import AgentLogger, LogLevel


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser."""
    parser = argparse.ArgumentParser(
        description="Security vulnerability scanner",
        epilog="""Examples:
  secgen-audit . --detectors uaf,npd,bof
  secgen-audit file.c -o report.json -f json
  secgen-audit . --min-severity high --disable-memory
  secgen-audit . --min-severity high --disable-memory"""
    )
    
    # Add subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    
    # Core arguments
    parser.add_argument("project_path", nargs='?', help="Project directory or file to analyze")
    parser.add_argument("--extensions", nargs="+", default=[".py", ".c", ".cpp", ".h", ".hpp", ".java", ".js", ".ts"], help="File extensions to analyze")
    parser.add_argument("--exclude", nargs="+", default=["__pycache__", ".git", "node_modules", "vendor"], help="Patterns to exclude")
    parser.add_argument("--min-severity", choices=["info", "low", "medium", "high", "critical"], default="low", help="Minimum severity level")
    parser.add_argument("--min-confidence", type=float, default=0.0, metavar="0.0-1.0", help="Minimum confidence threshold")
    
    # Detector selection
    available_detectors = ["uaf", "npd", "bof", "mlk", "df", "fs", "io", "taint", "sql", "cmd", "xss", "path"]
    parser.add_argument("--detectors", help=f"Comma-separated detectors to enable: {', '.join(available_detectors)}")
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


def parse_detectors(detector_string: str) -> List[VulnerabilityType]:
    """Parse detector string and return corresponding vulnerability types."""
    if not detector_string:
        return []
    
    # Mapping from short detector names to vulnerability types
    detector_map = {
        "uaf": VulnerabilityType.USE_AFTER_FREE,
        "npd": VulnerabilityType.NULL_POINTER_DEREF,
        "bof": VulnerabilityType.BUFFER_OVERFLOW,
        "mlk": VulnerabilityType.MEMORY_LEAK,
        "df": VulnerabilityType.USE_AFTER_FREE,  # Double free is a type of UAF
        "fs": VulnerabilityType.BUFFER_OVERFLOW,  # Format string is a type of buffer overflow
        "io": VulnerabilityType.INTEGER_OVERFLOW,
        "taint": VulnerabilityType.COMMAND_INJECTION,  # Generic taint analysis
        "sql": VulnerabilityType.SQL_INJECTION,
        "cmd": VulnerabilityType.COMMAND_INJECTION,
        "xss": VulnerabilityType.XSS,
        "path": VulnerabilityType.PATH_TRAVERSAL,
    }
    
    detectors = [d.strip().lower() for d in detector_string.split(",")]
    vuln_types = []
    
    for detector in detectors:
        if detector in detector_map:
            vuln_types.append(detector_map[detector])
        else:
            raise ValueError(f"Unknown detector: {detector}. Available: {', '.join(detector_map.keys())}")
    
    return vuln_types


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



async def main():
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Handle subcommands
    if hasattr(args, 'func'):
        args.func(args)
        return 0
    
    # Handle utility options
    if args.list_vuln_types:
        report_generator = ReportGenerator()
        report_generator.list_vulnerability_types()
        return 0
    
    # Setup logging
    logger = setup_logging(args)
    
    # Validate project path (only if not using subcommands)
    if args.project_path:
        project_path = Path(args.project_path)
        if not project_path.exists():
            logger.log(f"Error: Path does not exist: {project_path}", level=LogLevel.ERROR)
            return 1
    else:
        project_path = None
    
    if project_path:
        is_single_file = project_path.is_file()
        is_directory = project_path.is_dir()
        
        if not is_single_file and not is_directory:
            logger.log(f"Error: Path is neither a file nor a directory: {project_path}", level=LogLevel.ERROR)
            return 1
    else:
        is_single_file = False
        is_directory = False
    
    # Setup model if requested
    model = setup_model(args, logger)
    
    # Create detector
    config = {
        'disable_interprocedural': args.disable_interprocedural,
        'disable_taint': args.disable_taint,
        'disable_memory': args.disable_memory,
        'enable_llm_enhancement': args.enable_llm_enhancement
    }
    
    # detector = VulnerabilityDetector(config=config, logger=logger)  # TODO: Define VulnerabilityDetector class
    
    try:
        # Handle detector selection
        enabled_detectors = None
        if args.detectors:
            try:
                enabled_detectors = parse_detectors(args.detectors)
            except ValueError as e:
                logger.log(f"Error: {e}", level=LogLevel.ERROR)
                return 1
        
        # Perform analysis
        if not project_path:
            logger.log("Error: No project path specified and no subcommand used", level=LogLevel.ERROR)
            return 1
        elif is_single_file:
            logger.log(f"Starting analysis of single file: {project_path}")
            # report = detector.analyze_single_file(str(project_path), enabled_detectors)  # TODO: Implement single file analysis
            logger.log("Single file analysis not yet implemented", level=LogLevel.ERROR)
            return 1
        else:
            logger.log(f"Starting analysis of directory: {project_path}")

            logger.log("Directory analysis not yet implemented", level=LogLevel.ERROR)
            return 1
    
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
