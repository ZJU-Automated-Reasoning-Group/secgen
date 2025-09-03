"""SecGen: Advanced Code Quality Audit Agent."""

__version__ = "1.0.0"
__author__ = "SecGen Team"

from secgen.checker.vulnerability_detector import VulnerabilityDetector
from secgen.core.models import Vulnerability, VulnerabilityType, Severity
from secgen.cli.cli import cli_main

__all__ = ['VulnerabilityDetector', 'Vulnerability', 'VulnerabilityType', 'Severity', 'cli_main']
