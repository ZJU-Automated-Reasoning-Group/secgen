"""Unified vulnerability detection system with consolidated architecture."""

from secgen.checker.report_generator import AnalysisReport
from secgen.checker.cpp_checker import CppChecker
from secgen.checker.file_analyzer_core import FileAnalyzerCore, DetectionContext
from secgen.checker.project_analyzer import ProjectAnalyzer

# Legacy compatibility - VulnerabilityDetector is now just an alias
VulnerabilityDetector = FileAnalyzerCore

__all__ = [
    'FileAnalyzerCore',
    'ProjectAnalyzer', 
    'CppChecker',
    'DetectionContext',
    'VulnerabilityDetector',  # Legacy compatibility
    'AnalysisReport',
]
