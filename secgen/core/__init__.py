"""Core analysis modules for code quality audit agent."""

from secgen.ir.file_analyzer import FileAnalyzer
from secgen.core.interprocedural_analyzer import InterproceduralAnalyzer

__all__ = [
    'FileAnalyzer',
    'InterproceduralAnalyzer'
]
