"""Core analysis modules for code quality audit agent."""

from secgen.core.analyzer import CodeAnalyzer
from secgen.core.interprocedural_analyzer import InterproceduralAnalyzer

__all__ = [
    'CodeAnalyzer',
    'InterproceduralAnalyzer'
]
