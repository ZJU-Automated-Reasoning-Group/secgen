"""Alias analysis modules for secgen.

This package contains various alias analysis implementations:
- Bottom-up modular alias analysis
- Comprehensive alias analysis
- Local must-alias analysis
"""

from .bottom_up_alias_analyzer import BottomUpAliasAnalyzer, AliasOperationType, AliasOperation
from .alias_driver import ModularAliasAnalyzer, AnalysisConfig
from .local_must_alias_analyzer import LocalMustAliasAnalyzer, AliasType, AliasRelation

__all__ = [
    'BottomUpAliasAnalyzer',
    'AliasOperationType', 
    'AliasOperation',
    'ModularAliasAnalyzer',
    'AnalysisConfig',
    'LocalMustAliasAnalyzer',
    'AliasType',
    'AliasRelation'
]
