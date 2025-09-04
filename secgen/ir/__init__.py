"""IR (Intermediate Representation) module for data flow and call graphs.

This module provides classes and utilities for building and analyzing
intermediate representations of code, including:
- Call graphs for interprocedural analysis
"""

from .models import (
    CallSite,
    TaintPath,
    CallGraphNode,
    CallGraphEdge,
    IRMetrics,
)

from .call_graph import CallGraphBuilder

__all__ = [
    # Models
    'CallSite',
    'TaintPath',
    'CallGraphNode',
    'CallGraphEdge',
    'IRMetrics',# Builders
    'CallGraphBuilder'
]
