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
    CallGraphMetrics,
    BasicBlock,
    CFGNode,
    CFGEdge,
    ControlFlowType,
    CFGMetrics,
)

from .call_graph import CallGraphBuilder
from .control_flow_graph import CFGBuilder

__all__ = [
    # Models
    'CallSite',
    'TaintPath',
    'CallGraphNode',
    'CallGraphEdge',
    'CallGraphMetrics',
    'BasicBlock',
    'CFGNode',
    'CFGEdge',
    'ControlFlowType',
    'CFGMetrics',
    'ConcurrencyIssue',
    # Builders
    'CallGraphBuilder',
    'CFGBuilder'
]
