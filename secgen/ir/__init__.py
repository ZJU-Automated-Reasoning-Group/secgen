"""IR (Intermediate Representation) module for data flow and call graphs.

This module provides classes and utilities for building and analyzing
intermediate representations of code, including:
- Call graphs for interprocedural analysis
- Data flow graphs for taint propagation analysis
- IR data models and metrics
"""

from .models import (
    CallSite,
    DataFlowNode,
    TaintPath,
    CallGraphNode,
    CallGraphEdge,
    DataFlowGraphNode,
    DataFlowGraphEdge,
    IRMetrics
)

from .call_graph import CallGraphBuilder
from .data_flow_graph import DataFlowGraphBuilder

__all__ = [
    # Models
    'CallSite',
    'DataFlowNode', 
    'TaintPath',
    'CallGraphNode',
    'CallGraphEdge',
    'DataFlowGraphNode',
    'DataFlowGraphEdge',
    'IRMetrics',
    
    # Builders
    'CallGraphBuilder',
    'DataFlowGraphBuilder'
]
