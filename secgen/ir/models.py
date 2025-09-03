"""IR (Intermediate Representation) data models for data flow and call graphs."""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any
from secgen.core.models import VulnerabilityType


@dataclass 
class CallSite:
    """Represents a function call site."""
    caller: str
    callee: str
    file_path: str
    line_number: int
    arguments: List[str] = field(default_factory=list)
    context: str = ""


@dataclass
class DataFlowNode:
    """Node in data flow graph."""
    function: str
    variable: str
    line_number: int
    node_type: str  # 'source', 'sink', 'sanitizer', 'normal'
    taint_status: str = 'unknown'  # 'tainted', 'clean', 'unknown'


@dataclass
class TaintPath:
    """Path of tainted data flow."""
    source: DataFlowNode
    sink: DataFlowNode
    path: List[DataFlowNode]
    confidence: float
    vulnerability_type: VulnerabilityType


@dataclass
class CallGraphNode:
    """Node in call graph."""
    function_id: str
    function_name: str
    file_path: str
    start_line: int
    end_line: int
    calls: List[str] = field(default_factory=list)
    called_by: List[str] = field(default_factory=list)


@dataclass
class CallGraphEdge:
    """Edge in call graph."""
    caller: str
    callee: str
    call_sites: List[CallSite] = field(default_factory=list)


@dataclass
class DataFlowGraphNode:
    """Node in data flow graph."""
    node_id: str
    node_type: str  # 'source', 'sink', 'sanitizer', 'normal'
    line_number: int
    file_path: str
    content: str
    variables: Set[str] = field(default_factory=set)
    taint_status: str = 'unknown'


@dataclass
class DataFlowGraphEdge:
    """Edge in data flow graph."""
    source: str
    target: str
    edge_type: str  # 'data_flow', 'control_flow', 'call'
    variables: Set[str] = field(default_factory=set)


@dataclass
class IRMetrics:
    """Metrics for IR graphs."""
    num_nodes: int
    num_edges: int
    max_depth: int
    cyclic_dependencies: List[List[str]]
    strongly_connected_components: int
    entry_points: List[str]
    leaf_nodes: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'num_nodes': self.num_nodes,
            'num_edges': self.num_edges,
            'max_depth': self.max_depth,
            'cyclic_dependencies': self.cyclic_dependencies,
            'strongly_connected_components': self.strongly_connected_components,
            'entry_points': self.entry_points,
            'leaf_nodes': self.leaf_nodes
        }