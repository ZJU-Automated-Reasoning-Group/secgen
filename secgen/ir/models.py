"""IR (Intermediate Representation) data models for data flow and call graphs."""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any, Union
from enum import Enum
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
class CallGraphMetrics:
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


class ControlFlowType(Enum):
    """Types of control flow edges."""
    SEQUENTIAL = "sequential"        # Normal sequential execution
    CONDITIONAL_TRUE = "conditional_true"  # True branch of conditional
    CONDITIONAL_FALSE = "conditional_false"  # False branch of conditional
    LOOP_ENTRY = "loop_entry"        # Entry to loop
    LOOP_BACK = "loop_back"          # Back edge in loop
    LOOP_EXIT = "loop_exit"          # Exit from loop
    BREAK = "break"                  # Break statement
    CONTINUE = "continue"            # Continue statement
    RETURN = "return"                # Return statement
    GOTO = "goto"                    # Goto statement
    SWITCH_CASE = "switch_case"      # Switch case
    SWITCH_DEFAULT = "switch_default"  # Switch default case
    EXCEPTION = "exception"          # Exception handling
    FUNCTION_CALL = "function_call"  # Function call
    FUNCTION_RETURN = "function_return"  # Function return


@dataclass
class BasicBlock:
    """Represents a basic block in the control flow graph."""
    block_id: str
    function_id: str
    start_line: int
    end_line: int
    statements: List[str] = field(default_factory=list)
    variables_defined: Set[str] = field(default_factory=set)
    variables_used: Set[str] = field(default_factory=set)
    is_entry: bool = False
    is_exit: bool = False
    is_loop_header: bool = False
    is_loop_latch: bool = False
    node: Optional[Any] = None  # tree_sitter.Node reference


@dataclass
class CFGNode:
    """Node in control flow graph."""
    block_id: str
    basic_block: BasicBlock
    predecessors: List[str] = field(default_factory=list)
    successors: List[str] = field(default_factory=list)
    dominators: Set[str] = field(default_factory=set)
    immediate_dominator: Optional[str] = None
    dominance_frontier: Set[str] = field(default_factory=set)


@dataclass
class CFGEdge:
    """Edge in control flow graph."""
    source: str
    target: str
    edge_type: ControlFlowType
    condition: Optional[str] = None  # For conditional edges
    line_number: Optional[int] = None
    weight: float = 1.0


@dataclass
class CFGMetrics:
    """Metrics for control flow graph."""
    num_blocks: int
    num_edges: int
    cyclomatic_complexity: int
    max_depth: int
    num_loops: int
    num_conditionals: int
    entry_blocks: List[str]
    exit_blocks: List[str]
    loop_headers: List[str]
    strongly_connected_components: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'num_blocks': self.num_blocks,
            'num_edges': self.num_edges,
            'cyclomatic_complexity': self.cyclomatic_complexity,
            'max_depth': self.max_depth,
            'num_loops': self.num_loops,
            'num_conditionals': self.num_conditionals,
            'entry_blocks': self.entry_blocks,
            'exit_blocks': self.exit_blocks,
            'loop_headers': self.loop_headers,
            'strongly_connected_components': self.strongly_connected_components
        }