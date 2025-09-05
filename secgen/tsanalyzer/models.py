"""Data models and classes for tree-sitter analysis."""

import tree_sitter
from typing import Dict, List, Optional, Set, Any, Union
from dataclasses import dataclass


@dataclass
class SymbolInfo:
    """Information about symbols (functions, variables, calls)."""
    name: str
    symbol_type: str  # 'function', 'variable', 'call', 'memory_op'
    line_number: int
    byte_start: int
    byte_end: int
    node: tree_sitter.Node
    # Optional fields
    parameters: Optional[List[str]] = None
    return_type: Optional[str] = None
    arguments: Optional[List[str]] = None
    caller_function: Optional[str] = None
    operation_type: Optional[str] = None
    target_variable: Optional[str] = None


@dataclass
class VariableInfo:
    """Information about a variable extracted from AST."""
    name: str
    type: Optional[str] = None
    is_pointer: bool = False
    is_array: bool = False
    is_const: bool = False
    scope: str = "unknown"
    line_number: int = 0
    node: Optional[tree_sitter.Node] = None


@dataclass
class AssignmentInfo:
    """Information about an assignment extracted from AST."""
    lhs: str
    rhs: str
    assignment_type: str  # 'assignment', 'init_declarator', 'function_call'
    line_number: int = 0
    node: Optional[tree_sitter.Node] = None


@dataclass
class AnalysisResult:
    """Container for analysis results."""
    functions: List[SymbolInfo]
    variables: List[SymbolInfo]
    calls: List[SymbolInfo]
    memory_operations: List[SymbolInfo]
    assignments: List[AssignmentInfo]
    file_path: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'functions': self.functions,
            'variables': self.variables,
            'calls': self.calls,
            'memory_operations': self.memory_operations,
            'assignments': self.assignments,
            'file_path': self.file_path
        }
