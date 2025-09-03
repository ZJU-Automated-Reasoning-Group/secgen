"""Lightweight alias analysis for interprocedural dataflow analysis.

This module provides a simple but effective alias analysis that doesn't rely on complex pointer analysis but can handle basic alias relationships.
"""

import re
from typing import Dict, Set, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from .models import FunctionInfo


class AliasType(Enum):
    """Types of alias relationships."""
    DIRECT_ASSIGNMENT = "direct_assignment"      # x = y
    POINTER_ASSIGNMENT = "pointer_assignment"    # x = &y
    DEREFERENCE = "dereference"                  # x = *y
    FIELD_ACCESS = "field_access"                # x = y->field or x = y.field
    ARRAY_ELEMENT = "array_element"              # x = y[i]
    FUNCTION_CALL = "function_call"              # x = func(y)
    PARAMETER_PASSING = "parameter_passing"      # func(x) where x is passed


@dataclass
class AliasRelation:
    """Represents an alias relationship."""
    lhs: str                    # Left-hand side variable
    rhs: str                    # Right-hand side variable/expression
    alias_type: AliasType       # Type of alias relationship
    line_number: int            # Line where this relationship occurs
    confidence: float = 1.0     # Confidence in this alias relationship


@dataclass
class AliasSet:
    """Represents a set of aliased variables."""
    variables: Set[str] = field(default_factory=set)
    primary_var: Optional[str] = None  # The "canonical" variable in this set
    confidence: float = 1.0
    
    def add_variable(self, var: str, is_primary: bool = False):
        """Add a variable to the alias set."""
        self.variables.add(var)
        if is_primary or self.primary_var is None:
            self.primary_var = var
    
    def contains(self, var: str) -> bool:
        """Check if a variable is in this alias set."""
        return var in self.variables


class LightweightAliasAnalyzer:
    """Lightweight alias analyzer that handles basic alias relationships."""
    
    def __init__(self, logger=None):
        """Initialize the alias analyzer.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger
        self.alias_relations: List[AliasRelation] = []
        self.alias_sets: List[AliasSet] = []
        
        # Patterns for different types of alias relationships
        self._init_patterns()
    
    def _init_patterns(self):
        """Initialize regex patterns for alias detection."""
        # Direct assignment: x = y
        self.direct_assignment_pattern = re.compile(
            r'(\w+)\s*=\s*(\w+)(?:\s*[;,]|$)'
        )
        
        # Pointer assignment: x = &y
        self.pointer_assignment_pattern = re.compile(
            r'(\w+)\s*=\s*&(\w+)(?:\s*[;,]|$)'
        )
        
        # Dereference: x = *y
        self.dereference_pattern = re.compile(
            r'(\w+)\s*=\s*\*(\w+)(?:\s*[;,]|$)'
        )
        
        # Field access: x = y->field or x = y.field
        self.field_access_pattern = re.compile(
            r'(\w+)\s*=\s*(\w+)(?:->|\.)(\w+)(?:\s*[;,]|$)'
        )
        
        # Array element: x = y[i]
        self.array_element_pattern = re.compile(
            r'(\w+)\s*=\s*(\w+)\[([^\]]+)\](?:\s*[;,]|$)'
        )
        
        # Function call: x = func(y)
        self.function_call_pattern = re.compile(
            r'(\w+)\s*=\s*(\w+)\s*\([^)]*\)(?:\s*[;,]|$)'
        )
    
    def analyze_function(self, function_info: FunctionInfo, content: str) -> Dict[str, Set[str]]:
        """Analyze alias relationships in a function.
        
        Args:
            function_info: Function information
            content: Source code content
            
        Returns:
            Dictionary mapping variables to their alias sets
        """
        # Extract function code
        lines = content.split('\n')
        func_lines = lines[function_info.start_line-1:function_info.end_line]
        func_code = '\n'.join(func_lines)
        
        # Clear previous analysis
        self.alias_relations.clear()
        self.alias_sets.clear()
        
        # Find alias relationships
        self._find_alias_relations(func_code, function_info.start_line)
        
        # Build alias sets
        self._build_alias_sets()
        
        # Convert to dictionary format
        alias_dict = {}
        for alias_set in self.alias_sets:
            for var in alias_set.variables:
                alias_dict[var] = alias_set.variables.copy()
        
        if self.logger:
            self.logger.log(f"Found {len(self.alias_relations)} alias relations in {function_info.name}")
        
        return alias_dict
    
    def _find_alias_relations(self, code: str, start_line: int):
        """Find alias relationships in the code."""
        lines = code.split('\n')
        
        for i, line in enumerate(lines, start_line):
            line = line.strip()
            if not line or line.startswith('//') or line.startswith('/*'):
                continue
            
            # Check for different types of alias relationships
            self._check_direct_assignment(line, i)
            self._check_pointer_assignment(line, i)
            self._check_dereference(line, i)
            self._check_field_access(line, i)
            self._check_array_element(line, i)
            self._check_function_call(line, i)
    
    def _check_direct_assignment(self, line: str, line_number: int):
        """Check for direct assignment: x = y"""
        match = self.direct_assignment_pattern.search(line)
        if match:
            lhs, rhs = match.groups()
            if lhs != rhs:  # Avoid self-assignment
                self.alias_relations.append(AliasRelation(
                    lhs=lhs,
                    rhs=rhs,
                    alias_type=AliasType.DIRECT_ASSIGNMENT,
                    line_number=line_number,
                    confidence=0.9
                ))
    
    def _check_pointer_assignment(self, line: str, line_number: int):
        """Check for pointer assignment: x = &y"""
        match = self.pointer_assignment_pattern.search(line)
        if match:
            lhs, rhs = match.groups()
            self.alias_relations.append(AliasRelation(
                lhs=lhs,
                rhs=rhs,
                alias_type=AliasType.POINTER_ASSIGNMENT,
                line_number=line_number,
                confidence=0.95
            ))
    
    def _check_dereference(self, line: str, line_number: int):
        """Check for dereference: x = *y"""
        match = self.dereference_pattern.search(line)
        if match:
            lhs, rhs = match.groups()
            self.alias_relations.append(AliasRelation(
                lhs=lhs,
                rhs=rhs,
                alias_type=AliasType.DEREFERENCE,
                line_number=line_number,
                confidence=0.8
            ))
    
    def _check_field_access(self, line: str, line_number: int):
        """Check for field access: x = y->field or x = y.field"""
        match = self.field_access_pattern.search(line)
        if match:
            lhs, obj, field = match.groups()
            field_var = f"{obj}.{field}"
            self.alias_relations.append(AliasRelation(
                lhs=lhs,
                rhs=field_var,
                alias_type=AliasType.FIELD_ACCESS,
                line_number=line_number,
                confidence=0.85
            ))
    
    def _check_array_element(self, line: str, line_number: int):
        """Check for array element access: x = y[i]"""
        match = self.array_element_pattern.search(line)
        if match:
            lhs, array, index = match.groups()
            # Only consider if index is a simple variable or constant
            if re.match(r'^\w+$', index.strip()):
                array_element = f"{array}[{index}]"
                self.alias_relations.append(AliasRelation(
                    lhs=lhs,
                    rhs=array_element,
                    alias_type=AliasType.ARRAY_ELEMENT,
                    line_number=line_number,
                    confidence=0.7
                ))
    
    def _check_function_call(self, line: str, line_number: int):
        """Check for function call: x = func(y)"""
        match = self.function_call_pattern.search(line)
        if match:
            lhs, func_name = match.groups()
            # Only consider if it's a known function that might return aliases
            if self._is_alias_returning_function(func_name):
                self.alias_relations.append(AliasRelation(
                    lhs=lhs,
                    rhs=f"{func_name}()",
                    alias_type=AliasType.FUNCTION_CALL,
                    line_number=line_number,
                    confidence=0.6
                ))
    
    def _is_alias_returning_function(self, func_name: str) -> bool:
        """Check if a function might return aliases."""
        # Known functions that might return aliases
        alias_returning_functions = {
            'malloc', 'calloc', 'realloc',  # Memory allocation
            'strdup', 'strndup',            # String duplication
            'getenv', 'getcwd',             # Environment/system functions
        }
        return func_name in alias_returning_functions
    
    def _build_alias_sets(self):
        """Build alias sets from alias relations."""
        # Create a graph of alias relationships
        alias_graph = {}
        
        for relation in self.alias_relations:
            # Add bidirectional edges
            alias_graph.setdefault(relation.lhs, set()).add(relation.rhs)
            alias_graph.setdefault(relation.rhs, set()).add(relation.lhs)
        
        # Find connected components (alias sets)
        visited = set()
        
        for var in alias_graph:
            if var not in visited:
                alias_set = AliasSet()
                self._dfs_alias_set(var, alias_graph, visited, alias_set)
                if len(alias_set.variables) > 1:  # Only keep non-trivial alias sets
                    self.alias_sets.append(alias_set)
    
    def _dfs_alias_set(self, var: str, graph: Dict[str, Set[str]], 
                      visited: Set[str], alias_set: AliasSet):
        """DFS to find connected components in alias graph."""
        if var in visited:
            return
        
        visited.add(var)
        alias_set.add_variable(var)
        
        for neighbor in graph.get(var, set()):
            self._dfs_alias_set(neighbor, graph, visited, alias_set)
    
    def get_aliases(self, var: str) -> Set[str]:
        """Get all variables that alias with the given variable."""
        for alias_set in self.alias_sets:
            if alias_set.contains(var):
                return alias_set.variables.copy()
        return {var}  # Return self if no aliases found
    
    def are_aliases(self, var1: str, var2: str) -> bool:
        """Check if two variables are aliases."""
        for alias_set in self.alias_sets:
            if alias_set.contains(var1) and alias_set.contains(var2):
                return True
        return False
    
    def get_alias_confidence(self, var1: str, var2: str) -> float:
        """Get confidence that two variables are aliases."""
        for alias_set in self.alias_sets:
            if alias_set.contains(var1) and alias_set.contains(var2):
                return alias_set.confidence
        return 0.0
