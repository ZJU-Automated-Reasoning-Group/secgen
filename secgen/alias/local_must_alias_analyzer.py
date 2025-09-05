"""Intraprocedural must-alias analysis for function-level dataflow analysis.

This module provides a simple but effective intraprocedural alias analysis that focuses on 
definitive must-alias relationships within a single function scope. It only detects
cases where variables are guaranteed to alias, avoiding speculative may-alias analysis.

Key characteristics:
- Intraprocedural analysis only (within function boundaries)
- Must-alias only (definitive alias relationships)
- No confidence scoring (binary decisions)
- Focus on clear, unambiguous alias patterns
"""

import re
from typing import Dict, Set, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from secgen.core.models import FunctionInfo
from secgen.core.variable_reference import VariableReference, VariableScope, VariableReferenceExtractor


class AliasType(Enum):
    """Types of must-alias relationships."""
    DIRECT_ASSIGNMENT = "direct_assignment"      # x = y (definitive alias)
    POINTER_ASSIGNMENT = "pointer_assignment"    # x = &y (definitive alias)
    REFERENCE_ASSIGNMENT = "reference_assignment" # x = &y (C++ reference)
    ARRAY_ALIAS = "array_alias"                  # x = y (array name aliasing)


@dataclass
class AliasRelation:
    """Represents a must-alias relationship."""
    lhs: VariableReference      # Left-hand side variable reference
    rhs: VariableReference      # Right-hand side variable reference
    alias_type: AliasType       # Type of alias relationship
    line_number: int            # Line where this relationship occurs
    confidence: float = 1.0     # Confidence score (1.0 for must-alias)


@dataclass
class AliasSet:
    """Represents a set of must-aliased variables."""
    variables: Set[VariableReference] = field(default_factory=set)
    primary_var: Optional[VariableReference] = None  # The "canonical" variable in this set
    confidence: float = 1.0  # Confidence score (1.0 for must-alias)
    
    def add_variable(self, var_ref: VariableReference, is_primary: bool = False):
        """Add a variable reference to the alias set."""
        self.variables.add(var_ref)
        if is_primary or self.primary_var is None:
            self.primary_var = var_ref
    
    def contains(self, var_ref: VariableReference) -> bool:
        """Check if a variable reference is in this alias set."""
        return var_ref in self.variables


class LocalMustAliasAnalyzer:
    """Intraprocedural must-alias analyzer that detects definitive alias relationships within a function."""
    
    def __init__(self, logger=None, symbol_analyzer=None):
        """Initialize the local must-alias analyzer.
        
        Args:
            logger: Logger instance
            symbol_analyzer: Tree-sitter symbol analyzer
        """
        self.logger = logger
        self.symbol_analyzer = symbol_analyzer
        self.variable_extractor = VariableReferenceExtractor("c", symbol_analyzer)
        self.alias_relations: List[AliasRelation] = []
        self.alias_sets: List[AliasSet] = []
        
        # Patterns for different types of must-alias relationships
        self._init_patterns()
    
    def _init_patterns(self):
        """Initialize regex patterns for must-alias detection."""
        # Direct assignment: x = y (definitive alias)
        self.direct_assignment_pattern = re.compile(
            r'(\w+)\s*=\s*(\w+)(?:\s*[;,]|$)'
        )
        
        # Pointer assignment: x = &y (definitive alias)
        self.pointer_assignment_pattern = re.compile(
            r'(\w+)\s*=\s*&(\w+)(?:\s*[;,]|$)'
        )
        
        # Reference assignment: x = &y (C++ reference, definitive alias)
        self.reference_assignment_pattern = re.compile(
            r'(\w+)\s*&\s*=\s*(\w+)(?:\s*[;,]|$)'
        )
        
        # Array name aliasing: x = y (where y is array name)
        self.array_alias_pattern = re.compile(
            r'(\w+)\s*=\s*(\w+)(?:\s*[;,]|$)'
        )
    
    def analyze_function(self, function_info: FunctionInfo, content: str) -> Dict[str, Set[VariableReference]]:
        """Analyze must-alias relationships in a function.
        
        Args:
            function_info: Function information
            content: Source code content
            
        Returns:
            Dictionary mapping variable unique_ids to their must-alias sets
        """
        # Extract function code
        lines = content.split('\n')
        func_lines = lines[function_info.start_line-1:function_info.end_line]
        func_code = '\n'.join(func_lines)
        
        # Clear previous analysis
        self.alias_relations.clear()
        self.alias_sets.clear()
        
        # Extract variable references using tree-sitter if available
        variable_references = {}
        if self.symbol_analyzer:
            try:
                tree = self.symbol_analyzer.parse_file(func_code)
                variable_references = self.variable_extractor.extract_variable_references(tree, func_code, function_info.file_path)
            except Exception as e:
                if self.logger:
                    self.logger.log(f"Error extracting variable references: {e}", "WARNING")
        
        # Find must-alias relationships
        self._find_must_alias_relations(func_code, function_info.start_line, variable_references)
        
        # Build alias sets
        self._build_alias_sets()
        
        # Convert to dictionary format
        alias_dict = {}
        for alias_set in self.alias_sets:
            for var_ref in alias_set.variables:
                alias_dict[var_ref.unique_id] = alias_set.variables.copy()
        
        if self.logger:
            self.logger.log(f"Found {len(self.alias_relations)} must-alias relations in {function_info.name}")
        
        return alias_dict
    
    def _find_must_alias_relations(self, code: str, start_line: int, variable_references: Dict[str, VariableReference]):
        """Find must-alias relationships in the code."""
        lines = code.split('\n')
        
        for i, line in enumerate(lines, start_line):
            line = line.strip()
            if not line or line.startswith('//') or line.startswith('/*'):
                continue
            
            # Check for different types of must-alias relationships
            self._check_direct_assignment(line, i, variable_references)
            self._check_pointer_assignment(line, i, variable_references)
            self._check_reference_assignment(line, i, variable_references)
            self._check_array_alias(line, i, variable_references)
    
    def _check_direct_assignment(self, line: str, line_number: int, variable_references: Dict[str, VariableReference]):
        """Check for direct assignment: x = y (must-alias)"""
        match = self.direct_assignment_pattern.search(line)
        if match:
            lhs_name, rhs_name = match.groups()
            if lhs_name != rhs_name:  # Avoid self-assignment
                lhs_ref = self._find_variable_reference_by_name(variable_references, lhs_name)
                rhs_ref = self._find_variable_reference_by_name(variable_references, rhs_name)
                
                if lhs_ref and rhs_ref:
                    self.alias_relations.append(AliasRelation(
                        lhs=lhs_ref,
                        rhs=rhs_ref,
                        alias_type=AliasType.DIRECT_ASSIGNMENT,
                        line_number=line_number
                    ))
    
    def _check_pointer_assignment(self, line: str, line_number: int, variable_references: Dict[str, VariableReference]):
        """Check for pointer assignment: x = &y (must-alias)"""
        match = self.pointer_assignment_pattern.search(line)
        if match:
            lhs_name, rhs_name = match.groups()
            lhs_ref = self._find_variable_reference_by_name(variable_references, lhs_name)
            rhs_ref = self._find_variable_reference_by_name(variable_references, rhs_name)
            
            if lhs_ref and rhs_ref:
                self.alias_relations.append(AliasRelation(
                    lhs=lhs_ref,
                    rhs=rhs_ref,
                    alias_type=AliasType.POINTER_ASSIGNMENT,
                    line_number=line_number
                ))
    
    def _check_reference_assignment(self, line: str, line_number: int, variable_references: Dict[str, VariableReference]):
        """Check for reference assignment: x & = y (C++ reference, must-alias)"""
        match = self.reference_assignment_pattern.search(line)
        if match:
            lhs_name, rhs_name = match.groups()
            lhs_ref = self._find_variable_reference_by_name(variable_references, lhs_name)
            rhs_ref = self._find_variable_reference_by_name(variable_references, rhs_name)
            
            if lhs_ref and rhs_ref:
                self.alias_relations.append(AliasRelation(
                    lhs=lhs_ref,
                    rhs=rhs_ref,
                    alias_type=AliasType.REFERENCE_ASSIGNMENT,
                    line_number=line_number
                ))
    
    def _check_array_alias(self, line: str, line_number: int, variable_references: Dict[str, VariableReference]):
        """Check for array name aliasing: x = y (where y is array name, must-alias)"""
        match = self.array_alias_pattern.search(line)
        if match:
            lhs_name, rhs_name = match.groups()
            if lhs_name != rhs_name:  # Avoid self-assignment
                # Only consider if this looks like array name aliasing
                # This is a simplified check - in practice, you'd need more context
                if self._is_likely_array_alias(line, lhs_name, rhs_name):
                    lhs_ref = self._find_variable_reference_by_name(variable_references, lhs_name)
                    rhs_ref = self._find_variable_reference_by_name(variable_references, rhs_name)
                    
                    if lhs_ref and rhs_ref:
                        self.alias_relations.append(AliasRelation(
                            lhs=lhs_ref,
                            rhs=rhs_ref,
                            alias_type=AliasType.ARRAY_ALIAS,
                            line_number=line_number
                        ))
    
    def _is_likely_array_alias(self, line: str, lhs: str, rhs: str) -> bool:
        """Check if this is likely an array name aliasing pattern."""
        # Simple heuristic: if the line contains array-like syntax
        # This is a placeholder - in practice, you'd need more sophisticated analysis
        return '[' in line or ']' in line
    
    def _build_alias_sets(self):
        """Build must-alias sets from alias relations."""
        # Create a graph of alias relationships
        alias_graph = {}
        
        for relation in self.alias_relations:
            # Add bidirectional edges
            alias_graph.setdefault(relation.lhs.unique_id, set()).add(relation.rhs.unique_id)
            alias_graph.setdefault(relation.rhs.unique_id, set()).add(relation.lhs.unique_id)
        
        # Find connected components (alias sets)
        visited = set()
        
        for var_id in alias_graph:
            if var_id not in visited:
                alias_set = AliasSet()
                self._dfs_alias_set(var_id, alias_graph, visited, alias_set)
                if len(alias_set.variables) > 1:  # Only keep non-trivial alias sets
                    self.alias_sets.append(alias_set)
    
    def _dfs_alias_set(self, var_id: str, graph: Dict[str, Set[str]], 
                      visited: Set[str], alias_set: AliasSet):
        """DFS to find connected components in alias graph."""
        if var_id in visited:
            return
        
        visited.add(var_id)
        # Find the variable reference by unique_id
        var_ref = self._find_variable_reference_by_id(var_id)
        if var_ref:
            alias_set.add_variable(var_ref)
        
        for neighbor_id in graph.get(var_id, set()):
            self._dfs_alias_set(neighbor_id, graph, visited, alias_set)
    
    def get_must_aliases(self, var_ref: VariableReference) -> Set[VariableReference]:
        """Get all variables that must-alias with the given variable reference."""
        for alias_set in self.alias_sets:
            if alias_set.contains(var_ref):
                return alias_set.variables.copy()
        return {var_ref}  # Return self if no aliases found
    
    def are_must_aliases(self, var1: VariableReference, var2: VariableReference) -> bool:
        """Check if two variables are must-aliases."""
        for alias_set in self.alias_sets:
            if alias_set.contains(var1) and alias_set.contains(var2):
                return True
        return False
    
    def _find_variable_reference_by_name(self, variable_references: Dict[str, VariableReference], name: str) -> Optional[VariableReference]:
        """Find variable reference by name."""
        for var_ref in variable_references.values():
            if var_ref.name == name:
                return var_ref
        return None
    
    def _find_variable_reference_by_id(self, var_id: str) -> Optional[VariableReference]:
        """Find variable reference by unique ID."""
        for relation in self.alias_relations:
            if relation.lhs.unique_id == var_id:
                return relation.lhs
            if relation.rhs.unique_id == var_id:
                return relation.rhs
        return None
