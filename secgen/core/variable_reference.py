"""Enhanced variable reference system using tree-sitter AST information.

This module provides precise variable identification that considers:
- AST node information
- Scope context (function, block, global)
- Variable type and declaration information
- Source location and context
"""

import tree_sitter
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import hashlib

from secgen.tsanalyzer.base import BaseTreeSitterAnalyzer
from secgen.tsanalyzer.models import VariableInfo as TSVariableInfo


class VariableScope(Enum):
    """Variable scope types."""
    GLOBAL = "global"
    FUNCTION_PARAMETER = "function_parameter"
    LOCAL_VARIABLE = "local_variable"
    BLOCK_SCOPE = "block_scope"
    LOOP_VARIABLE = "loop_variable"
    MEMBER_VARIABLE = "member_variable"


@dataclass
class VariableReference:
    """Enhanced variable reference with precise identification."""
    name: str
    scope: VariableScope
    function_name: Optional[str] = None
    block_id: Optional[str] = None
    ast_node: Optional[tree_sitter.Node] = None
    declaration_node: Optional[tree_sitter.Node] = None
    variable_type: Optional[str] = None
    is_pointer: bool = False
    is_reference: bool = False
    is_array: bool = False
    array_dimensions: int = 0
    source_location: Optional[Tuple[int, int, int, int]] = None  # (file_path, start_line, end_line, column)
    unique_id: str = field(init=False)
    
    def __post_init__(self):
        """Generate unique identifier for this variable reference."""
        # Create a unique identifier based on context
        context_parts = [
            self.name,
            self.scope.value,
            self.function_name or "global",
            self.block_id or "root",
            str(self.source_location) if self.source_location else "unknown"
        ]
        self.unique_id = hashlib.md5("|".join(context_parts).encode()).hexdigest()[:16]
    
    def __hash__(self):
        return hash(self.unique_id)
    
    def __eq__(self, other):
        return isinstance(other, VariableReference) and self.unique_id == other.unique_id
    
    def __str__(self):
        scope_info = f"{self.scope.value}"
        if self.function_name:
            scope_info += f" in {self.function_name}"
        if self.block_id:
            scope_info += f" block:{self.block_id}"
        return f"{self.name} ({scope_info})"
    
    def is_same_variable(self, other: 'VariableReference') -> bool:
        """Check if this represents the same variable as another reference."""
        return (self.name == other.name and 
                self.scope == other.scope and
                self.function_name == other.function_name and
                self.block_id == other.block_id)
    
    def is_aliased_with(self, other: 'VariableReference') -> bool:
        """Check if this variable could be aliased with another (same scope)."""
        return (self.is_same_variable(other) or
                (self.scope == other.scope and 
                 self.function_name == other.function_name and
                 self.block_id == other.block_id))


@dataclass
class VariableContext:
    """Context information for variable analysis."""
    current_function: Optional[str] = None
    current_block_id: Optional[str] = None
    scope_stack: List[str] = field(default_factory=list)
    variable_declarations: Dict[str, VariableReference] = field(default_factory=dict)
    function_parameters: Dict[str, VariableReference] = field(default_factory=dict)
    global_variables: Dict[str, VariableReference] = field(default_factory=dict)


class VariableReferenceExtractor(BaseTreeSitterAnalyzer):
    """Extract precise variable references from tree-sitter AST."""
    
    def __init__(self, language_name: str = "c", symbol_analyzer=None):
        super().__init__(language_name)
        self.symbol_analyzer = symbol_analyzer
        self.variable_contexts: Dict[str, VariableContext] = {}
        self.variable_references: Dict[str, VariableReference] = {}
    
    def extract_variable_references(self, tree: tree_sitter.Tree, source_code: str, 
                                  file_path: str = "") -> Dict[str, VariableReference]:
        """Extract all variable references from AST with precise identification."""
        self.variable_references.clear()
        context = VariableContext()
        
        # Extract function definitions first to build context
        self._extract_function_contexts(tree, source_code, file_path, context)
        
        # Extract variable references within each function
        self._extract_variable_references_in_tree(tree, source_code, file_path, context)
        
        return self.variable_references.copy()
    
    def _extract_function_contexts(self, tree: tree_sitter.Tree, source_code: str, 
                                 file_path: str, context: VariableContext):
        """Extract function contexts and parameters."""
        for func_node in self.find_nodes_by_type(tree.root_node, "function_definition"):
            func_name = self._extract_function_name(func_node, source_code)
            if not func_name:
                continue
            
            # Extract parameters
            parameters = self._extract_function_parameters(func_node, source_code, file_path, func_name)
            for param_ref in parameters:
                context.function_parameters[param_ref.unique_id] = param_ref
                self.variable_references[param_ref.unique_id] = param_ref
    
    def _extract_variable_references_in_tree(self, tree: tree_sitter.Tree, source_code: str,
                                           file_path: str, context: VariableContext):
        """Extract variable references from the entire tree."""
        self._traverse_for_variables(tree.root_node, source_code, file_path, context)
    
    def _traverse_for_variables(self, node: tree_sitter.Node, source_code: str,
                              file_path: str, context: VariableContext):
        """Traverse AST to find variable references."""
        # Update context based on node type
        self._update_context_for_node(node, source_code, context)
        
        # Process variable declarations
        if node.type == "declaration":
            self._process_declaration(node, source_code, file_path, context)
        elif node.type == "init_declarator":
            self._process_init_declarator(node, source_code, file_path, context)
        elif node.type == "identifier":
            self._process_identifier(node, source_code, file_path, context)
        elif node.type == "assignment_expression":
            self._process_assignment(node, source_code, file_path, context)
        
        # Recursively process children
        for child in node.children:
            self._traverse_for_variables(child, source_code, file_path, context)
    
    def _update_context_for_node(self, node: tree_sitter.Node, source_code: str, context: VariableContext):
        """Update context based on current AST node."""
        if node.type == "function_definition":
            func_name = self._extract_function_name(node, source_code)
            if func_name:
                context.current_function = func_name
                context.scope_stack.append(func_name)
        elif node.type in ["compound_statement", "if_statement", "for_statement", "while_statement"]:
            # Create new block scope
            block_id = f"block_{node.start_byte}_{node.end_byte}"
            context.current_block_id = block_id
            context.scope_stack.append(block_id)
    
    def _process_declaration(self, node: tree_sitter.Node, source_code: str, 
                           file_path: str, context: VariableContext):
        """Process variable declaration."""
        var_type = self._extract_type_from_declaration(node, source_code)
        is_pointer = self._is_pointer_type(node, source_code)
        is_array = self._is_array_type(node, source_code)
        
        for child in node.children:
            if child.type == "init_declarator":
                self._process_init_declarator(child, source_code, file_path, context, var_type, is_pointer, is_array)
    
    def _process_init_declarator(self, node: tree_sitter.Node, source_code: str, 
                               file_path: str, context: VariableContext,
                               var_type: str = None, is_pointer: bool = False, is_array: bool = False):
        """Process init declarator (variable with initializer)."""
        var_name = self._extract_identifier(node, source_code)
        if not var_name:
            return
        
        scope = self._determine_variable_scope(node, context)
        source_location = self._get_source_location(node, source_code, file_path)
        
        var_ref = VariableReference(
            name=var_name,
            scope=scope,
            function_name=context.current_function,
            block_id=context.current_block_id,
            ast_node=node,
            variable_type=var_type,
            is_pointer=is_pointer,
            is_array=is_array,
            source_location=source_location
        )
        
        self.variable_references[var_ref.unique_id] = var_ref
        
        # Add to appropriate context
        if scope == VariableScope.GLOBAL:
            context.global_variables[var_ref.unique_id] = var_ref
        elif scope == VariableScope.FUNCTION_PARAMETER:
            context.function_parameters[var_ref.unique_id] = var_ref
        else:
            context.variable_declarations[var_ref.unique_id] = var_ref
    
    def _process_identifier(self, node: tree_sitter.Node, source_code: str,
                          file_path: str, context: VariableContext):
        """Process identifier usage (not declaration)."""
        var_name = self.get_node_text(node, source_code)
        if not var_name:
            return
        
        # Check if this is already a known variable
        existing_ref = self._find_existing_variable_reference(var_name, context)
        if existing_ref:
            # Create a usage reference
            usage_ref = VariableReference(
                name=var_name,
                scope=existing_ref.scope,
                function_name=context.current_function,
                block_id=context.current_block_id,
                ast_node=node,
                declaration_node=existing_ref.ast_node,
                variable_type=existing_ref.variable_type,
                is_pointer=existing_ref.is_pointer,
                is_reference=existing_ref.is_reference,
                is_array=existing_ref.is_array,
                source_location=self._get_source_location(node, source_code, file_path)
            )
            self.variable_references[usage_ref.unique_id] = usage_ref
    
    def _process_assignment(self, node: tree_sitter.Node, source_code: str,
                          file_path: str, context: VariableContext):
        """Process assignment expressions for alias analysis."""
        # This would be used to identify potential alias relationships
        # Implementation depends on specific alias analysis requirements
        pass
    
    def _extract_function_name(self, func_node: tree_sitter.Node, source_code: str) -> Optional[str]:
        """Extract function name from function definition."""
        declarator = self._find_child_by_type(func_node, "function_declarator")
        if declarator:
            return self._extract_identifier(declarator, source_code)
        return None
    
    def _extract_function_parameters(self, func_node: tree_sitter.Node, source_code: str,
                                   file_path: str, func_name: str) -> List[VariableReference]:
        """Extract function parameters."""
        parameters = []
        declarator = self._find_child_by_type(func_node, "function_declarator")
        if not declarator:
            return parameters
        
        param_list = self._find_child_by_type(declarator, "parameter_list")
        if not param_list:
            return parameters
        
        for child in param_list.children:
            if child.type == "parameter_declaration":
                param_name = self._extract_identifier(child, source_code)
                if param_name:
                    param_type = self._extract_type_from_declaration(child, source_code)
                    is_pointer = self._is_pointer_type(child, source_code)
                    
                    param_ref = VariableReference(
                        name=param_name,
                        scope=VariableScope.FUNCTION_PARAMETER,
                        function_name=func_name,
                        ast_node=child,
                        variable_type=param_type,
                        is_pointer=is_pointer,
                        source_location=self._get_source_location(child, source_code, file_path)
                    )
                    parameters.append(param_ref)
        
        return parameters
    
    def _determine_variable_scope(self, node: tree_sitter.Node, context: VariableContext) -> VariableScope:
        """Determine the scope of a variable based on context."""
        if not context.current_function:
            return VariableScope.GLOBAL
        
        # Check if it's a function parameter
        if self._is_in_parameter_list(node):
            return VariableScope.FUNCTION_PARAMETER
        
        # Check if it's in a loop
        if self._is_in_loop(node):
            return VariableScope.LOOP_VARIABLE
        
        # Check if it's in a block scope
        if context.current_block_id and context.current_block_id != "root":
            return VariableScope.BLOCK_SCOPE
        
        return VariableScope.LOCAL_VARIABLE
    
    def _find_existing_variable_reference(self, var_name: str, context: VariableContext) -> Optional[VariableReference]:
        """Find existing variable reference by name in current context."""
        # Search in reverse scope order (most specific first)
        for scope_id in reversed(context.scope_stack):
            # Search in current block
            for var_ref in context.variable_declarations.values():
                if var_ref.name == var_name and var_ref.block_id == context.current_block_id:
                    return var_ref
            
            # Search in function parameters
            for var_ref in context.function_parameters.values():
                if var_ref.name == var_name and var_ref.function_name == context.current_function:
                    return var_ref
        
        # Search in global variables
        for var_ref in context.global_variables.values():
            if var_ref.name == var_name:
                return var_ref
        
        return None
    
    def _extract_type_from_declaration(self, node: tree_sitter.Node, source_code: str) -> Optional[str]:
        """Extract type information from declaration."""
        for child in node.children:
            if child.type in ["primitive_type", "type_identifier", "qualified_identifier"]:
                return self.get_node_text(child, source_code)
        return None
    
    def _is_pointer_type(self, node: tree_sitter.Node, source_code: str) -> bool:
        """Check if the type is a pointer."""
        return "*" in self.get_node_text(node, source_code)
    
    def _is_array_type(self, node: tree_sitter.Node, source_code: str) -> bool:
        """Check if the type is an array."""
        return "[" in self.get_node_text(node, source_code)
    
    def _is_in_parameter_list(self, node: tree_sitter.Node) -> bool:
        """Check if node is in a parameter list."""
        current = node.parent
        while current:
            if current.type == "parameter_list":
                return True
            current = current.parent
        return False
    
    def _is_in_loop(self, node: tree_sitter.Node) -> bool:
        """Check if node is inside a loop."""
        current = node.parent
        while current:
            if current.type in ["for_statement", "while_statement", "do_statement"]:
                return True
            current = current.parent
        return False
    
    def _get_source_location(self, node: tree_sitter.Node, source_code: str, file_path: str) -> Tuple[int, int, int, int]:
        """Get source location information."""
        start_line = self.get_line_number(node, source_code)
        end_line = source_code[:node.end_byte].count('\n') + 1
        start_col = node.start_byte - source_code.rfind('\n', 0, node.start_byte) - 1
        return (file_path, start_line, end_line, start_col)
    
    def get_variable_references_by_name(self, var_name: str) -> List[VariableReference]:
        """Get all variable references with a given name."""
        return [ref for ref in self.variable_references.values() if ref.name == var_name]
    
    def get_variable_references_in_function(self, function_name: str) -> List[VariableReference]:
        """Get all variable references in a specific function."""
        return [ref for ref in self.variable_references.values() if ref.function_name == function_name]
    
    def get_variable_references_in_scope(self, scope: VariableScope) -> List[VariableReference]:
        """Get all variable references in a specific scope."""
        return [ref for ref in self.variable_references.values() if ref.scope == scope]