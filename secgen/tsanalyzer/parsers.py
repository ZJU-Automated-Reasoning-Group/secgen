"""Language-specific parsers and analyzers."""

import tree_sitter
from typing import Dict, List, Optional, Set, Any, Union

from .base import BaseTreeSitterAnalyzer
from .models import SymbolInfo, VariableInfo, AssignmentInfo, AnalysisResult


class SymbolAnalyzer(BaseTreeSitterAnalyzer):
    """Symbol analyzer using tree-sitter."""
    
    def analyze_file(self, source_code: str, file_path: str = "") -> AnalysisResult:
        """Comprehensive file analysis."""
        tree = self.parse_code(source_code)
        
        functions = self._extract_functions(tree, source_code)
        variables = self._extract_variables(tree, source_code)
        calls = self._extract_function_calls(tree, source_code)
        memory_ops = self._extract_memory_operations(tree, source_code)
        assignments = self._extract_assignments(tree, source_code)
        
        return AnalysisResult(
            functions=functions,
            variables=variables,
            calls=calls,
            memory_operations=memory_ops,
            assignments=assignments,
            file_path=file_path
        )
    
    def _extract_functions(self, tree: tree_sitter.Tree, source_code: str) -> List[SymbolInfo]:
        """Extract function definitions."""
        functions = []
        for func_node in self.find_nodes_by_type(tree.root_node, "function_definition"):
            func_info = self._parse_function_node(func_node, source_code)
            if func_info:
                functions.append(func_info)
        return functions
    
    def _parse_function_node(self, func_node: tree_sitter.Node, source_code: str) -> Optional[SymbolInfo]:
        """Parse a function definition node."""
        declarator = self._find_child_by_type(func_node, "function_declarator")
        if not declarator:
            return None
        
        func_name = self._extract_identifier(declarator, source_code)
        if not func_name:
            return None
        
        return_type = self._extract_return_type(func_node, source_code)
        parameters = self._extract_parameters(declarator, source_code)
        
        return SymbolInfo(
            name=func_name,
            symbol_type='function',
            line_number=self.get_line_number(func_node, source_code),
            byte_start=func_node.start_byte,
            byte_end=func_node.end_byte,
            node=func_node,
            parameters=parameters,
            return_type=return_type
        )
    
    def _extract_variables(self, tree: tree_sitter.Tree, source_code: str) -> List[SymbolInfo]:
        """Extract variable declarations and usage."""
        variables = []
        
        # Extract declarations
        for decl_node in self.find_nodes_by_type(tree.root_node, {"declaration", "init_declarator"}):
            var_info = self._extract_variable_from_declaration(decl_node, source_code)
            if var_info:
                variables.append(var_info)
        
        # Extract variable usage (identifiers not in declarations)
        for id_node in self.find_nodes_by_type(tree.root_node, "identifier"):
            if not self._is_in_declaration(id_node):
                variables.append(self._create_symbol_info(id_node, source_code, 'variable', 'usage'))
        
        return variables
    
    def _extract_function_calls(self, tree: tree_sitter.Tree, source_code: str) -> List[SymbolInfo]:
        """Extract function calls."""
        calls = []
        for call_node in self.find_nodes_by_type(tree.root_node, "call_expression"):
            func_name = self._get_called_function_name(call_node, source_code)
            if func_name:
                calls.append(SymbolInfo(
                    name=func_name,
                    symbol_type='call',
                    line_number=self.get_line_number(call_node, source_code),
                    byte_start=call_node.start_byte,
                    byte_end=call_node.end_byte,
                    node=call_node,
                    arguments=self._extract_call_arguments(call_node, source_code),
                    caller_function=self._get_symbol_scope(call_node, source_code)
                ))
        return calls
    
    def _extract_memory_operations(self, tree: tree_sitter.Tree, source_code: str) -> List[SymbolInfo]:
        """Extract memory operations."""
        memory_ops = []
        
        # Extract from function calls
        for call_node in self.find_nodes_by_type(tree.root_node, "call_expression"):
            func_name = self._get_called_function_name(call_node, source_code)
            if func_name in self.allocation_funcs | self.deallocation_funcs:
                op_type = 'allocation' if func_name in self.allocation_funcs else 'deallocation'
                var_name = self._extract_variable_from_memory_op(call_node, source_code, op_type)
                
                memory_ops.append(SymbolInfo(
                    name=var_name or func_name,
                    symbol_type='memory_op',
                    line_number=self.get_line_number(call_node, source_code),
                    byte_start=call_node.start_byte,
                    byte_end=call_node.end_byte,
                    node=call_node,
                    operation_type=op_type,
                    target_variable=var_name
                ))
        
        return memory_ops
    
    def _extract_assignments(self, tree: tree_sitter.Tree, source_code: str) -> List[AssignmentInfo]:
        """Extract assignment operations from the AST."""
        assignments = []
        
        # Find all assignment expressions
        for assign_node in self.find_nodes_by_type(tree.root_node, "assignment_expression"):
            assignment_info = self._parse_assignment_node(assign_node, source_code)
            if assignment_info:
                assignments.append(assignment_info)
        
        # Find all init declarators (variable declarations with initialization)
        for init_node in self.find_nodes_by_type(tree.root_node, "init_declarator"):
            assignment_info = self._parse_init_declarator_node(init_node, source_code)
            if assignment_info:
                assignments.append(assignment_info)
        
        return assignments
    
    def _parse_assignment_node(self, assign_node: tree_sitter.Node, source_code: str) -> Optional[AssignmentInfo]:
        """Parse an assignment expression node."""
        if len(assign_node.children) < 3:  # Need at least: lhs, =, rhs
            return None
        
        # Find the assignment operator
        op_index = None
        for i, child in enumerate(assign_node.children):
            if child.type == "=":
                op_index = i
                break
        
        if op_index is None or op_index < 1 or op_index >= len(assign_node.children) - 1:
            return None
        
        lhs_node = assign_node.children[op_index - 1]
        rhs_node = assign_node.children[op_index + 1]
        
        lhs_name = self._extract_identifier_from_node(lhs_node, source_code)
        rhs_name = self._extract_identifier_from_node(rhs_node, source_code)
        
        if not lhs_name or not rhs_name:
            return None
        
        return AssignmentInfo(
            lhs=lhs_name,
            rhs=rhs_name,
            assignment_type='assignment',
            line_number=self.get_line_number(assign_node, source_code),
            node=assign_node
        )
    
    def _parse_init_declarator_node(self, init_node: tree_sitter.Node, source_code: str) -> Optional[AssignmentInfo]:
        """Parse an init declarator node (variable declaration with initialization)."""
        if len(init_node.children) < 3:  # Need at least: declarator, =, initializer
            return None
        
        # Find the assignment operator
        op_index = None
        for i, child in enumerate(init_node.children):
            if child.type == "=":
                op_index = i
                break
        
        if op_index is None or op_index < 1 or op_index >= len(init_node.children) - 1:
            return None
        
        declarator_node = init_node.children[op_index - 1]
        initializer_node = init_node.children[op_index + 1]
        
        lhs_name = self._extract_identifier_from_node(declarator_node, source_code)
        rhs_name = self._extract_identifier_from_node(initializer_node, source_code)
        
        if not lhs_name or not rhs_name:
            return None
        
        return AssignmentInfo(
            lhs=lhs_name,
            rhs=rhs_name,
            assignment_type='init_declarator',
            line_number=self.get_line_number(init_node, source_code),
            node=init_node
        )
    
    # Helper methods
    def _extract_return_type(self, func_node: tree_sitter.Node, source_code: str) -> Optional[str]:
        """Extract return type from function node."""
        for child in func_node.children:
            if child.type in ["primitive_type", "type_identifier", "qualified_identifier"]:
                return self.get_node_text(child, source_code)
        return None
    
    def _extract_parameters(self, declarator: tree_sitter.Node, source_code: str) -> List[str]:
        """Extract parameters from function declarator."""
        parameters = []
        param_list = self._find_child_by_type(declarator, "parameter_list")
        if param_list:
            for param_child in param_list.children:
                if param_child.type == "parameter_declaration":
                    param_info = self._extract_parameter_info(param_child, source_code)
                    if param_info:
                        parameters.append(param_info)
        return parameters
    
    def _extract_parameter_info(self, param_node: tree_sitter.Node, source_code: str) -> Optional[str]:
        """Extract parameter type and name."""
        param_type = None
        param_name = None
        
        for child in param_node.children:
            if child.type in ["primitive_type", "type_identifier", "qualified_identifier"]:
                param_type = self.get_node_text(child, source_code)
            elif child.type == "identifier":
                param_name = self.get_node_text(child, source_code)
        
        return f"{param_type or 'unknown'} {param_name}" if param_name else None
    
    def _extract_variable_from_declaration(self, decl_node: tree_sitter.Node, source_code: str) -> Optional[SymbolInfo]:
        """Extract variable from declaration."""
        for child in decl_node.children:
            if child.type == "identifier":
                return self._create_symbol_info(child, source_code, 'variable', 'declaration')
        return None
    
    def _is_in_declaration(self, id_node: tree_sitter.Node) -> bool:
        """Check if identifier is in a declaration."""
        current = id_node.parent
        while current:
            if current.type in {"declaration", "assignment_expression", "init_declarator"}:
                return True
            current = current.parent
        return False
    
    def _extract_call_arguments(self, call_node: tree_sitter.Node, source_code: str) -> List[str]:
        """Extract arguments from function call."""
        arguments = []
        arg_list = self._find_child_by_type(call_node, "argument_list")
        if arg_list:
            for arg_child in arg_list.children:
                if arg_child.type not in {",", "(", ")"}:
                    arguments.append(self.get_node_text(arg_child, source_code))
        return arguments
    
    def _extract_variable_from_memory_op(self, call_node: tree_sitter.Node, source_code: str, op_type: str) -> Optional[str]:
        """Extract variable from memory operation."""
        if op_type == 'allocation':
            # Find assignment target
            current = call_node.parent
            while current:
                if current.type == "assignment_expression":
                    for child in current.children:
                        if child.type == "identifier" and child != call_node:
                            return self.get_node_text(child, source_code)
                current = current.parent
        else:
            # Find variable in arguments
            arg_list = self._find_child_by_type(call_node, "argument_list")
            if arg_list:
                for arg_child in arg_list.children:
                    if arg_child.type == "identifier":
                        return self.get_node_text(arg_child, source_code)
        return None
    
    def _create_symbol_info(self, node: tree_sitter.Node, source_code: str, symbol_type: str, operation_type: str = None) -> SymbolInfo:
        """Create SymbolInfo from node."""
        return SymbolInfo(
            name=self.get_node_text(node, source_code),
            symbol_type=symbol_type,
            line_number=self.get_line_number(node, source_code),
            byte_start=node.start_byte,
            byte_end=node.end_byte,
            node=node,
            operation_type=operation_type
        )
    
    # Analysis methods
    def get_dangerous_calls(self, calls: List[SymbolInfo]) -> List[SymbolInfo]:
        """Get dangerous function calls."""
        return [call for call in calls if call.name in self.dangerous_funcs]
    
    def get_memory_lifecycle(self, variable_name: str, memory_ops: List[SymbolInfo]) -> List[SymbolInfo]:
        """Get memory lifecycle for a variable."""
        lifecycle = [op for op in memory_ops if op.name == variable_name or op.target_variable == variable_name]
        return sorted(lifecycle, key=lambda x: x.line_number)
    
    def is_variable_allocated(self, variable_name: str, memory_ops: List[SymbolInfo]) -> bool:
        """Check if variable has been allocated."""
        return any(op.operation_type == 'allocation' and op.target_variable == variable_name for op in memory_ops)
    
    def is_variable_freed(self, variable_name: str, memory_ops: List[SymbolInfo]) -> bool:
        """Check if variable has been freed."""
        return any(op.operation_type == 'deallocation' and op.name == variable_name for op in memory_ops)


class CppSymbolAnalyzer(SymbolAnalyzer):
    """Convenience class for C++ symbol analysis."""
    
    def __init__(self):
        super().__init__("cpp")


class CSymbolAnalyzer(SymbolAnalyzer):
    """Convenience class for C symbol analysis."""
    
    def __init__(self):
        super().__init__("c")
