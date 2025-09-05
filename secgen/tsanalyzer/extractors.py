"""High-level extraction and analysis functionality."""

import os
import ast
import json
import tree_sitter
from pathlib import Path
from typing import Dict, List, Optional, Any

from secgen.core.models import FunctionInfo
from .base import BaseTreeSitterAnalyzer
from .parsers import CppSymbolAnalyzer
from .models import VariableInfo, AssignmentInfo


class CodeMetadataExtractor:
    """Code metadata extractor using tree-sitter for code parsing."""
    
    def __init__(self, logger=None):
        self.logger = logger
        self.cpp_analyzer = CppSymbolAnalyzer()
        self.analysis_cache: Dict[str, Dict[str, Any]] = {}
        
        self.extensions = {
            'cpp': {'.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx'},
            'python': {'.py', '.pyw'},
            'java': {'.java'},
            'javascript': {'.js', '.ts', '.jsx', '.tsx'}
        }
    
    def _log(self, message: str, level: str = "INFO"):
        """Simple logging method."""
        if self.logger:
            self.logger.log(message, level=getattr(self.logger, level.upper(), None))
        else:
            print(f"[{level}] {message}")
        
    def analyze_directory(self, directory: str, extensions: List[str] = None) -> Dict[str, Any]:
        """Analyze all files in a directory."""
        if extensions is None:
            extensions = [ext for ext_set in self.extensions.values() for ext in ext_set]
            
        results = {
            'files_analyzed': [],
            'functions': {},
            'symbols': {},
            'memory_operations': {},
            'function_calls': {},
            'statistics': {}
        }
        
        # Find and analyze files
        files_to_analyze = [
            os.path.join(root, file) for root, _, files in os.walk(directory)
            for file in files if any(file.endswith(ext) for ext in extensions)
        ]
        
        self._log(f"Found {len(files_to_analyze)} files to analyze")
        
        for file_path in files_to_analyze:
            try:
                file_results = self.analyze_file(file_path)
                if file_results:
                    results['files_analyzed'].append(file_path)
                    results['functions'].update(file_results.get('functions', {}))
                    results['symbols'][file_path] = file_results.get('symbol_table', {})
                    results['memory_operations'][file_path] = file_results.get('memory_operations', [])
                    results['function_calls'][file_path] = file_results.get('function_calls', [])
            except Exception as e:
                self._log(f"Error analyzing {file_path}: {e}", "ERROR")
        
        results['statistics'] = self._calculate_statistics(results)
        self._log(f"Analysis complete. Found {len(results['functions'])} functions across {len(results['files_analyzed'])} files")
        
        return results
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze a single file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            self._log(f"Error reading file {file_path}: {e}", "ERROR")
            return {}
        
        if file_path in self.analysis_cache:
            return self.analysis_cache[file_path]
        
        file_ext = Path(file_path).suffix.lower()
        
        # Route to appropriate analyzer
        analyzers = {
            'cpp': self._analyze_cpp_file,
            'python': self._analyze_python_file,
            'java': self._analyze_java_file,
            'javascript': self._analyze_javascript_file
        }
        
        for lang, ext_set in self.extensions.items():
            if file_ext in ext_set:
                return analyzers[lang](file_path, content)
        
        return {'functions': {}}
    
    def _analyze_cpp_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Analyze C/C++ file using tree-sitter."""
        try:
            analysis_results = self.cpp_analyzer.analyze_file(content, file_path)
            
            results = {
                'functions': {},
                'symbol_table': {},
                'memory_operations': [],
                'function_calls': [],
                'file_path': file_path
            }
            
            # Convert function info to standard format
            for func in analysis_results.functions:
                func_key = f"{file_path}:{func.name}"
                # Calculate end_line from start_line and node
                start_line = func.line_number
                end_line = start_line + 10  # Default estimate, could be improved
                
                results['functions'][func_key] = FunctionInfo(
                    name=func.name,
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    parameters=func.parameters or []
                )
            
            # Convert other results
            results['symbol_table'] = {var.name: var for var in analysis_results.variables}
            results['memory_operations'] = [op for op in analysis_results.memory_operations]
            results['function_calls'] = [call for call in analysis_results.calls]
            
            self.analysis_cache[file_path] = results
            return results
            
        except Exception as e:
            self._log(f"Error analyzing C/C++ file {file_path}: {e}", "ERROR")
            return {}
    
    def _analyze_python_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Analyze Python file using AST parsing."""
        results = {'functions': {}}
        
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    func_info = FunctionInfo(
                        name=node.name,
                        file_path=file_path,
                        start_line=node.lineno,
                        end_line=getattr(node, 'end_lineno', node.lineno),
                        parameters=[arg.arg for arg in node.args.args]
                    )
                    
                    # Extract function calls
                    for child in ast.walk(node):
                        if isinstance(child, ast.Call):
                            call_name = child.func.id if isinstance(child.func, ast.Name) else child.func.attr
                            func_info.calls.append(call_name)
                    
                    results['functions'][f"{file_path}:{node.name}"] = func_info
                    
        except SyntaxError as e:
            self._log(f"Syntax error in {file_path}: {e}", "ERROR")
        
        return results
    
    def _analyze_java_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Analyze Java file (placeholder)."""
        return {'functions': {}}
    
    def _analyze_javascript_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Analyze JavaScript/TypeScript file (placeholder)."""
        return {'functions': {}}
    
    def _calculate_statistics(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate analysis statistics."""
        total_functions = len(results['functions'])
        total_files = len(results['files_analyzed'])
        
        # Count by file
        functions_by_file = {}
        for func_info in results['functions'].values():
            file_path = func_info.file_path
            functions_by_file[file_path] = functions_by_file.get(file_path, 0) + 1
        
        memory_ops_by_file = {fp: len(ops) for fp, ops in results['memory_operations'].items()}
        calls_by_file = {fp: len(calls) for fp, calls in results['function_calls'].items()}
        
        return {
            'total_functions': total_functions,
            'total_files': total_files,
            'functions_by_file': functions_by_file,
            'memory_operations_by_file': memory_ops_by_file,
            'function_calls_by_file': calls_by_file,
            'average_functions_per_file': total_functions / total_files if total_files > 0 else 0
        }
    
    def get_function_by_name(self, function_name: str, results: Dict[str, Any]) -> Optional[FunctionInfo]:
        """Get function information by name."""
        return next((func_info for func_info in results['functions'].values() 
                    if func_info.name == function_name), None)
    
    def get_functions_in_file(self, file_path: str, results: Dict[str, Any]) -> List[FunctionInfo]:
        """Get all functions in a specific file."""
        return [func_info for func_info in results['functions'].values() 
                if func_info.file_path == file_path]
    
    def get_memory_operations_in_file(self, file_path: str, results: Dict[str, Any]) -> List[Any]:
        """Get all memory operations in a specific file."""
        return results.get('memory_operations', {}).get(file_path, [])
    
    def get_function_calls_in_file(self, file_path: str, results: Dict[str, Any]) -> List[Any]:
        """Get all function calls in a specific file."""
        return results.get('function_calls', {}).get(file_path, [])
    
    def get_symbols_in_file(self, file_path: str, results: Dict[str, Any]) -> Dict[str, List[Any]]:
        """Get all symbols in a specific file."""
        return results.get('symbols', {}).get(file_path, {})
    
    def clear_cache(self):
        """Clear the analysis cache."""
        self.analysis_cache.clear()
    
    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        return {
            'cached_files': len(self.analysis_cache),
            'total_functions': sum(len(results.get('functions', {})) 
                                 for results in self.analysis_cache.values()),
            'total_memory_operations': sum(len(results.get('memory_operations', [])) 
                                         for results in self.analysis_cache.values()),
            'total_function_calls': sum(len(results.get('function_calls', [])) 
                                      for results in self.analysis_cache.values())
        }
    
    def analyze_memory_safety(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze memory safety across all analyzed files."""
        memory_safety = {
            'use_after_free': [],
            'double_free': [],
            'memory_leaks': [],
            'buffer_overflows': []
        }
        
        for file_path in results['files_analyzed']:
            try:
                file_analysis = self.analyze_file(file_path)
                if file_path in file_analysis:
                    file_safety = self.cpp_analyzer.analyze_memory_safety()
                    
                    # Add file path to each issue
                    for issue_type, issues in file_safety.items():
                        for issue in issues:
                            issue['file_path'] = file_path
                            memory_safety[issue_type].append(issue)
                            
            except Exception as e:
                if self.logger:
                    self.logger.log(f"Error analyzing memory safety for {file_path}: {e}", level="ERROR")
        
        return memory_safety
    
    def export_analysis_results(self, results: Dict[str, Any], output_path: str):
        """Export analysis results to a file."""
        import json
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)
            
            if self.logger:
                self.logger.log(f"Analysis results exported to {output_path}")
                
        except Exception as e:
            if self.logger:
                self.logger.log(f"Error exporting results to {output_path}: {e}", level="ERROR")


class TreeSitterUtils(BaseTreeSitterAnalyzer):
    """Utility class for common tree-sitter operations."""
    
    def __init__(self, language_name: str = "c"):
        super().__init__(language_name)
    
    def extract_variable_from_assignment(self, node: tree_sitter.Node, source_code: str) -> Optional[AssignmentInfo]:
        """Extract variable information from assignment expression."""
        if node.type != "assignment_expression":
            return None
        
        # Find the assignment operator
        op_index = None
        for i, child in enumerate(node.children):
            if child.type == "=":
                op_index = i
                break
        
        if op_index is None or op_index < 1 or op_index >= len(node.children) - 1:
            return None
        
        lhs_node = node.children[op_index - 1]
        rhs_node = node.children[op_index + 1]
        
        lhs_name = self._extract_identifier_from_node(lhs_node, source_code)
        rhs_name = self._extract_identifier_from_node(rhs_node, source_code)
        
        if not lhs_name or not rhs_name:
            return None
        
        return AssignmentInfo(
            lhs=lhs_name,
            rhs=rhs_name,
            assignment_type='assignment',
            line_number=self.get_line_number(node, source_code),
            node=node
        )
    
    def extract_variable_from_init_declarator(self, node: tree_sitter.Node, source_code: str) -> Optional[AssignmentInfo]:
        """Extract variable information from init declarator."""
        if node.type != "init_declarator":
            return None
        
        # Find the assignment operator
        op_index = None
        for i, child in enumerate(node.children):
            if child.type == "=":
                op_index = i
                break
        
        if op_index is None or op_index < 1 or op_index >= len(node.children) - 1:
            return None
        
        declarator_node = node.children[op_index - 1]
        initializer_node = node.children[op_index + 1]
        
        lhs_name = self._extract_identifier_from_node(declarator_node, source_code)
        rhs_name = self._extract_identifier_from_node(initializer_node, source_code)
        
        if not lhs_name or not rhs_name:
            return None
        
        return AssignmentInfo(
            lhs=lhs_name,
            rhs=rhs_name,
            assignment_type='init_declarator',
            line_number=self.get_line_number(node, source_code),
            node=node
        )
    
    def extract_allocated_variable(self, node: tree_sitter.Node, source_code: str) -> Optional[VariableInfo]:
        """Extract variable from memory allocation (malloc, calloc, etc.)."""
        if node.type != "call_expression":
            return None
        
        func_name = self._get_called_function_name(node, source_code)
        if func_name not in {'malloc', 'calloc', 'realloc', 'strdup', 'new'}:
            return None
        
        # Find assignment target by looking up the AST
        current = node.parent
        while current:
            if current.type == "assignment_expression":
                lhs_node = current.children[0]  # First child should be the target
                var_name = self._extract_identifier_from_node(lhs_node, source_code)
                if var_name and self.is_valid_identifier(var_name):
                    return VariableInfo(
                        name=var_name,
                        type="allocated",
                        is_pointer=True,
                        line_number=self.get_line_number(node, source_code),
                        node=node
                    )
            elif current.type == "init_declarator":
                var_name = self._extract_identifier_from_node(current, source_code)
                if var_name and self.is_valid_identifier(var_name):
                    return VariableInfo(
                        name=var_name,
                        type="allocated",
                        is_pointer=True,
                        line_number=self.get_line_number(node, source_code),
                        node=node
                    )
            current = current.parent
        
        return None
    
    def extract_freed_variable(self, node: tree_sitter.Node, source_code: str) -> Optional[VariableInfo]:
        """Extract variable from memory deallocation (free, delete)."""
        if node.type != "call_expression":
            return None
        
        func_name = self._get_called_function_name(node, source_code)
        if func_name not in {'free', 'delete'}:
            return None
        
        # Find variable in arguments
        arg_list = self._find_child_by_type(node, "argument_list")
        if arg_list:
            for arg_child in arg_list.children:
                if arg_child.type == "identifier":
                    var_name = self.get_node_text(arg_child, source_code)
                    if var_name and self.is_valid_identifier(var_name):
                        return VariableInfo(
                            name=var_name,
                            type="freed",
                            line_number=self.get_line_number(node, source_code),
                            node=node
                        )
        
        return None
    
    def extract_null_assigned_variable(self, node: tree_sitter.Node, source_code: str) -> Optional[VariableInfo]:
        """Extract variable from NULL assignment."""
        if node.type != "assignment_expression":
            return None
        
        # Check if RHS is NULL or nullptr
        if len(node.children) < 3:
            return None
        
        op_index = None
        for i, child in enumerate(node.children):
            if child.type == "=":
                op_index = i
                break
        
        if op_index is None or op_index >= len(node.children) - 1:
            return None
        
        rhs_node = node.children[op_index + 1]
        rhs_text = self.get_node_text(rhs_node, source_code).strip()
        
        if rhs_text not in {'NULL', 'nullptr'}:
            return None
        
        lhs_node = node.children[op_index - 1]
        var_name = self._extract_identifier_from_node(lhs_node, source_code)
        
        if var_name and self.is_valid_identifier(var_name):
            return VariableInfo(
                name=var_name,
                type="null_assigned",
                line_number=self.get_line_number(node, source_code),
                node=node
            )
        
        return None
    
    def extract_used_variable(self, node: tree_sitter.Node, source_code: str, target_function: str = None) -> Optional[VariableInfo]:
        """Extract variable from function call or dereference."""
        if node.type == "call_expression":
            func_name = self._get_called_function_name(node, source_code)
            if target_function and func_name != target_function:
                return None
            
            # Find variable in arguments
            arg_list = self._find_child_by_type(node, "argument_list")
            if arg_list:
                for arg_child in arg_list.children:
                    if arg_child.type == "identifier":
                        var_name = self.get_node_text(arg_child, source_code)
                        if var_name and self.is_valid_identifier(var_name):
                            return VariableInfo(
                                name=var_name,
                                type="function_argument",
                                line_number=self.get_line_number(node, source_code),
                                node=node
                            )
        
        elif node.type == "pointer_expression" and target_function == "*":
            # For dereference operations like *ptr
            for child in node.children:
                if child.type == "identifier":
                    var_name = self.get_node_text(child, source_code)
                    if var_name and self.is_valid_identifier(var_name):
                        return VariableInfo(
                            name=var_name,
                            type="dereferenced",
                            is_pointer=True,
                            line_number=self.get_line_number(node, source_code),
                            node=node
                        )
        
        return None
    
    def find_all_assignments(self, tree: tree_sitter.Tree, source_code: str) -> List[AssignmentInfo]:
        """Find all assignment expressions in the AST."""
        assignments = []
        
        # Find assignment expressions
        for assign_node in self.find_nodes_by_type(tree.root_node, "assignment_expression"):
            assignment = self.extract_variable_from_assignment(assign_node, source_code)
            if assignment:
                assignments.append(assignment)
        
        # Find init declarators
        for init_node in self.find_nodes_by_type(tree.root_node, "init_declarator"):
            assignment = self.extract_variable_from_init_declarator(init_node, source_code)
            if assignment:
                assignments.append(assignment)
        
        return assignments
    
    def find_all_memory_operations(self, tree: tree_sitter.Tree, source_code: str) -> List[VariableInfo]:
        """Find all memory operations in the AST."""
        memory_ops = []
        
        # Find function calls
        for call_node in self.find_nodes_by_type(tree.root_node, "call_expression"):
            # Check for allocation
            allocated = self.extract_allocated_variable(call_node, source_code)
            if allocated:
                memory_ops.append(allocated)
            
            # Check for deallocation
            freed = self.extract_freed_variable(call_node, source_code)
            if freed:
                memory_ops.append(freed)
        
        # Find NULL assignments
        for assign_node in self.find_nodes_by_type(tree.root_node, "assignment_expression"):
            null_assigned = self.extract_null_assigned_variable(assign_node, source_code)
            if null_assigned:
                memory_ops.append(null_assigned)
        
        return memory_ops
    
    def find_all_variable_usage(self, tree: tree_sitter.Tree, source_code: str, target_functions: List[str] = None) -> List[VariableInfo]:
        """Find all variable usage in function calls."""
        usage = []
        
        if target_functions is None:
            target_functions = ['*']  # Default to dereference operations
        
        # Find function calls
        for call_node in self.find_nodes_by_type(tree.root_node, "call_expression"):
            for func in target_functions:
                used = self.extract_used_variable(call_node, source_code, func)
                if used:
                    usage.append(used)
        
        # Find dereference operations
        if '*' in target_functions:
            for deref_node in self.find_nodes_by_type(tree.root_node, "pointer_expression"):
                used = self.extract_used_variable(deref_node, source_code, '*')
                if used:
                    usage.append(used)
        
        return usage
