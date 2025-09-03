"""Enhanced file analyzer using tree-sitter for improved code parsing."""

import os
import ast
from pathlib import Path
from typing import Dict, List, Optional, Set, Any

from secgen.core.models import FunctionInfo
from secgen.tsanalyzer.symbol_analyzer import CppSymbolAnalyzer


class FileAnalyzer:
    """Enhanced file analyzer using tree-sitter for improved code parsing."""
    
    def __init__(self, logger=None):
        """Initialize enhanced file analyzer.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger
        self.cpp_analyzer = CppSymbolAnalyzer()
        self.analysis_cache: Dict[str, Dict[str, Any]] = {}
        
        # File extensions supported by different analyzers
        self.cpp_extensions = {'.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx'}
        self.python_extensions = {'.py', '.pyw'}
        self.java_extensions = {'.java'}
        self.javascript_extensions = {'.js', '.ts', '.jsx', '.tsx'}
        
    def analyze_directory(self, directory: str, extensions: List[str] = None) -> Dict[str, Any]:
        """Analyze all files in a directory using enhanced tree-sitter analysis.
        
        Args:
            directory: Path to directory to analyze
            extensions: File extensions to analyze (default: all supported)
            
        Returns:
            Analysis results dictionary with enhanced function information
        """
        if extensions is None:
            extensions = list(self.cpp_extensions | self.python_extensions | 
                            self.java_extensions | self.javascript_extensions)
            
        results = {
            'files_analyzed': [],
            'functions': {},
            'symbols': {},
            'memory_operations': {},
            'function_calls': {},
            'statistics': {}
        }
        
        # Find all relevant files
        files_to_analyze = []
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if any(file.endswith(ext) for ext in extensions):
                    files_to_analyze.append(file_path)
        
        if self.logger:
            self.logger.log(f"Found {len(files_to_analyze)} files to analyze")
        
        # Analyze each file
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
                if self.logger:
                    self.logger.log(f"Error analyzing {file_path}: {e}", level="ERROR")
        
        # Calculate statistics
        results['statistics'] = self._calculate_statistics(results)
        
        if self.logger:
            self.logger.log(f"Analysis complete. Found {len(results['functions'])} functions across {len(results['files_analyzed'])} files")
        
        return results
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze a single file using enhanced tree-sitter analysis.
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            Analysis results dictionary
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            if self.logger:
                self.logger.log(f"Error reading file {file_path}: {e}", level="ERROR")
            return {}
        
        # Check cache first
        if file_path in self.analysis_cache:
            return self.analysis_cache[file_path]
        
        # Determine file type and use appropriate analyzer
        file_ext = Path(file_path).suffix.lower()
        
        if file_ext in self.cpp_extensions:
            return self._analyze_cpp_file(file_path, content)
        elif file_ext in self.python_extensions:
            return self._analyze_python_file(file_path, content)
        elif file_ext in self.java_extensions:
            return self._analyze_java_file(file_path, content)
        elif file_ext in self.javascript_extensions:
            return self._analyze_javascript_file(file_path, content)
        else:
            return self._analyze_generic_file(file_path, content)
    
    def _analyze_cpp_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Analyze C/C++ file using enhanced tree-sitter analysis."""
        try:
            # Use enhanced C++ analyzer
            analysis_results = self.cpp_analyzer.analyze_file(content, file_path)
            
            # Convert to standard format
            results = {
                'functions': {},
                'symbol_table': analysis_results.get('symbol_table', {}),
                'memory_operations': analysis_results.get('memory_operations', []),
                'function_calls': analysis_results.get('function_calls', []),
                'file_path': file_path
            }
            
            # Convert function info to standard format
            functions = analysis_results.get('functions', [])
            for func in functions:
                func_key = f"{file_path}:{func.name}"
                results['functions'][func_key] = FunctionInfo(
                    name=func.name,
                    file_path=file_path,
                    start_line=func.start_line,
                    end_line=func.end_line,
                    parameters=func.parameters
                )
            
            # Cache results
            self.analysis_cache[file_path] = results
            
            return results
            
        except Exception as e:
            if self.logger:
                self.logger.log(f"Error analyzing C/C++ file {file_path}: {e}", level="ERROR")
            return {}
    
    def _analyze_python_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Analyze Python file using AST parsing."""
        results = {'functions': {}}
        
        try:
            tree = ast.parse(content)
            
            # Extract functions
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
                            if isinstance(child.func, ast.Name):
                                func_info.calls.append(child.func.id)
                            elif isinstance(child.func, ast.Attribute):
                                func_info.calls.append(child.func.attr)
                    
                    results['functions'][f"{file_path}:{node.name}"] = func_info
                    
        except SyntaxError as e:
            if self.logger:
                self.logger.log(f"Syntax error in {file_path}: {e}", level="ERROR")
        
        return results
    
    def _analyze_java_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Analyze Java file (simplified implementation)."""
        # This would need a Java-specific tree-sitter analyzer
        # For now, return basic results
        return {'functions': {}}
    
    def _analyze_javascript_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Analyze JavaScript/TypeScript file (simplified implementation)."""
        # This would need a JavaScript/TypeScript-specific tree-sitter analyzer
        # For now, return basic results
        return {'functions': {}}
    
    def _analyze_generic_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Generic file analysis for unsupported languages."""
        return {'functions': {}}
    
    def _calculate_statistics(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate analysis statistics."""
        total_functions = len(results['functions'])
        total_files = len(results['files_analyzed'])
        
        # Count functions by file
        functions_by_file = {}
        for func_key, func_info in results['functions'].items():
            file_path = func_info.file_path
            if file_path not in functions_by_file:
                functions_by_file[file_path] = 0
            functions_by_file[file_path] += 1
        
        # Count memory operations by file
        memory_ops_by_file = {}
        for file_path, operations in results['memory_operations'].items():
            memory_ops_by_file[file_path] = len(operations)
        
        # Count function calls by file
        calls_by_file = {}
        for file_path, calls in results['function_calls'].items():
            calls_by_file[file_path] = len(calls)
        
        return {
            'total_functions': total_functions,
            'total_files': total_files,
            'functions_by_file': functions_by_file,
            'memory_operations_by_file': memory_ops_by_file,
            'function_calls_by_file': calls_by_file,
            'average_functions_per_file': total_functions / total_files if total_files > 0 else 0
        }
    
    def get_function_by_name(self, function_name: str, results: Dict[str, Any]) -> Optional[FunctionInfo]:
        """Get function information by name from analysis results."""
        for func_key, func_info in results['functions'].items():
            if func_info.name == function_name:
                return func_info
        return None
    
    def get_functions_in_file(self, file_path: str, results: Dict[str, Any]) -> List[FunctionInfo]:
        """Get all functions in a specific file."""
        functions = []
        for func_key, func_info in results['functions'].items():
            if func_info.file_path == file_path:
                functions.append(func_info)
        return functions
    
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