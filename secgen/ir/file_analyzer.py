"""File analyzer using tree-sitter for code parsing."""

import os
import ast
import json
from pathlib import Path
from typing import Dict, List, Optional, Any

from secgen.core.models import FunctionInfo
from secgen.tsanalyzer.symbol_analyzer import CppSymbolAnalyzer


class FileAnalyzer:
    """File analyzer using tree-sitter for code parsing."""
    
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
                'symbol_table': analysis_results.get('symbol_table', {}),
                'memory_operations': analysis_results.get('memory_operations', []),
                'function_calls': analysis_results.get('function_calls', []),
                'file_path': file_path
            }
            
            # Convert function info to standard format
            for func in analysis_results.get('functions', []):
                func_key = f"{file_path}:{func.name}"
                results['functions'][func_key] = FunctionInfo(
                    name=func.name,
                    file_path=file_path,
                    start_line=func.start_line,
                    end_line=func.end_line,
                    parameters=func.parameters
                )
            
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