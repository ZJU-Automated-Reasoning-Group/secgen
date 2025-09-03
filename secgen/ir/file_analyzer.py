"""File analyzer for extracting function information from source code."""

import ast
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Any

from secgen.core.models import FunctionInfo


class FileAnalyzer:
    """Analyzes source files to extract function information."""
    
    def __init__(self, logger=None):
        """Initialize file analyzer.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger
        
    def analyze_directory(self, directory: str, extensions: List[str] = None) -> Dict[str, Any]:
        """Analyze all files in a directory.
        
        Args:
            directory: Path to directory to analyze
            extensions: File extensions to analyze (default: ['.py', '.c', '.cpp', '.h'])
            
        Returns:
            Analysis results dictionary with functions
        """
        if extensions is None:
            extensions = ['.py', '.c', '.cpp', '.h', '.java', '.js', '.ts']
            
        results = {
            'files_analyzed': [],
            'functions': {},
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
                results['files_analyzed'].append(file_path)
                
                # Merge results
                if 'functions' in file_results:
                    results['functions'].update(file_results['functions'])
                    
            except Exception as e:
                if self.logger:
                    self.logger.log(f"Error analyzing {file_path}: {e}", level="ERROR")
        
        # Generate statistics
        results['statistics'] = self._generate_statistics(results)
        
        return results
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze a single source file.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Analysis results for the file
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            if self.logger:
                self.logger.log(f"Error reading {file_path}: {e}", level="ERROR")
            return {}
        
        file_ext = Path(file_path).suffix.lower()
        
        if file_ext == '.py':
            return self._analyze_python_file(file_path, content)
        elif file_ext in ['.c', '.cpp', '.h', '.hpp']:
            return self._analyze_c_file(file_path, content)
        elif file_ext in ['.java']:
            return self._analyze_java_file(file_path, content)
        elif file_ext in ['.js', '.ts']:
            return self._analyze_javascript_file(file_path, content)
        else:
            return self._analyze_generic_file(file_path, content)
    
    def _analyze_python_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Analyze Python source file."""
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
    
    def _analyze_c_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Analyze C/C++ source file."""
        results = {'functions': {}}
        
        # Basic pattern matching for C functions (simplified)
        func_pattern = r'(?:^|\n)(?:static\s+|inline\s+)?(?:\w+\s+)*(\w+)\s*\([^)]*\)\s*\{'
        matches = re.finditer(func_pattern, content, re.MULTILINE)
        
        for match in matches:
            func_name = match.group(1)
            start_line = content[:match.start()].count('\n') + 1
            
            # Find end of function (simplified)
            brace_count = 0
            end_pos = match.end()
            for i, char in enumerate(content[match.end():], match.end()):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_pos = i
                        break
            
            end_line = content[:end_pos].count('\n') + 1
            
            func_info = FunctionInfo(
                name=func_name,
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                parameters=[]  # Would need more sophisticated parsing
            )
            
            results['functions'][f"{file_path}:{func_name}"] = func_info
        
        return results
    
    def _analyze_java_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Analyze Java source file."""
        # Simplified Java analysis
        return self._analyze_generic_file(file_path, content)
    
    def _analyze_javascript_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Analyze JavaScript/TypeScript file."""
        # Simplified JS analysis
        return self._analyze_generic_file(file_path, content)
    
    def _analyze_generic_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Generic file analysis for unsupported languages."""
        return {'functions': {}}
    
    def _generate_statistics(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate analysis statistics."""
        stats = {
            'total_files': len(results['files_analyzed']),
            'total_functions': len(results['functions']),
            'total_function_calls': sum(len(func_info.calls) for func_info in results['functions'].values())
        }
        
        return stats
