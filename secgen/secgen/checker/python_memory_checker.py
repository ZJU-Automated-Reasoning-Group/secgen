"""Python memory safety checker."""

import ast
from typing import Dict, List, Set, Any
from enum import Enum

from secgen.checker.base_checker import BaseChecker
from secgen.core.analyzer import Vulnerability, VulnerabilityType, Severity, CodeLocation


class PythonMemoryIssueType(Enum):
    CTYPES_UNSAFE = "ctypes_unsafe"
    RESOURCE_LEAK = "resource_leak"
    LARGE_OBJECT_CREATION = "large_object_creation"


class PythonMemoryChecker(BaseChecker):
    """Python specific memory safety checker."""
    
    def __init__(self, model=None, logger=None, interprocedural_analyzer=None):
        super().__init__(model, logger, interprocedural_analyzer)
        
        # Unsafe patterns
        self.unsafe_patterns = {
            'ctypes.pointer': 'ctypes_unsafe', 'ctypes.POINTER': 'ctypes_unsafe',
            'ctypes.cast': 'ctypes_unsafe', 'ctypes.addressof': 'ctypes_unsafe'
        }
        
        # Resource patterns
        self.resource_patterns = {
            'open': 'resource_leak', 'socket.socket': 'resource_leak',
            'threading.Thread': 'resource_leak', 'subprocess.Popen': 'resource_leak'
        }
        
        # Safe patterns
        self.safe_patterns = {'with', 'try', 'finally', 'close', '__enter__', '__exit__'}
    
    def supports_file_type(self, file_path: str) -> bool:
        return file_path.endswith('.py')
    
    def get_supported_extensions(self) -> Set[str]:
        return {'.py'}
    
    def analyze_file(self, file_path: str, content: str) -> List[Vulnerability]:
        if not self.supports_file_type(file_path):
            return []
        
        vulnerabilities = []
        
        try:
            tree = ast.parse(content)
            vulnerabilities.extend(self._detect_ctypes_issues(tree, file_path))
            vulnerabilities.extend(self._detect_resource_leaks(tree, file_path))
            vulnerabilities.extend(self._detect_large_object_creation(tree, file_path))
            
        except SyntaxError as e:
            if self.logger:
                self.logger.log(f"Syntax error in {file_path}: {e}", level="ERROR")
        
        return self._deduplicate_vulnerabilities(vulnerabilities)
    
    def _analyze_with_interprocedural_data(self, file_contents: Dict[str, str], 
                                         functions: Dict[str, Any],
                                         function_summaries: Dict[str, Any]) -> List[Vulnerability]:
        """Analyze Python memory safety using interprocedural context."""
        vulnerabilities = []
        
        if not self.interprocedural_analyzer:
            return super()._analyze_with_interprocedural_data(file_contents, functions, function_summaries)
        
        if self.logger:
            self.logger.log("Starting interprocedural Python memory analysis...")
        
        # Build call graph and function summaries
        self.interprocedural_analyzer.build_call_graph(functions)
        if not function_summaries:
            function_summaries = self.interprocedural_analyzer.build_function_summaries(functions, file_contents)
        
        # Analyze interprocedural memory patterns
        interprocedural_vulns = self._analyze_interprocedural_memory_patterns(
            file_contents, functions, function_summaries
        )
        vulnerabilities.extend(interprocedural_vulns)
        
        # Also run traditional file-level analysis to catch local patterns
        local_vulnerabilities = super()._analyze_with_interprocedural_data(file_contents, functions, function_summaries)
        vulnerabilities.extend(local_vulnerabilities)
        
        if self.logger:
            self.logger.log(f"Found {len(vulnerabilities)} total Python memory vulnerabilities ({len(interprocedural_vulns)} interprocedural)")
        
        return self._deduplicate_vulnerabilities(vulnerabilities)
    
    def _detect_ctypes_issues(self, tree: ast.AST, file_path: str) -> List[Vulnerability]:
        """Detect unsafe ctypes usage."""
        vulnerabilities = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_function_name(node)
                if any(pattern in func_name for pattern in self.unsafe_patterns):
                    line_num = getattr(node, 'lineno', 0)
                    vulnerabilities.append(Vulnerability(
                        vuln_type=VulnerabilityType.NULL_POINTER_DEREF,
                        severity=Severity.MEDIUM,
                        location=CodeLocation(file_path, line_num, line_num),
                        description=f"Use of ctypes {func_name} without proper validation",
                        evidence=f"Line {line_num}: {func_name}",
                        confidence=0.5,
                        recommendation="Validate ctypes pointers before dereferencing and handle potential exceptions"
                    ))
        
        return vulnerabilities
    
    def _detect_resource_leaks(self, tree: ast.AST, file_path: str) -> List[Vulnerability]:
        """Detect potential resource leaks."""
        vulnerabilities = []
        
        # Find with statements
        with_statements = {getattr(node, 'lineno', 0) for node in ast.walk(tree) if isinstance(node, ast.With)}
        
        # Find resource allocations
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_function_name(node)
                line_num = getattr(node, 'lineno', 0)
                
                if func_name in self.resource_patterns:
                    # Check if in with statement or has explicit close
                    in_with_statement = any(abs(line_num - with_line) <= 2 for with_line in with_statements)
                    has_close = self._has_explicit_close(tree, func_name)
                    
                    if not in_with_statement and not has_close:
                        vulnerabilities.append(Vulnerability(
                            vuln_type=VulnerabilityType.MEMORY_LEAK,
                            severity=Severity.LOW,
                            location=CodeLocation(file_path, line_num, line_num),
                            description=f"Potential resource leak: {func_name} without proper cleanup",
                            evidence=f"Line {line_num}: {func_name}",
                            confidence=0.6,
                            recommendation=f"Use 'with' statement or explicit close() for {func_name}"
                        ))
        
        return vulnerabilities
    
    def _detect_large_object_creation(self, tree: ast.AST, file_path: str) -> List[Vulnerability]:
        """Detect potentially problematic large object creation."""
        vulnerabilities = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_function_name(node)
                line_num = getattr(node, 'lineno', 0)
                
                if func_name in ['list', 'dict', 'set'] and node.args:
                    for arg in node.args:
                        if isinstance(arg, ast.Call):
                            arg_func = self._get_function_name(arg)
                            if arg_func == 'range' and arg.args:
                                if (isinstance(arg.args[-1], ast.Constant) and 
                                    isinstance(arg.args[-1].value, int) and 
                                    arg.args[-1].value > 1000000):
                                    
                                    vulnerabilities.append(Vulnerability(
                                        vuln_type=VulnerabilityType.MEMORY_LEAK,
                                        severity=Severity.LOW,
                                        location=CodeLocation(file_path, line_num, line_num),
                                        description=f"Large object creation: {func_name} with {arg.args[-1].value} elements",
                                        evidence=f"Line {line_num}: {func_name}(range({arg.args[-1].value}))",
                                        confidence=0.4,
                                        recommendation="Consider using generators or iterators for large datasets"
                                    ))
        
        return vulnerabilities
    
    def _get_function_name(self, call_node: ast.Call) -> str:
        """Extract function name from call node."""
        if isinstance(call_node.func, ast.Name):
            return call_node.func.id
        elif isinstance(call_node.func, ast.Attribute):
            if isinstance(call_node.func.value, ast.Name):
                return f"{call_node.func.value.id}.{call_node.func.attr}"
            return call_node.func.attr
        return ""
    
    def _has_explicit_close(self, tree: ast.AST, func_name: str) -> bool:
        """Check if there's an explicit close() call for the resource."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_func_name = self._get_function_name(node)
                if 'close' in call_func_name:
                    return True
        return False
    
    def _analyze_interprocedural_memory_patterns(self, file_contents: Dict[str, str], 
                                               functions: Dict[str, Any],
                                               function_summaries: Dict[str, Any]) -> List[Vulnerability]:
        """Analyze interprocedural memory patterns using function summaries."""
        vulnerabilities = []
        
        # Analyze resource leak patterns across function calls
        resource_leak_vulns = self._analyze_interprocedural_resource_leaks(
            file_contents, functions, function_summaries
        )
        vulnerabilities.extend(resource_leak_vulns)
        
        # Analyze unsafe ctypes usage patterns across function calls
        ctypes_vulns = self._analyze_interprocedural_ctypes_usage(
            file_contents, functions, function_summaries
        )
        vulnerabilities.extend(ctypes_vulns)
        
        return vulnerabilities
    
    def _analyze_interprocedural_resource_leaks(self, file_contents: Dict[str, str], 
                                              functions: Dict[str, Any],
                                              function_summaries: Dict[str, Any]) -> List[Vulnerability]:
        """Analyze resource leaks across function boundaries."""
        vulnerabilities = []
        
        # Find functions that allocate resources but don't clean them up
        for func_key, summary in function_summaries.items():
            func_info = functions.get(func_key)
            if not func_info:
                continue
            
            # Check if function allocates resources
            allocates_resources = any(
                effect.type in ['file_io', 'network_io', 'process_creation'] 
                for effect in summary.side_effects
            )
            
            if allocates_resources and not summary.cleanup_resources:
                # Find callers of this function
                callers = self._find_function_callers(func_key, functions)
                
                for caller_key in callers:
                    caller_info = functions.get(caller_key)
                    if caller_info:
                        vuln = Vulnerability(
                            vuln_type=VulnerabilityType.MEMORY_LEAK,
                            severity=Severity.MEDIUM,
                            location=CodeLocation(
                                caller_info.file_path, 
                                caller_info.start_line, 
                                caller_info.end_line
                            ),
                            description=f"Function '{caller_info.name}' calls resource-allocating function '{func_info.name}' without proper cleanup",
                            evidence=f"Call to {func_info.name} in {caller_info.name}",
                            confidence=0.7,
                            recommendation=f"Ensure proper cleanup of resources allocated by {func_info.name}"
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _analyze_interprocedural_ctypes_usage(self, file_contents: Dict[str, str], 
                                            functions: Dict[str, Any],
                                            function_summaries: Dict[str, Any]) -> List[Vulnerability]:
        """Analyze unsafe ctypes usage across function boundaries."""
        vulnerabilities = []
        
        # Find functions that use ctypes unsafely
        for func_key, summary in function_summaries.items():
            func_info = functions.get(func_key)
            if not func_info:
                continue
            
            # Check if function uses ctypes
            uses_ctypes = any(
                'ctypes' in effect.description.lower() 
                for effect in summary.side_effects
            )
            
            if uses_ctypes and not summary.validates_input:
                # Find all paths to this function from entry points
                entry_points = self._find_entry_points(functions)
                
                for entry_key in entry_points:
                    paths = self.interprocedural_analyzer.find_call_paths(entry_key, func_key)
                    
                    if paths:
                        # Create vulnerability for unsafe ctypes usage
                        vuln = Vulnerability(
                            vuln_type=VulnerabilityType.NULL_POINTER_DEREF,
                            severity=Severity.HIGH,
                            location=CodeLocation(
                                func_info.file_path, 
                                func_info.start_line, 
                                func_info.end_line
                            ),
                            description=f"Unsafe ctypes usage in function '{func_info.name}' reachable from entry point",
                            evidence=f"Function {func_info.name} uses ctypes without input validation",
                            confidence=0.6,
                            recommendation="Add input validation before ctypes operations and handle potential exceptions"
                        )
                        vulnerabilities.append(vuln)
                        break  # Only report once per function
        
        return vulnerabilities
    
    def _find_function_callers(self, func_key: str, functions: Dict[str, Any]) -> List[str]:
        """Find all functions that call the given function."""
        callers = []
        target_func = functions.get(func_key)
        if not target_func:
            return callers
        
        for caller_key, caller_info in functions.items():
            if target_func.name in caller_info.calls:
                callers.append(caller_key)
        
        return callers
    
    def _find_entry_points(self, functions: Dict[str, Any]) -> List[str]:
        """Find potential entry point functions."""
        entry_points = []
        
        for func_key, func_info in functions.items():
            # Consider main functions, test functions, and public API functions as entry points
            if (func_info.name in ['main', '__main__'] or 
                func_info.name.startswith('test_') or
                not func_info.name.startswith('_')):  # Public functions
                entry_points.append(func_key)
        
        return entry_points