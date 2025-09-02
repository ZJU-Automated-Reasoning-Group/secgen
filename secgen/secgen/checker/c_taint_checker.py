"""C/C++ taint analysis checker."""

import re
from typing import Dict, List, Set, Any
from enum import Enum

from secgen.checker.base_checker import BaseChecker
from secgen.core.analyzer import Vulnerability, VulnerabilityType, Severity, CodeLocation, PathStep, VulnerabilityPath


class CTaintType(Enum):
    USER_INPUT = "user_input"
    FILE_INPUT = "file_input"
    NETWORK_INPUT = "network_input"
    ENVIRONMENT = "environment"
    COMMAND_LINE = "command_line"


class CSinkType(Enum):
    COMMAND_EXECUTION = "command_execution"
    BUFFER_OPERATION = "buffer_operation"
    FORMAT_STRING = "format_string"
    FILE_OPERATION = "file_operation"


class CTaintChecker(BaseChecker):
    """C/C++ specific taint analysis checker."""
    
    def __init__(self, model=None, logger=None, interprocedural_analyzer=None):
        super().__init__(model, logger, interprocedural_analyzer)
        
        # C/C++ taint sources
        self.sources = {
            'scanf': CTaintType.USER_INPUT, 'gets': CTaintType.USER_INPUT, 'getchar': CTaintType.USER_INPUT,
            'fgets': CTaintType.FILE_INPUT, 'getc': CTaintType.FILE_INPUT, 'fread': CTaintType.FILE_INPUT,
            'recv': CTaintType.NETWORK_INPUT, 'recvfrom': CTaintType.NETWORK_INPUT,
            'getenv': CTaintType.ENVIRONMENT, 'argv': CTaintType.COMMAND_LINE
        }
        
        # C/C++ taint sinks
        self.sinks = {
            'system': CSinkType.COMMAND_EXECUTION, 'popen': CSinkType.COMMAND_EXECUTION,
            'execl': CSinkType.COMMAND_EXECUTION, 'execv': CSinkType.COMMAND_EXECUTION,
            'strcpy': CSinkType.BUFFER_OPERATION, 'strcat': CSinkType.BUFFER_OPERATION,
            'sprintf': CSinkType.FORMAT_STRING, 'printf': CSinkType.FORMAT_STRING,
            'fprintf': CSinkType.FORMAT_STRING, 'fopen': CSinkType.FILE_OPERATION, 'open': CSinkType.FILE_OPERATION
        }
        
        # Sanitizers
        self.sanitizers = {'strncpy', 'strncat', 'snprintf', 'vsnprintf', 'escape', 'sanitize', 'validate', 'check'}
    
    def supports_file_type(self, file_path: str) -> bool:
        return file_path.endswith(('.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx'))
    
    def get_supported_extensions(self) -> Set[str]:
        return {'.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx'}
    
    def analyze_file(self, file_path: str, content: str) -> List[Vulnerability]:
        if not self.supports_file_type(file_path):
            return []
        
        vulnerabilities = []
        lines = content.split('\n')
        tainted_vars = {}  # variable -> (source_info, path_steps)
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith(('//','/*')):
                continue
            
            # Track taint sources
            for source, taint_type in self.sources.items():
                if source in line and '=' in line:
                    var_match = re.search(rf'(\w+)\s*=.*{re.escape(source)}', line)
                    if var_match:
                        var_name = var_match.group(1)
                        source_info = {'name': source, 'type': taint_type, 'line': i, 'variable': var_name}
                        tainted_vars[var_name] = (source_info, [])
            
            # Track variable assignments (taint propagation)
            assign_match = re.search(r'(\w+)\s*=\s*(\w+)', line)
            if assign_match and assign_match.group(2) in tainted_vars:
                target_var = assign_match.group(1)
                source_var = assign_match.group(2)
                source_info, path_steps = tainted_vars[source_var]
                
                new_path_steps = path_steps + [{
                    'file_path': file_path, 'line_number': i,
                    'description': f"Variable assignment: {target_var} = {source_var}",
                    'variable': target_var
                }]
                tainted_vars[target_var] = (source_info, new_path_steps)
            
            # Check for taint sinks
            for sink, sink_type in self.sinks.items():
                if sink in line:
                    for var_name, (source_info, path_steps) in tainted_vars.items():
                        if var_name in line and not any(sanitizer in line for sanitizer in self.sanitizers):
                            vuln = self._create_vulnerability(source_info, sink, sink_type, file_path, i, line, path_steps)
                            vulnerabilities.append(vuln)
        
        return self._deduplicate_vulnerabilities(vulnerabilities)
    
    def _analyze_with_interprocedural_data(self, file_contents: Dict[str, str], 
                                         functions: Dict[str, Any],
                                         function_summaries: Dict[str, Any]) -> List[Vulnerability]:
        """Analyze C/C++ taint flows using interprocedural context."""
        vulnerabilities = []
        
        if not self.interprocedural_analyzer:
            return super()._analyze_with_interprocedural_data(file_contents, functions, function_summaries)
        
        if self.logger:
            self.logger.log("Starting interprocedural C/C++ taint analysis...")
        
        # Build call graph and function summaries
        self.interprocedural_analyzer.build_call_graph(functions)
        if not function_summaries:
            function_summaries = self.interprocedural_analyzer.build_function_summaries(functions, file_contents)
        
        # Get interprocedural taint paths
        taint_paths = self.interprocedural_analyzer.analyze_interprocedural_taint_flow()
        
        # Convert taint paths to vulnerabilities
        for taint_path in taint_paths:
            vuln = self._create_vulnerability_from_taint_path(taint_path, file_contents)
            if vuln:
                vulnerabilities.append(vuln)
        
        # Also run traditional file-level analysis to catch local patterns
        local_vulnerabilities = super()._analyze_with_interprocedural_data(file_contents, functions, function_summaries)
        vulnerabilities.extend(local_vulnerabilities)
        
        if self.logger:
            self.logger.log(f"Found {len(vulnerabilities)} total C/C++ taint vulnerabilities ({len(taint_paths)} interprocedural)")
        
        return self._deduplicate_vulnerabilities(vulnerabilities)
    
    def _create_vulnerability(self, source_info, sink_name, sink_type, file_path, line_num, evidence, path_steps):
        """Create vulnerability from C taint flow."""
        vuln_type_map = {
            CSinkType.COMMAND_EXECUTION: VulnerabilityType.COMMAND_INJECTION,
            CSinkType.BUFFER_OPERATION: VulnerabilityType.BUFFER_OVERFLOW,
            CSinkType.FORMAT_STRING: VulnerabilityType.COMMAND_INJECTION,
            CSinkType.FILE_OPERATION: VulnerabilityType.PATH_TRAVERSAL
        }
        
        # Create path information
        source_step = PathStep(
            location=CodeLocation(file_path, source_info['line'], source_info['line']),
            description=f"Taint source: {source_info['name']} ({source_info['type'].value})",
            node_type='source', variable=source_info['variable'], function_name=None
        )
        
        sink_step = PathStep(
            location=CodeLocation(file_path, line_num, line_num),
            description=f"Taint sink: {sink_name} ({sink_type.value})",
            node_type='sink', variable=None, function_name=None
        )
        
        intermediate_steps = [
            PathStep(
                location=CodeLocation(step.get('file_path', file_path), step.get('line_number', line_num), step.get('line_number', line_num)),
                description=step.get('description', 'Data propagation'),
                node_type='propagation', variable=step.get('variable'), function_name=None
            ) for step in path_steps
        ]
        
        vuln_path = VulnerabilityPath(source=source_step, sink=sink_step, intermediate_steps=intermediate_steps, sanitizers=[])
        
        return Vulnerability(
            vuln_type=vuln_type_map.get(sink_type, VulnerabilityType.COMMAND_INJECTION),
            severity=Severity.HIGH,
            location=CodeLocation(file_path, line_num, line_num),
            description=f"C/C++ taint flow from {source_info['type'].value} to {sink_type.value}",
            evidence=evidence, confidence=0.8,
            recommendation=self._get_recommendation(sink_type),
            path=vuln_path
        )
    
    def _get_recommendation(self, sink_type):
        """Get recommendation for C taint flow."""
        recommendations = {
            CSinkType.COMMAND_EXECUTION: "Avoid system() and similar functions; use execv() with validated arguments",
            CSinkType.BUFFER_OPERATION: "Use safe string functions like strncpy, strncat, snprintf",
            CSinkType.FORMAT_STRING: "Use format string literals or validate format strings",
            CSinkType.FILE_OPERATION: "Validate file paths and use secure file operations"
        }
        return recommendations.get(sink_type, "Validate and sanitize input data")
    
    def _create_vulnerability_from_taint_path(self, taint_path, file_contents: Dict[str, str]):
        """Create vulnerability from interprocedural taint path."""
        from secgen.core.interprocedural_analyzer import TaintPath
        
        if not isinstance(taint_path, TaintPath):
            return None
        
        # Map interprocedural vulnerability types to our types
        vuln_type_map = {
            VulnerabilityType.SQL_INJECTION: VulnerabilityType.SQL_INJECTION,
            VulnerabilityType.COMMAND_INJECTION: VulnerabilityType.COMMAND_INJECTION,
            VulnerabilityType.BUFFER_OVERFLOW: VulnerabilityType.BUFFER_OVERFLOW,
            VulnerabilityType.PATH_TRAVERSAL: VulnerabilityType.PATH_TRAVERSAL,
        }
        
        # Get file path from sink location
        sink_file = None
        sink_line = taint_path.sink.line_number
        
        # Try to determine file from path steps
        for step in taint_path.path:
            if hasattr(step, 'location') and hasattr(step.location, 'file_path'):
                sink_file = step.location.file_path
                break
        
        # Fallback: use first C/C++ file
        if not sink_file:
            for file_path in file_contents.keys():
                if file_path.endswith(('.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx')):
                    sink_file = file_path
                    break
        
        if not sink_file:
            return None
        
        # Create detailed path steps
        path_steps = []
        
        # Source step
        source_step = PathStep(
            location=CodeLocation(sink_file, taint_path.source.line_number, taint_path.source.line_number),
            description=f"Interprocedural taint source in function '{taint_path.source.function}': {taint_path.source.variable}",
            node_type='source',
            variable=taint_path.source.variable,
            function_name=taint_path.source.function
        )
        
        # Intermediate steps
        intermediate_steps = []
        for i, step in enumerate(taint_path.path):
            step_desc = f"Taint propagation through function '{step.function}'"
            if step.variable:
                step_desc += f" via variable '{step.variable}'"
            
            intermediate_steps.append(PathStep(
                location=CodeLocation(sink_file, step.line_number, step.line_number),
                description=step_desc,
                node_type='propagation',
                variable=step.variable,
                function_name=step.function
            ))
        
        # Sink step
        sink_step = PathStep(
            location=CodeLocation(sink_file, sink_line, sink_line),
            description=f"Interprocedural taint sink in function '{taint_path.sink.function}': {taint_path.sink.variable}",
            node_type='sink',
            variable=taint_path.sink.variable,
            function_name=taint_path.sink.function
        )
        
        vuln_path = VulnerabilityPath(
            source=source_step,
            sink=sink_step,
            intermediate_steps=intermediate_steps,
            sanitizers=[]
        )
        
        # Determine severity based on vulnerability type
        severity_map = {
            VulnerabilityType.SQL_INJECTION: Severity.HIGH,
            VulnerabilityType.COMMAND_INJECTION: Severity.CRITICAL,
            VulnerabilityType.BUFFER_OVERFLOW: Severity.CRITICAL,
            VulnerabilityType.PATH_TRAVERSAL: Severity.HIGH,
        }
        
        vuln_type = vuln_type_map.get(taint_path.vulnerability_type, VulnerabilityType.COMMAND_INJECTION)
        severity = severity_map.get(vuln_type, Severity.HIGH)
        
        return Vulnerability(
            vuln_type=vuln_type,
            severity=severity,
            location=CodeLocation(sink_file, sink_line, sink_line),
            description=f"Interprocedural C/C++ taint flow: {taint_path.vulnerability_type.value}",
            evidence=f"Taint flows from {taint_path.source.function}:{taint_path.source.variable} to {taint_path.sink.function}:{taint_path.sink.variable}",
            confidence=taint_path.confidence,
            recommendation=self._get_interprocedural_recommendation(vuln_type),
            path=vuln_path
        )
    
    def _get_interprocedural_recommendation(self, vuln_type: VulnerabilityType) -> str:
        """Get recommendation for interprocedural vulnerabilities."""
        recommendations = {
            VulnerabilityType.SQL_INJECTION: "Use parameterized queries and validate input at function boundaries",
            VulnerabilityType.COMMAND_INJECTION: "Avoid system() calls and sanitize input before passing to exec functions",
            VulnerabilityType.BUFFER_OVERFLOW: "Use safe string functions and validate buffer sizes at function interfaces",
            VulnerabilityType.PATH_TRAVERSAL: "Validate file paths at entry points and use secure file operations",
        }
        return recommendations.get(vuln_type, "Validate and sanitize input at function boundaries")