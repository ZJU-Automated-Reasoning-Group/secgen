"""Taint analysis vulnerability detector."""

import re
from typing import Dict, List, Optional, Any
from enum import Enum

from .base_detector import BaseVulnerabilityDetector, DetectionContext
from secgen.core.models import Vulnerability, VulnerabilityType, Severity, CodeLocation, PathStep, VulnerabilityPath


class TaintType(Enum):
    USER_INPUT = "user_input"
    FILE_INPUT = "file_input"
    NETWORK_INPUT = "network_input"
    ENVIRONMENT = "environment"
    COMMAND_LINE = "command_line"


class SinkType(Enum):
    COMMAND_EXECUTION = "command_execution"
    BUFFER_OPERATION = "buffer_operation"
    FORMAT_STRING = "format_string"
    FILE_OPERATION = "file_operation"
    SQL_EXECUTION = "sql_execution"
    TEMPLATE_RENDER = "template_render"


class TaintDetector(BaseVulnerabilityDetector):
    """Detector for Taint Analysis vulnerabilities."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, logger=None):
        super().__init__(config, logger)
        
        # Load configuration
        self.sources = {}
        self.sinks = {}
        self.sanitizers = set()
        
        if config:
            # Load sources
            sources_config = config.get('sources', {})
            for source_name, source_info in sources_config.items():
                taint_type_str = source_info.get('type', 'user_input')
                taint_type_map = {
                    'user_input': TaintType.USER_INPUT,
                    'file_input': TaintType.FILE_INPUT,
                    'network_input': TaintType.NETWORK_INPUT,
                    'environment': TaintType.ENVIRONMENT,
                    'command_line': TaintType.COMMAND_LINE
                }
                self.sources[source_name] = taint_type_map.get(taint_type_str, TaintType.USER_INPUT)
            
            # Load sinks
            sinks_config = config.get('sinks', {})
            for sink_name, sink_info in sinks_config.items():
                sink_type_str = sink_info.get('type', 'command_execution')
                sink_type_map = {
                    'command_execution': SinkType.COMMAND_EXECUTION,
                    'buffer_operation': SinkType.BUFFER_OPERATION,
                    'format_string': SinkType.FORMAT_STRING,
                    'file_operation': SinkType.FILE_OPERATION,
                    'sql_execution': SinkType.SQL_EXECUTION,
                    'template_render': SinkType.TEMPLATE_RENDER
                }
                self.sinks[sink_name] = sink_type_map.get(sink_type_str, SinkType.COMMAND_EXECUTION)
            
            # Load sanitizers
            self.sanitizers = set(config.get('sanitizers', []))
    
    def get_vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.COMMAND_INJECTION  # Default, can be overridden based on sink type
    
    def supports_file_type(self, file_path: str) -> bool:
        return file_path.endswith(('.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx', '.py'))
    
    def get_supported_extensions(self) -> List[str]:
        return ['.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx', '.py']
    
    def detect(self, context: DetectionContext) -> List[Vulnerability]:
        """Detect Taint Analysis vulnerabilities."""
        vulnerabilities = []
        tainted_vars = {}  # variable -> (source_info, path_steps)
        
        for i, line in enumerate(context.lines, 1):
            line = line.strip()
            if not line or line.startswith(('//', '/*')):
                continue
            
            # Track taint sources
            for source, taint_type in self.sources.items():
                if source in line and '=' in line:
                    var_match = re.search(rf'(\w+)\s*=.*{re.escape(source)}', line)
                    if var_match:
                        var_name = var_match.group(1)
                        source_info = {
                            'name': source, 
                            'type': taint_type, 
                            'line': i, 
                            'variable': var_name
                        }
                        tainted_vars[var_name] = (source_info, [])
            
            # Track variable assignments (taint propagation)
            assign_match = re.search(r'(\w+)\s*=\s*(\w+)', line)
            if assign_match and assign_match.group(2) in tainted_vars:
                target_var = assign_match.group(1)
                source_var = assign_match.group(2)
                source_info, path_steps = tainted_vars[source_var]
                
                new_path_steps = path_steps + [{
                    'file_path': context.file_path, 
                    'line_number': i,
                    'description': f"Variable assignment: {target_var} = {source_var}",
                    'variable': target_var
                }]
                tainted_vars[target_var] = (source_info, new_path_steps)
            
            # Check for taint sinks
            for sink, sink_type in self.sinks.items():
                if sink in line:
                    for var_name, (source_info, path_steps) in tainted_vars.items():
                        if var_name in line and not any(sanitizer in line for sanitizer in self.sanitizers):
                            vuln = self._create_taint_vulnerability(
                                source_info, sink, sink_type, context.file_path, i, line, path_steps
                            )
                            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _create_taint_vulnerability(self, source_info, sink_name, sink_type, 
                                  file_path, line_num, evidence, path_steps):
        """Create vulnerability from taint flow."""
        vuln_type_map = {
            SinkType.COMMAND_EXECUTION: VulnerabilityType.COMMAND_INJECTION,
            SinkType.BUFFER_OPERATION: VulnerabilityType.BUFFER_OVERFLOW,
            SinkType.FORMAT_STRING: VulnerabilityType.COMMAND_INJECTION,
            SinkType.FILE_OPERATION: VulnerabilityType.PATH_TRAVERSAL,
            SinkType.SQL_EXECUTION: VulnerabilityType.SQL_INJECTION,
            SinkType.TEMPLATE_RENDER: VulnerabilityType.XSS
        }
        
        vuln_type = vuln_type_map.get(sink_type, VulnerabilityType.COMMAND_INJECTION)
        
        # Create path information
        source_step = PathStep(
            location=CodeLocation(file_path, source_info['line'], source_info['line']),
            description=f"Taint source: {source_info['name']} ({source_info['type'].value})",
            node_type='source', 
            variable=source_info['variable'], 
            function_name=None
        )
        
        sink_step = PathStep(
            location=CodeLocation(file_path, line_num, line_num),
            description=f"Taint sink: {sink_name} ({sink_type.value})",
            node_type='sink', 
            variable=None, 
            function_name=None
        )
        
        intermediate_steps = [
            PathStep(
                location=CodeLocation(step.get('file_path', file_path), step.get('line_number', line_num), step.get('line_number', line_num)),
                description=step.get('description', 'Data propagation'),
                node_type='propagation', 
                variable=step.get('variable'), 
                function_name=None
            ) for step in path_steps
        ]
        
        vuln_path = VulnerabilityPath(
            source=source_step, 
            sink=sink_step, 
            intermediate_steps=intermediate_steps, 
            sanitizers=[]
        )
        
        return self.create_vulnerability(
            location=CodeLocation(file_path, line_num, line_num),
            description=f"Taint flow from {source_info['type'].value} to {sink_type.value}",
            evidence=evidence,
            severity=self._get_severity_for_sink_type(sink_type),
            confidence=0.8,
            cwe_id=self._get_cwe_for_sink_type(sink_type),
            recommendation=self._get_recommendation_for_sink_type(sink_type),
            path=vuln_path
        )
    
    def _get_severity_for_sink_type(self, sink_type: SinkType) -> Severity:
        """Get severity based on sink type."""
        severity_map = {
            SinkType.COMMAND_EXECUTION: Severity.CRITICAL,
            SinkType.BUFFER_OPERATION: Severity.HIGH,
            SinkType.FORMAT_STRING: Severity.HIGH,
            SinkType.FILE_OPERATION: Severity.HIGH,
            SinkType.SQL_EXECUTION: Severity.HIGH,
            SinkType.TEMPLATE_RENDER: Severity.MEDIUM
        }
        return severity_map.get(sink_type, Severity.HIGH)
    
    def _get_cwe_for_sink_type(self, sink_type: SinkType) -> str:
        """Get CWE ID based on sink type."""
        cwe_map = {
            SinkType.COMMAND_EXECUTION: "CWE-78",
            SinkType.BUFFER_OPERATION: "CWE-120",
            SinkType.FORMAT_STRING: "CWE-134",
            SinkType.FILE_OPERATION: "CWE-22",
            SinkType.SQL_EXECUTION: "CWE-89",
            SinkType.TEMPLATE_RENDER: "CWE-79"
        }
        return cwe_map.get(sink_type, "CWE-000")
    
    def _get_recommendation_for_sink_type(self, sink_type: SinkType) -> str:
        """Get recommendation based on sink type."""
        recommendations = {
            SinkType.COMMAND_EXECUTION: "Avoid system() and similar functions; use execv() with validated arguments",
            SinkType.BUFFER_OPERATION: "Use safe string functions like strncpy, strncat, snprintf",
            SinkType.FORMAT_STRING: "Use format string literals or validate format strings",
            SinkType.FILE_OPERATION: "Validate file paths and use secure file operations",
            SinkType.SQL_EXECUTION: "Use parameterized queries or prepared statements",
            SinkType.TEMPLATE_RENDER: "Use auto-escaping templates or manually escape output"
        }
        return recommendations.get(sink_type, "Validate and sanitize input data")
