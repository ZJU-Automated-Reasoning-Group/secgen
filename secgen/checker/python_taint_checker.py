"""Python taint analysis checker."""

import ast
from typing import Dict, List, Set, Any

from secgen.checker.base_checker import BaseChecker
from secgen.core.models import Vulnerability, VulnerabilityType, Severity, CodeLocation, PathStep, VulnerabilityPath


class PythonTaintChecker(BaseChecker):
    """Python specific taint analysis checker."""
    
    def __init__(self, model=None, logger=None, interprocedural_analyzer=None):
        super().__init__(model, logger, interprocedural_analyzer)
        
        # Consolidated taint sources and sinks with vulnerability mapping
        self.taint_config = {
            # Sources: (taint_type, vuln_type, severity)
            'input': ('user_input', VulnerabilityType.COMMAND_INJECTION, Severity.HIGH),
            'raw_input': ('user_input', VulnerabilityType.COMMAND_INJECTION, Severity.HIGH),
            'sys.stdin.read': ('user_input', VulnerabilityType.COMMAND_INJECTION, Severity.HIGH),
            'sys.stdin.readline': ('user_input', VulnerabilityType.COMMAND_INJECTION, Severity.HIGH),
            'request.args': ('user_input', VulnerabilityType.XSS, Severity.MEDIUM),
            'request.form': ('user_input', VulnerabilityType.XSS, Severity.MEDIUM),
            'request.json': ('user_input', VulnerabilityType.XSS, Severity.MEDIUM),
            'request.data': ('user_input', VulnerabilityType.XSS, Severity.MEDIUM),
            'request.files': ('user_input', VulnerabilityType.PATH_TRAVERSAL, Severity.HIGH),
            'request.cookies': ('user_input', VulnerabilityType.XSS, Severity.MEDIUM),
            'request.headers': ('user_input', VulnerabilityType.XSS, Severity.MEDIUM),
            'os.environ': ('environment', VulnerabilityType.COMMAND_INJECTION, Severity.HIGH),
            'os.getenv': ('environment', VulnerabilityType.COMMAND_INJECTION, Severity.HIGH),
            'sys.argv': ('command_line', VulnerabilityType.COMMAND_INJECTION, Severity.HIGH),
            'open': ('file_input', VulnerabilityType.PATH_TRAVERSAL, Severity.HIGH),
            'file.read': ('file_input', VulnerabilityType.PATH_TRAVERSAL, Severity.HIGH),
            'file.readline': ('file_input', VulnerabilityType.PATH_TRAVERSAL, Severity.HIGH),
            'socket.recv': ('network_input', VulnerabilityType.COMMAND_INJECTION, Severity.HIGH),
            'urllib.request.urlopen': ('network_input', VulnerabilityType.COMMAND_INJECTION, Severity.HIGH),
            'requests.get': ('network_input', VulnerabilityType.COMMAND_INJECTION, Severity.HIGH),
            'requests.post': ('network_input', VulnerabilityType.COMMAND_INJECTION, Severity.HIGH),
            
            # Sinks: (sink_type, vuln_type, severity)
            'os.system': ('command_execution', VulnerabilityType.COMMAND_INJECTION, Severity.CRITICAL),
            'os.popen': ('command_execution', VulnerabilityType.COMMAND_INJECTION, Severity.CRITICAL),
            'subprocess.call': ('command_execution', VulnerabilityType.COMMAND_INJECTION, Severity.CRITICAL),
            'subprocess.run': ('command_execution', VulnerabilityType.COMMAND_INJECTION, Severity.CRITICAL),
            'subprocess.Popen': ('command_execution', VulnerabilityType.COMMAND_INJECTION, Severity.CRITICAL),
            'exec': ('eval_execution', VulnerabilityType.COMMAND_INJECTION, Severity.CRITICAL),
            'eval': ('eval_execution', VulnerabilityType.COMMAND_INJECTION, Severity.CRITICAL),
            'compile': ('eval_execution', VulnerabilityType.COMMAND_INJECTION, Severity.CRITICAL),
            'cursor.execute': ('sql_execution', VulnerabilityType.SQL_INJECTION, Severity.HIGH),
            'cursor.executemany': ('sql_execution', VulnerabilityType.SQL_INJECTION, Severity.HIGH),
            'connection.execute': ('sql_execution', VulnerabilityType.SQL_INJECTION, Severity.HIGH),
            'file.write': ('file_write', VulnerabilityType.PATH_TRAVERSAL, Severity.HIGH),
            'render_template': ('template_render', VulnerabilityType.XSS, Severity.MEDIUM),
            'Template.render': ('template_render', VulnerabilityType.XSS, Severity.MEDIUM),
            'logging.info': ('log_output', VulnerabilityType.SQL_INJECTION, Severity.LOW),
            'logging.debug': ('log_output', VulnerabilityType.SQL_INJECTION, Severity.LOW),
            'print': ('log_output', VulnerabilityType.SQL_INJECTION, Severity.LOW)
        }
        
        # Sanitizers
        self.sanitizers = {
            'html.escape', 'cgi.escape', 'bleach.clean', 'quote', 'escape', 
            'parameterize', 'shlex.quote', 'pipes.quote', 'urllib.parse.quote', 
            'urllib.parse.quote_plus', 'validate', 'sanitize', 'clean'
        }
    
    def supports_file_type(self, file_path: str) -> bool:
        return file_path.endswith('.py')
    
    def get_supported_extensions(self) -> Set[str]:
        return {'.py'}
    
    def analyze_file(self, file_path: str, content: str) -> List[Vulnerability]:
        if not self.supports_file_type(file_path):
            return []
        
        try:
            tree = ast.parse(content)
            return self._deduplicate_vulnerabilities([
                self._create_vulnerability(flow, file_path) 
                for flow in self._track_taint_flow(tree, file_path)
            ])
        except SyntaxError as e:
            if self.logger:
                self.logger.log(f"Syntax error in {file_path}: {e}", level="ERROR")
            return []
    
    def _analyze_with_interprocedural_data(self, file_contents: Dict[str, str], 
                                         functions: Dict[str, Any],
                                         function_summaries: Dict[str, Any]) -> List[Vulnerability]:
        """Analyze Python taint flows using interprocedural context."""
        if not self.interprocedural_analyzer:
            return super()._analyze_with_interprocedural_data(file_contents, functions, function_summaries)
        
        if self.logger:
            self.logger.log("Starting interprocedural Python taint analysis...")
        
        # Build call graph and function summaries
        self.interprocedural_analyzer.build_call_graph(functions)
        if not function_summaries:
            function_summaries = self.interprocedural_analyzer.build_function_summaries(functions, file_contents)
        
        # Get interprocedural taint paths and convert to vulnerabilities
        taint_paths = self.interprocedural_analyzer.analyze_interprocedural_taint_flow()
        interprocedural_vulns = [v for v in [self._create_vulnerability_from_taint_path(p, file_contents) for p in taint_paths] if v]
        
        # Combine with local analysis
        local_vulns = super()._analyze_with_interprocedural_data(file_contents, functions, function_summaries)
        vulnerabilities = interprocedural_vulns + local_vulns
        
        if self.logger:
            self.logger.log(f"Found {len(vulnerabilities)} total Python taint vulnerabilities ({len(taint_paths)} interprocedural)")
        
        return self._deduplicate_vulnerabilities(vulnerabilities)
    
    def _track_taint_flow(self, tree: ast.AST, file_path: str) -> List[Dict]:
        """Track taint flow in Python AST."""
        flows, tainted_vars = [], {}
        
        for node in sorted(ast.walk(tree), key=lambda n: getattr(n, 'lineno', 0)):
            line_num = getattr(node, 'lineno', 0)
            
            # Track taint sources
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                func_name = self._get_function_name(node.value)
                if func_name in self.taint_config:
                    taint_type, vuln_type, severity = self.taint_config[func_name]
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            tainted_vars[target.id] = {
                                'source': {'name': func_name, 'type': taint_type, 'line': line_num, 'variable': target.id},
                                'path': []
                            }
            
            # Track taint propagation
            elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Name):
                if node.value.id in tainted_vars:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            tainted_vars[target.id] = {
                                'source': tainted_vars[node.value.id]['source'],
                                'path': tainted_vars[node.value.id]['path'] + [{
                                    'file_path': file_path, 'line_number': line_num,
                                    'description': f"Variable assignment: {target.id} = {node.value.id}",
                                    'variable': target.id
                                }]
                            }
            
            # Check taint sinks
            elif isinstance(node, ast.Call):
                func_name = self._get_function_name(node)
                if func_name in self.taint_config:
                    sink_type, vuln_type, severity = self.taint_config[func_name]
                    for arg in node.args:
                        if isinstance(arg, ast.Name) and arg.id in tainted_vars and not self._is_sanitized(node):
                            flows.append({
                                'source': tainted_vars[arg.id]['source'],
                                'sink': {'name': func_name, 'type': sink_type, 'line': line_num},
                                'path': tainted_vars[arg.id]['path']
                            })
        
        return flows
    
    def _get_function_name(self, call_node: ast.Call) -> str:
        """Extract function name from call node."""
        if isinstance(call_node.func, ast.Name):
            return call_node.func.id
        elif isinstance(call_node.func, ast.Attribute):
            if isinstance(call_node.func.value, ast.Name):
                return f"{call_node.func.value.id}.{call_node.func.attr}"
            return call_node.func.attr
        return ""
    
    def _is_sanitized(self, call_node: ast.Call) -> bool:
        """Check if the function call involves sanitization."""
        return any(
            isinstance(arg, ast.Call) and self._get_function_name(arg) in self.sanitizers
            for arg in call_node.args
        )
    
    def _create_vulnerability(self, flow, file_path):
        """Create vulnerability from Python taint flow."""
        source_info, sink_info = flow['source'], flow['sink']
        
        # Get vulnerability info from config
        _, vuln_type, severity = self.taint_config.get(sink_info['name'], 
                                                      ('unknown', VulnerabilityType.COMMAND_INJECTION, Severity.MEDIUM))
        
        # Create path steps
        source_step = PathStep(
            location=CodeLocation(file_path, source_info['line'], source_info['line']),
            description=f"Taint source: {source_info['name']} ({source_info['type']})",
            node_type='source', variable=source_info['variable'], function_name=None
        )
        
        sink_step = PathStep(
            location=CodeLocation(file_path, sink_info['line'], sink_info['line']),
            description=f"Taint sink: {sink_info['name']} ({sink_info['type']})",
            node_type='sink', variable=None, function_name=None
        )
        
        intermediate_steps = [
            PathStep(
                location=CodeLocation(step.get('file_path', file_path), step.get('line_number', 0), step.get('line_number', 0)),
                description=step.get('description', 'Data propagation'),
                node_type='propagation', variable=step.get('variable'), function_name=None
            ) for step in flow['path']
        ]
        
        return Vulnerability(
            vuln_type=vuln_type,
            severity=severity,
            location=CodeLocation(file_path, sink_info['line'], sink_info['line']),
            description=f"Taint flow from {source_info['type']} to {sink_info['type']}",
            evidence=f"Source: {source_info['name']}, Sink: {sink_info['name']}",
            confidence=0.8,
            recommendation=self._get_recommendation(vuln_type),
            path=VulnerabilityPath(source=source_step, sink=sink_step, intermediate_steps=intermediate_steps, sanitizers=[])
        )
    
    def _get_recommendation(self, vuln_type):
        """Get recommendation for vulnerability type."""
        recommendations = {
            VulnerabilityType.SQL_INJECTION: "Use parameterized queries or prepared statements",
            VulnerabilityType.COMMAND_INJECTION: "Validate input and use subprocess with shell=False",
            VulnerabilityType.XSS: "Use auto-escaping templates or manually escape output",
            VulnerabilityType.PATH_TRAVERSAL: "Validate file paths and use allowlist of permitted locations"
        }
        return recommendations.get(vuln_type, "Validate and sanitize input data")
    
    def _create_vulnerability_from_taint_path(self, taint_path, file_contents: Dict[str, str]):
        """Create vulnerability from interprocedural taint path."""
        from secgen.core.interprocedural_analyzer import TaintPath
        
        if not isinstance(taint_path, TaintPath):
            return None
        
        # Get file path from path steps or fallback to first Python file
        sink_file = next((step.location.file_path for step in taint_path.path 
                         if hasattr(step, 'location') and hasattr(step.location, 'file_path')), None)
        if not sink_file:
            sink_file = next((f for f in file_contents.keys() if f.endswith('.py')), None)
        if not sink_file:
            return None
        
        # Create path steps
        source_step = PathStep(
            location=CodeLocation(sink_file, taint_path.source.line_number, taint_path.source.line_number),
            description=f"Interprocedural taint source in '{taint_path.source.function}': {taint_path.source.variable}",
            node_type='source', variable=taint_path.source.variable, function_name=taint_path.source.function
        )
        
        intermediate_steps = [
            PathStep(
                location=CodeLocation(sink_file, step.line_number, step.line_number),
                description=f"Taint propagation through '{step.function}'" + (f" via '{step.variable}'" if step.variable else ""),
                node_type='propagation', variable=step.variable, function_name=step.function
            ) for step in taint_path.path
        ]
        
        sink_step = PathStep(
            location=CodeLocation(sink_file, taint_path.sink.line_number, taint_path.sink.line_number),
            description=f"Interprocedural taint sink in '{taint_path.sink.function}': {taint_path.sink.variable}",
            node_type='sink', variable=taint_path.sink.variable, function_name=taint_path.sink.function
        )
        
        # Determine severity
        severity_map = {
            VulnerabilityType.SQL_INJECTION: Severity.HIGH,
            VulnerabilityType.COMMAND_INJECTION: Severity.CRITICAL,
            VulnerabilityType.XSS: Severity.MEDIUM,
            VulnerabilityType.PATH_TRAVERSAL: Severity.HIGH,
        }
        
        vuln_type = taint_path.vulnerability_type
        severity = severity_map.get(vuln_type, Severity.MEDIUM)
        
        return Vulnerability(
            vuln_type=vuln_type,
            severity=severity,
            location=CodeLocation(sink_file, taint_path.sink.line_number, taint_path.sink.line_number),
            description=f"Interprocedural taint flow: {vuln_type.value}",
            evidence=f"Taint flows from {taint_path.source.function}:{taint_path.source.variable} to {taint_path.sink.function}:{taint_path.sink.variable}",
            confidence=taint_path.confidence,
            recommendation=self._get_recommendation(vuln_type),
            path=VulnerabilityPath(source=source_step, sink=sink_step, intermediate_steps=intermediate_steps, sanitizers=[])
        )
    
