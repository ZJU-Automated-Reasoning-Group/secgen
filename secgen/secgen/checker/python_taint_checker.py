"""Python taint analysis checker."""

import ast
from typing import Dict, List, Set, Any
from enum import Enum

from secgen.checker.base_checker import BaseChecker
from secgen.core.analyzer import Vulnerability, VulnerabilityType, Severity, CodeLocation, PathStep, VulnerabilityPath


class PythonTaintType(Enum):
    USER_INPUT = "user_input"
    FILE_INPUT = "file_input"
    NETWORK_INPUT = "network_input"
    DATABASE_INPUT = "database_input"
    ENVIRONMENT = "environment"
    COMMAND_LINE = "command_line"


class PythonSinkType(Enum):
    SQL_EXECUTION = "sql_execution"
    COMMAND_EXECUTION = "command_execution"
    FILE_WRITE = "file_write"
    NETWORK_SEND = "network_send"
    EVAL_EXECUTION = "eval_execution"
    TEMPLATE_RENDER = "template_render"
    LOG_OUTPUT = "log_output"


class PythonTaintChecker(BaseChecker):
    """Python specific taint analysis checker."""
    
    def __init__(self, model=None, logger=None, interprocedural_analyzer=None):
        super().__init__(model, logger, interprocedural_analyzer)
        
        # Python taint sources
        self.sources = {
            # User input
            'input': PythonTaintType.USER_INPUT, 'raw_input': PythonTaintType.USER_INPUT,
            'sys.stdin.read': PythonTaintType.USER_INPUT, 'sys.stdin.readline': PythonTaintType.USER_INPUT,
            # Web input
            'request.args': PythonTaintType.USER_INPUT, 'request.form': PythonTaintType.USER_INPUT,
            'request.json': PythonTaintType.USER_INPUT, 'request.data': PythonTaintType.USER_INPUT,
            'request.files': PythonTaintType.USER_INPUT, 'request.cookies': PythonTaintType.USER_INPUT,
            'request.headers': PythonTaintType.USER_INPUT,
            # Environment
            'os.environ': PythonTaintType.ENVIRONMENT, 'os.getenv': PythonTaintType.ENVIRONMENT,
            'sys.argv': PythonTaintType.COMMAND_LINE,
            # File input
            'open': PythonTaintType.FILE_INPUT, 'file.read': PythonTaintType.FILE_INPUT, 'file.readline': PythonTaintType.FILE_INPUT,
            # Network input
            'socket.recv': PythonTaintType.NETWORK_INPUT, 'urllib.request.urlopen': PythonTaintType.NETWORK_INPUT,
            'requests.get': PythonTaintType.NETWORK_INPUT, 'requests.post': PythonTaintType.NETWORK_INPUT
        }
        
        # Python taint sinks
        self.sinks = {
            # Command execution
            'os.system': PythonSinkType.COMMAND_EXECUTION, 'os.popen': PythonSinkType.COMMAND_EXECUTION,
            'subprocess.call': PythonSinkType.COMMAND_EXECUTION, 'subprocess.run': PythonSinkType.COMMAND_EXECUTION,
            'subprocess.Popen': PythonSinkType.COMMAND_EXECUTION,
            # Code execution
            'exec': PythonSinkType.EVAL_EXECUTION, 'eval': PythonSinkType.EVAL_EXECUTION, 'compile': PythonSinkType.EVAL_EXECUTION,
            # SQL execution
            'cursor.execute': PythonSinkType.SQL_EXECUTION, 'cursor.executemany': PythonSinkType.SQL_EXECUTION,
            'connection.execute': PythonSinkType.SQL_EXECUTION,
            # File operations
            'file.write': PythonSinkType.FILE_WRITE,
            # Template rendering
            'render_template': PythonSinkType.TEMPLATE_RENDER, 'Template.render': PythonSinkType.TEMPLATE_RENDER,
            # Logging
            'logging.info': PythonSinkType.LOG_OUTPUT, 'logging.debug': PythonSinkType.LOG_OUTPUT, 'print': PythonSinkType.LOG_OUTPUT
        }
        
        # Sanitizers
        self.sanitizers = {
            'html.escape': 'html', 'cgi.escape': 'html', 'bleach.clean': 'html',
            'quote': 'sql', 'escape': 'sql', 'parameterize': 'sql',
            'shlex.quote': 'shell', 'pipes.quote': 'shell',
            'urllib.parse.quote': 'url', 'urllib.parse.quote_plus': 'url',
            'validate': 'general', 'sanitize': 'general', 'clean': 'general'
        }
    
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
            taint_flows = self._track_taint_flow(tree, file_path)
            
            for flow in taint_flows:
                vuln = self._create_vulnerability(flow, file_path)
                vulnerabilities.append(vuln)
                
        except SyntaxError as e:
            if self.logger:
                self.logger.log(f"Syntax error in {file_path}: {e}", level="ERROR")
        
        return self._deduplicate_vulnerabilities(vulnerabilities)
    
    def _analyze_with_interprocedural_data(self, file_contents: Dict[str, str], 
                                         functions: Dict[str, Any],
                                         function_summaries: Dict[str, Any]) -> List[Vulnerability]:
        """Analyze Python taint flows using interprocedural context."""
        vulnerabilities = []
        
        if not self.interprocedural_analyzer:
            return super()._analyze_with_interprocedural_data(file_contents, functions, function_summaries)
        
        if self.logger:
            self.logger.log("Starting interprocedural Python taint analysis...")
        
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
            self.logger.log(f"Found {len(vulnerabilities)} total Python taint vulnerabilities ({len(taint_paths)} interprocedural)")
        
        return self._deduplicate_vulnerabilities(vulnerabilities)
    
    def _track_taint_flow(self, tree: ast.AST, file_path: str):
        """Track taint flow in Python AST."""
        flows = []
        tainted_vars = {}  # variable -> (source_info, path_steps)
        
        # Collect nodes sorted by line number
        nodes = [(node, getattr(node, 'lineno', 0)) for node in ast.walk(tree)]
        nodes.sort(key=lambda x: x[1])
        
        for node, line_num in nodes:
            # Track variable assignments from taint sources
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                func_name = self._get_function_name(node.value)
                if func_name in self.sources:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            source_info = {
                                'name': func_name, 'type': self.sources[func_name],
                                'line': line_num, 'variable': target.id
                            }
                            tainted_vars[target.id] = (source_info, [])
            
            # Track variable-to-variable assignments (taint propagation)
            elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Name):
                if node.value.id in tainted_vars:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            source_info, path_steps = tainted_vars[node.value.id]
                            new_path_steps = path_steps + [{
                                'file_path': file_path, 'line_number': line_num,
                                'description': f"Variable assignment: {target.id} = {node.value.id}",
                                'variable': target.id
                            }]
                            tainted_vars[target.id] = (source_info, new_path_steps)
            
            # Check for taint sinks
            elif isinstance(node, ast.Call):
                func_name = self._get_function_name(node)
                if func_name in self.sinks:
                    for i, arg in enumerate(node.args):
                        if isinstance(arg, ast.Name) and arg.id in tainted_vars:
                            source_info, path_steps = tainted_vars[arg.id]
                            
                            # Check if sanitized
                            if not self._is_sanitized(node):
                                flows.append({
                                    'source': source_info,
                                    'sink': {'name': func_name, 'type': self.sinks[func_name], 'line': line_num},
                                    'path': path_steps
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
        for arg in call_node.args:
            if isinstance(arg, ast.Call):
                arg_func_name = self._get_function_name(arg)
                if arg_func_name in self.sanitizers:
                    return True
        return False
    
    def _create_vulnerability(self, flow, file_path):
        """Create vulnerability from Python taint flow."""
        vuln_type_map = {
            PythonSinkType.SQL_EXECUTION: VulnerabilityType.SQL_INJECTION,
            PythonSinkType.COMMAND_EXECUTION: VulnerabilityType.COMMAND_INJECTION,
            PythonSinkType.EVAL_EXECUTION: VulnerabilityType.COMMAND_INJECTION,
            PythonSinkType.TEMPLATE_RENDER: VulnerabilityType.XSS,
            PythonSinkType.FILE_WRITE: VulnerabilityType.PATH_TRAVERSAL,
            PythonSinkType.NETWORK_SEND: VulnerabilityType.SQL_INJECTION,
            PythonSinkType.LOG_OUTPUT: VulnerabilityType.SQL_INJECTION
        }
        
        source_info = flow['source']
        sink_info = flow['sink']
        
        # Create path information
        source_step = PathStep(
            location=CodeLocation(file_path, source_info['line'], source_info['line']),
            description=f"Python taint source: {source_info['name']} ({source_info['type'].value})",
            node_type='source', variable=source_info['variable'], function_name=None
        )
        
        sink_step = PathStep(
            location=CodeLocation(file_path, sink_info['line'], sink_info['line']),
            description=f"Python taint sink: {sink_info['name']} ({sink_info['type'].value})",
            node_type='sink', variable=None, function_name=None
        )
        
        intermediate_steps = [
            PathStep(
                location=CodeLocation(step.get('file_path', file_path), step.get('line_number', 0), step.get('line_number', 0)),
                description=step.get('description', 'Data propagation'),
                node_type='propagation', variable=step.get('variable'), function_name=None
            ) for step in flow['path']
        ]
        
        vuln_path = VulnerabilityPath(source=source_step, sink=sink_step, intermediate_steps=intermediate_steps, sanitizers=[])
        
        sink_type = sink_info['type']
        severity = Severity.LOW if sink_type == PythonSinkType.LOG_OUTPUT else Severity.HIGH
        
        return Vulnerability(
            vuln_type=vuln_type_map.get(sink_type, VulnerabilityType.COMMAND_INJECTION),
            severity=severity,
            location=CodeLocation(file_path, sink_info['line'], sink_info['line']),
            description=f"Python taint flow from {source_info['type'].value} to {sink_type.value}",
            evidence=f"Source: {source_info['name']}, Sink: {sink_info['name']}",
            confidence=0.8,
            recommendation=self._get_recommendation(sink_type),
            path=vuln_path
        )
    
    def _get_recommendation(self, sink_type):
        """Get recommendation for Python taint flow."""
        recommendations = {
            PythonSinkType.SQL_EXECUTION: "Use parameterized queries or prepared statements",
            PythonSinkType.COMMAND_EXECUTION: "Validate input and use subprocess with shell=False",
            PythonSinkType.EVAL_EXECUTION: "Avoid eval/exec with user input; use safer alternatives",
            PythonSinkType.TEMPLATE_RENDER: "Use auto-escaping templates or manually escape output",
            PythonSinkType.FILE_WRITE: "Validate file paths and use allowlist of permitted locations",
            PythonSinkType.NETWORK_SEND: "Validate and sanitize data before transmission",
            PythonSinkType.LOG_OUTPUT: "Sanitize sensitive data before logging"
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
            VulnerabilityType.XSS: VulnerabilityType.XSS,
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
        
        # Fallback: use first Python file
        if not sink_file:
            for file_path in file_contents.keys():
                if file_path.endswith('.py'):
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
            VulnerabilityType.XSS: Severity.MEDIUM,
            VulnerabilityType.PATH_TRAVERSAL: Severity.HIGH,
        }
        
        vuln_type = vuln_type_map.get(taint_path.vulnerability_type, VulnerabilityType.COMMAND_INJECTION)
        severity = severity_map.get(vuln_type, Severity.MEDIUM)
        
        return Vulnerability(
            vuln_type=vuln_type,
            severity=severity,
            location=CodeLocation(sink_file, sink_line, sink_line),
            description=f"Interprocedural Python taint flow: {taint_path.vulnerability_type.value}",
            evidence=f"Taint flows from {taint_path.source.function}:{taint_path.source.variable} to {taint_path.sink.function}:{taint_path.sink.variable}",
            confidence=taint_path.confidence,
            recommendation=self._get_interprocedural_recommendation(vuln_type),
            path=vuln_path
        )
    
    def _get_interprocedural_recommendation(self, vuln_type: VulnerabilityType) -> str:
        """Get recommendation for interprocedural vulnerabilities."""
        recommendations = {
            VulnerabilityType.SQL_INJECTION: "Use parameterized queries and validate input at function boundaries",
            VulnerabilityType.COMMAND_INJECTION: "Sanitize input before passing to system functions across function calls",
            VulnerabilityType.XSS: "Escape output and validate input at all function interfaces",
            VulnerabilityType.PATH_TRAVERSAL: "Validate file paths at entry points and sanitize before file operations",
        }
        return recommendations.get(vuln_type, "Validate and sanitize input at function boundaries")