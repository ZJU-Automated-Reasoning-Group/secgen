"""Interprocedural analysis for cross-function vulnerability detection."""

import networkx as nx
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict, deque

from secgen.core.analyzer import FunctionInfo, Vulnerability, VulnerabilityType, Severity, CodeLocation, PathStep, VulnerabilityPath
from secgen.core.function_summary import FunctionSummaryGenerator, FunctionSummary, ParameterEffect, TaintEffect


@dataclass 
class CallSite:
    """Represents a function call site."""
    caller: str
    callee: str
    file_path: str
    line_number: int
    arguments: List[str] = field(default_factory=list)
    context: str = ""


@dataclass
class DataFlowNode:
    """Node in data flow graph."""
    function: str
    variable: str
    line_number: int
    node_type: str  # 'source', 'sink', 'sanitizer', 'normal'
    taint_status: str = 'unknown'  # 'tainted', 'clean', 'unknown'


@dataclass
class TaintPath:
    """Path of tainted data flow."""
    source: DataFlowNode
    sink: DataFlowNode
    path: List[DataFlowNode]
    confidence: float
    vulnerability_type: VulnerabilityType


class InterproceduralAnalyzer:
    """Performs interprocedural analysis for vulnerability detection."""
    
    def __init__(self, model=None, logger=None):
        """Initialize interprocedural analyzer.
        
        Args:
            model: LLM model for intelligent analysis
            logger: Logger instance
        """
        self.model = model
        self.logger = logger
        self.call_graph = nx.DiGraph()
        self.functions: Dict[str, FunctionInfo] = {}
        self.call_sites: List[CallSite] = []
        self.data_flow_graph = nx.DiGraph()
        self.taint_sources: Set[str] = set()
        self.taint_sinks: Set[str] = set()
        self.sanitizers: Set[str] = set()
        
        # Function summary generator for interprocedural analysis
        self.summary_generator = FunctionSummaryGenerator(model, logger)
        self.function_summaries: Dict[str, FunctionSummary] = {}
        
        # Initialize known taint sources and sinks
        self._init_taint_patterns()
    
    def _init_taint_patterns(self):
        """Initialize known taint sources, sinks, and sanitizers."""
        # Common taint sources (user input)
        self.taint_sources.update([
            'input', 'raw_input', 'sys.argv', 'os.environ',
            'request.args', 'request.form', 'request.json',
            'scanf', 'gets', 'fgets', 'getenv',
            'System.getProperty', 'Scanner.nextLine'
        ])
        
        # Common taint sinks (dangerous operations)
        self.taint_sinks.update([
            'exec', 'eval', 'os.system', 'subprocess.call',
            'cursor.execute', 'connection.execute',
            'printf', 'sprintf', 'strcpy', 'strcat',
            'Runtime.exec', 'ProcessBuilder'
        ])
        
        # Common sanitizers
        self.sanitizers.update([
            'escape', 'quote', 'sanitize', 'validate',
            'html.escape', 'urllib.parse.quote',
            'parameterize', 'prepare'
        ])
    
    def build_call_graph(self, functions: Dict[str, FunctionInfo]) -> nx.DiGraph:
        """Build interprocedural call graph.
        
        Args:
            functions: Dictionary of function information
            
        Returns:
            NetworkX directed graph representing call relationships
        """
        self.functions = functions
        self.call_graph.clear()
        
        # Add all functions as nodes
        for func_id, func_info in functions.items():
            self.call_graph.add_node(func_id, info=func_info)
        
        # Add call edges
        for caller_id, caller_info in functions.items():
            for callee_name in caller_info.calls:
                # Find matching callee function
                for callee_id, callee_info in functions.items():
                    if callee_info.name == callee_name:
                        self.call_graph.add_edge(caller_id, callee_id)
                        
                        # Record call site
                        call_site = CallSite(
                            caller=caller_id,
                            callee=callee_id,
                            file_path=caller_info.file_path,
                            line_number=caller_info.start_line  # Simplified
                        )
                        self.call_sites.append(call_site)
        
        if self.logger:
            self.logger.log(f"Built call graph with {self.call_graph.number_of_nodes()} nodes and {self.call_graph.number_of_edges()} edges")
        
        return self.call_graph
    
    def build_function_summaries(self, functions: Dict[str, FunctionInfo], 
                                file_contents: Dict[str, str]) -> Dict[str, FunctionSummary]:
        """Build function summaries for interprocedural analysis.
        
        Args:
            functions: Dictionary of function information
            file_contents: Dictionary mapping file paths to content
            
        Returns:
            Dictionary of function summaries
        """
        if self.logger:
            self.logger.log("Building function summaries for interprocedural analysis...")
        
        self.function_summaries = self.summary_generator.compute_summary_for_call_graph(
            functions, file_contents
        )
        
        if self.logger:
            self.logger.log(f"Generated {len(self.function_summaries)} function summaries")
        
        return self.function_summaries
    
    def find_reachable_functions(self, start_function: str) -> Set[str]:
        """Find all functions reachable from a starting function.
        
        Args:
            start_function: Starting function identifier
            
        Returns:
            Set of reachable function identifiers
        """
        if start_function not in self.call_graph:
            return set()
        
        return set(nx.descendants(self.call_graph, start_function)) | {start_function}
    
    def find_call_paths(self, source_func: str, target_func: str) -> List[List[str]]:
        """Find all call paths between two functions.
        
        Args:
            source_func: Source function identifier
            target_func: Target function identifier
            
        Returns:
            List of call paths (each path is a list of function identifiers)
        """
        if source_func not in self.call_graph or target_func not in self.call_graph:
            return []
        
        try:
            paths = list(nx.all_simple_paths(self.call_graph, source_func, target_func))
            return paths
        except nx.NetworkXNoPath:
            return []
    
    def analyze_interprocedural_taint_flow(self) -> List[TaintPath]:
        """Analyze taint flow using function summaries (IDFS-style).
        
        Returns:
            List of interprocedural taint paths
        """
        taint_paths = []
        
        if not self.function_summaries:
            if self.logger:
                self.logger.log("No function summaries available for interprocedural taint analysis")
            return taint_paths
        
        # Find entry points (functions that introduce taint)
        taint_sources = self._find_taint_source_functions()
        
        # Find sinks (functions that use tainted data dangerously)
        taint_sinks = self._find_taint_sink_functions()
        
        # Trace taint flow through call graph
        for source_func in taint_sources:
            for sink_func in taint_sinks:
                paths = self._trace_taint_through_call_graph(source_func, sink_func)
                taint_paths.extend(paths)
        
        if self.logger:
            self.logger.log(f"Found {len(taint_paths)} interprocedural taint paths")
        
        return taint_paths
    
    def _find_taint_source_functions(self) -> List[str]:
        """Find functions that can introduce taint."""
        sources = []
        
        for func_key, summary in self.function_summaries.items():
            # Functions that read user input
            if any(effect.type == 'user_input' for effect in summary.side_effects):
                sources.append(func_key)
            
            # Functions that return tainted data
            if (summary.return_value and 
                hasattr(summary.return_value, 'taint_source') and 
                summary.return_value.taint_source):
                sources.append(func_key)
        
        return sources
    
    def _find_taint_sink_functions(self) -> List[str]:
        """Find functions that are dangerous sinks for tainted data."""
        sinks = []
        
        for func_key, summary in self.function_summaries.items():
            # Functions with dangerous side effects
            if summary.has_dangerous_side_effects():
                sinks.append(func_key)
            
            # Functions that are security sensitive
            if summary.security_sensitive:
                sinks.append(func_key)
            
            # Functions that don't validate input
            if not summary.validates_input and summary.security_sensitive:
                sinks.append(func_key)
        
        return sinks
    
    def _trace_taint_through_call_graph(self, source_func: str, sink_func: str) -> List[TaintPath]:
        """Trace taint flow from source to sink through call graph."""
        paths = []
        
        # Find all call paths from source to sink
        try:
            call_paths = list(nx.all_simple_paths(self.call_graph, source_func, sink_func, cutoff=10))
        except nx.NetworkXNoPath:
            return paths
        
        for call_path in call_paths:
            # Check if taint can flow through this path
            if self._can_taint_flow_through_path(call_path):
                # Create taint path with detailed path information
                detailed_path_steps = self._create_detailed_path_steps(call_path)
                taint_path = TaintPath(
                    source=DataFlowNode(
                        function=source_func,
                        variable="return",
                        line_number=0,
                        node_type='source'
                    ),
                    sink=DataFlowNode(
                        function=sink_func,
                        variable="parameter",
                        line_number=0,
                        node_type='sink'
                    ),
                    path=detailed_path_steps,
                    confidence=self._calculate_path_confidence(call_path),
                    vulnerability_type=self._determine_vulnerability_from_sink(sink_func)
                )
                paths.append(taint_path)
        
        return paths
    
    def _can_taint_flow_through_path(self, call_path: List[str]) -> bool:
        """Check if taint can flow through a call path."""
        
        for i in range(len(call_path) - 1):
            current_func = call_path[i]
            next_func = call_path[i + 1]
            
            # Check if current function can propagate taint to next function
            if not self._can_propagate_taint(current_func, next_func):
                return False
            
            # Check if there's a sanitizer in the path
            current_summary = self.function_summaries.get(current_func)
            if current_summary and current_summary.sanitizes_output:
                return False
        
        return True
    
    def _can_propagate_taint(self, caller_func: str, callee_func: str) -> bool:
        """Check if caller can propagate taint to callee."""
        
        caller_summary = self.function_summaries.get(caller_func)
        if not caller_summary:
            return True  # Conservative assumption
        
        # Check if caller preserves taint in return value or parameters
        for param in caller_summary.parameters:
            if param.taint_flow == TaintEffect.PRESERVES_TAINT:
                return True
        
        # Check if return value can be tainted
        if (caller_summary.return_value and 
            caller_summary.return_value.depends_on_params):
            return True
        
        return False
    
    def _calculate_path_confidence(self, call_path: List[str]) -> float:
        """Calculate confidence for a taint path."""
        confidence = 1.0
        
        for func_key in call_path:
            summary = self.function_summaries.get(func_key)
            if summary:
                confidence *= summary.analysis_confidence
        
        return confidence
    
    def _create_detailed_path_steps(self, call_path: List[str]) -> List[DataFlowNode]:
        """Create detailed path steps for interprocedural taint flow."""
        path_steps = []
        
        for i, func_key in enumerate(call_path):
            func_info = self.functions.get(func_key)
            if func_info:
                step = DataFlowNode(
                    function=func_info.name,
                    variable="",
                    line_number=func_info.start_line,
                    node_type='propagation' if 0 < i < len(call_path) - 1 else 'endpoint'
                )
                path_steps.append(step)
        
        return path_steps
    
    def _determine_vulnerability_from_sink(self, sink_func: str) -> VulnerabilityType:
        """Determine vulnerability type based on sink function."""
        
        summary = self.function_summaries.get(sink_func)
        if not summary:
            return VulnerabilityType.SQL_INJECTION  # Default
        
        # Check side effects to determine vulnerability type
        for effect in summary.side_effects:
            if effect.type == 'system_call':
                return VulnerabilityType.COMMAND_INJECTION
            elif effect.type == 'file_io':
                return VulnerabilityType.PATH_TRAVERSAL
            elif 'sql' in effect.description.lower():
                return VulnerabilityType.SQL_INJECTION
        
        return VulnerabilityType.COMMAND_INJECTION  # Default for dangerous sinks
    
    def analyze_data_flow(self, file_content: Dict[str, str]) -> List[TaintPath]:
        """Analyze data flow for taint propagation.
        
        Args:
            file_content: Dictionary mapping file paths to their content
            
        Returns:
            List of taint paths representing potential vulnerabilities
        """
        taint_paths = []
        
        # Build data flow graph
        self._build_data_flow_graph(file_content)
        
        # Find taint paths from sources to sinks
        for source_node in self.data_flow_graph.nodes():
            if self.data_flow_graph.nodes[source_node].get('type') == 'source':
                for sink_node in self.data_flow_graph.nodes():
                    if self.data_flow_graph.nodes[sink_node].get('type') == 'sink':
                        paths = self._find_taint_paths(source_node, sink_node)
                        taint_paths.extend(paths)
        
        return taint_paths
    
    def _build_data_flow_graph(self, file_content: Dict[str, str]):
        """Build data flow graph from source code."""
        self.data_flow_graph.clear()
        
        for file_path, content in file_content.items():
            lines = content.split('\n')
            
            for i, line in enumerate(lines, 1):
                # Identify taint sources
                for source in self.taint_sources:
                    if source in line:
                        node_id = f"{file_path}:{i}:source"
                        self.data_flow_graph.add_node(
                            node_id,
                            type='source',
                            line=i,
                            file=file_path,
                            content=line.strip()
                        )
                
                # Identify taint sinks
                for sink in self.taint_sinks:
                    if sink in line:
                        node_id = f"{file_path}:{i}:sink"
                        self.data_flow_graph.add_node(
                            node_id,
                            type='sink',
                            line=i,
                            file=file_path,
                            content=line.strip()
                        )
                
                # Identify sanitizers
                for sanitizer in self.sanitizers:
                    if sanitizer in line:
                        node_id = f"{file_path}:{i}:sanitizer"
                        self.data_flow_graph.add_node(
                            node_id,
                            type='sanitizer',
                            line=i,
                            file=file_path,
                            content=line.strip()
                        )
        
        # Add edges based on data dependencies (simplified)
        self._add_data_flow_edges(file_content)
    
    def _add_data_flow_edges(self, file_content: Dict[str, str]):
        """Add data flow edges between nodes."""
        # This is a simplified implementation
        # In practice, would need more sophisticated data flow analysis
        
        nodes = list(self.data_flow_graph.nodes(data=True))
        
        # Connect nodes in the same function if they involve the same variable
        for i, (node1, data1) in enumerate(nodes):
            for j, (node2, data2) in enumerate(nodes[i+1:], i+1):
                if (data1['file'] == data2['file'] and 
                    abs(data1['line'] - data2['line']) < 10):  # Within 10 lines
                    
                    # Simple heuristic: if lines contain common variables
                    if self._have_common_variables(data1['content'], data2['content']):
                        self.data_flow_graph.add_edge(node1, node2)
    
    def _have_common_variables(self, line1: str, line2: str) -> bool:
        """Check if two lines have common variables (simplified)."""
        import re
        
        # Extract variable names (simplified pattern)
        var_pattern = r'\b[a-zA-Z_][a-zA-Z0-9_]*\b'
        vars1 = set(re.findall(var_pattern, line1))
        vars2 = set(re.findall(var_pattern, line2))
        
        # Remove common keywords
        keywords = {'if', 'else', 'for', 'while', 'def', 'class', 'return', 'import'}
        vars1 -= keywords
        vars2 -= keywords
        
        return bool(vars1 & vars2)
    
    def _find_taint_paths(self, source: str, sink: str) -> List[TaintPath]:
        """Find taint paths from source to sink."""
        paths = []
        
        try:
            # Find all simple paths from source to sink
            simple_paths = list(nx.all_simple_paths(self.data_flow_graph, source, sink, cutoff=10))
            
            for path in simple_paths:
                # Check if path goes through sanitizer
                has_sanitizer = any(
                    self.data_flow_graph.nodes[node].get('type') == 'sanitizer'
                    for node in path[1:-1]  # Exclude source and sink
                )
                
                if not has_sanitizer:  # Only report unsanitized paths
                    source_data = self.data_flow_graph.nodes[source]
                    sink_data = self.data_flow_graph.nodes[sink]
                    
                    # Create data flow nodes
                    source_node = DataFlowNode(
                        function="",  # Would need function context
                        variable="",
                        line_number=source_data['line'],
                        node_type='source'
                    )
                    
                    sink_node = DataFlowNode(
                        function="",
                        variable="",
                        line_number=sink_data['line'],
                        node_type='sink'
                    )
                    
                    # Determine vulnerability type based on sink
                    vuln_type = self._determine_vulnerability_type(sink_data['content'])
                    
                    taint_path = TaintPath(
                        source=source_node,
                        sink=sink_node,
                        path=[],  # Would populate with intermediate nodes
                        confidence=0.8,  # Would calculate based on path analysis
                        vulnerability_type=vuln_type
                    )
                    
                    paths.append(taint_path)
        
        except nx.NetworkXNoPath:
            pass
        
        return paths
    
    def _determine_vulnerability_type(self, sink_content: str) -> VulnerabilityType:
        """Determine vulnerability type based on sink content."""
        content_lower = sink_content.lower()
        
        if any(term in content_lower for term in ['execute', 'query', 'sql']):
            return VulnerabilityType.SQL_INJECTION
        elif any(term in content_lower for term in ['system', 'exec', 'subprocess']):
            return VulnerabilityType.COMMAND_INJECTION
        elif any(term in content_lower for term in ['strcpy', 'sprintf', 'strcat']):
            return VulnerabilityType.BUFFER_OVERFLOW
        else:
            return VulnerabilityType.SQL_INJECTION  # Default
    
    def detect_interprocedural_vulnerabilities(self, file_content: Dict[str, str]) -> List[Vulnerability]:
        """Detect vulnerabilities using interprocedural analysis.
        
        Args:
            file_content: Dictionary mapping file paths to content
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        
        # Analyze data flow for taint propagation
        taint_paths = self.analyze_data_flow(file_content)
        
        for taint_path in taint_paths:
            # Convert taint path to vulnerability
            vuln = Vulnerability(
                vuln_type=taint_path.vulnerability_type,
                severity=Severity.HIGH,
                location=CodeLocation(
                    file_path="",  # Would get from taint path
                    line_start=taint_path.sink.line_number,
                    line_end=taint_path.sink.line_number
                ),
                description=f"Tainted data flows from {taint_path.source.node_type} to {taint_path.sink.node_type}",
                evidence=f"Path: {len(taint_path.path)} steps",
                confidence=taint_path.confidence,
                recommendation="Sanitize input before using in sensitive operations"
            )
            vulnerabilities.append(vuln)
        
        # Analyze call graph for other patterns
        call_graph_vulns = self._analyze_call_graph_patterns()
        vulnerabilities.extend(call_graph_vulns)
        
        return vulnerabilities
    
    def _analyze_call_graph_patterns(self) -> List[Vulnerability]:
        """Analyze call graph for vulnerability patterns."""
        vulnerabilities = []
        
        # Look for dangerous call patterns
        for caller_id, caller_info in self.functions.items():
            # Check for calls to dangerous functions
            dangerous_calls = set(caller_info.calls) & self.taint_sinks
            
            for dangerous_call in dangerous_calls:
                vuln = Vulnerability(
                    vuln_type=VulnerabilityType.COMMAND_INJECTION,  # Generic
                    severity=Severity.MEDIUM,
                    location=CodeLocation(
                        file_path=caller_info.file_path,
                        line_start=caller_info.start_line,
                        line_end=caller_info.end_line
                    ),
                    description=f"Function calls potentially dangerous operation: {dangerous_call}",
                    evidence=f"Call to {dangerous_call} in {caller_info.name}",
                    confidence=0.6,
                    recommendation="Validate inputs and use safer alternatives"
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def analyze_reachability(self, entry_points: List[str], target_functions: List[str]) -> Dict[str, List[str]]:
        """Analyze reachability from entry points to target functions.
        
        Args:
            entry_points: List of entry point function identifiers
            target_functions: List of target function identifiers
            
        Returns:
            Dictionary mapping target functions to reachable entry points
        """
        reachability = {}
        
        for target in target_functions:
            reachable_from = []
            
            for entry in entry_points:
                paths = self.find_call_paths(entry, target)
                if paths:
                    reachable_from.append(entry)
            
            reachability[target] = reachable_from
        
        return reachability
    
    def get_call_graph_metrics(self) -> Dict[str, Any]:
        """Get metrics about the call graph.
        
        Returns:
            Dictionary with call graph metrics
        """
        if not self.call_graph:
            return {}
        
        return {
            'num_functions': self.call_graph.number_of_nodes(),
            'num_calls': self.call_graph.number_of_edges(),
            'max_depth': self._calculate_max_depth(),
            'cyclic_dependencies': list(nx.simple_cycles(self.call_graph)),
            'strongly_connected_components': len(list(nx.strongly_connected_components(self.call_graph)))
        }
    
    def _calculate_max_depth(self) -> int:
        """Calculate maximum call depth in the call graph."""
        max_depth = 0
        
        # Find functions with no incoming edges (potential entry points)
        entry_points = [node for node in self.call_graph.nodes() 
                       if self.call_graph.in_degree(node) == 0]
        
        if not entry_points:
            # If no clear entry points, use all nodes
            entry_points = list(self.call_graph.nodes())
        
        for entry in entry_points:
            try:
                # Calculate longest path from this entry point
                lengths = nx.single_source_shortest_path_length(self.call_graph, entry)
                if lengths:
                    max_depth = max(max_depth, max(lengths.values()))
            except:
                continue
        
        return max_depth
