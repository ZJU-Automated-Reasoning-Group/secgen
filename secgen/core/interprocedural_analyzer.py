"""Interprocedural analysis for cross-function vulnerability detection."""

from typing import Dict, List, Set, Tuple, Optional, Any

from secgen.core.models import FunctionInfo, Vulnerability, VulnerabilityType, Severity, CodeLocation, PathStep, VulnerabilityPath
from secgen.core.function_summary import FunctionSummaryGenerator, FunctionSummary, ParameterEffect, TaintEffect
from secgen.ir import CallGraphBuilder, DataFlowGraphBuilder, TaintPath, DataFlowNode


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
        self.functions: Dict[str, FunctionInfo] = {}
        
        # IR builders
        self.call_graph_builder = CallGraphBuilder(logger)
        self.data_flow_builder = DataFlowGraphBuilder(logger)
        
        # Function summary generator for interprocedural analysis
        self.summary_generator = FunctionSummaryGenerator(model, logger)
        self.function_summaries: Dict[str, FunctionSummary] = {}
    

    
    def build_call_graph(self, functions: Dict[str, FunctionInfo]):
        """Build interprocedural call graph.
        
        Args:
            functions: Dictionary of function information
            
        Returns:
            NetworkX directed graph representing call relationships
        """
        self.functions = functions
        return self.call_graph_builder.build_call_graph(functions)
    
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
        return self.call_graph_builder.find_reachable_functions(start_function)
    
    def find_call_paths(self, source_func: str, target_func: str) -> List[List[str]]:
        """Find all call paths between two functions.
        
        Args:
            source_func: Source function identifier
            target_func: Target function identifier
            
        Returns:
            List of call paths (each path is a list of function identifiers)
        """
        return self.call_graph_builder.find_call_paths(source_func, target_func)
    
    def get_functions_calling(self, function_id: str) -> List[str]:
        """Get all functions that call a specific function.
        
        Args:
            function_id: Function identifier
            
        Returns:
            List of function identifiers that call this function
        """
        return self.call_graph_builder.get_functions_calling(function_id)
    
    def get_functions_called_by(self, function_id: str) -> List[str]:
        """Get all functions called by a specific function.
        
        Args:
            function_id: Function identifier
            
        Returns:
            List of function identifiers called by this function
        """
        return self.call_graph_builder.get_functions_called_by(function_id)
    
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
        call_paths = self.call_graph_builder.find_call_paths(source_func, sink_func)
        if not call_paths:
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
        return self.data_flow_builder.analyze_data_flow(file_content)
    

    
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
            dangerous_calls = set(caller_info.calls) & self.data_flow_builder.taint_sinks
            
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
        return self.call_graph_builder.analyze_reachability(entry_points, target_functions)
    
    def get_call_graph_metrics(self):
        """Get metrics about the call graph.
        
        Returns:
            IRMetrics object with call graph metrics
        """
        return self.call_graph_builder.get_call_graph_metrics()
    

