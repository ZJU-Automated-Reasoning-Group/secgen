"""Interprocedural analyzer integrating all new components.

This module provides the main interprocedural analyzer that integrates
lightweight alias analysis, function summaries, hybrid taint propagation,
and specialized LLM tools.
"""

from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field

from .summary import FunctionSummary
from .alias_analyzer import LightweightAliasAnalyzer
from .hybrid_taint_analyzer import HybridTaintAnalyzer, TaintPath, TaintPropagationResult
from .llm_tools import LLMToolsManager, TaintAnalysisInput, PathAnalysisInput
from .models import FunctionInfo, Vulnerability, VulnerabilityType, Severity, CodeLocation
from secgen.ir import CallGraphBuilder, DataFlowGraphBuilder


@dataclass
class AnalysisResult:
    """Result of interprocedural analysis."""
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    taint_paths: List[TaintPath] = field(default_factory=list)
    function_summaries: Dict[str, FunctionSummary] = field(default_factory=dict)
    analysis_statistics: Dict[str, Any] = field(default_factory=dict)
    llm_usage_stats: Dict[str, Any] = field(default_factory=dict)


class InterproceduralAnalyzer:
    """Interprocedural analyzer with hybrid approach."""
    
    def __init__(self, model=None, logger=None, max_workers: int = 3):
        """Initialize interprocedural analyzer.
        
        Args:
            model: LLM model for analysis
            logger: Logger instance
            max_workers: Maximum number of parallel workers
        """
        self.model = model
        self.logger = logger
        self.max_workers = max_workers
        
        # Core components
        self.functions: Dict[str, FunctionInfo] = {}
        self.function_summaries: Dict[str, FunctionSummary] = {}
        
        # Analysis components
        self.alias_analyzer = LightweightAliasAnalyzer(logger)
        self.call_graph_builder = CallGraphBuilder(logger)
        self.data_flow_builder = DataFlowGraphBuilder(logger)
        
        # LLM tools
        self.llm_tools_manager = LLMToolsManager(model, logger) if model else None
        self.hybrid_taint_analyzer = HybridTaintAnalyzer(
            llm_tools=self.llm_tools_manager.tools if self.llm_tools_manager else None,
            logger=logger
        )
        
        # Analysis state
        self.analysis_cache: Dict[str, Any] = {}
    
    def analyze_project(self, functions: Dict[str, FunctionInfo], 
                       file_contents: Dict[str, str]) -> AnalysisResult:
        """Perform comprehensive interprocedural analysis.
        
        Args:
            functions: Dictionary of function information
            file_contents: Dictionary mapping file paths to content
            
        Returns:
            Analysis result
        """
        if self.logger:
            self.logger.log("Starting interprocedural analysis...")
        
        self.functions = functions
        
        # Step 1: Build call graph
        call_graph = self._build_call_graph()
        
        # Step 2: Generate function summaries
        self._generate_summaries(file_contents)
        
        # Step 3: Perform hybrid taint analysis
        taint_paths = self._perform_hybrid_taint_analysis()
        
        # Step 4: Detect vulnerabilities
        vulnerabilities = self._detect_vulnerabilities(taint_paths)
        
        # Step 5: Generate analysis statistics
        analysis_stats = self._generate_analysis_statistics()
        llm_stats = self._generate_llm_usage_statistics()
        
        result = AnalysisResult(
            vulnerabilities=vulnerabilities,
            taint_paths=taint_paths,
            function_summaries=self.function_summaries,
            analysis_statistics=analysis_stats,
            llm_usage_stats=llm_stats
        )
        
        if self.logger:
            self.logger.log(f"Analysis complete. Found {len(vulnerabilities)} vulnerabilities.")
        
        return result
    
    def _build_call_graph(self):
        """Build interprocedural call graph."""
        if self.logger:
            self.logger.log("Building call graph...")
        
        call_graph = self.call_graph_builder.build_call_graph(self.functions)
        
        if self.logger:
            self.logger.log(f"Call graph built with {call_graph.number_of_nodes()} nodes and {call_graph.number_of_edges()} edges")
        
        return call_graph
    
    def _generate_summaries(self, file_contents: Dict[str, str]):
        """Generate function summaries."""
        if self.logger:
            self.logger.log("Generating function summaries...")
        
        for func_key, func_info in self.functions.items():
            if func_info.file_path in file_contents:
                summary = self._generate_single_summary(func_info, file_contents[func_info.file_path])
                self.function_summaries[func_key] = summary
        
        if self.logger:
            self.logger.log(f"Generated {len(self.function_summaries)} summaries")
    
    def _generate_single_summary(self, func_info: FunctionInfo, content: str) -> FunctionSummary:
        """Generate summary for a single function."""
        
        # Step 1: Perform alias analysis
        alias_dict = self.alias_analyzer.analyze_function(func_info, content)
        
        # Step 2: Generate basic summary
        summary = self._create_basic_summary(func_info, alias_dict)
        
        # Step 3: Enhance with LLM if available
        if self.llm_tools_manager:
            summary = self._enhance_summary_with_llm(summary, func_info, content)
        
        return summary
    
    def _create_basic_summary(self, func_info: FunctionInfo, alias_dict: Dict[str, Set[str]]) -> FunctionSummary:
        """Create basic summary from static analysis."""
        
        from .summary import (
            ParameterSummary, ReturnValueSummary, SideEffect,
            CallSiteSummary, AliasSummary, TaintFlowSummary,
            TaintPropagationType, SideEffectType, MemoryOperationType
        )
        
        # Create parameter summaries
        parameters = []
        for i, param_name in enumerate(func_info.parameters):
            param_summary = ParameterSummary(
                index=i,
                name=param_name,
                aliases=alias_dict.get(param_name, set()),
                alias_confidence=0.8 if param_name in alias_dict else 0.0,
                taint_propagation=TaintPropagationType.NO_EFFECT,  # Will be enhanced later
                taint_confidence=0.5
            )
            parameters.append(param_summary)
        
        # Create return value summary
        return_value = ReturnValueSummary(
            type=func_info.return_type or "unknown",
            can_be_null=True,  # Conservative assumption
            is_allocation=False  # Will be enhanced later
        )
        
        # Analyze side effects from function calls
        side_effects = []
        memory_operations = []
        
        for call_name in func_info.calls:
            if call_name in ['malloc', 'calloc', 'realloc']:
                memory_operations.append(MemoryOperationType.ALLOCATION)
                side_effects.append(SideEffect(
                    effect_type=SideEffectType.MEMORY_OPERATION,
                    description=f"Calls {call_name}",
                    is_dangerous=False,
                    confidence=1.0
                ))
            elif call_name == 'free':
                memory_operations.append(MemoryOperationType.DEALLOCATION)
                side_effects.append(SideEffect(
                    effect_type=SideEffectType.MEMORY_OPERATION,
                    description="Calls free",
                    is_dangerous=True,
                    risk_level=3,
                    confidence=1.0
                ))
            elif call_name in ['system', 'exec', 'popen']:
                side_effects.append(SideEffect(
                    effect_type=SideEffectType.SYSTEM_CALL,
                    description=f"Calls {call_name}",
                    is_dangerous=True,
                    risk_level=5,
                    confidence=1.0
                ))
        
        # Create alias summary
        alias_summary = AliasSummary(
            internal_aliases=alias_dict,
            parameter_aliases={i: alias_dict.get(param, set()) for i, param in enumerate(func_info.parameters)},
            alias_confidence={var: 0.8 for var in alias_dict.keys()}
        )
        
        # Create taint flow summary
        taint_flow = TaintFlowSummary()
        
        # Create call site summaries
        call_sites = []
        for call_name in func_info.calls:
            call_site = CallSiteSummary(
                callee_name=call_name,
                line_number=0,  # Would need more sophisticated parsing
                confidence=0.8
            )
            call_sites.append(call_site)
        
        # Create summary
        summary = FunctionSummary(
            function_name=func_info.name,
            file_path=func_info.file_path,
            start_line=func_info.start_line,
            end_line=func_info.end_line,
            parameters=parameters,
            return_value=return_value,
            side_effects=side_effects,
            call_sites=call_sites,
            alias_summary=alias_summary,
            taint_flow=taint_flow,
            memory_operations=memory_operations,
            allocates_memory=MemoryOperationType.ALLOCATION in memory_operations,
            frees_memory=MemoryOperationType.DEALLOCATION in memory_operations,
            memory_safe=not any(op in memory_operations for op in [MemoryOperationType.ALLOCATION, MemoryOperationType.DEALLOCATION]),
            security_sensitive=any(effect.is_dangerous for effect in side_effects),
            complexity_score=self._calculate_complexity_score(func_info),
            analysis_confidence=0.7,
            analysis_method="static"
        )
        
        return summary
    
    def _enhance_summary_with_llm(self, summary: FunctionSummary, 
                                 func_info: FunctionInfo, content: str) -> FunctionSummary:
        """Enhance summary using LLM."""
        
        if not self.llm_tools_manager:
            return summary
        
        try:
            # Extract function code
            lines = content.split('\n')
            func_lines = lines[func_info.start_line-1:func_info.end_line]
            func_code = '\n'.join(func_lines)
            
            # Create LLM input
            from .llm_tools import FunctionSummaryInput
            llm_input = FunctionSummaryInput(
                function_name=func_info.name,
                function_code=func_code,
                file_path=func_info.file_path,
                parameters=func_info.parameters,
                calls=func_info.calls
            )
            
            # Get LLM analysis
            llm_output = self.llm_tools_manager.function_summarizer.invoke(
                llm_input, 
                type(llm_input)  # This should be FunctionSummaryOutput
            )
            
            if llm_output:
                # Update summary with LLM insights
                summary = self._merge_llm_insights(summary, llm_output.summary)
                summary.llm_analysis_used = True
                summary.llm_confidence = llm_output.confidence
                summary.analysis_method = "hybrid"
                summary.analysis_confidence = max(summary.analysis_confidence, llm_output.confidence)
        
        except Exception as e:
            if self.logger:
                self.logger.log(f"Error enhancing summary with LLM for {func_info.name}: {e}", level="ERROR")
        
        return summary
    
    def _merge_llm_insights(self, summary: FunctionSummary, llm_data: Dict[str, Any]) -> FunctionSummary:
        """Merge LLM insights into the summary."""
        
        # Update parameters
        if 'parameters' in llm_data:
            for i, param_data in enumerate(llm_data['parameters']):
                if i < len(summary.parameters):
                    param = summary.parameters[i]
                    from .summary import TaintPropagationType
                    param.taint_propagation = TaintPropagationType(param_data.get('taint_propagation', 'no_effect'))
                    param.taint_confidence = param_data.get('taint_confidence', 0.5)
                    param.may_be_freed = param_data.get('may_be_freed', False)
                    param.may_be_modified = param_data.get('may_be_modified', False)
                    param.may_escape = param_data.get('may_escape', False)
        
        # Update return value
        if 'return_value' in llm_data:
            ret_data = llm_data['return_value']
            if summary.return_value:
                summary.return_value.can_introduce_taint = ret_data.get('can_introduce_taint', False)
                summary.return_value.is_allocation = ret_data.get('is_allocation', False)
                summary.return_value.can_be_null = ret_data.get('can_be_null', True)
        
        # Update side effects
        if 'side_effects' in llm_data:
            # Clear existing side effects and add LLM ones
            summary.side_effects.clear()
            for effect_data in llm_data['side_effects']:
                from .summary import SideEffect, SideEffectType
                side_effect = SideEffect(
                    effect_type=SideEffectType(effect_data.get('effect_type', 'memory_operation')),
                    description=effect_data.get('description', ''),
                    affected_params=set(effect_data.get('affected_params', [])),
                    is_dangerous=effect_data.get('is_dangerous', False),
                    risk_level=effect_data.get('risk_level', 1),
                    confidence=effect_data.get('confidence', 0.8)
                )
                summary.side_effects.append(side_effect)
        
        # Update security properties
        summary.security_sensitive = llm_data.get('security_sensitive', summary.security_sensitive)
        summary.validates_input = llm_data.get('validates_input', summary.validates_input)
        summary.sanitizes_output = llm_data.get('sanitizes_output', summary.sanitizes_output)
        summary.security_concerns = llm_data.get('security_concerns', summary.security_concerns)
        
        # Add LLM insights
        summary.llm_insights = llm_data.get('llm_insights', [])
        
        return summary
    
    def _perform_hybrid_taint_analysis(self) -> List[TaintPath]:
        """Perform hybrid taint analysis."""
        if self.logger:
            self.logger.log("Performing hybrid taint analysis...")
        
        # Find taint sources and sinks
        taint_sources = self._find_taint_sources()
        taint_sinks = self._find_taint_sinks()
        
        if self.logger:
            self.logger.log(f"Found {len(taint_sources)} taint sources and {len(taint_sinks)} taint sinks")
        
        # Build call graph for path finding
        call_graph = {}
        for func_key, func_info in self.functions.items():
            call_graph[func_key] = func_info.calls
        
        # Find taint paths
        taint_paths = self.hybrid_taint_analyzer.find_taint_paths(
            taint_sources, taint_sinks, self.function_summaries, call_graph
        )
        
        if self.logger:
            self.logger.log(f"Found {len(taint_paths)} taint paths")
        
        return taint_paths
    
    def _find_taint_sources(self) -> List[str]:
        """Find functions that can be taint sources."""
        sources = []
        
        for func_key, summary in self.function_summaries.items():
            if summary.is_taint_source():
                sources.append(func_key)
        
        return sources
    
    def _find_taint_sinks(self) -> List[str]:
        """Find functions that can be taint sinks."""
        sinks = []
        
        for func_key, summary in self.function_summaries.items():
            if summary.is_taint_sink():
                sinks.append(func_key)
        
        return sinks
    
    def _detect_vulnerabilities(self, taint_paths: List[TaintPath]) -> List[Vulnerability]:
        """Detect vulnerabilities from taint paths."""
        vulnerabilities = []
        
        for taint_path in taint_paths:
            if taint_path.confidence > 0.5:  # Only consider high-confidence paths
                vuln = self._create_vulnerability_from_taint_path(taint_path)
                if vuln:
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _create_vulnerability_from_taint_path(self, taint_path: TaintPath) -> Optional[Vulnerability]:
        """Create vulnerability from taint path."""
        
        # Determine vulnerability type based on sink
        sink_func = taint_path.sink_function
        vuln_type = self._determine_vulnerability_type(sink_func)
        
        # Get function info for location
        if sink_func in self.functions:
            func_info = self.functions[sink_func]
            location = CodeLocation(
                file_path=func_info.file_path,
                line_start=func_info.start_line,
                line_end=func_info.end_line
            )
        else:
            location = CodeLocation(file_path="unknown", line_start=0, line_end=0)
        
        # Create vulnerability
        vulnerability = Vulnerability(
            vuln_type=vuln_type,
            severity=Severity.HIGH if taint_path.confidence > 0.8 else Severity.MEDIUM,
            location=location,
            description=f"Tainted data flows from {taint_path.source_function} to {taint_path.sink_function}",
            evidence=f"Path: {' -> '.join(taint_path.path)} (confidence: {taint_path.confidence:.2f})",
            confidence=taint_path.confidence,
            recommendation="Validate and sanitize input data before using in sensitive operations"
        )
        
        return vulnerability
    
    def _determine_vulnerability_type(self, sink_func: str) -> VulnerabilityType:
        """Determine vulnerability type based on sink function."""
        
        if sink_func in self.function_summaries:
            summary = self.function_summaries[sink_func]
            
            # Check side effects
            for effect in summary.side_effects:
                if effect.effect_type.value == 'system_call':
                    return VulnerabilityType.COMMAND_INJECTION
                elif effect.effect_type.value == 'file_io':
                    return VulnerabilityType.PATH_TRAVERSAL
        
        # Default based on function name
        if any(keyword in sink_func.lower() for keyword in ['sql', 'query', 'execute']):
            return VulnerabilityType.SQL_INJECTION
        elif any(keyword in sink_func.lower() for keyword in ['system', 'exec', 'shell']):
            return VulnerabilityType.COMMAND_INJECTION
        else:
            return VulnerabilityType.BUFFER_OVERFLOW
    
    def _calculate_complexity_score(self, func_info: FunctionInfo) -> int:
        """Calculate complexity score for a function."""
        param_count = len(func_info.parameters)
        call_count = len(func_info.calls)
        line_count = func_info.end_line - func_info.start_line
        
        complexity = 1
        if param_count > 5:
            complexity += 1
        if call_count > 10:
            complexity += 1
        if line_count > 50:
            complexity += 1
        if line_count > 100:
            complexity += 1
        
        return min(complexity, 5)
    
    def _generate_analysis_statistics(self) -> Dict[str, Any]:
        """Generate analysis statistics."""
        return {
            'total_functions': len(self.functions),
            'analyzed_functions': len(self.function_summaries),
            'taint_sources': len(self._find_taint_sources()),
            'taint_sinks': len(self._find_taint_sinks()),
            'vulnerabilities_found': 0,  # Will be updated by caller
            'analysis_methods': {
                'static_only': sum(1 for s in self.function_summaries.values() if s.analysis_method == 'static'),
                'llm_enhanced': sum(1 for s in self.function_summaries.values() if s.analysis_method == 'hybrid')
            }
        }
    
    def _generate_llm_usage_statistics(self) -> Dict[str, Any]:
        """Generate LLM usage statistics."""
        if not self.llm_tools_manager:
            return {'llm_available': False}
        
        return {
            'llm_available': True,
            'tool_stats': self.llm_tools_manager.get_all_stats(),
            'hybrid_taint_stats': self.hybrid_taint_analyzer.get_analysis_statistics()
        }
