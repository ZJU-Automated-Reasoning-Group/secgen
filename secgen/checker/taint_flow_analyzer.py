"""Unified taint analyzer combining static analysis and LLM for interprocedural taint propagation.

This module provides a comprehensive taint analysis system that:
- Performs interprocedural analysis
- Combines static analysis with LLM enhancement
- Tracks taint propagation through function calls
- Detects injection vulnerabilities and other taint-based issues


Taint Source → [Function Chain] → Taint Sink
     ↓              ↓                ↓
  Parameter    Propagation      Side Effect
     ↓              ↓                ↓
  Return Value  Alias Chain    Vulnerability
"""

from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum

from secgen.core.summary import FunctionSummary, TaintPropagationType
from secgen.core.llm_tools import LLMToolsManager, AnalysisInput, PathAnalysisInput
from secgen.core.models import FunctionInfo, Vulnerability, VulnerabilityType, Severity, CodeLocation, VulnerabilityPath, PathStep
from secgen.ir import CallGraphBuilder
from secgen.alias.local_must_alias_analyzer import LocalMustAliasAnalyzer


class TaintComplexity(Enum):
    """Complexity levels for taint analysis."""
    SIMPLE = "simple"           # Can be handled by static analysis
    MODERATE = "moderate"       # Requires some LLM assistance
    COMPLEX = "complex"         # Requires full LLM analysis


@dataclass
class TaintPropagationResult:
    """Result of taint propagation analysis."""
    can_propagate: bool
    confidence: float
    propagation_type: TaintPropagationType
    complexity: TaintComplexity
    explanation: str = ""
    llm_used: bool = False


@dataclass
class TaintPath:
    """Taint propagation path from source to sink."""
    source_function: str
    sink_function: str
    path: List[str]
    confidence: float
    propagation_details: List[Dict[str, Any]] = field(default_factory=list)
    requires_llm_analysis: bool = False


@dataclass
class AnalysisResult:
    """Result of comprehensive taint analysis."""
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    taint_paths: List[TaintPath] = field(default_factory=list)
    function_summaries: Dict[str, FunctionSummary] = field(default_factory=dict)
    analysis_statistics: Dict[str, Any] = field(default_factory=dict)
    llm_usage_stats: Dict[str, Any] = field(default_factory=dict)


class TaintAnalyzer:
    """Unified taint analyzer with hybrid approach combining static analysis and LLM."""
    
    def __init__(self, model=None, logger=None, max_workers: int = 3):
        """Initialize taint analyzer.
        
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
        self.alias_analyzer = LocalMustAliasAnalyzer(logger)
        self.call_graph_builder = CallGraphBuilder(logger)
        
        # LLM tools
        self.llm_tools_manager = LLMToolsManager(model, logger) if model else None
        
        # Cache for analysis results
        self.propagation_cache: Dict[Tuple[str, str], TaintPropagationResult] = {}
        self.path_cache: Dict[Tuple[str, str], List[TaintPath]] = {}
        self.analysis_cache: Dict[str, Any] = {}
        
        # Static analysis rules
        self._init_static_rules()
    
    def _init_static_rules(self):
        """Initialize static analysis rules for simple cases."""
        # Functions that always preserve taint
        self.taint_preserving_functions = {
            'strcpy', 'strcat', 'sprintf', 'memcpy', 'memmove',
            'strdup', 'strndup', 'asprintf', 'vasprintf'
        }
        
        # Functions that always sanitize taint
        self.taint_sanitizing_functions = {
            'strlen', 'strcmp', 'strncmp', 'memcmp',
            'atoi', 'atol', 'atof', 'strtol', 'strtoul'
        }
        
        # Functions that introduce taint
        self.taint_introducing_functions = {
            'scanf', 'gets', 'fgets', 'getenv', 'getcwd',
            'read', 'recv', 'fread', 'getchar', 'getc'
        }
        
        # Functions that are dangerous sinks
        self.dangerous_sink_functions = {
            'system', 'exec', 'popen', 'eval', 'printf', 'fprintf',
            'sprintf', 'snprintf', 'vsprintf', 'vsnprintf'
        }
    
    def analyze_project(self, functions: Dict[str, FunctionInfo], 
                       file_contents: Dict[str, str]) -> AnalysisResult:
        """Perform comprehensive taint analysis.
        
        Args:
            functions: Dictionary of function information
            file_contents: Dictionary mapping file paths to content
            
        Returns:
            Analysis result
        """
        if self.logger:
            self.logger.log("Starting taint analysis...")
        
        self.functions = functions
        
        # Step 1: Build call graph
        call_graph = self._build_call_graph()
        
        # Step 2: Generate function summaries
        self._generate_summaries(file_contents)
        
        # Step 3: Perform taint analysis
        taint_paths = self._perform_taint_analysis()
        
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
            self.logger.log(f"Taint analysis complete. Found {len(vulnerabilities)} vulnerabilities.")
        
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
    
    def analyze_taint_propagation(self, caller_summary: FunctionSummary,
                                callee_summary: FunctionSummary,
                                call_site: Dict[str, Any]) -> TaintPropagationResult:
        """Analyze taint propagation between two functions.
        
        Args:
            caller_summary: Summary of the calling function
            callee_summary: Summary of the called function
            call_site: Information about the call site
            
        Returns:
            Taint propagation analysis result
        """
        # Check cache first
        cache_key = (caller_summary.function_name, callee_summary.function_name)
        if cache_key in self.propagation_cache:
            return self.propagation_cache[cache_key]
        
        # Determine complexity
        complexity = self._assess_complexity(caller_summary, callee_summary, call_site)
        
        # Route to appropriate analysis method
        if complexity == TaintComplexity.SIMPLE:
            result = self._analyze_simple_taint_propagation(caller_summary, callee_summary, call_site)
        elif complexity == TaintComplexity.MODERATE:
            result = self._analyze_moderate_taint_propagation(caller_summary, callee_summary, call_site)
        else:  # COMPLEX
            result = self._analyze_complex_taint_propagation(caller_summary, callee_summary, call_site)
        
        # Cache result
        self.propagation_cache[cache_key] = result
        
        return result
    
    def _assess_complexity(self, caller_summary: FunctionSummary,
                          callee_summary: FunctionSummary,
                          call_site: Dict[str, Any]) -> TaintComplexity:
        """Assess the complexity of taint propagation analysis."""
        
        # Simple cases
        if (callee_summary.function_name in self.taint_preserving_functions or
            callee_summary.function_name in self.taint_sanitizing_functions or
            callee_summary.function_name in self.taint_introducing_functions):
            return TaintComplexity.SIMPLE
        
        # Check for complex patterns
        complex_indicators = 0
        
        # Complex alias relationships
        if len(callee_summary.alias_summary.internal_aliases) > 3:
            complex_indicators += 1
        
        # Complex control flow
        if callee_summary.has_loops or callee_summary.has_recursion:
            complex_indicators += 1
        
        # Multiple side effects
        if len(callee_summary.side_effects) > 2:
            complex_indicators += 1
        
        # Conditional taint flow
        if callee_summary.taint_flow.conditional_flows:
            complex_indicators += 1
        
        # Low confidence in static analysis
        if callee_summary.analysis_confidence < 0.7:
            complex_indicators += 1
        
        # Determine complexity based on indicators
        if complex_indicators == 0:
            return TaintComplexity.SIMPLE
        elif complex_indicators <= 2:
            return TaintComplexity.MODERATE
        else:
            return TaintComplexity.COMPLEX
    
    def _analyze_simple_taint_propagation(self, caller_summary: FunctionSummary,
                                        callee_summary: FunctionSummary,
                                        call_site: Dict[str, Any]) -> TaintPropagationResult:
        """Analyze simple taint propagation using static rules."""
        
        func_name = callee_summary.function_name
        
        # Check predefined rules
        if func_name in self.taint_preserving_functions:
            return TaintPropagationResult(
                can_propagate=True,
                confidence=0.95,
                propagation_type=TaintPropagationType.PRESERVES_TAINT,
                complexity=TaintComplexity.SIMPLE,
                explanation=f"Function {func_name} is known to preserve taint"
            )
        
        if func_name in self.taint_sanitizing_functions:
            return TaintPropagationResult(
                can_propagate=False,
                confidence=0.95,
                propagation_type=TaintPropagationType.SANITIZES,
                complexity=TaintComplexity.SIMPLE,
                explanation=f"Function {func_name} is known to sanitize taint"
            )
        
        if func_name in self.taint_introducing_functions:
            return TaintPropagationResult(
                can_propagate=True,
                confidence=0.95,
                propagation_type=TaintPropagationType.INTRODUCES_TAINT,
                complexity=TaintComplexity.SIMPLE,
                explanation=f"Function {func_name} is known to introduce taint"
            )
        
        # Check function summary
        if callee_summary.taint_flow.is_taint_preserving():
            return TaintPropagationResult(
                can_propagate=True,
                confidence=callee_summary.analysis_confidence,
                propagation_type=TaintPropagationType.PRESERVES_TAINT,
                complexity=TaintComplexity.SIMPLE,
                explanation="Function summary indicates taint preservation"
            )
        
        # Default: no propagation
        return TaintPropagationResult(
            can_propagate=False,
            confidence=0.8,
            propagation_type=TaintPropagationType.NO_EFFECT,
            complexity=TaintComplexity.SIMPLE,
            explanation="No taint propagation detected"
        )
    
    def _analyze_moderate_taint_propagation(self, caller_summary: FunctionSummary,
                                          callee_summary: FunctionSummary,
                                          call_site: Dict[str, Any]) -> TaintPropagationResult:
        """Analyze moderate complexity taint propagation with limited LLM assistance."""
        
        # Start with static analysis
        static_result = self._analyze_simple_taint_propagation(caller_summary, callee_summary, call_site)
        
        # If static analysis is confident, use it
        if static_result.confidence > 0.8:
            return static_result
        
        # Use LLM for specific questions
        if self.llm_tools_manager and 'taint_verifier' in self.llm_tools_manager.tools:
            llm_result = self._verify_taint_with_llm(caller_summary, callee_summary, call_site)
            if llm_result:
                return llm_result
        
        # Fall back to static analysis
        return static_result
    
    def _analyze_complex_taint_propagation(self, caller_summary: FunctionSummary,
                                         callee_summary: FunctionSummary,
                                         call_site: Dict[str, Any]) -> TaintPropagationResult:
        """Analyze complex taint propagation using LLM."""
        
        if not self.llm_tools_manager or 'taint_analyzer' not in self.llm_tools_manager.tools:
            # Fall back to static analysis if no LLM available
            return self._analyze_simple_taint_propagation(caller_summary, callee_summary, call_site)
        
        # Use LLM for complex analysis
        llm_result = self._analyze_taint_with_llm(caller_summary, callee_summary, call_site)
        if llm_result:
            llm_result.llm_used = True
            return llm_result
        
        # Fall back to static analysis
        return self._analyze_simple_taint_propagation(caller_summary, callee_summary, call_site)
    
    def _verify_taint_with_llm(self, caller_summary: FunctionSummary,
                              callee_summary: FunctionSummary,
                              call_site: Dict[str, Any]) -> Optional[TaintPropagationResult]:
        """Use LLM to verify taint propagation."""
        try:
            verifier = self.llm_tools_manager.tools['taint_verifier']
            
            # Create verification input
            verification_input = {
                'caller_function': caller_summary.function_name,
                'callee_function': callee_summary.function_name,
                'call_site': call_site,
                'static_analysis_result': {
                    'can_propagate': True,  # Assume propagation for verification
                    'confidence': 0.5,
                    'explanation': 'Static analysis uncertain'
                }
            }
            
            # Get LLM verification
            verification_result = verifier.verify_taint_propagation(verification_input)
            
            if verification_result:
                return TaintPropagationResult(
                    can_propagate=verification_result['can_propagate'],
                    confidence=verification_result['confidence'],
                    propagation_type=TaintPropagationType(verification_result['propagation_type']),
                    complexity=TaintComplexity.MODERATE,
                    explanation=verification_result['explanation'],
                    llm_used=True
                )
        
        except Exception as e:
            if self.logger:
                self.logger.log(f"Error in LLM taint verification: {e}", level="ERROR")
        
        return None
    
    def _analyze_taint_with_llm(self, caller_summary: FunctionSummary,
                               callee_summary: FunctionSummary,
                               call_site: Dict[str, Any]) -> Optional[TaintPropagationResult]:
        """Use LLM for complex taint analysis."""
        try:
            analyzer = self.llm_tools_manager.tools['taint_analyzer']
            
            # Create analysis input
            analysis_input = {
                'caller_summary': caller_summary.to_dict(),
                'callee_summary': callee_summary.to_dict(),
                'call_site': call_site,
                'alias_relationships': self._extract_alias_relationships(caller_summary, callee_summary)
            }
            
            # Get LLM analysis
            analysis_result = analyzer.analyze_taint_propagation(analysis_input)
            
            if analysis_result:
                return TaintPropagationResult(
                    can_propagate=analysis_result['can_propagate'],
                    confidence=analysis_result['confidence'],
                    propagation_type=TaintPropagationType(analysis_result['propagation_type']),
                    complexity=TaintComplexity.COMPLEX,
                    explanation=analysis_result['explanation'],
                    llm_used=True
                )
        
        except Exception as e:
            if self.logger:
                self.logger.log(f"Error in LLM taint analysis: {e}", level="ERROR")
        
        return None
    
    def _extract_alias_relationships(self, caller_summary: FunctionSummary,
                                   callee_summary: FunctionSummary) -> Dict[str, Any]:
        """Extract alias relationships between caller and callee."""
        relationships = {
            'parameter_aliases': {},
            'return_aliases': {},
            'global_aliases': {}
        }
        
        # Extract parameter aliases
        for param in callee_summary.parameters:
            if param.aliases:
                relationships['parameter_aliases'][param.index] = list(param.aliases)
        
        # Extract return aliases
        if callee_summary.return_value and callee_summary.return_value.may_alias_with:
            relationships['return_aliases'] = list(callee_summary.return_value.may_alias_with)
        
        return relationships
    
    def _perform_taint_analysis(self) -> List[TaintPath]:
        """Perform taint analysis."""
        if self.logger:
            self.logger.log("Performing taint analysis...")
        
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
        taint_paths = self.find_taint_paths(taint_sources, taint_sinks, self.function_summaries, call_graph)
        
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
    
    def find_taint_paths(self, source_functions: List[str], sink_functions: List[str],
                        function_summaries: Dict[str, FunctionSummary],
                        call_graph: Dict[str, List[str]]) -> List[TaintPath]:
        """Find taint propagation paths from sources to sinks."""
        
        paths = []
        
        for source_func in source_functions:
            for sink_func in sink_functions:
                # Check cache
                cache_key = (source_func, sink_func)
                if cache_key in self.path_cache:
                    paths.extend(self.path_cache[cache_key])
                    continue
                
                # Find call paths
                call_paths = self._find_call_paths(source_func, sink_func, call_graph)
                
                # Analyze each path
                path_results = []
                for call_path in call_paths:
                    path_result = self._analyze_taint_path(call_path, function_summaries)
                    if path_result:
                        path_results.append(path_result)
                
                # Cache results
                self.path_cache[cache_key] = path_results
                paths.extend(path_results)
        
        return paths
    
    def _find_call_paths(self, source: str, sink: str, call_graph: Dict[str, List[str]]) -> List[List[str]]:
        """Find all call paths from source to sink."""
        paths = []
        visited = set()
        
        def dfs(current: str, target: str, path: List[str]):
            if current == target:
                paths.append(path + [current])
                return
            
            if current in visited:
                return
            
            visited.add(current)
            
            for callee in call_graph.get(current, []):
                dfs(callee, target, path + [current])
            
            visited.remove(current)
        
        dfs(source, sink, [])
        return paths
    
    def _analyze_taint_path(self, path: List[str], 
                           function_summaries: Dict[str, FunctionSummary]) -> Optional[TaintPath]:
        """Analyze taint propagation along a call path."""
        
        if len(path) < 2:
            return None
        
        total_confidence = 1.0
        propagation_details = []
        requires_llm = False
        
        # Analyze each step in the path
        for i in range(len(path) - 1):
            caller = path[i]
            callee = path[i + 1]
            
            if caller not in function_summaries or callee not in function_summaries:
                continue
            
            caller_summary = function_summaries[caller]
            callee_summary = function_summaries[callee]
            
            # Analyze taint propagation
            propagation_result = self.analyze_taint_propagation(
                caller_summary, callee_summary, {}
            )
            
            if not propagation_result.can_propagate:
                return None  # Path is broken
            
            total_confidence *= propagation_result.confidence
            requires_llm = requires_llm or propagation_result.llm_used
            
            propagation_details.append({
                'caller': caller,
                'callee': callee,
                'propagation_type': propagation_result.propagation_type.value,
                'confidence': propagation_result.confidence,
                'explanation': propagation_result.explanation
            })
        
        return TaintPath(
            source_function=path[0],
            sink_function=path[-1],
            path=path,
            confidence=total_confidence,
            propagation_details=propagation_details,
            requires_llm_analysis=requires_llm
        )
    
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
            'taint_analysis_stats': self.get_analysis_statistics()
        }
    
    def get_analysis_statistics(self) -> Dict[str, Any]:
        """Get statistics about the analysis."""
        total_analyses = len(self.propagation_cache)
        llm_analyses = sum(1 for result in self.propagation_cache.values() if result.llm_used)
        
        complexity_counts = {}
        for result in self.propagation_cache.values():
            complexity = result.complexity.value
            complexity_counts[complexity] = complexity_counts.get(complexity, 0) + 1
        
        return {
            'total_analyses': total_analyses,
            'llm_analyses': llm_analyses,
            'static_analyses': total_analyses - llm_analyses,
            'llm_usage_ratio': llm_analyses / total_analyses if total_analyses > 0 else 0,
            'complexity_distribution': complexity_counts,
            'cache_hit_ratio': len(self.propagation_cache) / (len(self.propagation_cache) + len(self.path_cache))
        }
