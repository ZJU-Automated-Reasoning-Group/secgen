"""Hybrid taint propagation analyzer combining static analysis and LLM.

This module implements a hybrid approach where static analysis handles simple cases
and LLM handles complex taint propagation scenarios.
"""

from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum

from .summary import (
    FunctionSummary, TaintPropagationType
)
from .alias_analyzer import LightweightAliasAnalyzer
# from .models import FunctionInfo


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
    """Represents a taint propagation path."""
    source_function: str
    sink_function: str
    path: List[str]  # Function names in the path
    confidence: float
    propagation_details: List[Dict[str, Any]] = field(default_factory=list)
    requires_llm_analysis: bool = False


class HybridTaintAnalyzer:
    """Hybrid taint analyzer that combines static analysis and LLM."""
    
    def __init__(self, llm_tools=None, logger=None):
        """Initialize the hybrid taint analyzer.
        
        Args:
            llm_tools: Dictionary of LLM tools for complex analysis
            logger: Logger instance
        """
        self.llm_tools = llm_tools or {}
        self.logger = logger
        self.alias_analyzer = LightweightAliasAnalyzer(logger)
        
        # Cache for analysis results
        self.propagation_cache: Dict[Tuple[str, str], TaintPropagationResult] = {}
        self.path_cache: Dict[Tuple[str, str], List[TaintPath]] = {}
        
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
        if 'taint_verifier' in self.llm_tools:
            llm_result = self._verify_taint_with_llm(caller_summary, callee_summary, call_site)
            if llm_result:
                return llm_result
        
        # Fall back to static analysis
        return static_result
    
    def _analyze_complex_taint_propagation(self, caller_summary: FunctionSummary,
                                         callee_summary: FunctionSummary,
                                         call_site: Dict[str, Any]) -> TaintPropagationResult:
        """Analyze complex taint propagation using LLM."""
        
        if 'taint_analyzer' not in self.llm_tools:
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
            verifier = self.llm_tools['taint_verifier']
            
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
            analyzer = self.llm_tools['taint_analyzer']
            
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
