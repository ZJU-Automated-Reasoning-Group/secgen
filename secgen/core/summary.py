"""Function summary representation for improved interprocedural analysis.

This module provides data structures for function summaries that support
precise alias analysis, taint propagation, and LLM integration.
"""

from typing import Dict, List, Set, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum

from .alias_analyzer import AliasRelation, AliasType


class TaintPropagationType(Enum):
    """Types of taint propagation."""
    PRESERVES_TAINT = "preserves_taint"       # Input taint → Output taint
    SANITIZES = "sanitizes"                   # Removes taint
    INTRODUCES_TAINT = "introduces_taint"     # Introduces new taint
    CONDITIONAL_TAINT = "conditional_taint"   # Taint depends on conditions
    NO_EFFECT = "no_effect"                   # No taint effect


class MemoryOperationType(Enum):
    """Types of memory operations."""
    ALLOCATION = "allocation"                 # malloc, calloc, new
    DEALLOCATION = "deallocation"             # free, delete
    REALLOCATION = "reallocation"             # realloc
    COPY = "copy"                             # memcpy, strcpy
    MOVE = "move"                             # memmove
    COMPARE = "compare"                       # memcmp, strcmp


class SideEffectType(Enum):
    """Types of side effects."""
    FILE_IO = "file_io"                       # File operations
    NETWORK_IO = "network_io"                 # Network operations
    SYSTEM_CALL = "system_call"               # System calls
    MEMORY_OPERATION = "memory_operation"     # Memory operations
    GLOBAL_MODIFICATION = "global_modification"  # Global variable modification
    EXTERNAL_STATE = "external_state"         # External state changes


@dataclass
class ParameterSummary:
    """Parameter summary with alias and taint information."""
    index: int
    name: str
    type: str = ""
    
    # Alias information
    aliases: Set[str] = field(default_factory=set)
    alias_confidence: float = 0.0
    
    # Taint propagation
    taint_propagation: TaintPropagationType = TaintPropagationType.NO_EFFECT
    taint_confidence: float = 0.0
    
    # Memory effects
    may_be_freed: bool = False
    may_be_modified: bool = False
    may_escape: bool = False
    
    # Usage patterns
    is_input_only: bool = True
    is_output_only: bool = False
    is_input_output: bool = False
    
    def is_tainted(self) -> bool:
        """Check if parameter can carry taint."""
        return self.taint_propagation in {
            TaintPropagationType.PRESERVES_TAINT,
            TaintPropagationType.INTRODUCES_TAINT,
            TaintPropagationType.CONDITIONAL_TAINT
        }


@dataclass
class ReturnValueSummary:
    """Return value summary."""
    type: str = "unknown"
    
    # Dependencies
    depends_on_params: Set[int] = field(default_factory=set)
    depends_on_globals: Set[str] = field(default_factory=set)
    
    # Taint information
    can_introduce_taint: bool = False
    taint_source_params: Set[int] = field(default_factory=set)
    
    # Memory information
    is_allocation: bool = False
    can_be_null: bool = False
    allocation_size_depends_on: Set[int] = field(default_factory=set)
    
    # Alias information
    may_alias_with: Set[str] = field(default_factory=set)
    alias_confidence: float = 0.0


@dataclass
class SideEffect:
    """Side effect representation."""
    effect_type: SideEffectType
    description: str
    
    # Affected variables/parameters
    affected_params: Set[int] = field(default_factory=set)
    affected_globals: Set[str] = field(default_factory=set)
    
    # Risk assessment
    is_dangerous: bool = False
    risk_level: int = 1  # 1-5 scale
    
    # Conditions
    conditional: bool = False
    condition_description: str = ""
    
    # Confidence
    confidence: float = 1.0


@dataclass
class CallSiteSummary:
    """Call site summary."""
    callee_name: str
    line_number: int
    
    # Arguments
    arguments: List[str] = field(default_factory=list)
    argument_types: List[str] = field(default_factory=list)
    
    # Return value usage
    return_used: bool = False
    return_assigned_to: Optional[str] = None
    
    # Taint propagation through call
    taint_propagation: Dict[int, TaintPropagationType] = field(default_factory=dict)
    
    # Error handling
    may_fail: bool = False
    error_handling: str = ""
    
    # Confidence
    confidence: float = 1.0


@dataclass
class AliasSummary:
    """Summary of alias relationships in a function."""
    internal_aliases: Dict[str, Set[str]] = field(default_factory=dict)
    parameter_aliases: Dict[int, Set[str]] = field(default_factory=dict)
    return_aliases: Set[str] = field(default_factory=set)
    
    # Confidence scores
    alias_confidence: Dict[str, float] = field(default_factory=dict)
    
    def get_aliases_for_param(self, param_index: int) -> Set[str]:
        """Get aliases for a parameter."""
        return self.parameter_aliases.get(param_index, set())
    
    def get_aliases_for_var(self, var_name: str) -> Set[str]:
        """Get aliases for a variable."""
        return self.internal_aliases.get(var_name, {var_name})


@dataclass
class TaintFlowSummary:
    """Summary of taint flow in a function."""
    # Parameter taint flow
    param_taint_flow: Dict[int, TaintPropagationType] = field(default_factory=dict)
    
    # Return value taint flow
    return_taint_flow: TaintPropagationType = TaintPropagationType.NO_EFFECT
    
    # Global taint flow
    global_taint_flow: Dict[str, TaintPropagationType] = field(default_factory=dict)
    
    # Conditional taint flow
    conditional_flows: List[Dict[str, Any]] = field(default_factory=list)
    
    # Confidence scores
    taint_confidence: Dict[str, float] = field(default_factory=dict)
    
    def get_param_taint_flow(self, param_index: int) -> TaintPropagationType:
        """Get taint flow for a parameter."""
        return self.param_taint_flow.get(param_index, TaintPropagationType.NO_EFFECT)
    
    def is_taint_preserving(self) -> bool:
        """Check if function preserves taint."""
        return any(
            flow == TaintPropagationType.PRESERVES_TAINT 
            for flow in self.param_taint_flow.values()
        ) or self.return_taint_flow == TaintPropagationType.PRESERVES_TAINT


@dataclass
class FunctionSummary:
    """Function summary with comprehensive analysis information."""
    
    # Basic information
    function_name: str
    file_path: str
    start_line: int
    end_line: int
    
    # Parameter analysis
    parameters: List[ParameterSummary] = field(default_factory=list)
    
    # Return value analysis
    return_value: Optional[ReturnValueSummary] = None
    
    # Side effects
    side_effects: List[SideEffect] = field(default_factory=list)
    
    # Call sites
    call_sites: List[CallSiteSummary] = field(default_factory=list)
    
    # Alias analysis
    alias_summary: AliasSummary = field(default_factory=AliasSummary)
    
    # Taint flow analysis
    taint_flow: TaintFlowSummary = field(default_factory=TaintFlowSummary)
    
    # Memory analysis
    memory_operations: List[MemoryOperationType] = field(default_factory=list)
    allocates_memory: bool = False
    frees_memory: bool = False
    memory_safe: bool = True
    
    # Security analysis
    security_sensitive: bool = False
    validates_input: bool = False
    sanitizes_output: bool = False
    security_concerns: List[str] = field(default_factory=list)
    
    # Control flow analysis
    may_not_return: bool = False
    has_loops: bool = False
    has_recursion: bool = False
    complexity_score: int = 1
    
    # Analysis metadata
    analysis_confidence: float = 1.0
    analysis_method: str = "static"  # "static", "llm", "hybrid"
    requires_context: bool = False
    
    # LLM-specific information
    llm_analysis_used: bool = False
    llm_confidence: float = 0.0
    llm_insights: List[str] = field(default_factory=list)
    
    def get_parameter_by_index(self, index: int) -> Optional[ParameterSummary]:
        """Get parameter by index."""
        if 0 <= index < len(self.parameters):
            return self.parameters[index]
        return None
    
    def get_tainted_parameters(self) -> List[int]:
        """Get indices of parameters that can carry taint."""
        return [
            i for i, param in enumerate(self.parameters)
            if param.is_tainted()
        ]
    
    def get_dangerous_side_effects(self) -> List[SideEffect]:
        """Get dangerous side effects."""
        return [effect for effect in self.side_effects if effect.is_dangerous]
    
    def has_memory_operation(self, op_type: MemoryOperationType) -> bool:
        """Check if function has specific memory operation."""
        return op_type in self.memory_operations
    
    def is_taint_source(self) -> bool:
        """Check if function can be a taint source."""
        return (
            self.return_value and self.return_value.can_introduce_taint
        ) or any(
            effect.effect_type == SideEffectType.SYSTEM_CALL
            for effect in self.side_effects
        )
    
    def is_taint_sink(self) -> bool:
        """Check if function can be a taint sink."""
        return (
            self.security_sensitive and not self.validates_input
        ) or any(
            effect.is_dangerous for effect in self.side_effects
        )
    
    def get_taint_propagation_paths(self) -> List[Dict[str, Any]]:
        """Get possible taint propagation paths."""
        paths = []
        
        # Parameter to return value paths
        for param in self.parameters:
            if param.is_tainted():
                paths.append({
                    'source': f'param_{param.index}',
                    'sink': 'return_value',
                    'confidence': param.taint_confidence,
                    'type': param.taint_propagation.value
                })
        
        # Parameter to side effect paths
        for effect in self.side_effects:
            if effect.is_dangerous:
                for param_idx in effect.affected_params:
                    paths.append({
                        'source': f'param_{param_idx}',
                        'sink': f'side_effect_{effect.effect_type.value}',
                        'confidence': effect.confidence,
                        'type': 'side_effect'
                    })
        
        return paths
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'function_name': self.function_name,
            'file_path': self.file_path,
            'start_line': self.start_line,
            'end_line': self.end_line,
            'parameters': [
                {
                    'index': p.index,
                    'name': p.name,
                    'type': p.type,
                    'aliases': list(p.aliases),
                    'taint_propagation': p.taint_propagation.value,
                    'taint_confidence': p.taint_confidence,
                    'may_be_freed': p.may_be_freed,
                    'may_be_modified': p.may_be_modified,
                    'may_escape': p.may_escape,
                    'is_input_only': p.is_input_only,
                    'is_output_only': p.is_output_only,
                    'is_input_output': p.is_input_output
                }
                for p in self.parameters
            ],
            'return_value': {
                'type': self.return_value.type if self.return_value else 'unknown',
                'depends_on_params': list(self.return_value.depends_on_params) if self.return_value else [],
                'can_introduce_taint': self.return_value.can_introduce_taint if self.return_value else False,
                'is_allocation': self.return_value.is_allocation if self.return_value else False,
                'can_be_null': self.return_value.can_be_null if self.return_value else False
            } if self.return_value else None,
            'side_effects': [
                {
                    'type': effect.effect_type.value,
                    'description': effect.description,
                    'affected_params': list(effect.affected_params),
                    'is_dangerous': effect.is_dangerous,
                    'risk_level': effect.risk_level,
                    'confidence': effect.confidence
                }
                for effect in self.side_effects
            ],
            'alias_summary': {
                'internal_aliases': {k: list(v) for k, v in self.alias_summary.internal_aliases.items()},
                'parameter_aliases': {k: list(v) for k, v in self.alias_summary.parameter_aliases.items()},
                'return_aliases': list(self.alias_summary.return_aliases)
            },
            'taint_flow': {
                'param_taint_flow': {k: v.value for k, v in self.taint_flow.param_taint_flow.items()},
                'return_taint_flow': self.taint_flow.return_taint_flow.value,
                'conditional_flows': self.taint_flow.conditional_flows
            },
            'memory_operations': [op.value for op in self.memory_operations],
            'allocates_memory': self.allocates_memory,
            'frees_memory': self.frees_memory,
            'memory_safe': self.memory_safe,
            'security_sensitive': self.security_sensitive,
            'validates_input': self.validates_input,
            'sanitizes_output': self.sanitizes_output,
            'security_concerns': self.security_concerns,
            'complexity_score': self.complexity_score,
            'analysis_confidence': self.analysis_confidence,
            'analysis_method': self.analysis_method,
            'llm_analysis_used': self.llm_analysis_used,
            'llm_confidence': self.llm_confidence,
            'llm_insights': self.llm_insights
        }
