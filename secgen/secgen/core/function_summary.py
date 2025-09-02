"""Function summary for interprocedural dataflow analysis.

This module provides function summaries that capture the essential behavior
of functions for interprocedural analysis, similar to IDFS (Interprocedural
Dataflow Analysis) summaries.
"""

from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

from .analyzer import FunctionInfo


class ParameterEffect(Enum):
    """Effects that a function can have on its parameters."""
    READ_ONLY = "read_only"           # Parameter is only read
    MODIFIED = "modified"             # Parameter is modified
    FREED = "freed"                   # Parameter (pointer) is freed
    ALIASED = "aliased"               # Parameter is aliased to another
    ESCAPED = "escaped"               # Parameter escapes function scope


class ReturnValueType(Enum):
    """Types of return values from functions."""
    CONSTANT = "constant"             # Returns constant value
    PARAMETER = "parameter"           # Returns one of the parameters
    NEW_ALLOCATION = "new_allocation" # Returns newly allocated memory
    GLOBAL = "global"                 # Returns global variable
    NULL = "null"                     # Always returns NULL
    UNKNOWN = "unknown"               # Unknown return behavior


class TaintEffect(Enum):
    """Taint propagation effects."""
    PRESERVES_TAINT = "preserves_taint"   # Input taint → Output taint
    SANITIZES = "sanitizes"               # Removes taint
    INTRODUCES_TAINT = "introduces_taint" # Introduces new taint
    NO_EFFECT = "no_effect"               # No taint effect


@dataclass
class ParameterSummary:
    """Summary of how a parameter is used in a function."""
    index: int                                    # Parameter index
    name: str                                     # Parameter name
    effects: Set[ParameterEffect] = field(default_factory=set)
    taint_flow: TaintEffect = TaintEffect.NO_EFFECT
    points_to: Set[str] = field(default_factory=set)  # What this parameter might point to
    modified_fields: Set[str] = field(default_factory=set)  # If struct, which fields are modified
    
    def is_input_only(self) -> bool:
        """Check if parameter is only used as input."""
        return ParameterEffect.READ_ONLY in self.effects
    
    def is_modified(self) -> bool:
        """Check if parameter is modified."""
        return ParameterEffect.MODIFIED in self.effects
    
    def escapes_function(self) -> bool:
        """Check if parameter escapes function scope."""
        return ParameterEffect.ESCAPED in self.effects


@dataclass
class ReturnValueSummary:
    """Summary of function return behavior."""
    type: ReturnValueType
    depends_on_params: Set[int] = field(default_factory=set)  # Which parameters affect return value
    taint_source: bool = False                                # Can introduce taint
    can_be_null: bool = False                                 # Can return NULL
    allocation_site: bool = False                             # Returns allocated memory
    
    def is_allocation_function(self) -> bool:
        """Check if function allocates memory."""
        return self.type == ReturnValueType.NEW_ALLOCATION or self.allocation_site


@dataclass
class SideEffect:
    """Represents a side effect of function execution."""
    type: str                          # Type of side effect (file_io, network, system_call, etc.)
    description: str                   # Description of the side effect
    dangerous: bool = False            # Whether this is a dangerous side effect
    parameters_involved: Set[int] = field(default_factory=set)  # Which parameters are involved


@dataclass
class CallSiteSummary:
    """Summary of function calls within this function."""
    callee_name: str
    arguments: List[str]               # Argument expressions
    return_used: bool                  # Whether return value is used
    line_number: int
    may_fail: bool = False             # Whether call may fail


@dataclass
class FunctionSummary:
    """Comprehensive function summary for interprocedural analysis.
    
    This captures the essential behavior of a function that is needed
    for interprocedural dataflow analysis.
    """
    function_name: str
    file_path: str
    parameters: List[ParameterSummary] = field(default_factory=list)
    return_value: Optional[ReturnValueSummary] = None
    side_effects: List[SideEffect] = field(default_factory=list)
    calls: List[CallSiteSummary] = field(default_factory=list)
    
    # Memory behavior
    allocates_memory: bool = False
    frees_memory: bool = False
    memory_safe: bool = True
    
    # Control flow
    may_not_return: bool = False       # Function may not return (exit, throw, etc.)
    conditional_behavior: bool = False  # Behavior depends on input values
    
    # Security properties
    validates_input: bool = False      # Performs input validation
    sanitizes_output: bool = False     # Sanitizes output
    security_sensitive: bool = False   # Handles sensitive operations
    
    # Analysis metadata
    analysis_confidence: float = 1.0   # Confidence in this summary
    requires_context: bool = False     # Needs calling context for precise analysis
    
    def get_modified_parameters(self) -> List[int]:
        """Get indices of parameters that are modified."""
        return [p.index for p in self.parameters if p.is_modified()]
    
    def get_input_parameters(self) -> List[int]:
        """Get indices of parameters used only as input."""
        return [p.index for p in self.parameters if p.is_input_only()]
    
    def has_dangerous_side_effects(self) -> bool:
        """Check if function has dangerous side effects."""
        return any(effect.dangerous for effect in self.side_effects)
    
    def propagates_taint(self, param_index: int) -> bool:
        """Check if taint from parameter propagates to return value."""
        if param_index < len(self.parameters):
            param = self.parameters[param_index]
            return param.taint_flow == TaintEffect.PRESERVES_TAINT
        return False
    
    def sanitizes_input(self, param_index: int) -> bool:
        """Check if function sanitizes input parameter."""
        if param_index < len(self.parameters):
            param = self.parameters[param_index]
            return param.taint_flow == TaintEffect.SANITIZES
        return False


class FunctionSummaryGenerator:
    """Generates function summaries for interprocedural analysis."""
    
    def __init__(self, model=None, logger=None):
        """Initialize function summary generator.
        
        Args:
            model: LLM model for enhanced analysis
            logger: Logger instance
        """
        self.model = model
        self.logger = logger
        self.summaries: Dict[str, FunctionSummary] = {}
        
        # Known function behaviors (can be extended)
        self._init_known_functions()
    
    def _init_known_functions(self):
        """Initialize summaries for well-known library functions."""
        self.known_functions = {
            # Memory functions
            'malloc': FunctionSummary(
                function_name='malloc',
                file_path='<stdlib>',
                return_value=ReturnValueSummary(
                    type=ReturnValueType.NEW_ALLOCATION,
                    can_be_null=True,
                    allocation_site=True
                ),
                allocates_memory=True,
                memory_safe=False  # Can return NULL
            ),
            
            'free': FunctionSummary(
                function_name='free',
                file_path='<stdlib>',
                parameters=[ParameterSummary(
                    index=0,
                    name='ptr',
                    effects={ParameterEffect.FREED}
                )],
                frees_memory=True
            ),
            
            # String functions
            'strcpy': FunctionSummary(
                function_name='strcpy',
                file_path='<string>',
                parameters=[
                    ParameterSummary(
                        index=0,
                        name='dest',
                        effects={ParameterEffect.MODIFIED}
                    ),
                    ParameterSummary(
                        index=1,
                        name='src',
                        effects={ParameterEffect.READ_ONLY}
                    )
                ],
                return_value=ReturnValueSummary(
                    type=ReturnValueType.PARAMETER,
                    depends_on_params={0}
                ),
                side_effects=[SideEffect(
                    type='buffer_operation',
                    description='Copies string without bounds checking',
                    dangerous=True,
                    parameters_involved={0, 1}
                )],
                memory_safe=False
            ),
            
            # Input functions
            'scanf': FunctionSummary(
                function_name='scanf',
                file_path='<stdio>',
                parameters=[
                    ParameterSummary(
                        index=0,
                        name='format',
                        effects={ParameterEffect.READ_ONLY}
                    )
                ],
                side_effects=[SideEffect(
                    type='user_input',
                    description='Reads user input',
                    dangerous=True
                )],
                security_sensitive=True,
                memory_safe=False
            )
        }
    
    def generate_summary(self, function_info: FunctionInfo, content: str) -> FunctionSummary:
        """Generate summary for a function.
        
        Args:
            function_info: Function information from static analysis
            content: Source code content
            
        Returns:
            Function summary for interprocedural analysis
        """
        # Check if we have a known summary
        if function_info.name in self.known_functions:
            return self.known_functions[function_info.name]
        
        # Generate summary based on static analysis
        summary = self._analyze_function_statically(function_info, content)
        
        # Enhance with LLM if available
        if self.model:
            summary = self._enhance_with_llm(summary, function_info, content)
        
        # Cache the summary
        func_key = f"{function_info.file_path}:{function_info.name}"
        self.summaries[func_key] = summary
        
        return summary
    
    def _analyze_function_statically(self, function_info: FunctionInfo, content: str) -> FunctionSummary:
        """Perform static analysis to generate basic function summary."""
        
        # Extract function code
        lines = content.split('\n')
        func_lines = lines[function_info.start_line-1:function_info.end_line]
        func_code = '\n'.join(func_lines)
        
        summary = FunctionSummary(
            function_name=function_info.name,
            file_path=function_info.file_path
        )
        
        # Analyze parameters
        for i, param_name in enumerate(function_info.parameters):
            param_summary = ParameterSummary(
                index=i,
                name=param_name,
                effects={ParameterEffect.READ_ONLY}  # Default assumption
            )
            
            # Check if parameter is modified
            if self._parameter_is_modified(param_name, func_code):
                param_summary.effects.add(ParameterEffect.MODIFIED)
                param_summary.effects.discard(ParameterEffect.READ_ONLY)
            
            summary.parameters.append(param_summary)
        
        # Analyze function calls
        for call_name in function_info.calls:
            call_summary = CallSiteSummary(
                callee_name=call_name,
                arguments=[],  # Would need more sophisticated parsing
                return_used=False,  # Simplified
                line_number=0  # Would need to find actual line
            )
            summary.calls.append(call_summary)
            
            # Check for dangerous calls
            if call_name in ['malloc', 'calloc']:
                summary.allocates_memory = True
            elif call_name == 'free':
                summary.frees_memory = True
            elif call_name in ['strcpy', 'strcat', 'sprintf']:
                summary.memory_safe = False
                summary.side_effects.append(SideEffect(
                    type='unsafe_operation',
                    description=f'Calls unsafe function {call_name}',
                    dangerous=True
                ))
            elif call_name in ['system', 'exec', 'popen']:
                summary.security_sensitive = True
                summary.side_effects.append(SideEffect(
                    type='system_call',
                    description=f'Executes system command via {call_name}',
                    dangerous=True
                ))
        
        # Analyze return behavior
        if 'return' in func_code:
            summary.return_value = ReturnValueSummary(
                type=ReturnValueType.UNKNOWN
            )
            
            # Simple heuristics for return value analysis
            if 'malloc' in func_code or 'calloc' in func_code:
                summary.return_value.type = ReturnValueType.NEW_ALLOCATION
                summary.return_value.can_be_null = True
                summary.return_value.allocation_site = True
        
        return summary
    
    def _parameter_is_modified(self, param_name: str, func_code: str) -> bool:
        """Check if parameter is modified in function (simplified heuristic)."""
        import re
        
        # Look for assignment to parameter or its fields
        patterns = [
            rf'{param_name}\s*=',           # Direct assignment
            rf'{param_name}\s*\[.*\]\s*=',  # Array element assignment
            rf'{param_name}\s*->\s*\w+\s*=', # Pointer field assignment
            rf'{param_name}\s*\.\s*\w+\s*=', # Struct field assignment
        ]
        
        for pattern in patterns:
            if re.search(pattern, func_code):
                return True
        
        return False
    
    def _enhance_with_llm(self, summary: FunctionSummary, 
                         function_info: FunctionInfo, content: str) -> FunctionSummary:
        """Enhance summary using LLM analysis."""
        
        # Extract function code
        lines = content.split('\n')
        func_lines = lines[function_info.start_line-1:function_info.end_line]
        func_code = '\n'.join(func_lines)
        
        prompt = f"""Analyze this C/C++ function for interprocedural dataflow analysis.
        
Function: {function_info.name}
```c
{func_code}
```

Please provide a JSON analysis focusing on:

1. Parameter effects (read_only, modified, freed, escaped)
2. Return value behavior (constant, parameter-dependent, allocation, etc.)
3. Side effects (file I/O, network, system calls, memory operations)
4. Taint propagation (which inputs affect outputs)
5. Memory safety properties

Return JSON format:
{{
    "parameters": [
        {{
            "index": 0,
            "effects": ["read_only", "modified", "freed", "escaped"],
            "taint_flow": "preserves_taint|sanitizes|introduces_taint|no_effect"
        }}
    ],
    "return_value": {{
        "type": "constant|parameter|new_allocation|global|null|unknown",
        "depends_on_params": [0, 1],
        "can_be_null": true/false,
        "allocation_site": true/false
    }},
    "side_effects": [
        {{
            "type": "file_io|network|system_call|memory_operation",
            "description": "What the side effect does",
            "dangerous": true/false
        }}
    ],
    "memory_safe": true/false,
    "validates_input": true/false,
    "security_sensitive": true/false
}}"""

        try:
            from secgen.agent.models import ChatMessage, MessageRole
            
            messages = [
                ChatMessage(
                    role=MessageRole.SYSTEM,
                    content="You are an expert in static analysis and interprocedural dataflow analysis. Analyze functions for their dataflow properties."
                ),
                ChatMessage(
                    role=MessageRole.USER,
                    content=prompt
                )
            ]
            
            response = self.model.generate(messages)
            if response.content:
                import json
                
                # Parse LLM response
                content_str = response.content.strip()
                if content_str.startswith('```json'):
                    content_str = content_str[7:]
                if content_str.endswith('```'):
                    content_str = content_str[:-3]
                
                llm_analysis = json.loads(content_str.strip())
                
                # Update summary with LLM insights
                self._update_summary_from_llm(summary, llm_analysis)
                summary.analysis_confidence = 0.9  # Higher confidence with LLM
                
        except Exception as e:
            if self.logger:
                self.logger.log(f"Error in LLM enhancement for {function_info.name}: {e}", level="ERROR")
        
        return summary
    
    def _update_summary_from_llm(self, summary: FunctionSummary, llm_analysis: Dict[str, Any]):
        """Update function summary with LLM analysis results."""
        
        # Update parameter information
        if 'parameters' in llm_analysis:
            for param_data in llm_analysis['parameters']:
                param_idx = param_data.get('index', 0)
                if param_idx < len(summary.parameters):
                    param = summary.parameters[param_idx]
                    
                    # Update effects
                    if 'effects' in param_data:
                        param.effects.clear()
                        for effect_str in param_data['effects']:
                            try:
                                effect = ParameterEffect(effect_str)
                                param.effects.add(effect)
                            except ValueError:
                                pass
                    
                    # Update taint flow
                    if 'taint_flow' in param_data:
                        try:
                            param.taint_flow = TaintEffect(param_data['taint_flow'])
                        except ValueError:
                            pass
        
        # Update return value information
        if 'return_value' in llm_analysis:
            ret_data = llm_analysis['return_value']
            if not summary.return_value:
                summary.return_value = ReturnValueSummary(type=ReturnValueType.UNKNOWN)
            
            if 'type' in ret_data:
                try:
                    summary.return_value.type = ReturnValueType(ret_data['type'])
                except ValueError:
                    pass
            
            summary.return_value.can_be_null = ret_data.get('can_be_null', False)
            summary.return_value.allocation_site = ret_data.get('allocation_site', False)
            
            if 'depends_on_params' in ret_data:
                summary.return_value.depends_on_params = set(ret_data['depends_on_params'])
        
        # Update side effects
        if 'side_effects' in llm_analysis:
            summary.side_effects.clear()
            for effect_data in llm_analysis['side_effects']:
                side_effect = SideEffect(
                    type=effect_data.get('type', 'unknown'),
                    description=effect_data.get('description', ''),
                    dangerous=effect_data.get('dangerous', False)
                )
                summary.side_effects.append(side_effect)
        
        # Update properties
        summary.memory_safe = llm_analysis.get('memory_safe', True)
        summary.validates_input = llm_analysis.get('validates_input', False)
        summary.security_sensitive = llm_analysis.get('security_sensitive', False)
    
    def get_summary(self, func_key: str) -> Optional[FunctionSummary]:
        """Get cached function summary."""
        return self.summaries.get(func_key)
    
    def get_all_summaries(self) -> Dict[str, FunctionSummary]:
        """Get all cached function summaries."""
        return self.summaries.copy()
    
    def compute_summary_for_call_graph(self, functions: Dict[str, FunctionInfo], 
                                     file_contents: Dict[str, str]) -> Dict[str, FunctionSummary]:
        """Compute summaries for all functions in call graph."""
        
        summaries = {}
        
        for func_key, func_info in functions.items():
            if func_info.file_path in file_contents:
                summary = self.generate_summary(func_info, file_contents[func_info.file_path])
                summaries[func_key] = summary
                
                if self.logger:
                    self.logger.log(f"Generated summary for {func_info.name}")
        
        return summaries
