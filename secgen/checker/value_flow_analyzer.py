"""Enhanced memory safety analyzer for detecting null pointer dereference, use-after-free, and memory leaks.


Tracked "Values"/States:
- Pointer addresses and their allocation status
- Memory allocation/deallocation events
- NULL pointer propagation
- Buffer bounds and sizes
- Variable initialization status
- Alias relationships between pointers
- Alias-aware memory state transitions
"""

from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum

from secgen.core.summary import FunctionSummary, MemoryOperationType, SideEffectType
from secgen.core.models import Vulnerability, VulnerabilityType, Severity, CodeLocation, VulnerabilityPath, PathStep, FunctionInfo
from secgen.alias.local_must_alias_analyzer import LocalMustAliasAnalyzer
from secgen.tsanalyzer import TreeSitterUtils


class MemoryFlowType(Enum):
    """Types of memory-related value flows."""
    NULL_POINTER_FLOW = "null_pointer_flow"           # NULL → dereference
    USE_AFTER_FREE = "use_after_free"                 # free() → use
    MEMORY_LEAK = "memory_leak"                       # malloc() → no free()
    DOUBLE_FREE = "double_free"                       # free() → free()
    BUFFER_OVERFLOW = "buffer_overflow"               # write beyond bounds
    UNINITIALIZED_USE = "uninitialized_use"           # use before init
    USE_AFTER_FREE_VIA_ALIAS = "use_after_free_via_alias"  # free() → use via alias
    DOUBLE_FREE_VIA_ALIAS = "double_free_via_alias"        # free() → free() via alias
    NULL_DEREF_VIA_ALIAS = "null_deref_via_alias"          # NULL → dereference via alias


class MemoryState(Enum):
    """Memory state of a pointer."""
    UNINITIALIZED = "uninitialized"
    ALLOCATED = "allocated"
    FREED = "freed"
    NULL = "null"
    UNKNOWN = "unknown"


@dataclass
class AliasAwareMemoryState:
    """Memory state that tracks aliases."""
    primary_var: str
    aliases: Set[str]
    memory_state: MemoryState
    confidence: float
    line_number: int = 0
    
    def get_all_aliases(self) -> Set[str]:
        """Get all variables in this alias set."""
        return self.aliases | {self.primary_var}
    
    def update_state_for_aliases(self, new_state: MemoryState, line_number: int = 0):
        """Update state for all aliases."""
        self.memory_state = new_state
        self.line_number = line_number
    
    def is_alias_of(self, var: str) -> bool:
        """Check if a variable is an alias of the primary variable."""
        return var in self.get_all_aliases()
    
    def add_alias(self, var: str):
        """Add a new alias to this set."""
        if var != self.primary_var:
            self.aliases.add(var)


@dataclass
class MemoryFlowResult:
    """Result of memory flow analysis."""
    flow_type: MemoryFlowType
    can_flow: bool
    confidence: float
    explanation: str
    source_state: MemoryState
    sink_state: MemoryState
    path: List[str] = field(default_factory=list)
    # Alias-aware fields
    involves_aliases: bool = False
    alias_chain: List[str] = field(default_factory=list)
    primary_variable: Optional[str] = None
    alias_variables: Set[str] = field(default_factory=set)


@dataclass
class MemoryFlowPath:
    """Memory flow path from source to sink."""
    source_function: str
    sink_function: str
    flow_type: MemoryFlowType
    path: List[str]
    confidence: float
    memory_states: Dict[str, MemoryState] = field(default_factory=dict)
    flow_details: List[Dict[str, Any]] = field(default_factory=list)


class MemorySafetyAnalyzer:
    """Enhanced analyzer for memory safety issues using value flow analysis with alias support."""
    
    def __init__(self, logger=None, language: str = "c"):
        """Initialize memory safety analyzer.
        
        Args:
            logger: Logger instance
            language: Programming language for tree-sitter parsing
        """
        self.logger = logger
        self.tree_sitter_utils = TreeSitterUtils(language)
        
        # Core components
        self.alias_analyzer = LocalMustAliasAnalyzer(logger)
        
        # Cache for analysis results
        self.flow_cache: Dict[Tuple[str, str], MemoryFlowResult] = {}
        self.path_cache: Dict[Tuple[str, str], List[MemoryFlowPath]] = {}
        self.alias_cache: Dict[str, Dict[str, Set[str]]] = {}
        self.memory_state_cache: Dict[str, Dict[str, AliasAwareMemoryState]] = {}
        
        # Memory operation patterns
        self._init_memory_patterns()
    
    def _init_memory_patterns(self):
        """Initialize patterns for memory operations."""
        
        # Functions that allocate memory
        self.allocating_functions = {
            'malloc', 'calloc', 'realloc', 'strdup', 'strndup',
            'asprintf', 'vasprintf', 'new', 'new[]'
        }
        
        # Functions that free memory
        self.freeing_functions = {
            'free', 'delete', 'delete[]'
        }
        
        # Functions that can return NULL
        # FIXME: if we set thses as "value flow sources", there may exist many false positives.
        # A more under-approximate approach is to set the explicit NULL as sources, e.g., 
        # a = NULL; return NULL;, etc.
        self.null_returning_functions = {
            'malloc', 'calloc', 'realloc', 'strdup', 'strndup',
            'asprintf', 'vasprintf', 'getenv', 'getcwd'
        }
        
        # Functions that dereference pointers
        self.dereferencing_functions = {
            'printf', 'fprintf', 'sprintf', 'snprintf',
            'strcpy', 'strcat', 'strcmp', 'strncmp',
            'memcpy', 'memmove', 'memset', 'memcmp'
        }
    
    def analyze_memory_flow(self, caller_summary: FunctionSummary,
                           callee_summary: FunctionSummary,
                           call_site: Dict[str, Any]) -> MemoryFlowResult:
        """Analyze memory flow between two functions.
        
        Args:
            caller_summary: Summary of the calling function
            callee_summary: Summary of the called function
            call_site: Information about the call site
            
        Returns:
            Memory flow analysis result
        """
        # Check cache first
        cache_key = (caller_summary.function_name, callee_summary.function_name)
        if cache_key in self.flow_cache:
            return self.flow_cache[cache_key]
        
        # Analyze different types of memory flows
        result = self._analyze_null_pointer_flow(caller_summary, callee_summary, call_site)
        if not result.can_flow:
            result = self._analyze_use_after_free_flow(caller_summary, callee_summary, call_site)
        if not result.can_flow:
            result = self._analyze_memory_leak_flow(caller_summary, callee_summary, call_site)
        
        # Cache result
        self.flow_cache[cache_key] = result
        return result
    
    def _analyze_null_pointer_flow(self, caller_summary: FunctionSummary,
                                  callee_summary: FunctionSummary,
                                  call_site: Dict[str, Any]) -> MemoryFlowResult:
        """Analyze null pointer flow."""
        
        # Check if callee can return NULL
        if callee_summary.function_name in self.null_returning_functions:
            return MemoryFlowResult(
                flow_type=MemoryFlowType.NULL_POINTER_FLOW,
                can_flow=True,
                confidence=0.9,
                explanation=f"Function {callee_summary.function_name} can return NULL",
                source_state=MemoryState.NULL,
                sink_state=MemoryState.UNKNOWN
            )
        
        # Check if callee dereferences parameters
        if callee_summary.function_name in self.dereferencing_functions:
            # Check if any parameter could be NULL
            for param in callee_summary.parameters:
                if param.may_be_null or not param.validates_input:
                    return MemoryFlowResult(
                        flow_type=MemoryFlowType.NULL_POINTER_FLOW,
                        can_flow=True,
                        confidence=0.7,
                        explanation=f"Function {callee_summary.function_name} dereferences parameter {param.name} without null check",
                        source_state=MemoryState.NULL,
                        sink_state=MemoryState.UNKNOWN
                    )
        
        return MemoryFlowResult(
            flow_type=MemoryFlowType.NULL_POINTER_FLOW,
            can_flow=False,
            confidence=0.8,
            explanation="No null pointer flow detected",
            source_state=MemoryState.UNKNOWN,
            sink_state=MemoryState.UNKNOWN
        )
    
    def _analyze_use_after_free_flow(self, caller_summary: FunctionSummary,
                                    callee_summary: FunctionSummary,
                                    call_site: Dict[str, Any]) -> MemoryFlowResult:
        """Analyze use-after-free flow."""
        
        # Check if callee frees memory
        if callee_summary.function_name in self.freeing_functions:
            return MemoryFlowResult(
                flow_type=MemoryFlowType.USE_AFTER_FREE,
                can_flow=True,
                confidence=0.9,
                explanation=f"Function {callee_summary.function_name} frees memory",
                source_state=MemoryState.ALLOCATED,
                sink_state=MemoryState.FREED
            )
        
        # Check if callee uses freed memory
        if callee_summary.function_name in self.dereferencing_functions:
            # Check if any parameter might have been freed
            for param in callee_summary.parameters:
                if param.may_be_freed:
                    return MemoryFlowResult(
                        flow_type=MemoryFlowType.USE_AFTER_FREE,
                        can_flow=True,
                        confidence=0.7,
                        explanation=f"Function {callee_summary.function_name} uses potentially freed parameter {param.name}",
                        source_state=MemoryState.FREED,
                        sink_state=MemoryState.UNKNOWN
                    )
        
        return MemoryFlowResult(
            flow_type=MemoryFlowType.USE_AFTER_FREE,
            can_flow=False,
            confidence=0.8,
            explanation="No use-after-free flow detected",
            source_state=MemoryState.UNKNOWN,
            sink_state=MemoryState.UNKNOWN
        )
    
    def _analyze_memory_leak_flow(self, caller_summary: FunctionSummary,
                                 callee_summary: FunctionSummary,
                                 call_site: Dict[str, Any]) -> MemoryFlowResult:
        """Analyze memory leak flow."""
        
        # Check if callee allocates memory
        if callee_summary.function_name in self.allocating_functions:
            return MemoryFlowResult(
                flow_type=MemoryFlowType.MEMORY_LEAK,
                can_flow=True,
                confidence=0.8,
                explanation=f"Function {callee_summary.function_name} allocates memory",
                source_state=MemoryState.UNKNOWN,
                sink_state=MemoryState.ALLOCATED
            )
        
        return MemoryFlowResult(
            flow_type=MemoryFlowType.MEMORY_LEAK,
            can_flow=False,
            confidence=0.8,
            explanation="No memory leak flow detected",
            source_state=MemoryState.UNKNOWN,
            sink_state=MemoryState.UNKNOWN
        )
    
    # ===== ALIAS-AWARE ANALYSIS METHODS =====
    
    def analyze_function_with_aliases(self, func_info: FunctionInfo, content: str) -> Dict[str, Any]:
        """Analyze a function with comprehensive alias analysis.
        
        Args:
            func_info: Function information
            content: Source code content
            
        Returns:
            Analysis results including alias-aware memory flows
        """
        if self.logger:
            self.logger.log(f"Analyzing function {func_info.name} with alias analysis...")
        
        # Get aliases for this function
        aliases = self._get_function_aliases(func_info, content)
        
        # Track memory states with aliases
        memory_states = self._track_memory_states_with_aliases(func_info, content, aliases)
        
        # Detect alias-aware vulnerabilities
        vulnerabilities = self._detect_aliasing_vulnerabilities(func_info, aliases, memory_states)
        
        return {
            'function_name': func_info.name,
            'aliases': aliases,
            'memory_states': memory_states,
            'vulnerabilities': vulnerabilities,
            'analysis_confidence': self._calculate_alias_analysis_confidence(aliases, memory_states)
        }
    
    def _get_function_aliases(self, func_info: FunctionInfo, content: str) -> Dict[str, Set[str]]:
        """Get alias relationships for a function."""
        cache_key = func_info.name
        if cache_key in self.alias_cache:
            return self.alias_cache[cache_key]
        
        # Analyze aliases using the alias analyzer
        aliases = self.alias_analyzer.analyze_function(func_info, content)
        
        # Cache results
        self.alias_cache[cache_key] = aliases
        
        if self.logger:
            self.logger.log(f"Found {len(aliases)} alias relationships in {func_info.name}")
        
        return aliases
    
    def _track_memory_states_with_aliases(self, func_info: FunctionInfo, content: str, 
                                        aliases: Dict[str, Set[str]]) -> Dict[str, AliasAwareMemoryState]:
        """Track memory states considering aliases."""
        memory_states = {}
        lines = content.split('\n')
        
        # Extract function lines
        func_lines = lines[func_info.start_line-1:func_info.end_line]
        
        for i, line in enumerate(func_lines, func_info.start_line):
            line = line.strip()
            
            # Track memory allocations
            if any(func in line for func in self.allocating_functions):
                var = self._extract_allocated_variable(line)
                if var:
                    # Create or update memory state for variable and its aliases
                    self._update_memory_state_for_aliases(
                        memory_states, var, aliases, MemoryState.ALLOCATED, i
                    )
            
            # Track memory deallocations
            elif any(func in line for func in self.freeing_functions):
                var = self._extract_freed_variable(line)
                if var:
                    # Update memory state for variable and its aliases
                    self._update_memory_state_for_aliases(
                        memory_states, var, aliases, MemoryState.FREED, i
                    )
            
            # Track NULL assignments
            elif '= NULL' in line or '= nullptr' in line:
                var = self._extract_null_assigned_variable(line)
                if var:
                    self._update_memory_state_for_aliases(
                        memory_states, var, aliases, MemoryState.NULL, i
                    )
        
        return memory_states
    
    def _update_memory_state_for_aliases(self, memory_states: Dict[str, AliasAwareMemoryState],
                                       var: str, aliases: Dict[str, Set[str]], 
                                       new_state: MemoryState, line_number: int):
        """Update memory state for a variable and all its aliases."""
        # Get all aliases for this variable
        var_aliases = aliases.get(var, {var})
        
        # Find existing memory state or create new one
        existing_state = None
        for existing_var, state in memory_states.items():
            if var in state.get_all_aliases() or any(alias in state.get_all_aliases() for alias in var_aliases):
                existing_state = state
                break
        
        if existing_state:
            # Update existing state
            existing_state.update_state_for_aliases(new_state, line_number)
            # Add new aliases if any
            for alias in var_aliases:
                existing_state.add_alias(alias)
        else:
            # Create new state
            new_memory_state = AliasAwareMemoryState(
                primary_var=var,
                aliases=var_aliases - {var},
                memory_state=new_state,
                confidence=0.9,
                line_number=line_number
            )
            memory_states[var] = new_memory_state
    
    def _detect_aliasing_vulnerabilities(self, func_info: FunctionInfo, 
                                       aliases: Dict[str, Set[str]], 
                                       memory_states: Dict[str, AliasAwareMemoryState]) -> List[MemoryFlowResult]:
        """Detect vulnerabilities considering aliases."""
        vulnerabilities = []
        lines = func_info.content.split('\n') if hasattr(func_info, 'content') else []
        
        for i, line in enumerate(lines, func_info.start_line):
            line = line.strip()
            
            # Check for use-after-free via aliases
            uaf_result = self._check_use_after_free_via_aliases(line, i, aliases, memory_states)
            if uaf_result:
                vulnerabilities.append(uaf_result)
            
            # Check for double-free via aliases
            df_result = self._check_double_free_via_aliases(line, i, aliases, memory_states)
            if df_result:
                vulnerabilities.append(df_result)
            
            # Check for null dereference via aliases
            nd_result = self._check_null_deref_via_aliases(line, i, aliases, memory_states)
            if nd_result:
                vulnerabilities.append(nd_result)
        
        return vulnerabilities
    
    def _check_use_after_free_via_aliases(self, line: str, line_number: int, 
                                        aliases: Dict[str, Set[str]], 
                                        memory_states: Dict[str, AliasAwareMemoryState]) -> Optional[MemoryFlowResult]:
        """Check for use-after-free via aliases."""
        # Look for memory usage operations
        usage_functions = ['strcpy', 'memcpy', 'strcat', 'sprintf', 'printf', 'strlen']
        
        for func in usage_functions:
            if func in line:
                used_var = self._extract_used_variable(line, func)
                if used_var:
                    # Check if this variable or any of its aliases was freed
                    var_aliases = aliases.get(used_var, {used_var})
                    
                    for var in var_aliases:
                        for state in memory_states.values():
                            if var in state.get_all_aliases() and state.memory_state == MemoryState.FREED:
                                return MemoryFlowResult(
                                    flow_type=MemoryFlowType.USE_AFTER_FREE_VIA_ALIAS,
                                    can_flow=True,
                                    confidence=0.9,
                                    explanation=f"Use-after-free via alias: {var} was freed at line {state.line_number} but {used_var} is used at line {line_number}",
                                    source_state=MemoryState.FREED,
                                    sink_state=MemoryState.UNKNOWN,
                                    involves_aliases=True,
                                    alias_chain=[var, used_var],
                                    primary_variable=state.primary_var,
                                    alias_variables=state.get_all_aliases()
                                )
        return None
    
    def _check_double_free_via_aliases(self, line: str, line_number: int, 
                                     aliases: Dict[str, Set[str]], 
                                     memory_states: Dict[str, AliasAwareMemoryState]) -> Optional[MemoryFlowResult]:
        """Check for double-free via aliases."""
        if 'free(' in line:
            freed_var = self._extract_freed_variable(line)
            if freed_var:
                var_aliases = aliases.get(freed_var, {freed_var})
                
                for var in var_aliases:
                    for state in memory_states.values():
                        if var in state.get_all_aliases() and state.memory_state == MemoryState.FREED:
                            return MemoryFlowResult(
                                flow_type=MemoryFlowType.DOUBLE_FREE_VIA_ALIAS,
                                can_flow=True,
                                confidence=0.95,
                                explanation=f"Double-free via alias: {var} was already freed at line {state.line_number} and freed again at line {line_number}",
                                source_state=MemoryState.FREED,
                                sink_state=MemoryState.FREED,
                                involves_aliases=True,
                                alias_chain=[var, freed_var],
                                primary_variable=state.primary_var,
                                alias_variables=state.get_all_aliases()
                            )
        return None
    
    def _check_null_deref_via_aliases(self, line: str, line_number: int, 
                                    aliases: Dict[str, Set[str]], 
                                    memory_states: Dict[str, AliasAwareMemoryState]) -> Optional[MemoryFlowResult]:
        """Check for null dereference via aliases."""
        # Look for dereference operations
        deref_functions = ['strcpy', 'memcpy', 'strcat', 'sprintf', 'printf', 'strlen', '*']
        
        for func in deref_functions:
            if func in line:
                used_var = self._extract_used_variable(line, func)
                if used_var:
                    var_aliases = aliases.get(used_var, {used_var})
                    
                    for var in var_aliases:
                        for state in memory_states.values():
                            if var in state.get_all_aliases() and state.memory_state == MemoryState.NULL:
                                return MemoryFlowResult(
                                    flow_type=MemoryFlowType.NULL_DEREF_VIA_ALIAS,
                                    can_flow=True,
                                    confidence=0.9,
                                    explanation=f"Null dereference via alias: {var} is NULL but {used_var} is dereferenced at line {line_number}",
                                    source_state=MemoryState.NULL,
                                    sink_state=MemoryState.UNKNOWN,
                                    involves_aliases=True,
                                    alias_chain=[var, used_var],
                                    primary_variable=state.primary_var,
                                    alias_variables=state.get_all_aliases()
                                )
        return None
    
    def _extract_allocated_variable(self, line: str) -> Optional[str]:
        """Extract variable name from allocation line using tree-sitter."""
        tree = self.tree_sitter_utils.parse_code(line)
        memory_ops = self.tree_sitter_utils.find_all_memory_operations(tree, line)
        
        for op in memory_ops:
            if op.type == "allocated":
                return op.name
        
        return None
    
    def _extract_freed_variable(self, line: str) -> Optional[str]:
        """Extract variable name from free line using tree-sitter."""
        tree = self.tree_sitter_utils.parse_code(line)
        memory_ops = self.tree_sitter_utils.find_all_memory_operations(tree, line)
        
        for op in memory_ops:
            if op.type == "freed":
                return op.name
        
        return None
    
    def _extract_null_assigned_variable(self, line: str) -> Optional[str]:
        """Extract variable name from NULL assignment using tree-sitter."""
        tree = self.tree_sitter_utils.parse_code(line)
        memory_ops = self.tree_sitter_utils.find_all_memory_operations(tree, line)
        
        for op in memory_ops:
            if op.type == "null_assigned":
                return op.name
        
        return None
    
    def _extract_used_variable(self, line: str, func: str) -> Optional[str]:
        """Extract variable name from usage line using tree-sitter."""
        tree = self.tree_sitter_utils.parse_code(line)
        usage = self.tree_sitter_utils.find_all_variable_usage(tree, line, [func])
        
        for var_info in usage:
            return var_info.name
        
        return None
    
    def _calculate_alias_analysis_confidence(self, aliases: Dict[str, Set[str]], 
                                           memory_states: Dict[str, AliasAwareMemoryState]) -> float:
        """Calculate confidence in alias analysis."""
        if not aliases and not memory_states:
            return 0.5
        
        # Higher confidence if we found aliases and can track memory states
        alias_confidence = min(0.9, 0.5 + len(aliases) * 0.1)
        state_confidence = min(0.9, 0.5 + len(memory_states) * 0.1)
        
        return (alias_confidence + state_confidence) / 2
    
    def find_memory_flow_paths(self, source_functions: List[str], sink_functions: List[str],
                              function_summaries: Dict[str, FunctionSummary],
                              call_graph: Dict[str, List[str]]) -> List[MemoryFlowPath]:
        """Find memory flow paths from sources to sinks."""
        
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
                    path_result = self._analyze_memory_flow_path(call_path, function_summaries)
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
    
    def _analyze_memory_flow_path(self, path: List[str], 
                                 function_summaries: Dict[str, FunctionSummary]) -> Optional[MemoryFlowPath]:
        """Analyze memory flow along a call path."""
        
        if len(path) < 2:
            return None
        
        total_confidence = 1.0
        flow_details = []
        memory_states = {}
        
        # Analyze each step in the path
        for i in range(len(path) - 1):
            caller = path[i]
            callee = path[i + 1]
            
            if caller not in function_summaries or callee not in function_summaries:
                continue
            
            caller_summary = function_summaries[caller]
            callee_summary = function_summaries[callee]
            
            # Analyze memory flow
            flow_result = self.analyze_memory_flow(caller_summary, callee_summary, {})
            
            if not flow_result.can_flow:
                return None  # Path is broken
            
            total_confidence *= flow_result.confidence
            
            flow_details.append({
                'caller': caller,
                'callee': callee,
                'flow_type': flow_result.flow_type.value,
                'confidence': flow_result.confidence,
                'explanation': flow_result.explanation
            })
            
            # Track memory states
            memory_states[caller] = flow_result.source_state
            memory_states[callee] = flow_result.sink_state
        
        return MemoryFlowPath(
            source_function=path[0],
            sink_function=path[-1],
            flow_type=flow_details[0]['flow_type'] if flow_details else MemoryFlowType.NULL_POINTER_FLOW,
            path=path,
            confidence=total_confidence,
            memory_states=memory_states,
            flow_details=flow_details
        )
    
    def detect_memory_vulnerabilities(self, memory_paths: List[MemoryFlowPath]) -> List[Vulnerability]:
        """Detect memory safety vulnerabilities from flow paths."""
        vulnerabilities = []
        
        for path in memory_paths:
            if path.confidence > 0.5:  # Only consider high-confidence paths
                vuln = self._create_vulnerability_from_memory_path(path)
                if vuln:
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _create_vulnerability_from_memory_path(self, path: MemoryFlowPath) -> Optional[Vulnerability]:
        """Create vulnerability from memory flow path."""
        
        # Determine vulnerability type
        vuln_type = self._determine_memory_vulnerability_type(path.flow_type)
        
        # Create location (would need function info in real implementation)
        location = CodeLocation(
            file_path="unknown",
            line_start=0,
            line_end=0
        )
        
        # Create vulnerability
        vulnerability = Vulnerability(
            vuln_type=vuln_type,
            severity=Severity.HIGH if path.confidence > 0.8 else Severity.MEDIUM,
            location=location,
            description=f"Memory safety issue: {path.flow_type.value} from {path.source_function} to {path.sink_function}",
            evidence=f"Path: {' -> '.join(path.path)} (confidence: {path.confidence:.2f})",
            confidence=path.confidence,
            recommendation=self._get_memory_safety_recommendation(path.flow_type)
        )
        
        return vulnerability
    
    def _determine_memory_vulnerability_type(self, flow_type: MemoryFlowType) -> VulnerabilityType:
        """Determine vulnerability type from memory flow type."""
        mapping = {
            MemoryFlowType.NULL_POINTER_FLOW: VulnerabilityType.NULL_POINTER_DEREF,
            MemoryFlowType.USE_AFTER_FREE: VulnerabilityType.USE_AFTER_FREE,
            MemoryFlowType.MEMORY_LEAK: VulnerabilityType.MEMORY_LEAK,
            MemoryFlowType.DOUBLE_FREE: VulnerabilityType.USE_AFTER_FREE,
            MemoryFlowType.BUFFER_OVERFLOW: VulnerabilityType.BUFFER_OVERFLOW,
            MemoryFlowType.UNINITIALIZED_USE: VulnerabilityType.NULL_POINTER_DEREF,
            # Alias-aware vulnerability types
            MemoryFlowType.USE_AFTER_FREE_VIA_ALIAS: VulnerabilityType.USE_AFTER_FREE,
            MemoryFlowType.DOUBLE_FREE_VIA_ALIAS: VulnerabilityType.USE_AFTER_FREE,
            MemoryFlowType.NULL_DEREF_VIA_ALIAS: VulnerabilityType.NULL_POINTER_DEREF
        }
        return mapping.get(flow_type, VulnerabilityType.BUFFER_OVERFLOW)
    
    def _get_memory_safety_recommendation(self, flow_type: MemoryFlowType) -> str:
        """Get recommendation for memory safety issue."""
        recommendations = {
            MemoryFlowType.NULL_POINTER_FLOW: "Add null pointer checks before dereferencing",
            MemoryFlowType.USE_AFTER_FREE: "Ensure memory is not used after being freed",
            MemoryFlowType.MEMORY_LEAK: "Ensure all allocated memory is properly freed",
            MemoryFlowType.DOUBLE_FREE: "Avoid calling free() on the same pointer twice",
            MemoryFlowType.BUFFER_OVERFLOW: "Add bounds checking before buffer operations",
            MemoryFlowType.UNINITIALIZED_USE: "Initialize variables before use",
            # Alias-aware recommendations
            MemoryFlowType.USE_AFTER_FREE_VIA_ALIAS: "Track pointer aliases and ensure aliases are not used after primary pointer is freed",
            MemoryFlowType.DOUBLE_FREE_VIA_ALIAS: "Avoid freeing the same memory through different aliases",
            MemoryFlowType.NULL_DEREF_VIA_ALIAS: "Check for null pointers before dereferencing, including through aliases"
        }
        return recommendations.get(flow_type, "Review memory usage patterns")
    
    def get_analysis_statistics(self) -> Dict[str, Any]:
        """Get statistics about the analysis."""
        total_analyses = len(self.flow_cache)
        
        flow_type_counts = {}
        for result in self.flow_cache.values():
            flow_type = result.flow_type.value
            flow_type_counts[flow_type] = flow_type_counts.get(flow_type, 0) + 1
        
        return {
            'total_analyses': total_analyses,
            'flow_type_distribution': flow_type_counts,
            'cache_hit_ratio': len(self.flow_cache) / (len(self.flow_cache) + len(self.path_cache))
        }
