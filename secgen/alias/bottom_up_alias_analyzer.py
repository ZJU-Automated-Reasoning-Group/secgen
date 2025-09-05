"""Bottom-up modular alias analysis system.

This module implements true modular alias analysis where each function is treated
as a "module" and analysis proceeds bottom-up from leaf functions to callers.
"""

from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum
import networkx as nx

from secgen.core.models import FunctionInfo, CodeLocation
from secgen.core.variable_reference import VariableReference, VariableScope, VariableReferenceExtractor
from secgen.tsanalyzer import TreeSitterUtils


class AliasOperationType(Enum):
    """Types of alias operations."""
    ASSIGNMENT = "assignment"           # x = y
    POINTER_TAKE = "pointer_take"       # x = &y
    POINTER_DEREF = "pointer_deref"     # x = *y
    FIELD_ACCESS = "field_access"       # x = obj.field
    ARRAY_ACCESS = "array_access"       # x = arr[i]
    FUNCTION_CALL = "function_call"     # x = func(y)
    PARAMETER_PASS = "parameter_pass"   # func(x)
    RETURN_VALUE = "return_value"       # return x


@dataclass
class AliasOperation:
    """Represents a single alias operation."""
    op_type: AliasOperationType
    lhs: VariableReference      # Left-hand side variable reference
    rhs: VariableReference      # Right-hand side variable reference
    location: CodeLocation      # Where this operation occurs
    confidence: float = 1.0     # Confidence in this operation
    context: Dict[str, Any] = field(default_factory=dict)  # Additional context
    
    def __str__(self) -> str:
        return f"{self.lhs} = {self.rhs} [{self.op_type.value}]"


@dataclass
class AliasNode:
    """Represents a variable in the alias graph."""
    variable_ref: VariableReference  # Precise variable reference
    var_type: str = "variable"  # variable, pointer, field, array_element
    attributes: Dict[str, Any] = field(default_factory=dict)
    
    def __hash__(self):
        return hash(self.variable_ref.unique_id)
    
    def __eq__(self, other):
        return isinstance(other, AliasNode) and self.variable_ref.unique_id == other.variable_ref.unique_id


@dataclass
class AliasEdge:
    """Represents an alias relationship between two nodes."""
    source: VariableReference
    target: VariableReference
    operation: AliasOperation
    weight: float = 1.0
    transitive: bool = False  # Whether this is a transitive relationship


class AliasGraph:
    """Graph representation of alias relationships."""
    
    def __init__(self):
        self.nodes: Dict[str, AliasNode] = {}  # keyed by unique_id
        self.edges: List[AliasEdge] = []
        self.graph = nx.DiGraph()
        self._alias_sets: Dict[str, Set[str]] = {}
        self._transitive_closure: Optional[Dict[str, Set[str]]] = None
    
    def add_node(self, node: AliasNode):
        """Add a node to the graph."""
        self.nodes[node.variable_ref.unique_id] = node
        self.graph.add_node(node.variable_ref.unique_id, **node.attributes)
    
    def add_edge(self, edge: AliasEdge):
        """Add an edge to the graph."""
        self.edges.append(edge)
        self.graph.add_edge(edge.source.unique_id, edge.target.unique_id, 
                          operation=edge.operation, weight=edge.weight)
        self._invalidate_cache()
    
    def get_aliases(self, var_ref: VariableReference) -> Set[VariableReference]:
        """Get all variables that alias with the given variable reference."""
        if self._transitive_closure is None:
            self._compute_transitive_closure()
        
        alias_ids = self._transitive_closure.get(var_ref.unique_id, {var_ref.unique_id})
        return {self.nodes[alias_id].variable_ref for alias_id in alias_ids if alias_id in self.nodes}
    
    def are_aliases(self, var1: VariableReference, var2: VariableReference) -> bool:
        """Check if two variables are aliases."""
        aliases = self.get_aliases(var1)
        return var2 in aliases
    
    def get_alias_sets(self) -> List[Set[str]]:
        """Get all alias sets (connected components)."""
        if self._alias_sets:
            return list(self._alias_sets.values())
        
        # Find connected components
        undirected = self.graph.to_undirected()
        components = nx.connected_components(undirected)
        
        alias_sets = []
        for component in components:
            if len(component) > 1:  # Only non-trivial sets
                alias_sets.append(set(component))
        
        self._alias_sets = {f"set_{i}": s for i, s in enumerate(alias_sets)}
        return alias_sets
    
    def _compute_transitive_closure(self):
        """Compute transitive closure of alias relationships."""
        self._transitive_closure = {}
        
        # For each node, find all reachable nodes
        for node in self.graph.nodes():
            reachable = set()
            # BFS to find all reachable nodes
            queue = deque([node])
            visited = set()
            
            while queue:
                current = queue.popleft()
                if current in visited:
                    continue
                visited.add(current)
                reachable.add(current)
                
                # Add all neighbors (both incoming and outgoing)
                for neighbor in self.graph.neighbors(current):
                    if neighbor not in visited:
                        queue.append(neighbor)
                for predecessor in self.graph.predecessors(current):
                    if predecessor not in visited:
                        queue.append(predecessor)
            
            self._transitive_closure[node] = reachable
    
    def _invalidate_cache(self):
        """Invalidate cached computations."""
        self._transitive_closure = None
        self._alias_sets = {}


@dataclass
class FunctionModule:
    """Represents a function as a module in the bottom-up analysis."""
    function_info: FunctionInfo
    local_aliases: Dict[str, Set[VariableReference]] = field(default_factory=dict)  # var_id -> aliases
    input_aliases: Dict[str, Set[VariableReference]] = field(default_factory=dict)  # param_id -> aliases
    output_aliases: Dict[str, Set[VariableReference]] = field(default_factory=dict)  # return_id -> aliases
    operations: List[AliasOperation] = field(default_factory=list)
    analyzed: bool = False
    dependencies: Set[str] = field(default_factory=set)  # functions this depends on
    variable_references: Dict[str, VariableReference] = field(default_factory=dict)  # unique_id -> var_ref
    
    def get_all_aliases(self, var_ref: VariableReference) -> Set[VariableReference]:
        """Get all aliases for a variable reference in this module."""
        aliases = {var_ref}
        aliases.update(self.local_aliases.get(var_ref.unique_id, set()))
        aliases.update(self.input_aliases.get(var_ref.unique_id, set()))
        aliases.update(self.output_aliases.get(var_ref.unique_id, set()))
        return aliases


@dataclass
class ModuleAnalysisResult:
    """Result of analyzing a function module."""
    module: FunctionModule
    new_aliases: Dict[str, Set[VariableReference]]  # newly discovered aliases
    propagated_aliases: Dict[str, Set[VariableReference]]  # aliases propagated from dependencies
    confidence: float = 1.0


class BottomUpAliasAnalyzer:
    """Bottom-up modular alias analyzer using functions as modules."""
    
    def __init__(self, symbol_analyzer=None, code_extractor=None, language: str = "c"):
        self.symbol_analyzer = symbol_analyzer
        self.code_extractor = code_extractor
        self.variable_extractor = VariableReferenceExtractor("c", symbol_analyzer)
        self.tree_sitter_utils = TreeSitterUtils(language)
        
        # Module management
        self.function_modules: Dict[str, FunctionModule] = {}
        self.call_graph: nx.DiGraph = nx.DiGraph()
        self.analysis_order: List[str] = []
        
        # Analysis state
        self.global_aliases: Dict[str, Set[VariableReference]] = defaultdict(set)
        self.analysis_results: Dict[str, ModuleAnalysisResult] = {}
    
    def add_function_module(self, function_info: FunctionInfo, code: str) -> FunctionModule:
        """Add a function as a module to the analysis."""
        module = FunctionModule(function_info=function_info)
        
        # Extract variable references using tree-sitter
        if self.symbol_analyzer:
            try:
                tree = self.symbol_analyzer.parse_code(code)
                variable_references = self.variable_extractor.extract_variable_references(tree, code, function_info.file_path)
                module.variable_references = variable_references
            except Exception as e:
                # Fallback to simple analysis
                pass
        
        # Analyze the function locally first
        self._analyze_function_locally(module, code)
        
        # Store the module
        self.function_modules[function_info.name] = module
        
        # Add to call graph
        self.call_graph.add_node(function_info.name)
        
        return module
    
    def _analyze_function_locally(self, module: FunctionModule, code: str):
        """Analyze a function module locally (without interprocedural effects)."""
        function_info = module.function_info
        
        # Use tree-sitter AST analysis for robust assignment detection
        if self.symbol_analyzer:
            try:
                analysis_results = self.symbol_analyzer.analyze_file(code, function_info.file_path)
                self._extract_local_aliases_from_ast(module, analysis_results, code)
            except Exception as e:
                print(f"DEBUG: AST analysis failed for {function_info.name}: {e}")
                # Fallback to pattern matching if AST analysis fails
                self._extract_local_aliases_from_patterns(module, code)
        else:
            # Fallback to pattern matching if no symbol analyzer available
            self._extract_local_aliases_from_patterns(module, code)
    
    def _extract_local_aliases_from_ast(self, module: FunctionModule, analysis_results, code: str):
        """Extract local aliases from AST analysis results."""
        # Extract function calls to build dependencies
        function_calls = analysis_results.calls
        for call in function_calls:
            if hasattr(call, 'name'):
                module.dependencies.add(call.name)
                self.call_graph.add_edge(module.function_info.name, call.name)
        
        # Extract assignment operations from AST
        assignments = analysis_results.assignments
        for assignment in assignments:
            if hasattr(assignment, 'lhs') and hasattr(assignment, 'rhs'):
                # Find or create variable references
                lhs_ref = self._find_or_create_variable_reference(
                    module, assignment.lhs, assignment.line_number, module.function_info.file_path
                )
                rhs_ref = self._find_or_create_variable_reference(
                    module, assignment.rhs, assignment.line_number, module.function_info.file_path
                )
                
                if lhs_ref and rhs_ref:
                    location = CodeLocation(
                        file_path=module.function_info.file_path,
                        line_start=assignment.line_number,
                        line_end=assignment.line_number
                    )
                    
                    operation = AliasOperation(
                        op_type=AliasOperationType.ASSIGNMENT,
                        lhs=lhs_ref,
                        rhs=rhs_ref,
                        location=location,
                        confidence=0.9  # High confidence for AST-based detection
                    )
                    module.operations.append(operation)
        
        # Build aliases from variable references
        self._build_local_aliases_from_variable_references(module)
    
    def _extract_local_aliases_from_patterns(self, module: FunctionModule, code: str):
        """Extract local aliases using pattern matching (fallback)."""
        lines = code.split('\n')
        function_info = module.function_info
        
        for i, line in enumerate(lines[function_info.start_line-1:function_info.end_line], function_info.start_line):
            line = line.strip()
            if not line or line.startswith('//'):
                continue
            
            # Look for assignment patterns
            if '=' in line:
                assignment_ops = self._parse_assignment_pattern(line, function_info, i, module)
                module.operations.extend(assignment_ops)
                
                # Build alias relationships from assignments
                for op in assignment_ops:
                    if op.op_type == AliasOperationType.ASSIGNMENT:
                        module.local_aliases.setdefault(op.lhs.unique_id, set()).add(op.rhs)
                        module.local_aliases.setdefault(op.rhs.unique_id, set()).add(op.lhs)
    
    def _parse_assignment_pattern(self, line: str, function_info: FunctionInfo, line_number: int, module: FunctionModule) -> List[AliasOperation]:
        """Parse assignment patterns in a line."""
        operations = []
        
        # Look for assignment patterns with or without spaces around =
        if '=' in line and not any(op in line for op in ['&', '*', '->', '.', '[', '==', '!=']):
            # Split on = and handle both ' = ' and '=' patterns
            if ' = ' in line:
                parts = line.split(' = ', 1)
            else:
                parts = line.split('=', 1)
            
            if len(parts) == 2:
                lhs_name = parts[0].strip()
                rhs_name = parts[1].strip().rstrip(';')
                
                # Remove comments and semicolon from rhs
                if '//' in rhs_name:
                    rhs_name = rhs_name.split('//')[0].strip()
                rhs_name = rhs_name.rstrip(';').strip()
                
                # Remove type declarations from lhs (e.g., "int local_x" -> "local_x")
                lhs_name = self._extract_variable_name(lhs_name)
                
                # Only process if both sides are valid variable names (not literals)
                if (self._is_valid_variable_name(lhs_name) and 
                    self._is_valid_variable_name(rhs_name) and
                    lhs_name != rhs_name and
                    not rhs_name.isdigit()):  # Skip numeric literals
                    
                    # Find or create variable references
                    lhs_ref = self._find_or_create_variable_reference(module, lhs_name, line_number, function_info.file_path)
                    rhs_ref = self._find_or_create_variable_reference(module, rhs_name, line_number, function_info.file_path)
                    
                    if lhs_ref and rhs_ref:
                        location = CodeLocation(
                            file_path=function_info.file_path,
                            line_start=line_number,
                            line_end=line_number
                        )
                        
                        operations.append(AliasOperation(
                            op_type=AliasOperationType.ASSIGNMENT,
                            lhs=lhs_ref,
                            rhs=rhs_ref,
                            location=location,
                            confidence=0.8
                        ))
        
        return operations
    
    def _extract_variable_name(self, declaration: str) -> str:
        """Extract variable name from declaration using tree-sitter."""
        tree = self.tree_sitter_utils.parse_code(declaration)
        
        # Look for identifier nodes
        for node in self.tree_sitter_utils.find_nodes_by_type(tree.root_node, "identifier"):
            var_name = self.tree_sitter_utils.get_node_text(node, declaration)
            if self.tree_sitter_utils.is_valid_identifier(var_name):
                return var_name
        
        # If no valid identifier found, return the original string
        return declaration.strip()
    
    def _is_valid_variable_name(self, name: str) -> bool:
        """Check if a string is a valid variable name using tree-sitter."""
        return self.tree_sitter_utils.is_valid_identifier(name)
    
    def _build_local_aliases_from_symbols(self, module: FunctionModule, symbol_table: Dict):
        """Build local aliases from symbol table information using tree-sitter."""
        # Use tree-sitter to find actual assignment relationships
        if not hasattr(module, 'source_code') or not module.source_code:
            return
        
        tree = self.tree_sitter_utils.parse_code(module.source_code)
        assignments = self.tree_sitter_utils.find_all_assignments(tree, module.source_code)
        
        # Build aliases from actual assignments
        for assignment in assignments:
            lhs_name = assignment.lhs
            rhs_name = assignment.rhs
            
            # Only process if both sides are valid variable names
            if (self.tree_sitter_utils.is_valid_identifier(lhs_name) and 
                self.tree_sitter_utils.is_valid_identifier(rhs_name) and
                lhs_name != rhs_name and
                not rhs_name.isdigit()):  # Skip numeric literals
                
                # Create alias relationship
                module.local_aliases.setdefault(lhs_name, set()).add(rhs_name)
                module.local_aliases.setdefault(rhs_name, set()).add(lhs_name)
    
    def analyze_bottom_up(self) -> Dict[str, ModuleAnalysisResult]:
        """Perform bottom-up analysis of all function modules."""
        # Determine analysis order (topological sort of call graph)
        try:
            self.analysis_order = list(nx.topological_sort(self.call_graph))
        except (nx.NetworkXError, nx.NetworkXUnfeasible):
            # If there are cycles or other issues, use a simple ordering
            self.analysis_order = list(self.function_modules.keys())
        
        # Analyze modules in bottom-up order
        for function_name in self.analysis_order:
            if function_name in self.function_modules:
                result = self._analyze_module_bottom_up(function_name)
                self.analysis_results[function_name] = result
        
        return self.analysis_results
    
    def _analyze_module_bottom_up(self, function_name: str) -> ModuleAnalysisResult:
        """Analyze a single module in bottom-up fashion."""
        module = self.function_modules[function_name]
        
        # Get aliases from dependencies (callees)
        propagated_aliases = self._get_aliases_from_dependencies(module)
        
        # Combine with local aliases
        new_aliases = self._combine_aliases(module, propagated_aliases)
        
        # Update module with new aliases
        self._update_module_aliases(module, new_aliases)
        
        # Mark as analyzed
        module.analyzed = True
        
        return ModuleAnalysisResult(
            module=module,
            new_aliases=new_aliases,
            propagated_aliases=propagated_aliases,
            confidence=1.0
        )
    
    def _get_aliases_from_dependencies(self, module: FunctionModule) -> Dict[str, Set[VariableReference]]:
        """Get aliases propagated from dependency modules."""
        propagated = defaultdict(set)
        
        for dep_name in module.dependencies:
            if dep_name in self.analysis_results:
                dep_result = self.analysis_results[dep_name]
                dep_module = dep_result.module
                
                # Propagate output aliases from dependency
                for var_id, aliases in dep_module.output_aliases.items():
                    propagated[var_id].update(aliases)
                
                # Propagate global aliases
                for var_id, aliases in dep_module.local_aliases.items():
                    # Check if this variable corresponds to a parameter in current module
                    for param in module.function_info.parameters:
                        if any(var_ref.name == param for var_ref in module.variable_references.values()):
                            propagated[var_id].update(aliases)
        
        return dict(propagated)
    
    def _combine_aliases(self, module: FunctionModule, propagated_aliases: Dict[str, Set[VariableReference]]) -> Dict[str, Set[VariableReference]]:
        """Combine local and propagated aliases."""
        combined = defaultdict(set)
        
        # Start with local aliases
        for var_id, aliases in module.local_aliases.items():
            combined[var_id].update(aliases)
        
        # Add propagated aliases
        for var_id, aliases in propagated_aliases.items():
            combined[var_id].update(aliases)
        
        # Transitive closure within the module
        for var_id in combined:
            self._compute_transitive_closure(combined, var_id)
        
        return dict(combined)
    
    def _compute_transitive_closure(self, aliases: Dict[str, Set[VariableReference]], var_id: str):
        """Compute transitive closure for a variable's aliases."""
        visited = set()
        to_visit = {var_id}
        
        while to_visit:
            current = to_visit.pop()
            if current in visited:
                continue
            
            visited.add(current)
            
            # Add all aliases of current variable
            if current in aliases:
                for alias in aliases[current]:
                    if alias.unique_id not in visited:
                        to_visit.add(alias.unique_id)
                        aliases[var_id].add(alias)
    
    def _update_module_aliases(self, module: FunctionModule, new_aliases: Dict[str, Set[VariableReference]]):
        """Update module with new alias information."""
        # Update local aliases
        for var_id, aliases in new_aliases.items():
            module.local_aliases[var_id] = aliases.copy()
        
        # Update input aliases (parameters)
        for param in module.function_info.parameters:
            # Find variable reference for this parameter
            param_var_ref = None
            for var_ref in module.variable_references.values():
                if var_ref.name == param and var_ref.scope == VariableScope.FUNCTION_PARAMETER:
                    param_var_ref = var_ref
                    break
            
            if param_var_ref and param_var_ref.unique_id in new_aliases:
                module.input_aliases[param_var_ref.unique_id] = new_aliases[param_var_ref.unique_id].copy()
        
        # Update output aliases (return values)
        # This would need more sophisticated analysis to determine return value aliases
        # For now, we'll use a simple heuristic
        for var_id, aliases in new_aliases.items():
            if var_id in module.variable_references:
                var_ref = module.variable_references[var_id]
                if var_ref.scope == VariableScope.FUNCTION_PARAMETER:
                    module.output_aliases[var_id] = aliases.copy()
    
    def get_aliases(self, var_ref: VariableReference, function: str = None) -> Set[VariableReference]:
        """Get aliases for a variable reference, considering interprocedural effects."""
        if function and function in self.function_modules:
            module = self.function_modules[function]
            return module.get_all_aliases(var_ref)
        
        # Global aliases
        return self.global_aliases.get(var_ref.unique_id, {var_ref})
    
    def are_aliases(self, var1: VariableReference, var2: VariableReference, function: str = None) -> bool:
        """Check if two variables are aliases."""
        aliases = self.get_aliases(var1, function)
        return var2 in aliases
    
    def get_module_aliases(self, function: str) -> Dict[str, Set[VariableReference]]:
        """Get all aliases for a specific function module."""
        if function in self.function_modules:
            module = self.function_modules[function]
            return module.local_aliases.copy()
        return {}
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get summary of the bottom-up analysis."""
        summary = {
            'total_modules': len(self.function_modules),
            'analyzed_modules': sum(1 for m in self.function_modules.values() if m.analyzed),
            'call_graph_nodes': self.call_graph.number_of_nodes(),
            'call_graph_edges': self.call_graph.number_of_edges(),
            'analysis_order': self.analysis_order,
            'modules': {}
        }
        
        for name, module in self.function_modules.items():
            summary['modules'][name] = {
                'analyzed': module.analyzed,
                'local_aliases_count': len(module.local_aliases),
                'operations_count': len(module.operations),
                'dependencies': list(module.dependencies)
            }
        
        return summary
    
    def _find_variable_reference_by_name(self, module: FunctionModule, name: str) -> Optional[VariableReference]:
        """Find variable reference by name in module."""
        for var_ref in module.variable_references.values():
            if var_ref.name == name:
                return var_ref
        return None
    
    def _find_or_create_variable_reference(self, module: FunctionModule, name: str, 
                                         line_number: int, file_path: str) -> Optional[VariableReference]:
        """Find existing or create new variable reference."""
        # First try to find existing
        existing = self._find_variable_reference_by_name(module, name)
        if existing:
            return existing
        
        # Create new variable reference
        from secgen.core.variable_reference import VariableScope
        var_ref = VariableReference(
            name=name,
            scope=VariableScope.LOCAL_VARIABLE,
            function_name=module.function_info.name,
            source_location=(file_path, line_number, line_number, 0)
        )
        
        module.variable_references[var_ref.unique_id] = var_ref
        return var_ref
    
    def _build_local_aliases_from_variable_references(self, module: FunctionModule):
        """Build local aliases from variable references and operations."""
        # Build aliases from assignment operations only
        for operation in module.operations:
            if operation.op_type == AliasOperationType.ASSIGNMENT:
                # Create bidirectional alias relationship
                module.local_aliases.setdefault(operation.lhs.unique_id, set()).add(operation.rhs)
                module.local_aliases.setdefault(operation.rhs.unique_id, set()).add(operation.lhs)
        
        # Remove the proximity heuristic as it creates false positives
        # Only use actual assignment operations to determine aliases
