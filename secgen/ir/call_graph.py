"""Call graph construction and analysis for interprocedural analysis."""

import networkx as nx
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict

from secgen.core.models import FunctionInfo
from secgen.ir.models import CallSite, CallGraphNode, CallGraphEdge, CallGraphMetrics


class CallGraphBuilder:
    """Builds and manages call graphs for interprocedural analysis."""
    
    def __init__(self, logger=None):
        """Initialize call graph builder.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger
        self.call_graph = nx.DiGraph()
        self.functions: Dict[str, FunctionInfo] = {}
        self.call_sites: List[CallSite] = []
    
    def build_call_graph(self, functions: Dict[str, FunctionInfo]) -> nx.DiGraph:
        """Build interprocedural call graph.
        
        Args:
            functions: Dictionary of function information
            
        Returns:
            NetworkX directed graph representing call relationships
        """
        self.functions = functions
        self.call_graph.clear()
        self.call_sites.clear()
        
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
            A data class "CallGraphMetrics" with call graph metrics
        """
        if not self.call_graph:
            return CallGraphMetrics(
                num_nodes=0,
                num_edges=0,
                max_depth=0,
                cyclic_dependencies=[],
                strongly_connected_components=0,
                entry_points=[],
                leaf_nodes=[]
            )
        
        # Find entry points (functions with no incoming edges)
        entry_points = [node for node in self.call_graph.nodes() 
                       if self.call_graph.in_degree(node) == 0]
        
        # Find leaf nodes (functions with no outgoing edges)
        leaf_nodes = [node for node in self.call_graph.nodes() 
                     if self.call_graph.out_degree(node) == 0]
        
        return CallGraphMetrics(
            num_nodes=self.call_graph.number_of_nodes(),
            num_edges=self.call_graph.number_of_edges(),
            max_depth=self._calculate_max_depth(),
            cyclic_dependencies=list(nx.simple_cycles(self.call_graph)),
            strongly_connected_components=len(list(nx.strongly_connected_components(self.call_graph))),
            entry_points=entry_points,
            leaf_nodes=leaf_nodes
        )

    
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
    
    def get_call_sites_for_function(self, function_id: str) -> List[CallSite]:
        """Get all call sites for a specific function.
        
        Args:
            function_id: Function identifier
            
        Returns:
            List of call sites where this function is called
        """
        return [site for site in self.call_sites if site.callee == function_id]
    
    def get_functions_called_by(self, function_id: str) -> List[str]:
        """Get all functions called by a specific function.
        
        Args:
            function_id: Function identifier
            
        Returns:
            List of function identifiers called by this function
        """
        if function_id not in self.call_graph:
            return []
        
        return list(self.call_graph.successors(function_id))
    
    def get_functions_calling(self, function_id: str) -> List[str]:
        """Get all functions that call a specific function.
        
        Args:
            function_id: Function identifier
            
        Returns:
            List of function identifiers that call this function
        """
        if function_id not in self.call_graph:
            return []
        
        return list(self.call_graph.predecessors(function_id))
    
    def is_recursive(self, function_id: str) -> bool:
        """Check if a function is recursive.
        
        Args:
            function_id: Function identifier
            
        Returns:
            True if function is recursive, False otherwise
        """
        if function_id not in self.call_graph:
            return False
        
        # Check if function calls itself directly
        if function_id in self.call_graph.successors(function_id):
            return True
        
        # Check if function is part of a cycle
        try:
            cycles = nx.simple_cycles(self.call_graph)
            for cycle in cycles:
                if function_id in cycle:
                    return True
        except:
            pass
        
        return False
    
    def get_recursive_functions(self) -> List[str]:
        """Get all recursive functions in the call graph.
        
        Returns:
            List of recursive function identifiers
        """
        recursive_functions = []
        
        for func_id in self.call_graph.nodes():
            if self.is_recursive(func_id):
                recursive_functions.append(func_id)
        
        return recursive_functions
