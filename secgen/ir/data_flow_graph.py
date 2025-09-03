"""Data flow graph construction and analysis for taint propagation."""

import networkx as nx
import re
from typing import Dict, List, Set, Tuple, Optional, Any

from secgen.core.models import VulnerabilityType
from secgen.ir.models import DataFlowNode, TaintPath, DataFlowGraphNode, DataFlowGraphEdge


class DataFlowGraphBuilder:
    """Builds and manages data flow graphs for taint analysis."""
    
    def __init__(self, logger=None):
        """Initialize data flow graph builder.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger
        self.data_flow_graph = nx.DiGraph()
        self.taint_sources: Set[str] = set()
        self.taint_sinks: Set[str] = set()
        self.sanitizers: Set[str] = set()
        
        # Initialize known taint patterns
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
    
    def build_data_flow_graph(self, file_content: Dict[str, str]) -> nx.DiGraph:
        """Build data flow graph from source code.
        
        Args:
            file_content: Dictionary mapping file paths to their content
            
        Returns:
            NetworkX directed graph representing data flow
        """
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
        
        # Add edges based on data dependencies
        self._add_data_flow_edges(file_content)
        
        if self.logger:
            self.logger.log(f"Built data flow graph with {self.data_flow_graph.number_of_nodes()} nodes and {self.data_flow_graph.number_of_edges()} edges")
        
        return self.data_flow_graph
    
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
        # Extract variable names (simplified pattern)
        var_pattern = r'\b[a-zA-Z_][a-zA-Z0-9_]*\b'
        vars1 = set(re.findall(var_pattern, line1))
        vars2 = set(re.findall(var_pattern, line2))
        
        # Remove common keywords
        keywords = {'if', 'else', 'for', 'while', 'def', 'class', 'return', 'import'}
        vars1 -= keywords
        vars2 -= keywords
        
        return bool(vars1 & vars2)
    
    def find_taint_paths(self, source: str, sink: str) -> List[TaintPath]:
        """Find taint paths from source to sink.
        
        Args:
            source: Source node identifier
            sink: Sink node identifier
            
        Returns:
            List of taint paths
        """
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
    
    def analyze_data_flow(self, file_content: Dict[str, str]) -> List[TaintPath]:
        """Analyze data flow for taint propagation.
        
        Args:
            file_content: Dictionary mapping file paths to their content
            
        Returns:
            List of taint paths representing potential vulnerabilities
        """
        taint_paths = []
        
        # Build data flow graph
        self.build_data_flow_graph(file_content)
        
        # Find taint paths from sources to sinks
        for source_node in self.data_flow_graph.nodes():
            if self.data_flow_graph.nodes[source_node].get('type') == 'source':
                for sink_node in self.data_flow_graph.nodes():
                    if self.data_flow_graph.nodes[sink_node].get('type') == 'sink':
                        paths = self.find_taint_paths(source_node, sink_node)
                        taint_paths.extend(paths)
        
        return taint_paths
    
    def get_taint_sources(self) -> List[str]:
        """Get all taint source nodes in the graph.
        
        Returns:
            List of taint source node identifiers
        """
        return [node for node in self.data_flow_graph.nodes() 
                if self.data_flow_graph.nodes[node].get('type') == 'source']
    
    def get_taint_sinks(self) -> List[str]:
        """Get all taint sink nodes in the graph.
        
        Returns:
            List of taint sink node identifiers
        """
        return [node for node in self.data_flow_graph.nodes() 
                if self.data_flow_graph.nodes[node].get('type') == 'sink']
    
    def get_sanitizers(self) -> List[str]:
        """Get all sanitizer nodes in the graph.
        
        Returns:
            List of sanitizer node identifiers
        """
        return [node for node in self.data_flow_graph.nodes() 
                if self.data_flow_graph.nodes[node].get('type') == 'sanitizer']
    
    def is_tainted_path(self, path: List[str]) -> bool:
        """Check if a path contains tainted data flow.
        
        Args:
            path: List of node identifiers representing a path
            
        Returns:
            True if path contains tainted data flow, False otherwise
        """
        if not path:
            return False
        
        # Check if path starts with a taint source
        first_node = path[0]
        if self.data_flow_graph.nodes[first_node].get('type') != 'source':
            return False
        
        # Check if path ends with a taint sink
        last_node = path[-1]
        if self.data_flow_graph.nodes[last_node].get('type') != 'sink':
            return False
        
        # Check if path goes through any sanitizers
        for node in path[1:-1]:
            if self.data_flow_graph.nodes[node].get('type') == 'sanitizer':
                return False  # Sanitized path
        
        return True
    
    def get_data_flow_metrics(self) -> Dict[str, Any]:
        """Get metrics about the data flow graph.
        
        Returns:
            Dictionary with data flow graph metrics
        """
        if not self.data_flow_graph:
            return {}
        
        return {
            'num_nodes': self.data_flow_graph.number_of_nodes(),
            'num_edges': self.data_flow_graph.number_of_edges(),
            'num_sources': len(self.get_taint_sources()),
            'num_sinks': len(self.get_taint_sinks()),
            'num_sanitizers': len(self.get_sanitizers()),
            'is_connected': nx.is_weakly_connected(self.data_flow_graph),
            'num_components': nx.number_weakly_connected_components(self.data_flow_graph)
        }
