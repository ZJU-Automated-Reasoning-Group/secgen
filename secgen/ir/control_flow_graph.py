"""Control Flow Graph construction and analysis for intraprocedural analysis."""

import networkx as nx
from typing import Dict, List, Set, Tuple, Optional, Any, Union
from collections import defaultdict, deque
import tree_sitter

from secgen.core.models import FunctionInfo
from secgen.ir.models import (
    BasicBlock, CFGNode, CFGEdge, ControlFlowType, CFGMetrics
)
from secgen.tsanalyzer.base import BaseTreeSitterAnalyzer


class CFGBuilder:
    """Builds and manages control flow graphs for intraprocedural analysis."""
    
    def __init__(self, logger=None):
        """Initialize CFG builder.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger
        self.cfg_graph = nx.DiGraph()
        self.basic_blocks: Dict[str, BasicBlock] = {}
        self.cfg_nodes: Dict[str, CFGNode] = {}
        self.cfg_edges: List[CFGEdge] = []
        self.analyzer = BaseTreeSitterAnalyzer("c")
        
    def build_cfg(self, function_info: FunctionInfo, source_code: str) -> nx.DiGraph:
        """Build control flow graph for a function.
        
        Args:
            function_info: Function information
            source_code: Source code content
            
        Returns:
            NetworkX directed graph representing control flow
        """
        self.cfg_graph.clear()
        self.basic_blocks.clear()
        self.cfg_nodes.clear()
        self.cfg_edges.clear()
        
        # Parse the function body
        tree = self.analyzer.parse_code(source_code)
        function_node = self._find_function_node(tree, function_info.name)
        
        if not function_node:
            if self.logger:
                self.logger.log(f"Function {function_info.name} not found in source code", "WARNING")
            return self.cfg_graph
            
        # Extract basic blocks
        basic_blocks = self._extract_basic_blocks(function_node, function_info, source_code)
        
        # Build CFG edges
        self._build_cfg_edges(basic_blocks, function_node, source_code)
        
        # Add nodes and edges to graph
        for block_id, block in self.basic_blocks.items():
            self.cfg_graph.add_node(block_id, block=block)
            
        for edge in self.cfg_edges:
            self.cfg_graph.add_edge(edge.source, edge.target, edge=edge)
            
        return self.cfg_graph
    
    def _find_function_node(self, tree: tree_sitter.Tree, function_name: str) -> Optional[tree_sitter.Node]:
        """Find function node by name."""
        for func_node in self.analyzer.find_nodes_by_type(tree.root_node, "function_definition"):
            declarator = self.analyzer._find_child_by_type(func_node, "function_declarator")
            if declarator:
                name = self.analyzer._extract_identifier(declarator, "")
                if name == function_name:
                    return func_node
        return None
    
    def _extract_basic_blocks(self, function_node: tree_sitter.Node, 
                            function_info: FunctionInfo, source_code: str) -> List[BasicBlock]:
        """Extract basic blocks from function body."""
        body = self.analyzer._find_child_by_type(function_node, "compound_statement")
        if not body:
            return []
            
        statements = self._get_statements(body)
        basic_blocks = []
        current_block = []
        
        for stmt in statements:
            stmt_text = self.analyzer.get_node_text(stmt, source_code)
            current_block.append(stmt_text)
            
            # Create new block for control flow statements
            if self._is_block_terminator(stmt) or self._is_block_starter(stmt):
                block_id = f"{function_info.name}_block_{len(basic_blocks)}"
                block = BasicBlock(
                    block_id=block_id,
                    function_id=function_info.name,
                    start_line=self.analyzer.get_line_number(stmt, source_code),
                    end_line=self.analyzer.get_line_number(stmt, source_code),
                    statements=current_block,
                    is_loop_header=self._is_loop_header(stmt)
                )
                basic_blocks.append(block)
                self.basic_blocks[block_id] = block
                self.cfg_nodes[block_id] = CFGNode(block_id=block_id, basic_block=block)
                current_block = []
        
        # Handle remaining statements
        if current_block:
            block_id = f"{function_info.name}_block_{len(basic_blocks)}"
            block = BasicBlock(
                block_id=block_id,
                function_id=function_info.name,
                start_line=function_info.start_line,
                end_line=function_info.end_line,
                statements=current_block
            )
            basic_blocks.append(block)
            self.basic_blocks[block_id] = block
            self.cfg_nodes[block_id] = CFGNode(block_id=block_id, basic_block=block)
        
        # Mark entry and exit
        if basic_blocks:
            basic_blocks[0].is_entry = True
            basic_blocks[-1].is_exit = True
            
        return basic_blocks
    
    def _get_statements(self, compound_stmt: tree_sitter.Node) -> List[tree_sitter.Node]:
        """Get all statements from compound statement."""
        statements = []
        for child in compound_stmt.children:
            if child.type in {
                "expression_statement", "if_statement", "while_statement", 
                "for_statement", "do_statement", "return_statement",
                "break_statement", "continue_statement", "goto_statement",
                "switch_statement", "case_statement", "default_statement",
                "compound_statement", "declaration"
            }:
                statements.append(child)
        return statements
    
    def _is_block_terminator(self, stmt: tree_sitter.Node) -> bool:
        """Check if statement terminates a basic block."""
        return stmt.type in {
            "return_statement", "break_statement", "continue_statement",
            "goto_statement", "if_statement", "while_statement", 
            "for_statement", "do_statement", "switch_statement"
        }
    
    def _is_block_starter(self, stmt: tree_sitter.Node) -> bool:
        """Check if statement starts a new basic block."""
        return stmt.type in {
            "if_statement", "while_statement", "for_statement", 
            "do_statement", "switch_statement", "case_statement", "default_statement"
        }
    
    def _is_loop_header(self, stmt: tree_sitter.Node) -> bool:
        """Check if statement is a loop header."""
        return stmt.type in {"while_statement", "for_statement", "do_statement"}
    
    def _is_loop_latch(self, stmt: tree_sitter.Node) -> bool:
        """Check if statement is a loop latch (increment/update)."""
        # This is a simplified check - in practice, you'd need more sophisticated analysis
        return stmt.type == "expression_statement" and "++" in str(stmt) or "--" in str(stmt)
    
    def _build_cfg_edges(self, basic_blocks: List[BasicBlock], 
                        function_node: tree_sitter.Node, source_code: str):
        """Build control flow edges between basic blocks."""
        if not basic_blocks:
            return
            
        # Build sequential edges
        for i in range(len(basic_blocks) - 1):
            current = basic_blocks[i]
            next_block = basic_blocks[i + 1]
            
            # Check if current block has control flow
            has_control_flow = any(keyword in stmt for stmt in current.statements 
                                 for keyword in ["if", "while", "for", "return", "break", "continue"])
            
            if not has_control_flow:
                self.cfg_edges.append(CFGEdge(
                    source=current.block_id,
                    target=next_block.block_id,
                    edge_type=ControlFlowType.SEQUENTIAL
                ))
            else:
                # Add conditional/loop edges
                for stmt in current.statements:
                    if "if" in stmt and i + 1 < len(basic_blocks):
                        self.cfg_edges.append(CFGEdge(
                            source=current.block_id,
                            target=basic_blocks[i + 1].block_id,
                            edge_type=ControlFlowType.CONDITIONAL_TRUE
                        ))
                    elif "while" in stmt or "for" in stmt:
                        if i + 1 < len(basic_blocks):
                            self.cfg_edges.append(CFGEdge(
                                source=current.block_id,
                                target=basic_blocks[i + 1].block_id,
                                edge_type=ControlFlowType.LOOP_ENTRY
                            ))
                        # Add back edge (simplified)
                        if i + 2 < len(basic_blocks):
                            self.cfg_edges.append(CFGEdge(
                                source=basic_blocks[i + 2].block_id,
                                target=current.block_id,
                                edge_type=ControlFlowType.LOOP_BACK
                            ))
    
    def compute_dominators(self) -> Dict[str, Set[str]]:
        """Compute dominators for all nodes."""
        dominators = {n: set(self.cfg_graph.nodes()) for n in self.cfg_graph.nodes()}
        
        # Entry nodes dominate only themselves
        for entry in [n for n in self.cfg_graph.nodes() if self.basic_blocks[n].is_entry]:
            dominators[entry] = {entry}
        
        # Iterative algorithm
        changed = True
        while changed:
            changed = False
            for node_id in self.cfg_graph.nodes():
                if self.basic_blocks[node_id].is_entry:
                    continue
                    
                new_doms = {node_id}
                preds = list(self.cfg_graph.predecessors(node_id))
                if preds:
                    new_doms.update(set.intersection(*[dominators[p] for p in preds]))
                
                if new_doms != dominators[node_id]:
                    dominators[node_id] = new_doms
                    changed = True
        
        return dominators
    
    def find_loops(self) -> List[Tuple[str, str, Set[str]]]:
        """Find natural loops in the CFG."""
        loops = []
        for edge in self.cfg_edges:
            if edge.edge_type == ControlFlowType.LOOP_BACK:
                # Find loop nodes using DFS
                loop_nodes = {edge.target, edge.source}
                stack = [edge.source]
                visited = {edge.target}
                
                while stack:
                    current = stack.pop()
                    if current not in visited:
                        visited.add(current)
                        loop_nodes.add(current)
                        stack.extend(self.cfg_graph.predecessors(current))
                
                loops.append((edge.target, edge.source, loop_nodes))
        return loops
    
    def compute_metrics(self) -> CFGMetrics:
        """Compute CFG metrics."""
        num_blocks = len(self.basic_blocks)
        num_edges = len(self.cfg_edges)
        num_components = nx.number_weakly_connected_components(self.cfg_graph)
        
        return CFGMetrics(
            num_blocks=num_blocks,
            num_edges=num_edges,
            cyclomatic_complexity=num_edges - num_blocks + 2 * num_components,
            max_depth=len(self.basic_blocks),  # Simplified
            num_loops=len([e for e in self.cfg_edges if e.edge_type in {
                ControlFlowType.LOOP_ENTRY, ControlFlowType.LOOP_BACK
            }]),
            num_conditionals=len([e for e in self.cfg_edges if e.edge_type in {
                ControlFlowType.CONDITIONAL_TRUE, ControlFlowType.CONDITIONAL_FALSE
            }]),
            entry_blocks=[b.block_id for b in self.basic_blocks.values() if b.is_entry],
            exit_blocks=[b.block_id for b in self.basic_blocks.values() if b.is_exit],
            loop_headers=[b.block_id for b in self.basic_blocks.values() if b.is_loop_header],
            strongly_connected_components=num_components
        )
    
    def get_all_paths(self, source: str, target: str) -> List[List[str]]:
        """Get all simple paths from source to target."""
        try:
            return list(nx.all_simple_paths(self.cfg_graph, source, target))
        except nx.NetworkXNoPath:
            return []
    
    def is_reachable(self, source: str, target: str) -> bool:
        """Check if target is reachable from source."""
        return nx.has_path(self.cfg_graph, source, target)
    
    def visualize(self, output_file: str = None) -> str:
        """Generate DOT representation of the CFG."""
        dot = "digraph CFG {\n  rankdir=TB;\n  node [shape=box];\n"
        
        # Add nodes
        for block_id, block in self.basic_blocks.items():
            label = f"Block {block_id}\\nLines {block.start_line}-{block.end_line}"
            if block.is_entry:
                label += "\\n[ENTRY]"
            if block.is_exit:
                label += "\\n[EXIT]"
            if block.is_loop_header:
                label += "\\n[LOOP HEADER]"
            dot += f'  "{block_id}" [label="{label}"];\n'
        
        # Add edges
        for edge in self.cfg_edges:
            style = ""
            if edge.edge_type == ControlFlowType.CONDITIONAL_TRUE:
                style = ' [label="T", color="green"]'
            elif edge.edge_type == ControlFlowType.CONDITIONAL_FALSE:
                style = ' [label="F", color="red"]'
            elif edge.edge_type == ControlFlowType.LOOP_BACK:
                style = ' [color="blue", style="dashed"]'
            dot += f'  "{edge.source}" -> "{edge.target}"{style};\n'
        
        dot += "}\n"
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(dot)
        
        return dot

