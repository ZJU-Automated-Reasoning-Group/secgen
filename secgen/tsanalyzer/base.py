"""Base tree-sitter utilities and common functionality."""

import tree_sitter
from tree_sitter import Language, Parser
from typing import Dict, List, Optional, Set, Any, Union
from pathlib import Path

from .models import SymbolInfo, VariableInfo, AssignmentInfo


class BaseTreeSitterAnalyzer:
    """Base class for tree-sitter based analyzers."""
    
    def __init__(self, language_name: str):
        self.language_name = language_name
        self.parser = Parser()
        self._setup_language()
        
        # Memory operation functions
        self.allocation_funcs = {'malloc', 'calloc', 'realloc', 'new'}
        self.deallocation_funcs = {'free', 'delete'}
        self.dangerous_funcs = {'strcpy', 'strcat', 'sprintf', 'gets', 'scanf'}
    
    def _setup_language(self):
        """Setup tree-sitter language."""
        cwd = Path(__file__).resolve().parent.parent.parent.absolute()
        language_path = cwd / "lib/build/my-languages.so"
        
        try:
            if self.language_name.lower() in ["cpp", "c++"]:
                self.language = Language(str(language_path), 'cpp')
            elif self.language_name.lower() == "c":
                self.language = Language(str(language_path), "c")
            elif self.language_name.lower() == "python":
                self.language = Language(str(language_path), "python")
            else:
                raise ValueError(f"Unsupported language: {self.language_name}")
        except:
            raise RuntimeError("Tree-sitter language not found. Please build the language bindings.")
        
        self.parser.set_language(self.language)
    
    def parse_code(self, source_code: str) -> tree_sitter.Tree:
        """Parse source code and return AST."""
        return self.parser.parse(bytes(source_code, "utf8"))
    
    # Utility methods
    def get_line_number(self, node: tree_sitter.Node, source_code: str) -> int:
        """Get line number for a node."""
        return source_code[:node.start_byte].count('\n') + 1
    
    def get_node_text(self, node: tree_sitter.Node, source_code: str) -> str:
        """Get text content of a node."""
        return source_code[node.start_byte:node.end_byte]
    
    def find_nodes_by_type(self, root: tree_sitter.Node, node_type: Union[str, Set[str]]) -> List[tree_sitter.Node]:
        """Find all nodes of specific type(s)."""
        nodes = []
        types = {node_type} if isinstance(node_type, str) else node_type
        
        def traverse(node):
            if node.type in types:
                nodes.append(node)
            for child in node.children:
                traverse(child)
        
        traverse(root)
        return nodes
    
    def _find_child_by_type(self, node: tree_sitter.Node, node_type: str) -> Optional[tree_sitter.Node]:
        """Find first child of specific type."""
        for child in node.children:
            if child.type == node_type:
                return child
        return None
    
    def _extract_identifier_from_node(self, node: tree_sitter.Node, source_code: str) -> Optional[str]:
        """Extract identifier from a node, handling various node types."""
        if node.type == "identifier":
            return self.get_node_text(node, source_code)
        elif node.type == "declarator":
            # For declarators, find the identifier child
            for child in node.children:
                if child.type == "identifier":
                    return self.get_node_text(child, source_code)
        elif node.type == "parenthesized_declarator":
            # For parenthesized declarators, recurse
            for child in node.children:
                if child.type == "declarator":
                    return self._extract_identifier_from_node(child, source_code)
        return None
    
    def _get_called_function_name(self, call_node: tree_sitter.Node, source_code: str) -> Optional[str]:
        """Get function name from call expression."""
        if call_node.children:
            func_node = call_node.children[0]
            if func_node.type == "identifier":
                return self.get_node_text(func_node, source_code)
            elif func_node.type == "field_expression":
                return self._extract_identifier_from_node(func_node, source_code)
        return None
    
    def is_valid_identifier(self, name: str) -> bool:
        """Check if a string is a valid C/C++ identifier using tree-sitter."""
        if not name or not name.strip():
            return False
        
        # C/C++ identifier rules:
        # - Must start with letter or underscore
        # - Can contain letters, digits, and underscores
        # - Cannot be a keyword
        
        if not (name[0].isalpha() or name[0] == '_'):
            return False
        
        if not all(c.isalnum() or c == '_' for c in name):
            return False
        
        # Check against C/C++ keywords
        c_keywords = {
            'auto', 'break', 'case', 'char', 'const', 'continue', 'default', 'do',
            'double', 'else', 'enum', 'extern', 'float', 'for', 'goto', 'if',
            'int', 'long', 'register', 'return', 'short', 'signed', 'sizeof', 'static',
            'struct', 'switch', 'typedef', 'union', 'unsigned', 'void', 'volatile', 'while'
        }
        
        cpp_keywords = {
            'asm', 'bool', 'catch', 'class', 'const_cast', 'delete', 'dynamic_cast',
            'explicit', 'export', 'false', 'friend', 'inline', 'mutable', 'namespace',
            'new', 'operator', 'private', 'protected', 'public', 'reinterpret_cast',
            'static_cast', 'template', 'this', 'throw', 'true', 'try', 'typeid',
            'typename', 'using', 'virtual', 'wchar_t', 'nullptr'
        }
        
        all_keywords = c_keywords | cpp_keywords
        return name not in all_keywords
    
    def _get_symbol_scope(self, node: tree_sitter.Node, source_code: str) -> str:
        """Get function scope of a symbol."""
        current = node.parent
        while current:
            if current.type == 'function_definition':
                func_declarator = self._find_child_by_type(current, 'function_declarator')
                if func_declarator:
                    return self._extract_identifier(func_declarator, source_code) or 'unknown'
            current = current.parent
        return 'global'
    
    def _extract_identifier(self, node: tree_sitter.Node, source_code: str) -> Optional[str]:
        """Extract identifier from node."""
        for child in node.children:
            if child.type == "identifier":
                return self.get_node_text(child, source_code)
            elif child.type == "qualified_identifier":
                return self.get_node_text(child, source_code).split("::")[-1]
        return None
