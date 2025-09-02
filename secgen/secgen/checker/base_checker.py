"""Base class for all vulnerability checkers."""

from abc import ABC, abstractmethod
from typing import Dict, List, Set, Optional, Any
from secgen.core.analyzer import Vulnerability


class BaseChecker(ABC):
    """Base class for all vulnerability checkers."""
    
    def __init__(self, model=None, logger=None, interprocedural_analyzer=None):
        self.model = model
        self.logger = logger
        self.interprocedural_analyzer = interprocedural_analyzer
    
    @abstractmethod
    def analyze_file(self, file_path: str, content: str) -> List[Vulnerability]:
        """Analyze a file for vulnerabilities."""
        pass
    
    def analyze_with_interprocedural_context(self, file_contents: Dict[str, str], 
                                           functions: Dict[str, Any],
                                           function_summaries: Dict[str, Any]) -> List[Vulnerability]:
        """Analyze using interprocedural context."""
        if not self.interprocedural_analyzer:
            # Fallback to file-by-file analysis if no interprocedural analyzer
            vulnerabilities = []
            for file_path, content in file_contents.items():
                if self.supports_file_type(file_path):
                    vulnerabilities.extend(self.analyze_file(file_path, content))
            return vulnerabilities
        
        # Use interprocedural analysis capabilities
        return self._analyze_with_interprocedural_data(file_contents, functions, function_summaries)
    
    def _analyze_with_interprocedural_data(self, file_contents: Dict[str, str], 
                                         functions: Dict[str, Any],
                                         function_summaries: Dict[str, Any]) -> List[Vulnerability]:
        """Override this method in subclasses to implement interprocedural analysis."""
        # Default implementation: delegate to file-by-file analysis
        vulnerabilities = []
        for file_path, content in file_contents.items():
            if self.supports_file_type(file_path):
                vulnerabilities.extend(self.analyze_file(file_path, content))
        return vulnerabilities
    
    @abstractmethod
    def supports_file_type(self, file_path: str) -> bool:
        """Check if this checker supports the given file type."""
        pass
    
    def get_supported_extensions(self) -> Set[str]:
        """Get file extensions supported by this checker."""
        return set()
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities."""
        seen = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            signature = (vuln.vuln_type, vuln.location.file_path, 
                        vuln.location.line_start, vuln.description[:50])
            if signature not in seen:
                seen.add(signature)
                unique_vulns.append(vuln)
        
        return unique_vulns
