"""Double Free vulnerability detector."""

import re
from typing import Dict, List, Optional, Any

from .base_detector import BaseVulnerabilityDetector, DetectionContext
from secgen.core.models import Vulnerability, VulnerabilityType, Severity, CodeLocation


class DoubleFreeDetector(BaseVulnerabilityDetector):
    """Detector for Double Free vulnerabilities."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, logger=None):
        super().__init__(config, logger)
    
    def get_vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.USE_AFTER_FREE  # Double-free is a type of use-after-free
    
    def supports_file_type(self, file_path: str) -> bool:
        return file_path.endswith(('.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx'))
    
    def get_supported_extensions(self) -> List[str]:
        return ['.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx']
    
    def detect(self, context: DetectionContext) -> List[Vulnerability]:
        """Detect Double Free vulnerabilities."""
        vulnerabilities = []
        freed_vars = {}
        
        for i, line in enumerate(context.lines, 1):
            free_match = re.search(r'free\s*\(\s*(\w+)\s*\)', line)
            if free_match:
                var_name = free_match.group(1)
                if var_name in freed_vars:
                    vuln = self.create_vulnerability(
                        location=CodeLocation(context.file_path, i, i),
                        description=f"Double free of pointer '{var_name}' (first freed at line {freed_vars[var_name]})",
                        evidence=line,
                        severity=Severity.HIGH,
                        confidence=0.9,
                        cwe_id="CWE-415",
                        recommendation="Set pointer to NULL after freeing to prevent double free"
                    )
                    vulnerabilities.append(vuln)
                else:
                    freed_vars[var_name] = i
        
        return vulnerabilities
    
    def analyze_interprocedural_double_free(self, context: DetectionContext) -> List[Vulnerability]:
        """Analyze double-free patterns across function boundaries."""
        vulnerabilities = []
        
        if not context.interprocedural_analyzer or not context.function_summaries:
            return vulnerabilities
        
        # Find functions that free memory
        freeing_functions = []
        
        for func_key, summary in context.function_summaries.items():
            func_info = context.functions.get(func_key)
            if not func_info:
                continue
            
            # Check if function frees memory
            frees_memory = any(
                'free' in effect.description.lower()
                for effect in summary.side_effects
            )
            
            if frees_memory:
                freeing_functions.append(func_key)
        
        # Look for potential double-free patterns
        for i, free_func1_key in enumerate(freeing_functions):
            for free_func2_key in freeing_functions[i+1:]:
                # Check if there's a call path from one freeing function to another
                paths = context.interprocedural_analyzer.find_call_paths(free_func1_key, free_func2_key)
                
                if paths:
                    free_func1 = context.functions.get(free_func1_key)
                    free_func2 = context.functions.get(free_func2_key)
                    
                    if free_func1 and free_func2:
                        vuln = self.create_vulnerability(
                            location=CodeLocation(
                                free_func2.file_path, 
                                free_func2.start_line, 
                                free_func2.end_line
                            ),
                            description=f"Potential double-free: function '{free_func2.name}' may free memory already freed by '{free_func1.name}'",
                            evidence=f"Call path from {free_func1.name} to {free_func2.name}",
                            severity=Severity.HIGH,
                            confidence=0.5,
                            cwe_id="CWE-415",
                            recommendation="Ensure memory is only freed once, or set pointers to NULL after freeing"
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
