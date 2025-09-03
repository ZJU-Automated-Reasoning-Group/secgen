"""Memory Leak vulnerability detector."""

from typing import Dict, List, Optional, Any

from .base_detector import BaseVulnerabilityDetector, DetectionContext
from secgen.core.models import Vulnerability, VulnerabilityType, Severity, CodeLocation


class MemoryLeakDetector(BaseVulnerabilityDetector):
    """Detector for Memory Leak vulnerabilities."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, logger=None):
        super().__init__(config, logger)
    
    def get_vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.MEMORY_LEAK
    
    def supports_file_type(self, file_path: str) -> bool:
        return file_path.endswith(('.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx'))
    
    def get_supported_extensions(self) -> List[str]:
        return ['.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx']
    
    def detect(self, context: DetectionContext) -> List[Vulnerability]:
        """Detect Memory Leak vulnerabilities."""
        vulnerabilities = []
        
        # Use allocations from context if available (from UAF detector)
        if hasattr(context, 'allocations') and context.allocations:
            for var_name, allocation in context.allocations.items():
                if not allocation.freed:
                    vuln = self.create_vulnerability(
                        location=CodeLocation(context.file_path, allocation.line_number, allocation.line_number),
                        description=f"Memory allocated to '{var_name}' is never freed",
                        evidence=f"Allocation at line {allocation.line_number}",
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        cwe_id="CWE-401",
                        recommendation=f"Add free({var_name}) before variable goes out of scope"
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def analyze_interprocedural_memory_leaks(self, context: DetectionContext) -> List[Vulnerability]:
        """Analyze memory leaks across function boundaries."""
        vulnerabilities = []
        
        if not context.interprocedural_analyzer or not context.function_summaries:
            return vulnerabilities
        
        # Find functions that allocate memory but don't free it
        for func_key, summary in context.function_summaries.items():
            func_info = context.functions.get(func_key)
            if not func_info:
                continue
            
            # Check if function allocates memory
            allocates_memory = any(
                'malloc' in effect.description.lower() or 'alloc' in effect.description.lower()
                for effect in summary.side_effects
            )
            
            if allocates_memory and not summary.cleanup_resources:
                # Find callers of this function
                callers = context.interprocedural_analyzer.get_functions_calling(func_key)
                
                for caller_key in callers:
                    caller_info = context.functions.get(caller_key)
                    if caller_info:
                        vuln = self.create_vulnerability(
                            location=CodeLocation(
                                caller_info.file_path, 
                                caller_info.start_line, 
                                caller_info.end_line
                            ),
                            description=f"Function '{caller_info.name}' calls memory-allocating function '{func_info.name}' without ensuring proper deallocation",
                            evidence=f"Call to {func_info.name} in {caller_info.name}",
                            severity=Severity.HIGH,
                            confidence=0.8,
                            cwe_id="CWE-401",
                            recommendation=f"Ensure proper deallocation of memory allocated by {func_info.name}"
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
