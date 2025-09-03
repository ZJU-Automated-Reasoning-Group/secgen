"""Integer Overflow vulnerability detector."""

import re
from typing import Dict, List, Optional, Any

from .base_detector import BaseVulnerabilityDetector, DetectionContext
from secgen.core.models import Vulnerability, VulnerabilityType, Severity, CodeLocation


class IntegerOverflowDetector(BaseVulnerabilityDetector):
    """Detector for Integer Overflow vulnerabilities."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, logger=None):
        super().__init__(config, logger)
    
    def get_vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.INTEGER_OVERFLOW
    
    def supports_file_type(self, file_path: str) -> bool:
        return file_path.endswith(('.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx'))
    
    def get_supported_extensions(self) -> List[str]:
        return ['.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx']
    
    def detect(self, context: DetectionContext) -> List[Vulnerability]:
        """Detect Integer Overflow vulnerabilities."""
        vulnerabilities = []
        
        for i, line in enumerate(context.lines, 1):
            line = line.strip()
            
            # Check for malloc with multiplication in size calculation
            malloc_match = re.search(r'malloc\s*\(\s*([^)]+)\s*\)', line)
            if malloc_match:
                size_expr = malloc_match.group(1)
                if '*' in size_expr and 'sizeof' not in size_expr:
                    vuln = self.create_vulnerability(
                        location=CodeLocation(context.file_path, i, i),
                        description="Potential integer overflow in malloc size calculation",
                        evidence=line,
                        severity=Severity.MEDIUM,
                        confidence=0.6,
                        cwe_id="CWE-190",
                        recommendation="Check for integer overflow before malloc or use safer allocation functions"
                    )
                    vulnerabilities.append(vuln)
            
            # Check for arithmetic operations that might overflow
            arithmetic_patterns = [
                r'(\w+)\s*\+\s*(\w+)',  # addition
                r'(\w+)\s*\*\s*(\w+)',  # multiplication
                r'(\w+)\s*-\s*(\w+)',   # subtraction
            ]
            
            for pattern in arithmetic_patterns:
                match = re.search(pattern, line)
                if match:
                    var1, var2 = match.groups()
                    # Check if this is used in a context that could cause overflow
                    if 'malloc' in line or 'calloc' in line or 'realloc' in line:
                        vuln = self.create_vulnerability(
                            location=CodeLocation(context.file_path, i, i),
                            description=f"Potential integer overflow in arithmetic operation: {var1} and {var2}",
                            evidence=line,
                            severity=Severity.MEDIUM,
                            confidence=0.5,
                            cwe_id="CWE-190",
                            recommendation="Check for integer overflow before using result in memory allocation"
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
