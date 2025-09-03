"""Format String vulnerability detector."""

import re
from typing import Dict, List, Optional, Any

from .base_detector import BaseVulnerabilityDetector, DetectionContext
from secgen.core.models import Vulnerability, VulnerabilityType, Severity, CodeLocation


class FormatStringDetector(BaseVulnerabilityDetector):
    """Detector for Format String vulnerabilities."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, logger=None):
        super().__init__(config, logger)
        
        # Load configuration
        self.format_functions = set(self.config.get('format_functions', [
            'printf', 'fprintf', 'sprintf', 'snprintf', 'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf'
        ]))
    
    def get_vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.COMMAND_INJECTION  # Format string bugs can lead to command injection
    
    def supports_file_type(self, file_path: str) -> bool:
        return file_path.endswith(('.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx'))
    
    def get_supported_extensions(self) -> List[str]:
        return ['.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx']
    
    def detect(self, context: DetectionContext) -> List[Vulnerability]:
        """Detect Format String vulnerabilities."""
        vulnerabilities = []
        
        for i, line in enumerate(context.lines, 1):
            line = line.strip()
            
            for func in self.format_functions:
                match = re.search(rf'{func}\s*\(\s*(\w+)\s*[,)]', line)
                if match:
                    format_arg = match.group(1)
                    if not (format_arg.startswith('"') and format_arg.endswith('"')):
                        vuln = self.create_vulnerability(
                            location=CodeLocation(context.file_path, i, i),
                            description=f"Format string vulnerability in {func} with variable format string",
                            evidence=line,
                            severity=Severity.HIGH,
                            confidence=0.8,
                            cwe_id="CWE-134",
                            recommendation="Use literal format strings or validate format string content"
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
