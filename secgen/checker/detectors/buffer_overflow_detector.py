"""Buffer Overflow vulnerability detector."""

import re
from typing import Dict, List, Optional, Any

from .base_detector import BaseVulnerabilityDetector, DetectionContext
from secgen.core.models import Vulnerability, VulnerabilityType, Severity, CodeLocation


class BufferOverflowDetector(BaseVulnerabilityDetector):
    """Detector for Buffer Overflow vulnerabilities."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, logger=None):
        super().__init__(config, logger)
        
        # Load configuration
        self.dangerous_functions = self.config.get('dangerous_functions', {})
        self.bounds_check_patterns = self.config.get('bounds_check_patterns', [
            '<', '>', '<=', '>=', 'sizeof(', 'strlen('
        ])
    
    def get_vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.BUFFER_OVERFLOW
    
    def supports_file_type(self, file_path: str) -> bool:
        return file_path.endswith(('.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx'))
    
    def get_supported_extensions(self) -> List[str]:
        return ['.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx']
    
    def detect(self, context: DetectionContext) -> List[Vulnerability]:
        """Detect Buffer Overflow vulnerabilities."""
        vulnerabilities = []
        
        for i, line in enumerate(context.lines, 1):
            line = line.strip()
            
            # Check for dangerous string functions
            for func_name, info in self.dangerous_functions.items():
                if info.get('type') in ['buffer_copy', 'input'] and re.search(rf'{func_name}\s*\(', line):
                    vuln = self.create_vulnerability(
                        location=CodeLocation(context.file_path, i, i),
                        description=f"Use of dangerous C function '{func_name}' that can cause buffer overflow",
                        evidence=line,
                        severity=Severity.HIGH,
                        confidence=0.8,
                        cwe_id="CWE-120",
                        recommendation=f"Replace {func_name} with {info.get('safe_alternative', 'safe alternative')}"
                    )
                    vulnerabilities.append(vuln)
            
            # Check for array access without bounds checking
            array_access = re.search(r'(\w+)\s*\[\s*(\w+)\s*\]', line)
            if array_access:
                array_name, index_var = array_access.groups()
                
                # Check for bounds checking nearby
                bounds_check_found = any(
                    f'{index_var} <' in context.lines[j].strip() or 
                    f'sizeof({array_name})' in context.lines[j].strip()
                    for j in range(max(0, i-5), min(len(context.lines), i+5))
                )
                
                if not bounds_check_found:
                    vuln = self.create_vulnerability(
                        location=CodeLocation(context.file_path, i, i),
                        description=f"Array access without bounds checking: {array_name}[{index_var}]",
                        evidence=line,
                        severity=Severity.MEDIUM,
                        confidence=0.6,
                        cwe_id="CWE-119",
                        recommendation="Add bounds checking before array access"
                    )
                    vulnerabilities.append(vuln)
            
            # Check for sprintf without bounds checking
            sprintf_match = re.search(r'sprintf\s*\(\s*(\w+)\s*,', line)
            if sprintf_match:
                buffer_name = sprintf_match.group(1)
                vuln = self.create_vulnerability(
                    location=CodeLocation(context.file_path, i, i),
                    description=f"Use of sprintf without bounds checking on buffer '{buffer_name}'",
                    evidence=line,
                    severity=Severity.HIGH,
                    confidence=0.8,
                    cwe_id="CWE-120",
                    recommendation="Use snprintf with proper buffer size"
                )
                vulnerabilities.append(vuln)
            
            # Check for strcpy without bounds checking
            strcpy_match = re.search(r'strcpy\s*\(\s*(\w+)\s*,', line)
            if strcpy_match:
                buffer_name = strcpy_match.group(1)
                vuln = self.create_vulnerability(
                    location=CodeLocation(context.file_path, i, i),
                    description=f"Use of strcpy without bounds checking on buffer '{buffer_name}'",
                    evidence=line,
                    severity=Severity.HIGH,
                    confidence=0.8,
                    cwe_id="CWE-120",
                    recommendation="Use strncpy with proper buffer size"
                )
                vulnerabilities.append(vuln)
            
            # Check for strcat without bounds checking
            strcat_match = re.search(r'strcat\s*\(\s*(\w+)\s*,', line)
            if strcat_match:
                buffer_name = strcat_match.group(1)
                vuln = self.create_vulnerability(
                    location=CodeLocation(context.file_path, i, i),
                    description=f"Use of strcat without bounds checking on buffer '{buffer_name}'",
                    evidence=line,
                    severity=Severity.HIGH,
                    confidence=0.8,
                    cwe_id="CWE-120",
                    recommendation="Use strncat with proper buffer size"
                )
                vulnerabilities.append(vuln)
            
            # Check for gets function (always dangerous)
            if 'gets(' in line:
                vuln = self.create_vulnerability(
                    location=CodeLocation(context.file_path, i, i),
                    description="Use of dangerous gets() function that can cause buffer overflow",
                    evidence=line,
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    cwe_id="CWE-242",
                    recommendation="Use fgets() with proper buffer size"
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def analyze_interprocedural_buffer_overflow(self, context: DetectionContext) -> List[Vulnerability]:
        """Analyze buffer overflow patterns across function boundaries."""
        vulnerabilities = []
        
        if not context.interprocedural_analyzer or not context.function_summaries:
            return vulnerabilities
        
        # Find functions that perform buffer operations
        buffer_operations = []
        
        for func_key, summary in context.function_summaries.items():
            func_info = context.functions.get(func_key)
            if not func_info:
                continue
            
            # Check if function performs buffer operations
            performs_buffer_ops = any(
                'strcpy' in effect.description.lower() or
                'strcat' in effect.description.lower() or
                'sprintf' in effect.description.lower() or
                'buffer' in effect.description.lower()
                for effect in summary.side_effects
            )
            
            if performs_buffer_ops:
                buffer_operations.append(func_key)
        
        # Find functions that call buffer operations without proper validation
        for func_key, summary in context.function_summaries.items():
            func_info = context.functions.get(func_key)
            if not func_info:
                continue
            
            # Check if this function calls buffer operations
            for buffer_func_key in buffer_operations:
                if buffer_func_key != func_key:
                    # Check if there's a call path
                    paths = context.interprocedural_analyzer.find_call_paths(func_key, buffer_func_key)
                    
                    if paths:
                        buffer_func = context.functions.get(buffer_func_key)
                        
                        if buffer_func:
                            vuln = self.create_vulnerability(
                                location=CodeLocation(
                                    func_info.file_path, 
                                    func_info.start_line, 
                                    func_info.end_line
                                ),
                                description=f"Potential buffer overflow: function '{func_info.name}' calls buffer operation '{buffer_func.name}' without proper validation",
                                evidence=f"Call path from {func_info.name} to {buffer_func.name}",
                                severity=Severity.HIGH,
                                confidence=0.7,
                                cwe_id="CWE-120",
                                recommendation=f"Add input validation before calling {buffer_func.name}"
                            )
                            vulnerabilities.append(vuln)
        
        return vulnerabilities
