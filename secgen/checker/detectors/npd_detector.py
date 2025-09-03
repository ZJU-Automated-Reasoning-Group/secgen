"""Null Pointer Dereference (NPD) vulnerability detector."""

import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from .base_detector import BaseVulnerabilityDetector, DetectionContext
from secgen.core.models import Vulnerability, VulnerabilityType, Severity, CodeLocation, PathStep, VulnerabilityPath


@dataclass
class PointerInfo:
    """Information about a pointer variable."""
    name: str
    line: int
    evidence: str
    null_checked: bool = False
    is_null: bool = False


class NPDDetector(BaseVulnerabilityDetector):
    """Detector for Null Pointer Dereference vulnerabilities."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, logger=None):
        super().__init__(config, logger)
        
        # Load configuration
        self.null_check_patterns = self.config.get('null_check_patterns', [
            '== NULL', '!= NULL', '!', 'if (', 'while ('
        ])
    
    def get_vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.NULL_POINTER_DEREF
    
    def supports_file_type(self, file_path: str) -> bool:
        return file_path.endswith(('.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx'))
    
    def get_supported_extensions(self) -> List[str]:
        return ['.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx']
    
    def detect(self, context: DetectionContext) -> List[Vulnerability]:
        """Detect Null Pointer Dereference vulnerabilities."""
        vulnerabilities = []
        allocated_vars = {}  # Track allocated variables and their allocation lines
        
        for i, line in enumerate(context.lines, 1):
            line = line.strip()
            
            # Track memory allocations
            malloc_match = re.search(r'(\w+)\s*=\s*(malloc|calloc|realloc)\s*\(', line)
            if malloc_match:
                var_name = malloc_match.group(1)
                allocated_vars[var_name] = PointerInfo(
                    name=var_name,
                    line=i,
                    evidence=line,
                    null_checked=False
                )
                
                # Check for null check in next few lines
                null_check_patterns = [f'if ({var_name} == NULL)', f'if (!{var_name})', 
                                     f'if ({var_name} != NULL)', f'if ({var_name})']
                for j in range(i, min(len(context.lines), i + 5)):
                    if any(pattern in context.lines[j].strip() for pattern in null_check_patterns):
                        allocated_vars[var_name].null_checked = True
                        break
            
            # Track direct NULL assignments
            null_assign_match = re.search(r'(\w+)\s*=\s*NULL', line)
            if null_assign_match:
                var_name = null_assign_match.group(1)
                allocated_vars[var_name] = PointerInfo(
                    name=var_name,
                    line=i,
                    evidence=line,
                    null_checked=False,
                    is_null=True
                )
            
            # Track pointer member assignments to NULL
            member_null_match = re.search(r'(\w+)->(\w+)\s*=\s*NULL', line)
            if member_null_match:
                var_name = member_null_match.group(1)
                member_name = member_null_match.group(2)
                member_key = f"{var_name}->{member_name}"
                allocated_vars[member_key] = PointerInfo(
                    name=member_key,
                    line=i,
                    evidence=line,
                    null_checked=False,
                    is_null=True
                )
            
            # Check for pointer dereferences
            for var_name, ptr_info in allocated_vars.items():
                # Handle member access patterns (e.g., c->data)
                if '->' in var_name:
                    if var_name in line and '=' in line and var_name.split('->')[0] in line:
                        # This is the member access dereference
                        if not ptr_info.null_checked or ptr_info.is_null:
                            vuln = self._create_null_deref_vulnerability(
                                var_name, ptr_info, context.file_path, i, line
                            )
                            vulnerabilities.append(vuln)
                else:
                    # Direct pointer dereference
                    if f'*{var_name}' in line or f'*({var_name})' in line:
                        if not ptr_info.null_checked or ptr_info.is_null:
                            vuln = self._create_null_deref_vulnerability(
                                var_name, ptr_info, context.file_path, i, line
                            )
                            vulnerabilities.append(vuln)
                    
                    # Member access dereference (e.g., ptr->member)
                    elif f'{var_name}->' in line:
                        if not ptr_info.null_checked or ptr_info.is_null:
                            vuln = self._create_null_deref_vulnerability(
                                var_name, ptr_info, context.file_path, i, line
                            )
                            vulnerabilities.append(vuln)
                    
                    # Array-style access (ptr[index])
                    elif re.search(rf'{re.escape(var_name)}\s*\[', line):
                        if not ptr_info.null_checked or ptr_info.is_null:
                            vuln = self._create_null_deref_vulnerability(
                                var_name, ptr_info, context.file_path, i, line
                            )
                            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _create_null_deref_vulnerability(self, var_name: str, ptr_info: PointerInfo, 
                                       file_path: str, line_number: int, evidence: str) -> Vulnerability:
        """Create null pointer dereference vulnerability with path information."""
        # Create source step (where variable becomes null or is allocated without check)
        if ptr_info.is_null:
            source_description = f"Variable '{var_name}' assigned NULL value"
        else:
            source_description = f"Memory allocation for '{var_name}' without NULL check"
        
        source_step = PathStep(
            location=CodeLocation(file_path, ptr_info.line, ptr_info.line),
            description=source_description,
            node_type='source',
            variable=var_name,
            function_name=None
        )
        
        # Create sink step (where null pointer is dereferenced)
        sink_step = PathStep(
            location=CodeLocation(file_path, line_number, line_number),
            description=f"Null pointer dereference of '{var_name}'",
            node_type='sink',
            variable=var_name,
            function_name=None
        )
        
        # Create vulnerability path
        vuln_path = VulnerabilityPath(
            source=source_step,
            sink=sink_step,
            intermediate_steps=[],
            sanitizers=[]
        )
        
        return self.create_vulnerability(
            location=CodeLocation(file_path, line_number, line_number),
            description=f"Null pointer dereference: '{var_name}' dereferenced without NULL check",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=0.8,
            cwe_id="CWE-476",
            recommendation=f"Check if {var_name} is NULL before dereferencing",
            path=vuln_path
        )
    
    def analyze_interprocedural_npd(self, context: DetectionContext) -> List[Vulnerability]:
        """Analyze null pointer dereference patterns across function boundaries."""
        vulnerabilities = []
        
        if not context.interprocedural_analyzer or not context.function_summaries:
            return vulnerabilities
        
        # Find functions that may return null pointers
        null_returning_functions = []
        
        for func_key, summary in context.function_summaries.items():
            func_info = context.functions.get(func_key)
            if not func_info:
                continue
            
            # Check if function may return null
            may_return_null = any(
                'null' in effect.description.lower() or 'NULL' in effect.description
                for effect in summary.side_effects
            )
            
            if may_return_null:
                null_returning_functions.append(func_key)
        
        # Find functions that dereference pointers without null checks
        for func_key, summary in context.function_summaries.items():
            func_info = context.functions.get(func_key)
            if not func_info:
                continue
            
            # Check if function dereferences pointers
            dereferences_pointers = any(
                param.is_pointer for param in summary.parameters
            )
            
            if dereferences_pointers:
                # Check if this function calls null-returning functions
                for null_func_key in null_returning_functions:
                    if null_func_key != func_key:
                        # Check if there's a call path
                        paths = context.interprocedural_analyzer.find_call_paths(null_func_key, func_key)
                        
                        if paths:
                            null_func = context.functions.get(null_func_key)
                            
                            if null_func:
                                vuln = self.create_vulnerability(
                                    location=CodeLocation(
                                        func_info.file_path, 
                                        func_info.start_line, 
                                        func_info.end_line
                                    ),
                                    description=f"Potential null pointer dereference: function '{func_info.name}' may dereference null pointer returned by '{null_func.name}'",
                                    evidence=f"Call path from {null_func.name} to {func_info.name}",
                                    severity=Severity.HIGH,
                                    confidence=0.7,
                                    cwe_id="CWE-476",
                                    recommendation=f"Add null checks for return value from {null_func.name}"
                                )
                                vulnerabilities.append(vuln)
        
        return vulnerabilities
