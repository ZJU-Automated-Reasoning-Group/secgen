"""Use-After-Free (UAF) vulnerability detector."""

import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from .base_detector import BaseVulnerabilityDetector, DetectionContext
from secgen.core.models import Vulnerability, VulnerabilityType, Severity, CodeLocation, PathStep, VulnerabilityPath


@dataclass
class MemoryAllocation:
    """Represents a memory allocation."""
    variable: str
    file_path: str
    line_number: int
    allocation_type: str
    size: Optional[str] = None
    freed: bool = False
    freed_line: Optional[int] = None


class UAFDetector(BaseVulnerabilityDetector):
    """Detector for Use-After-Free vulnerabilities."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, logger=None):
        super().__init__(config, logger)
        self.allocations: Dict[str, MemoryAllocation] = {}
        
        # Load configuration
        self.memory_allocation_functions = set(self.config.get('memory_allocation_functions', [
            'malloc', 'calloc', 'realloc', 'new'
        ]))
        self.memory_deallocation_functions = set(self.config.get('memory_deallocation_functions', [
            'free', 'delete'
        ]))
    
    def get_vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.USE_AFTER_FREE
    
    def supports_file_type(self, file_path: str) -> bool:
        return file_path.endswith(('.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx'))
    
    def get_supported_extensions(self) -> List[str]:
        return ['.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx']
    
    def detect(self, context: DetectionContext) -> List[Vulnerability]:
        """Detect Use-After-Free vulnerabilities."""
        vulnerabilities = []
        
        # Track memory operations
        self._track_memory_operations(context)
        
        # Detect UAF vulnerabilities
        vulnerabilities.extend(self._detect_use_after_free(context))
        
        return vulnerabilities
    
    def _track_memory_operations(self, context: DetectionContext) -> None:
        """Track memory allocation and deallocation operations."""
        for i, line in enumerate(context.lines, 1):
            line = line.strip()
            
            # Track memory allocation functions
            alloc_pattern = '|'.join(self.memory_allocation_functions)
            alloc_match = re.search(rf'(\w+)\s*=\s*({alloc_pattern})\s*\(([^)]+)\)', line)
            if alloc_match:
                var_name, alloc_type, size_expr = alloc_match.groups()
                self.allocations[var_name] = MemoryAllocation(
                    variable=var_name, 
                    file_path=context.file_path, 
                    line_number=i,
                    allocation_type=alloc_type, 
                    size=size_expr
                )
            
            # Track C++ new operations
            new_match = re.search(r'(\w+)\s*=\s*new\s+([^;(]+)(?:\([^)]*\))?', line)
            if new_match:
                var_name, type_expr = new_match.groups()
                self.allocations[var_name] = MemoryAllocation(
                    variable=var_name, 
                    file_path=context.file_path, 
                    line_number=i,
                    allocation_type='new', 
                    size=type_expr.strip()
                )
            
            # Track memory deallocation functions
            dealloc_pattern = '|'.join(self.memory_deallocation_functions)
            dealloc_match = re.search(rf'({dealloc_pattern})\s*(?:\(\s*(\w+)\s*\)|(\w+))', line)
            if dealloc_match:
                dealloc_func, var_name1, var_name2 = dealloc_match.groups()
                var_name = var_name1 or var_name2
                if var_name and var_name in self.allocations:
                    self.allocations[var_name].freed = True
                    self.allocations[var_name].freed_line = i
    
    def _detect_use_after_free(self, context: DetectionContext) -> List[Vulnerability]:
        """Detect use-after-free vulnerabilities with path tracking."""
        vulnerabilities = []
        
        for i, line in enumerate(context.lines, 1):
            line = line.strip()
            
            # Skip comments and delete/free statements
            if line.startswith(('//', '/*')) or 'free(' in line or 'delete ' in line:
                continue
            
            for var_name, allocation in self.allocations.items():
                if allocation.freed and allocation.freed_line and allocation.freed_line < i:
                    # Check for actual usage patterns after free
                    usage_patterns = [
                        rf'\*{re.escape(var_name)}',  # *ptr
                        rf'{re.escape(var_name)}\s*\[',  # ptr[index]
                        rf'{re.escape(var_name)}\s*\.',  # ptr.member
                        rf'{re.escape(var_name)}\s*\->'  # ptr->member
                    ]
                    
                    if any(re.search(pattern, line) for pattern in usage_patterns):
                        vuln = self._create_use_after_free_vulnerability(
                            allocation, context.file_path, i, line, var_name
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _create_use_after_free_vulnerability(self, allocation: MemoryAllocation, 
                                           file_path: str, line_number: int, 
                                           evidence: str, var_name: str) -> Vulnerability:
        """Create use-after-free vulnerability with path information."""
        source_step = PathStep(
            location=CodeLocation(allocation.file_path, allocation.line_number, allocation.line_number),
            description=f"Memory allocation: {var_name} = {allocation.allocation_type}({allocation.size})",
            node_type='source', 
            variable=var_name, 
            function_name=None
        )
        
        # Determine the correct free operation description
        if allocation.allocation_type == 'new':
            free_description = f"Memory freed: delete {var_name}"
        else:
            free_description = f"Memory freed: free({var_name})"
        
        intermediate_step = PathStep(
            location=CodeLocation(file_path, allocation.freed_line, allocation.freed_line),
            description=free_description,
            node_type='propagation', 
            variable=var_name, 
            function_name=None
        )
        
        sink_step = PathStep(
            location=CodeLocation(file_path, line_number, line_number),
            description=f"Use after free: {var_name}",
            node_type='sink', 
            variable=var_name, 
            function_name=None
        )
        
        vuln_path = VulnerabilityPath(
            source=source_step, 
            sink=sink_step, 
            intermediate_steps=[intermediate_step], 
            sanitizers=[]
        )
        
        return self.create_vulnerability(
            location=CodeLocation(file_path, line_number, line_number),
            description=f"Use of freed pointer '{var_name}' (freed at line {allocation.freed_line})",
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=0.9,
            cwe_id="CWE-416",
            recommendation="Set pointer to NULL after freeing or avoid using after free",
            path=vuln_path
        )
    
    def analyze_interprocedural_uaf(self, context: DetectionContext) -> List[Vulnerability]:
        """Analyze use-after-free patterns across function boundaries."""
        vulnerabilities = []
        
        if not context.interprocedural_analyzer or not context.function_summaries:
            return vulnerabilities
        
        # Find functions that free memory and functions that use memory
        freeing_functions = []
        using_functions = []
        
        for func_key, summary in context.function_summaries.items():
            func_info = context.functions.get(func_key)
            if not func_info:
                continue
            
            # Check if function frees memory
            frees_memory = any(
                'free' in effect.description.lower()
                for effect in summary.side_effects
            )
            
            # Check if function uses/dereferences pointers
            uses_pointers = any(
                param.is_pointer for param in summary.parameters
            )
            
            if frees_memory:
                freeing_functions.append(func_key)
            if uses_pointers:
                using_functions.append(func_key)
        
        # Look for potential use-after-free patterns
        for free_func_key in freeing_functions:
            for use_func_key in using_functions:
                if free_func_key != use_func_key:
                    # Check if there's a call path where free happens before use
                    paths = context.interprocedural_analyzer.find_call_paths(free_func_key, use_func_key)
                    
                    if paths:
                        free_func = context.functions.get(free_func_key)
                        use_func = context.functions.get(use_func_key)
                        
                        if free_func and use_func:
                            vuln = self.create_vulnerability(
                                location=CodeLocation(
                                    use_func.file_path, 
                                    use_func.start_line, 
                                    use_func.end_line
                                ),
                                description=f"Potential use-after-free: function '{use_func.name}' may use memory freed by '{free_func.name}'",
                                evidence=f"Call path from {free_func.name} to {use_func.name}",
                                severity=Severity.CRITICAL,
                                confidence=0.6,
                                cwe_id="CWE-416",
                                recommendation="Ensure pointers are not used after being freed, or set pointers to NULL after freeing"
                            )
                            vulnerabilities.append(vuln)
        
        return vulnerabilities
