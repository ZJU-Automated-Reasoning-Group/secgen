"""C/C++ memory safety checker."""

import re
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass

from secgen.checker.base_checker import BaseChecker
from secgen.core.models import Vulnerability, VulnerabilityType, Severity, CodeLocation, PathStep, VulnerabilityPath


@dataclass
class CMemoryAllocation:
    variable: str
    file_path: str
    line_number: int
    allocation_type: str
    size: Optional[str] = None
    freed: bool = False
    freed_line: Optional[int] = None


class CMemoryChecker(BaseChecker):
    """C/C++ specific memory safety checker."""
    
    def __init__(self, model=None, logger=None, interprocedural_analyzer=None):
        super().__init__(model, logger, interprocedural_analyzer)
        
        # Track memory allocations
        self.allocations: Dict[str, CMemoryAllocation] = {}
        
        # Dangerous C functions
        self.dangerous_functions = {
            # Buffer overflow prone
            'strcpy': {'type': 'buffer_copy', 'safe_alternative': 'strncpy'},
            'strcat': {'type': 'buffer_copy', 'safe_alternative': 'strncat'},
            'sprintf': {'type': 'format_string', 'safe_alternative': 'snprintf'},
            'vsprintf': {'type': 'format_string', 'safe_alternative': 'vsnprintf'},
            'gets': {'type': 'input', 'safe_alternative': 'fgets'},
            'scanf': {'type': 'input', 'safe_alternative': 'use with field width'},
            # Memory management
            'malloc': {'type': 'allocation', 'requires': 'null_check_and_free'},
            'calloc': {'type': 'allocation', 'requires': 'null_check_and_free'},
            'realloc': {'type': 'allocation', 'requires': 'null_check_and_free'}
        }
        
        # Format string functions
        self.format_functions = {'printf', 'fprintf', 'sprintf', 'snprintf', 'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf'}
    
    def supports_file_type(self, file_path: str) -> bool:
        return file_path.endswith(('.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx'))
    
    def get_supported_extensions(self) -> Set[str]:
        return {'.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx'}
    
    def analyze_file(self, file_path: str, content: str) -> List[Vulnerability]:
        if not self.supports_file_type(file_path):
            return []
        
        vulnerabilities = []
        lines = content.split('\n')
        
        # Track memory operations
        self._track_memory_operations(file_path, lines)
        
        # Detect vulnerabilities
        vulnerabilities.extend(self._detect_buffer_overflows(file_path, lines))
        vulnerabilities.extend(self._detect_use_after_free(file_path, lines))
        vulnerabilities.extend(self._detect_memory_leaks(file_path, lines))
        vulnerabilities.extend(self._detect_null_pointer_dereference(file_path, lines))
        vulnerabilities.extend(self._detect_double_free(file_path, lines))
        vulnerabilities.extend(self._detect_format_string_bugs(file_path, lines))
        vulnerabilities.extend(self._detect_integer_overflows(file_path, lines))
        
        return self._deduplicate_vulnerabilities(vulnerabilities)
    
    def _analyze_with_interprocedural_data(self, file_contents: Dict[str, str], 
                                         functions: Dict[str, Any],
                                         function_summaries: Dict[str, Any]) -> List[Vulnerability]:
        """Analyze C/C++ memory safety using interprocedural context."""
        vulnerabilities = []
        
        if not self.interprocedural_analyzer:
            return super()._analyze_with_interprocedural_data(file_contents, functions, function_summaries)
        
        if self.logger:
            self.logger.log("Starting interprocedural C/C++ memory analysis...")
        
        # Build call graph and function summaries
        self.interprocedural_analyzer.build_call_graph(functions)
        if not function_summaries:
            function_summaries = self.interprocedural_analyzer.build_function_summaries(functions, file_contents)
        
        # Analyze interprocedural memory patterns
        interprocedural_vulns = self._analyze_interprocedural_memory_patterns(
            file_contents, functions, function_summaries
        )
        vulnerabilities.extend(interprocedural_vulns)
        
        # Also run traditional file-level analysis to catch local patterns
        local_vulnerabilities = super()._analyze_with_interprocedural_data(file_contents, functions, function_summaries)
        vulnerabilities.extend(local_vulnerabilities)
        
        if self.logger:
            self.logger.log(f"Found {len(vulnerabilities)} total C/C++ memory vulnerabilities ({len(interprocedural_vulns)} interprocedural)")
        
        return self._deduplicate_vulnerabilities(vulnerabilities)
    
    def _track_memory_operations(self, file_path: str, lines: List[str]):
        """Track memory allocation and deallocation operations."""
        for i, line in enumerate(lines, 1):
            line = line.strip()
            
            # Track malloc/calloc/realloc
            alloc_match = re.search(r'(\w+)\s*=\s*(malloc|calloc|realloc)\s*\(([^)]+)\)', line)
            if alloc_match:
                var_name, alloc_type, size_expr = alloc_match.groups()
                self.allocations[var_name] = CMemoryAllocation(
                    variable=var_name, file_path=file_path, line_number=i,
                    allocation_type=alloc_type, size=size_expr
                )
            
            # Track C++ new operations
            new_match = re.search(r'(\w+)\s*=\s*new\s+([^;(]+)(?:\([^)]*\))?', line)
            if new_match:
                var_name, type_expr = new_match.groups()
                self.allocations[var_name] = CMemoryAllocation(
                    variable=var_name, file_path=file_path, line_number=i,
                    allocation_type='new', size=type_expr.strip()
                )
            
            # Track free operations
            free_match = re.search(r'free\s*\(\s*(\w+)\s*\)', line)
            if free_match:
                var_name = free_match.group(1)
                if var_name in self.allocations:
                    self.allocations[var_name].freed = True
                    self.allocations[var_name].freed_line = i
            
            # Track delete operations
            delete_match = re.search(r'delete\s+(\w+)', line)
            if delete_match:
                var_name = delete_match.group(1)
                if var_name in self.allocations:
                    self.allocations[var_name].freed = True
                    self.allocations[var_name].freed_line = i
    
    def _detect_buffer_overflows(self, file_path: str, lines: List[str]) -> List[Vulnerability]:
        """Detect buffer overflow vulnerabilities."""
        vulnerabilities = []
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            
            # Check for dangerous string functions
            for func_name, info in self.dangerous_functions.items():
                if info['type'] in ['buffer_copy', 'input'] and re.search(rf'{func_name}\s*\(', line):
                    vulnerabilities.append(Vulnerability(
                        vuln_type=VulnerabilityType.BUFFER_OVERFLOW,
                        severity=Severity.HIGH,
                        location=CodeLocation(file_path, i, i),
                        description=f"Use of dangerous C function '{func_name}' that can cause buffer overflow",
                        evidence=line, confidence=0.8, cwe_id="CWE-120",
                        recommendation=f"Replace {func_name} with {info['safe_alternative']}"
                    ))
            
            # Check for array access without bounds checking
            array_access = re.search(r'(\w+)\s*\[\s*(\w+)\s*\]', line)
            if array_access:
                array_name, index_var = array_access.groups()
                
                # Check for bounds checking nearby
                bounds_check_found = any(
                    f'{index_var} <' in lines[j].strip() or f'sizeof({array_name})' in lines[j].strip()
                    for j in range(max(0, i-5), min(len(lines), i+5))
                )
                
                if not bounds_check_found:
                    vulnerabilities.append(Vulnerability(
                        vuln_type=VulnerabilityType.BUFFER_OVERFLOW,
                        severity=Severity.MEDIUM,
                        location=CodeLocation(file_path, i, i),
                        description=f"Array access without bounds checking: {array_name}[{index_var}]",
                        evidence=line, confidence=0.6, cwe_id="CWE-119",
                        recommendation="Add bounds checking before array access"
                    ))
        
        return vulnerabilities
    
    def _detect_use_after_free(self, file_path: str, lines: List[str]) -> List[Vulnerability]:
        """Detect use-after-free vulnerabilities with path tracking."""
        vulnerabilities = []
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            
            # Skip comments and delete/free statements
            if line.startswith(('//','/*')) or 'free(' in line or 'delete ' in line:
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
                            allocation, file_path, i, line, var_name
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _detect_memory_leaks(self, file_path: str, lines: List[str]) -> List[Vulnerability]:
        """Detect memory leak vulnerabilities."""
        vulnerabilities = []
        
        for var_name, allocation in self.allocations.items():
            if not allocation.freed:
                vulnerabilities.append(Vulnerability(
                    vuln_type=VulnerabilityType.MEMORY_LEAK,
                    severity=Severity.MEDIUM,
                    location=CodeLocation(file_path, allocation.line_number, allocation.line_number),
                    description=f"Memory allocated to '{var_name}' is never freed",
                    evidence=f"Allocation at line {allocation.line_number}",
                    confidence=0.7, cwe_id="CWE-401",
                    recommendation=f"Add free({var_name}) before variable goes out of scope"
                ))
        
        return vulnerabilities
    
    def _detect_null_pointer_dereference(self, file_path: str, lines: List[str]) -> List[Vulnerability]:
        """Detect null pointer dereference vulnerabilities with path tracking."""
        vulnerabilities = []
        allocated_vars = {}  # Track allocated variables and their allocation lines
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            
            # Track memory allocations
            malloc_match = re.search(r'(\w+)\s*=\s*(malloc|calloc|realloc)\s*\(', line)
            if malloc_match:
                var_name = malloc_match.group(1)
                allocated_vars[var_name] = {
                    'line': i,
                    'evidence': line,
                    'null_checked': False
                }
                
                # Check for null check in next few lines
                null_check_patterns = [f'if ({var_name} == NULL)', f'if (!{var_name})', f'if ({var_name} != NULL)', f'if ({var_name})']
                for j in range(i, min(len(lines), i + 5)):
                    if any(pattern in lines[j].strip() for pattern in null_check_patterns):
                        allocated_vars[var_name]['null_checked'] = True
                        break
            
            # Track direct NULL assignments
            null_assign_match = re.search(r'(\w+)\s*=\s*NULL', line)
            if null_assign_match:
                var_name = null_assign_match.group(1)
                allocated_vars[var_name] = {
                    'line': i,
                    'evidence': line,
                    'null_checked': False,
                    'is_null': True
                }
            
            # Track pointer member assignments to NULL
            member_null_match = re.search(r'(\w+)->(\w+)\s*=\s*NULL', line)
            if member_null_match:
                var_name = member_null_match.group(1)
                member_name = member_null_match.group(2)
                member_key = f"{var_name}->{member_name}"
                allocated_vars[member_key] = {
                    'line': i,
                    'evidence': line,
                    'null_checked': False,
                    'is_null': True
                }
            
            # Check for pointer dereferences
            for var_name, alloc_info in allocated_vars.items():
                # Handle member access patterns (e.g., c->data)
                if '->' in var_name:
                    if var_name in line and '=' in line and var_name.split('->')[0] in line:
                        # This is the member access dereference
                        if not alloc_info['null_checked'] or alloc_info.get('is_null', False):
                            vuln = self._create_null_deref_vulnerability(
                                var_name, alloc_info, file_path, i, line
                            )
                            vulnerabilities.append(vuln)
                else:
                    # Direct pointer dereference
                    if f'*{var_name}' in line or f'*({var_name})' in line:
                        if not alloc_info['null_checked'] or alloc_info.get('is_null', False):
                            vuln = self._create_null_deref_vulnerability(
                                var_name, alloc_info, file_path, i, line
                            )
                            vulnerabilities.append(vuln)
                    
                    # Member access dereference (e.g., ptr->member)
                    elif f'{var_name}->' in line:
                        if not alloc_info['null_checked'] or alloc_info.get('is_null', False):
                            vuln = self._create_null_deref_vulnerability(
                                var_name, alloc_info, file_path, i, line
                            )
                            vulnerabilities.append(vuln)
                    
                    # Array-style access (ptr[index])
                    elif re.search(rf'{re.escape(var_name)}\s*\[', line):
                        if not alloc_info['null_checked'] or alloc_info.get('is_null', False):
                            vuln = self._create_null_deref_vulnerability(
                                var_name, alloc_info, file_path, i, line
                            )
                            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _create_null_deref_vulnerability(self, var_name: str, alloc_info: dict, 
                                        file_path: str, line_number: int, evidence: str) -> Vulnerability:
        """Create null pointer dereference vulnerability with path information."""
        from secgen.core.models import PathStep, VulnerabilityPath
        
        # Create source step (where variable becomes null or is allocated without check)
        if alloc_info.get('is_null', False):
            source_description = f"Variable '{var_name}' assigned NULL value"
        else:
            source_description = f"Memory allocation for '{var_name}' without NULL check"
        
        source_step = PathStep(
            location=CodeLocation(file_path, alloc_info['line'], alloc_info['line']),
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
        
        return Vulnerability(
            vuln_type=VulnerabilityType.NULL_POINTER_DEREF,
            severity=Severity.HIGH,
            location=CodeLocation(file_path, line_number, line_number),
            description=f"Null pointer dereference: '{var_name}' dereferenced without NULL check",
            evidence=evidence,
            confidence=0.8,
            cwe_id="CWE-476",
            recommendation=f"Check if {var_name} is NULL before dereferencing",
            path=vuln_path
        )
    
    def _detect_double_free(self, file_path: str, lines: List[str]) -> List[Vulnerability]:
        """Detect double free vulnerabilities."""
        vulnerabilities = []
        freed_vars = {}
        
        for i, line in enumerate(lines, 1):
            free_match = re.search(r'free\s*\(\s*(\w+)\s*\)', line)
            if free_match:
                var_name = free_match.group(1)
                if var_name in freed_vars:
                    vulnerabilities.append(Vulnerability(
                        vuln_type=VulnerabilityType.USE_AFTER_FREE,
                        severity=Severity.HIGH,
                        location=CodeLocation(file_path, i, i),
                        description=f"Double free of pointer '{var_name}' (first freed at line {freed_vars[var_name]})",
                        evidence=line, confidence=0.9, cwe_id="CWE-415",
                        recommendation="Set pointer to NULL after freeing to prevent double free"
                    ))
                else:
                    freed_vars[var_name] = i
        
        return vulnerabilities
    
    def _detect_format_string_bugs(self, file_path: str, lines: List[str]) -> List[Vulnerability]:
        """Detect format string vulnerabilities."""
        vulnerabilities = []
        
        for i, line in enumerate(lines, 1):
            for func in self.format_functions:
                match = re.search(rf'{func}\s*\(\s*(\w+)\s*[,)]', line)
                if match:
                    format_arg = match.group(1)
                    if not (format_arg.startswith('"') and format_arg.endswith('"')):
                        vulnerabilities.append(Vulnerability(
                            vuln_type=VulnerabilityType.COMMAND_INJECTION,
                            severity=Severity.HIGH,
                            location=CodeLocation(file_path, i, i),
                            description=f"Format string vulnerability in {func} with variable format string",
                            evidence=line, confidence=0.8, cwe_id="CWE-134",
                            recommendation="Use literal format strings or validate format string content"
                        ))
        
        return vulnerabilities
    
    def _detect_integer_overflows(self, file_path: str, lines: List[str]) -> List[Vulnerability]:
        """Detect potential integer overflow vulnerabilities."""
        vulnerabilities = []
        
        for i, line in enumerate(lines, 1):
            malloc_match = re.search(r'malloc\s*\(\s*([^)]+)\s*\)', line)
            if malloc_match:
                size_expr = malloc_match.group(1)
                if '*' in size_expr and 'sizeof' not in size_expr:
                    vulnerabilities.append(Vulnerability(
                        vuln_type=VulnerabilityType.INTEGER_OVERFLOW,
                        severity=Severity.MEDIUM,
                        location=CodeLocation(file_path, i, i),
                        description="Potential integer overflow in malloc size calculation",
                        evidence=line, confidence=0.6, cwe_id="CWE-190",
                        recommendation="Check for integer overflow before malloc or use safer allocation functions"
                    ))
        
        return vulnerabilities
    
    def _create_use_after_free_vulnerability(self, allocation: CMemoryAllocation, file_path: str, 
                                           line_number: int, evidence: str, var_name: str) -> Vulnerability:
        """Create use-after-free vulnerability with path information."""
        source_step = PathStep(
            location=CodeLocation(allocation.file_path, allocation.line_number, allocation.line_number),
            description=f"Memory allocation: {var_name} = {allocation.allocation_type}({allocation.size})",
            node_type='source', variable=var_name, function_name=None
        )
        
        # Determine the correct free operation description
        if allocation.allocation_type == 'new':
            free_description = f"Memory freed: delete {var_name}"
        else:
            free_description = f"Memory freed: free({var_name})"
        
        intermediate_step = PathStep(
            location=CodeLocation(file_path, allocation.freed_line, allocation.freed_line),
            description=free_description,
            node_type='propagation', variable=var_name, function_name=None
        )
        
        sink_step = PathStep(
            location=CodeLocation(file_path, line_number, line_number),
            description=f"Use after free: {var_name}",
            node_type='sink', variable=var_name, function_name=None
        )
        
        vuln_path = VulnerabilityPath(source=source_step, sink=sink_step, 
                                    intermediate_steps=[intermediate_step], sanitizers=[])
        
        return Vulnerability(
            vuln_type=VulnerabilityType.USE_AFTER_FREE,
            severity=Severity.HIGH,
            location=CodeLocation(file_path, line_number, line_number),
            description=f"Use of freed pointer '{var_name}' (freed at line {allocation.freed_line})",
            evidence=evidence, confidence=0.9, cwe_id="CWE-416",
            recommendation="Set pointer to NULL after freeing or avoid using after free",
            path=vuln_path
        )
    
    def _analyze_interprocedural_memory_patterns(self, file_contents: Dict[str, str], 
                                               functions: Dict[str, Any],
                                               function_summaries: Dict[str, Any]) -> List[Vulnerability]:
        """Analyze interprocedural memory patterns using function summaries."""
        vulnerabilities = []
        
        # Analyze memory leak patterns across function calls
        memory_leak_vulns = self._analyze_interprocedural_memory_leaks(
            file_contents, functions, function_summaries
        )
        vulnerabilities.extend(memory_leak_vulns)
        
        # Analyze use-after-free patterns across function calls
        uaf_vulns = self._analyze_interprocedural_use_after_free(
            file_contents, functions, function_summaries
        )
        vulnerabilities.extend(uaf_vulns)
        
        # Analyze double-free patterns across function calls
        double_free_vulns = self._analyze_interprocedural_double_free(
            file_contents, functions, function_summaries
        )
        vulnerabilities.extend(double_free_vulns)
        
        return vulnerabilities
    
    def _analyze_interprocedural_memory_leaks(self, file_contents: Dict[str, str], 
                                            functions: Dict[str, Any],
                                            function_summaries: Dict[str, Any]) -> List[Vulnerability]:
        """Analyze memory leaks across function boundaries."""
        vulnerabilities = []
        
        # Find functions that allocate memory but don't free it
        for func_key, summary in function_summaries.items():
            func_info = functions.get(func_key)
            if not func_info:
                continue
            
            # Check if function allocates memory
            allocates_memory = any(
                'malloc' in effect.description.lower() or 'alloc' in effect.description.lower()
                for effect in summary.side_effects
            )
            
            if allocates_memory and not summary.cleanup_resources:
                # Find callers of this function
                callers = self.interprocedural_analyzer.get_functions_calling(func_key)
                
                for caller_key in callers:
                    caller_info = functions.get(caller_key)
                    if caller_info:
                        vuln = Vulnerability(
                            vuln_type=VulnerabilityType.MEMORY_LEAK,
                            severity=Severity.HIGH,
                            location=CodeLocation(
                                caller_info.file_path, 
                                caller_info.start_line, 
                                caller_info.end_line
                            ),
                            description=f"Function '{caller_info.name}' calls memory-allocating function '{func_info.name}' without ensuring proper deallocation",
                            evidence=f"Call to {func_info.name} in {caller_info.name}",
                            confidence=0.8,
                            cwe_id="CWE-401",
                            recommendation=f"Ensure proper deallocation of memory allocated by {func_info.name}"
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _analyze_interprocedural_use_after_free(self, file_contents: Dict[str, str], 
                                              functions: Dict[str, Any],
                                              function_summaries: Dict[str, Any]) -> List[Vulnerability]:
        """Analyze use-after-free patterns across function boundaries."""
        vulnerabilities = []
        
        # Find functions that free memory and functions that use memory
        freeing_functions = []
        using_functions = []
        
        for func_key, summary in function_summaries.items():
            func_info = functions.get(func_key)
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
                    paths = self.interprocedural_analyzer.find_call_paths(free_func_key, use_func_key)
                    
                    if paths:
                        free_func = functions.get(free_func_key)
                        use_func = functions.get(use_func_key)
                        
                        if free_func and use_func:
                            vuln = Vulnerability(
                                vuln_type=VulnerabilityType.USE_AFTER_FREE,
                                severity=Severity.CRITICAL,
                                location=CodeLocation(
                                    use_func.file_path, 
                                    use_func.start_line, 
                                    use_func.end_line
                                ),
                                description=f"Potential use-after-free: function '{use_func.name}' may use memory freed by '{free_func.name}'",
                                evidence=f"Call path from {free_func.name} to {use_func.name}",
                                confidence=0.6,
                                cwe_id="CWE-416",
                                recommendation="Ensure pointers are not used after being freed, or set pointers to NULL after freeing"
                            )
                            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _analyze_interprocedural_double_free(self, file_contents: Dict[str, str], 
                                           functions: Dict[str, Any],
                                           function_summaries: Dict[str, Any]) -> List[Vulnerability]:
        """Analyze double-free patterns across function boundaries."""
        vulnerabilities = []
        
        # Find functions that free memory
        freeing_functions = []
        
        for func_key, summary in function_summaries.items():
            func_info = functions.get(func_key)
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
                paths = self.interprocedural_analyzer.find_call_paths(free_func1_key, free_func2_key)
                
                if paths:
                    free_func1 = functions.get(free_func1_key)
                    free_func2 = functions.get(free_func2_key)
                    
                    if free_func1 and free_func2:
                        vuln = Vulnerability(
                            vuln_type=VulnerabilityType.USE_AFTER_FREE,  # Double-free is a type of use-after-free
                            severity=Severity.HIGH,
                            location=CodeLocation(
                                free_func2.file_path, 
                                free_func2.start_line, 
                                free_func2.end_line
                            ),
                            description=f"Potential double-free: function '{free_func2.name}' may free memory already freed by '{free_func1.name}'",
                            evidence=f"Call path from {free_func1.name} to {free_func2.name}",
                            confidence=0.5,
                            cwe_id="CWE-415",
                            recommendation="Ensure memory is only freed once, or set pointers to NULL after freeing"
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
