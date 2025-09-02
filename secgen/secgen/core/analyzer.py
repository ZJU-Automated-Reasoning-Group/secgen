"""Core code analyzer for static analysis and vulnerability detection."""

import ast
import os
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass
from enum import Enum

from secgen.agent.models import ChatMessage, MessageRole


class VulnerabilityType(Enum):
    """Types of vulnerabilities to detect."""
    BUFFER_OVERFLOW = "buffer_overflow"
    NULL_POINTER_DEREF = "null_pointer_dereference"
    USE_AFTER_FREE = "use_after_free"
    MEMORY_LEAK = "memory_leak"
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    XSS = "cross_site_scripting"
    PATH_TRAVERSAL = "path_traversal"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    INTEGER_OVERFLOW = "integer_overflow"


class Severity(Enum):
    """Severity levels for vulnerabilities."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CodeLocation:
    """Represents a location in source code."""
    file_path: str
    line_start: int
    line_end: int
    column_start: int = 0
    column_end: int = 0
    
    def __str__(self) -> str:
        if self.line_start == self.line_end:
            return f"{self.file_path}:{self.line_start}"
        return f"{self.file_path}:{self.line_start}-{self.line_end}"


@dataclass
class PathStep:
    """Represents a step in a vulnerability path."""
    location: CodeLocation
    description: str
    node_type: str  # 'source', 'propagation', 'sink', 'sanitizer'
    variable: Optional[str] = None
    function_name: Optional[str] = None


@dataclass
class VulnerabilityPath:
    """Represents the complete path from source to sink."""
    source: PathStep
    sink: PathStep
    intermediate_steps: List[PathStep]
    sanitizers: List[PathStep]
    
    def get_all_steps(self) -> List[PathStep]:
        """Get all steps in the path ordered from source to sink."""
        return [self.source] + self.intermediate_steps + [self.sink]


@dataclass
class Vulnerability:
    """Represents a detected vulnerability."""
    vuln_type: VulnerabilityType
    severity: Severity
    location: CodeLocation
    description: str
    evidence: str
    confidence: float
    cwe_id: Optional[str] = None
    recommendation: Optional[str] = None
    path: Optional[VulnerabilityPath] = None  # New field for path information
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        result = {
            'type': self.vuln_type.value,
            'severity': self.severity.value,
            'location': str(self.location),
            'description': self.description,
            'evidence': self.evidence,
            'confidence': self.confidence,
            'cwe_id': self.cwe_id,
            'recommendation': self.recommendation
        }
        
        # Add path information if available
        if self.path:
            result['path'] = {
                'source': {
                    'location': str(self.path.source.location),
                    'description': self.path.source.description,
                    'node_type': self.path.source.node_type,
                    'variable': self.path.source.variable,
                    'function': self.path.source.function_name
                },
                'sink': {
                    'location': str(self.path.sink.location),
                    'description': self.path.sink.description,
                    'node_type': self.path.sink.node_type,
                    'variable': self.path.sink.variable,
                    'function': self.path.sink.function_name
                },
                'intermediate_steps': [
                    {
                        'location': str(step.location),
                        'description': step.description,
                        'node_type': step.node_type,
                        'variable': step.variable,
                        'function': step.function_name
                    }
                    for step in self.path.intermediate_steps
                ],
                'sanitizers': [
                    {
                        'location': str(step.location),
                        'description': step.description,
                        'node_type': step.node_type,
                        'variable': step.variable,
                        'function': step.function_name
                    }
                    for step in self.path.sanitizers
                ]
            }
        
        return result


@dataclass
class FunctionInfo:
    """Information about a function."""
    name: str
    file_path: str
    start_line: int
    end_line: int
    parameters: List[str]
    return_type: Optional[str] = None
    calls: List[str] = None
    variables: List[str] = None
    
    def __post_init__(self):
        if self.calls is None:
            self.calls = []
        if self.variables is None:
            self.variables = []


class CodeAnalyzer:
    """Main code analyzer for static analysis."""
    
    def __init__(self, model=None, logger=None):
        """Initialize the code analyzer.
        
        Args:
            model: LLM model for intelligent analysis
            logger: Logger instance
        """
        self.model = model
        self.logger = logger
        self.functions: Dict[str, FunctionInfo] = {}
        self.call_graph: Dict[str, Set[str]] = {}
        self.vulnerabilities: List[Vulnerability] = []
        
    def analyze_directory(self, directory: str, extensions: List[str] = None) -> Dict[str, Any]:
        """Analyze all files in a directory.
        
        Args:
            directory: Path to directory to analyze
            extensions: File extensions to analyze (default: ['.py', '.c', '.cpp', '.h'])
            
        Returns:
            Analysis results dictionary
        """
        if extensions is None:
            extensions = ['.py', '.c', '.cpp', '.h', '.java', '.js', '.ts']
            
        results = {
            'files_analyzed': [],
            'functions': {},
            'vulnerabilities': [],
            'call_graph': {},
            'statistics': {}
        }
        
        # Find all relevant files
        files_to_analyze = []
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if any(file.endswith(ext) for ext in extensions):
                    files_to_analyze.append(file_path)
        
        if self.logger:
            self.logger.log(f"Found {len(files_to_analyze)} files to analyze")
        
        # Analyze each file
        for file_path in files_to_analyze:
            try:
                file_results = self.analyze_file(file_path)
                results['files_analyzed'].append(file_path)
                
                # Merge results
                if 'functions' in file_results:
                    results['functions'].update(file_results['functions'])
                if 'vulnerabilities' in file_results:
                    results['vulnerabilities'].extend(file_results['vulnerabilities'])
                if 'call_graph' in file_results:
                    results['call_graph'].update(file_results['call_graph'])
                    
            except Exception as e:
                if self.logger:
                    self.logger.log(f"Error analyzing {file_path}: {e}", level="ERROR")
        
        # Generate statistics
        results['statistics'] = self._generate_statistics(results)
        
        return results
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze a single source file.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Analysis results for the file
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            if self.logger:
                self.logger.log(f"Error reading {file_path}: {e}", level="ERROR")
            return {}
        
        file_ext = Path(file_path).suffix.lower()
        
        if file_ext == '.py':
            return self._analyze_python_file(file_path, content)
        elif file_ext in ['.c', '.cpp', '.h', '.hpp']:
            return self._analyze_c_file(file_path, content)
        elif file_ext in ['.java']:
            return self._analyze_java_file(file_path, content)
        elif file_ext in ['.js', '.ts']:
            return self._analyze_javascript_file(file_path, content)
        else:
            return self._analyze_generic_file(file_path, content)
    
    def _analyze_python_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Analyze Python source file."""
        results = {
            'functions': {},
            'vulnerabilities': [],
            'call_graph': {}
        }
        
        try:
            tree = ast.parse(content)
            
            # Extract functions
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    func_info = FunctionInfo(
                        name=node.name,
                        file_path=file_path,
                        start_line=node.lineno,
                        end_line=getattr(node, 'end_lineno', node.lineno),
                        parameters=[arg.arg for arg in node.args.args]
                    )
                    
                    # Extract function calls
                    for child in ast.walk(node):
                        if isinstance(child, ast.Call):
                            if isinstance(child.func, ast.Name):
                                func_info.calls.append(child.func.id)
                            elif isinstance(child.func, ast.Attribute):
                                func_info.calls.append(child.func.attr)
                    
                    results['functions'][f"{file_path}:{node.name}"] = func_info
                    
            # Build call graph for this file
            for func_key, func_info in results['functions'].items():
                if func_key not in results['call_graph']:
                    results['call_graph'][func_key] = set()
                results['call_graph'][func_key].update(func_info.calls)
            
            # Detect vulnerabilities
            vulnerabilities = self._detect_python_vulnerabilities(file_path, content, tree)
            results['vulnerabilities'].extend(vulnerabilities)
            
        except SyntaxError as e:
            if self.logger:
                self.logger.log(f"Syntax error in {file_path}: {e}", level="ERROR")
        
        return results
    
    def _analyze_c_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Analyze C/C++ source file."""
        results = {
            'functions': {},
            'vulnerabilities': [],
            'call_graph': {}
        }
        
        # Basic pattern matching for C functions (simplified)
        import re
        
        # Find function definitions
        func_pattern = r'(?:^|\n)(?:static\s+|inline\s+)?(?:\w+\s+)*(\w+)\s*\([^)]*\)\s*\{'
        matches = re.finditer(func_pattern, content, re.MULTILINE)
        
        for match in matches:
            func_name = match.group(1)
            start_line = content[:match.start()].count('\n') + 1
            
            # Find end of function (simplified)
            brace_count = 0
            end_pos = match.end()
            for i, char in enumerate(content[match.end():], match.end()):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_pos = i
                        break
            
            end_line = content[:end_pos].count('\n') + 1
            
            func_info = FunctionInfo(
                name=func_name,
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                parameters=[]  # Would need more sophisticated parsing
            )
            
            results['functions'][f"{file_path}:{func_name}"] = func_info
        
        # Detect C-specific vulnerabilities
        vulnerabilities = self._detect_c_vulnerabilities(file_path, content)
        results['vulnerabilities'].extend(vulnerabilities)
        
        return results
    
    def _analyze_java_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Analyze Java source file."""
        # Simplified Java analysis
        return self._analyze_generic_file(file_path, content)
    
    def _analyze_javascript_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Analyze JavaScript/TypeScript file."""
        # Simplified JS analysis
        return self._analyze_generic_file(file_path, content)
    
    def _analyze_generic_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Generic file analysis for unsupported languages."""
        results = {
            'functions': {},
            'vulnerabilities': [],
            'call_graph': {}
        }
        
        # Basic vulnerability detection using patterns
        vulnerabilities = self._detect_generic_vulnerabilities(file_path, content)
        results['vulnerabilities'].extend(vulnerabilities)
        
        return results
    
    def _detect_python_vulnerabilities(self, file_path: str, content: str, tree: ast.AST) -> List[Vulnerability]:
        """Detect Python-specific vulnerabilities."""
        vulnerabilities = []
        
        for node in ast.walk(tree):
            # SQL Injection detection
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr in ['execute', 'executemany']:
                    if node.args and isinstance(node.args[0], ast.BinOp):
                        if isinstance(node.args[0].op, ast.Mod) or isinstance(node.args[0].op, ast.Add):
                            vuln = Vulnerability(
                                vuln_type=VulnerabilityType.SQL_INJECTION,
                                severity=Severity.HIGH,
                                location=CodeLocation(file_path, node.lineno, node.lineno),
                                description="Potential SQL injection via string formatting",
                                evidence=ast.unparse(node) if hasattr(ast, 'unparse') else str(node),
                                confidence=0.8,
                                cwe_id="CWE-89",
                                recommendation="Use parameterized queries instead of string formatting"
                            )
                            vulnerabilities.append(vuln)
            
            # Command injection detection
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in ['system', 'popen', 'subprocess']:
                    vuln = Vulnerability(
                        vuln_type=VulnerabilityType.COMMAND_INJECTION,
                        severity=Severity.HIGH,
                        location=CodeLocation(file_path, node.lineno, node.lineno),
                        description="Potential command injection",
                        evidence=ast.unparse(node) if hasattr(ast, 'unparse') else str(node),
                        confidence=0.7,
                        cwe_id="CWE-78",
                        recommendation="Validate and sanitize input before executing commands"
                    )
                    vulnerabilities.append(vuln)
            
            # Insecure deserialization
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr == 'loads':
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == 'pickle':
                        vuln = Vulnerability(
                            vuln_type=VulnerabilityType.INSECURE_DESERIALIZATION,
                            severity=Severity.CRITICAL,
                            location=CodeLocation(file_path, node.lineno, node.lineno),
                            description="Insecure pickle deserialization",
                            evidence=ast.unparse(node) if hasattr(ast, 'unparse') else str(node),
                            confidence=0.9,
                            cwe_id="CWE-502",
                            recommendation="Avoid pickle.loads() on untrusted data"
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _detect_c_vulnerabilities(self, file_path: str, content: str) -> List[Vulnerability]:
        """Detect C/C++ specific vulnerabilities."""
        vulnerabilities = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Buffer overflow patterns
            if any(func in line for func in ['strcpy', 'strcat', 'sprintf', 'gets']):
                vuln = Vulnerability(
                    vuln_type=VulnerabilityType.BUFFER_OVERFLOW,
                    severity=Severity.HIGH,
                    location=CodeLocation(file_path, i, i),
                    description="Use of unsafe string function",
                    evidence=line.strip(),
                    confidence=0.8,
                    cwe_id="CWE-120",
                    recommendation="Use safe alternatives like strncpy, strncat, snprintf"
                )
                vulnerabilities.append(vuln)
            
            # Null pointer dereference patterns
            if 'malloc' in line and 'if' not in line:
                # Simple heuristic: malloc without immediate null check
                vuln = Vulnerability(
                    vuln_type=VulnerabilityType.NULL_POINTER_DEREF,
                    severity=Severity.MEDIUM,
                    location=CodeLocation(file_path, i, i),
                    description="Memory allocation without null check",
                    evidence=line.strip(),
                    confidence=0.6,
                    cwe_id="CWE-476",
                    recommendation="Always check malloc return value for NULL"
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _detect_generic_vulnerabilities(self, file_path: str, content: str) -> List[Vulnerability]:
        """Detect generic vulnerabilities using pattern matching."""
        vulnerabilities = []
        lines = content.split('\n')
        
        # Look for hardcoded credentials
        import re
        
        for i, line in enumerate(lines, 1):
            # Hardcoded passwords/keys
            if re.search(r'(password|pwd|key|secret|token)\s*[=:]\s*["\'][^"\']+["\']', line, re.IGNORECASE):
                vuln = Vulnerability(
                    vuln_type=VulnerabilityType.SQL_INJECTION,  # Using as generic security issue
                    severity=Severity.MEDIUM,
                    location=CodeLocation(file_path, i, i),
                    description="Potential hardcoded credential",
                    evidence=line.strip(),
                    confidence=0.7,
                    cwe_id="CWE-798",
                    recommendation="Use environment variables or secure credential storage"
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _generate_statistics(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate analysis statistics."""
        stats = {
            'total_files': len(results['files_analyzed']),
            'total_functions': len(results['functions']),
            'total_vulnerabilities': len(results['vulnerabilities']),
            'vulnerability_by_severity': {},
            'vulnerability_by_type': {}
        }
        
        # Count by severity
        for vuln in results['vulnerabilities']:
            severity = vuln.severity.value if hasattr(vuln, 'severity') else str(vuln.get('severity', 'unknown'))
            stats['vulnerability_by_severity'][severity] = stats['vulnerability_by_severity'].get(severity, 0) + 1
        
        # Count by type
        for vuln in results['vulnerabilities']:
            vuln_type = vuln.vuln_type.value if hasattr(vuln, 'vuln_type') else str(vuln.get('type', 'unknown'))
            stats['vulnerability_by_type'][vuln_type] = stats['vulnerability_by_type'].get(vuln_type, 0) + 1
        
        return stats
    
    async def generate_function_summary(self, function_info: FunctionInfo, content: str) -> str:
        """Generate LLM-based function summary."""
        if not self.model:
            return "No model available for summary generation"
        
        # Extract function code
        lines = content.split('\n')
        func_lines = lines[function_info.start_line-1:function_info.end_line]
        func_code = '\n'.join(func_lines)
        
        messages = [
            ChatMessage(
                role=MessageRole.SYSTEM,
                content="You are a code analysis expert. Analyze the given function and provide a concise summary."
            ),
            ChatMessage(
                role=MessageRole.USER,
                content=f"Analyze this function and provide a summary:\n\n```\n{func_code}\n```\n\nProvide a brief summary of what this function does, its inputs, outputs, and any potential security concerns."
            )
        ]
        
        try:
            response = self.model.generate(messages)
            return response.content or "Unable to generate summary"
        except Exception as e:
            if self.logger:
                self.logger.log(f"Error generating function summary: {e}", level="ERROR")
            return "Error generating summary"
