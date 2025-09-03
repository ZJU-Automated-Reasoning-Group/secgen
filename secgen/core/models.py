"""Data models and enums for static analysis and vulnerability detection."""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Any


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
