"""Base class for vulnerability detectors."""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from secgen.core.models import Vulnerability, VulnerabilityType, Severity, CodeLocation


@dataclass
class DetectionContext:
    """Context information for vulnerability detection."""
    file_path: str
    lines: List[str]
    allocations: Dict[str, Any] = None
    tainted_vars: Dict[str, Any] = None
    functions: Dict[str, Any] = None
    function_summaries: Dict[str, Any] = None
    interprocedural_analyzer: Any = None


class BaseVulnerabilityDetector(ABC):
    """Base class for all vulnerability detectors."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, logger=None):
        """Initialize the detector.
        
        Args:
            config: Configuration dictionary for this detector
            logger: Logger instance for logging
        """
        self.config = config or {}
        self.logger = logger
        self.vuln_type = self.get_vulnerability_type()
    
    @abstractmethod
    def get_vulnerability_type(self) -> VulnerabilityType:
        """Get the vulnerability type this detector handles."""
        pass
    
    @abstractmethod
    def detect(self, context: DetectionContext) -> List[Vulnerability]:
        """Detect vulnerabilities in the given context.
        
        Args:
            context: Detection context containing file information and analysis data
            
        Returns:
            List of detected vulnerabilities
        """
        pass
    
    def supports_file_type(self, file_path: str) -> bool:
        """Check if this detector supports the given file type.
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            True if the detector supports this file type
        """
        return True  # Override in subclasses for specific file type support
    
    def get_supported_extensions(self) -> List[str]:
        """Get file extensions supported by this detector.
        
        Returns:
            List of supported file extensions
        """
        return []  # Override in subclasses for specific extensions
    
    def log_detection(self, message: str, level: str = "INFO") -> None:
        """Log a detection message.
        
        Args:
            message: Message to log
            level: Log level (INFO, WARNING, ERROR)
        """
        if self.logger:
            self.logger.log(f"[{self.vuln_type.value}] {message}", level=level)
    
    def create_vulnerability(self, 
                           location: CodeLocation,
                           description: str,
                           evidence: str,
                           severity: Severity = None,
                           confidence: float = 0.8,
                           cwe_id: str = None,
                           recommendation: str = None,
                           path: Any = None) -> Vulnerability:
        """Create a vulnerability instance.
        
        Args:
            location: Code location of the vulnerability
            description: Description of the vulnerability
            evidence: Evidence code/line
            severity: Severity level (defaults to detector's default)
            confidence: Confidence level (0.0-1.0)
            cwe_id: CWE identifier
            recommendation: Fix recommendation
            path: Vulnerability path information
            
        Returns:
            Vulnerability instance
        """
        if severity is None:
            severity = self.get_default_severity()
        
        return Vulnerability(
            vuln_type=self.vuln_type,
            severity=severity,
            location=location,
            description=description,
            evidence=evidence,
            confidence=confidence,
            cwe_id=cwe_id,
            recommendation=recommendation,
            path=path
        )
    
    def get_default_severity(self) -> Severity:
        """Get the default severity for this vulnerability type.
        
        Returns:
            Default severity level
        """
        # Default severity mapping - can be overridden in subclasses
        severity_map = {
            VulnerabilityType.USE_AFTER_FREE: Severity.HIGH,
            VulnerabilityType.NULL_POINTER_DEREF: Severity.HIGH,
            VulnerabilityType.BUFFER_OVERFLOW: Severity.HIGH,
            VulnerabilityType.MEMORY_LEAK: Severity.MEDIUM,
            VulnerabilityType.SQL_INJECTION: Severity.HIGH,
            VulnerabilityType.COMMAND_INJECTION: Severity.CRITICAL,
            VulnerabilityType.XSS: Severity.MEDIUM,
            VulnerabilityType.PATH_TRAVERSAL: Severity.HIGH,
            VulnerabilityType.INTEGER_OVERFLOW: Severity.MEDIUM,
        }
        return severity_map.get(self.vuln_type, Severity.MEDIUM)
    
    def get_default_cwe_id(self) -> str:
        """Get the default CWE ID for this vulnerability type.
        
        Returns:
            Default CWE identifier
        """
        # Default CWE mapping - can be overridden in subclasses
        cwe_map = {
            VulnerabilityType.USE_AFTER_FREE: "CWE-416",
            VulnerabilityType.NULL_POINTER_DEREF: "CWE-476",
            VulnerabilityType.BUFFER_OVERFLOW: "CWE-120",
            VulnerabilityType.MEMORY_LEAK: "CWE-401",
            VulnerabilityType.SQL_INJECTION: "CWE-89",
            VulnerabilityType.COMMAND_INJECTION: "CWE-78",
            VulnerabilityType.XSS: "CWE-79",
            VulnerabilityType.PATH_TRAVERSAL: "CWE-22",
            VulnerabilityType.INTEGER_OVERFLOW: "CWE-190",
        }
        return cwe_map.get(self.vuln_type, "CWE-000")
    
    def get_default_recommendation(self) -> str:
        """Get the default fix recommendation for this vulnerability type.
        
        Returns:
            Default recommendation
        """
        # Default recommendations - can be overridden in subclasses
        recommendations = {
            VulnerabilityType.USE_AFTER_FREE: "Set pointer to NULL after freeing or avoid using after free",
            VulnerabilityType.NULL_POINTER_DEREF: "Check if pointer is NULL before dereferencing",
            VulnerabilityType.BUFFER_OVERFLOW: "Use safe string functions and validate buffer sizes",
            VulnerabilityType.MEMORY_LEAK: "Ensure proper deallocation of allocated memory",
            VulnerabilityType.SQL_INJECTION: "Use parameterized queries or prepared statements",
            VulnerabilityType.COMMAND_INJECTION: "Validate and sanitize input data",
            VulnerabilityType.XSS: "Use auto-escaping templates or manually escape output",
            VulnerabilityType.PATH_TRAVERSAL: "Validate file paths and use allowlist of permitted locations",
            VulnerabilityType.INTEGER_OVERFLOW: "Check for integer overflow before operations",
        }
        return recommendations.get(self.vuln_type, "Validate and sanitize input data")
