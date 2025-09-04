"""Unit tests for core models and data structures."""

import pytest
from secgen.core.models import (
    VulnerabilityType, 
    Severity, 
    CodeLocation, 
    PathStep, 
    Vulnerability,
    FunctionInfo
)


class TestVulnerabilityType:
    """Test cases for VulnerabilityType enum."""
    
    def test_vulnerability_types(self):
        """Test that all vulnerability types are defined."""
        expected_types = {
            'buffer_overflow', 'null_pointer_dereference', 'use_after_free',
            'memory_leak', 'sql_injection', 'command_injection', 'cross_site_scripting',
            'path_traversal', 'insecure_deserialization', 'integer_overflow'
        }
        
        actual_types = {vtype.value for vtype in VulnerabilityType}
        assert actual_types == expected_types
    
    def test_vulnerability_type_values(self):
        """Test that vulnerability type values are correct."""
        assert VulnerabilityType.BUFFER_OVERFLOW.value == "buffer_overflow"
        assert VulnerabilityType.NULL_POINTER_DEREF.value == "null_pointer_dereference"
        assert VulnerabilityType.USE_AFTER_FREE.value == "use_after_free"
        assert VulnerabilityType.SQL_INJECTION.value == "sql_injection"


class TestSeverity:
    """Test cases for Severity enum."""
    
    def test_severity_levels(self):
        """Test that all severity levels are defined."""
        expected_levels = {'critical', 'high', 'medium', 'low', 'info'}
        actual_levels = {severity.value for severity in Severity}
        assert actual_levels == expected_levels
    
    def test_severity_values(self):
        """Test that severity values are correct."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"


class TestCodeLocation:
    """Test cases for CodeLocation dataclass."""
    
    def test_code_location_creation(self):
        """Test basic CodeLocation creation."""
        location = CodeLocation(
            file_path="test.c",
            line_start=10,
            line_end=15,
            column_start=5,
            column_end=20
        )
        
        assert location.file_path == "test.c"
        assert location.line_start == 10
        assert location.line_end == 15
        assert location.column_start == 5
        assert location.column_end == 20
    
    def test_code_location_default_columns(self):
        """Test CodeLocation with default column values."""
        location = CodeLocation(
            file_path="test.c",
            line_start=10,
            line_end=15
        )
        
        assert location.column_start == 0
        assert location.column_end == 0
    
    def test_code_location_str_single_line(self):
        """Test string representation for single line."""
        location = CodeLocation(
            file_path="test.c",
            line_start=10,
            line_end=10
        )
        
        assert str(location) == "test.c:10"
    
    def test_code_location_str_range(self):
        """Test string representation for line range."""
        location = CodeLocation(
            file_path="test.c",
            line_start=10,
            line_end=15
        )
        
        assert str(location) == "test.c:10-15"


class TestPathStep:
    """Test cases for PathStep dataclass."""
    
    def test_path_step_creation(self):
        """Test basic PathStep creation."""
        location = CodeLocation("test.c", 10, 15)
        step = PathStep(
            location=location,
            description="Test step description",
            node_type="source"
        )
        
        assert step.location == location
        assert step.description == "Test step description"
        assert step.node_type == "source"


class TestVulnerability:
    """Test cases for Vulnerability dataclass."""
    
    def test_vulnerability_creation(self):
        """Test basic Vulnerability creation."""
        location = CodeLocation("test.c", 10, 15)
        vulnerability = Vulnerability(
            vuln_type=VulnerabilityType.BUFFER_OVERFLOW,
            severity=Severity.HIGH,
            location=location,
            description="Test vulnerability",
            evidence="Buffer overflow detected",
            confidence=0.8
        )
        
        assert vulnerability.vuln_type == VulnerabilityType.BUFFER_OVERFLOW
        assert vulnerability.severity == Severity.HIGH
        assert vulnerability.location == location
        assert vulnerability.description == "Test vulnerability"
        assert vulnerability.evidence == "Buffer overflow detected"
        assert vulnerability.confidence == 0.8
        assert vulnerability.path is None
        assert vulnerability.recommendation is None
    
    def test_vulnerability_with_path(self):
        """Test Vulnerability with path steps."""
        location1 = CodeLocation("test.c", 10, 15)
        location2 = CodeLocation("test.c", 20, 25)
        
        step1 = PathStep(location1, "Source of taint", "source")
        step2 = PathStep(location2, "Sink where taint is used", "sink")
        
        vulnerability = Vulnerability(
            vuln_type=VulnerabilityType.COMMAND_INJECTION,
            severity=Severity.CRITICAL,
            location=location2,
            description="Command injection vulnerability",
            evidence="Command injection detected",
            confidence=0.9,
            recommendation="Use parameterized queries"
        )
        
        assert vulnerability.recommendation == "Use parameterized queries"


class TestFunctionInfo:
    """Test cases for FunctionInfo dataclass."""
    
    def test_function_info_creation(self):
        """Test basic FunctionInfo creation."""
        function_info = FunctionInfo(
            name="test_function",
            file_path="test.c",
            start_line=10,
            end_line=20,
            parameters=["int x", "char* str"],
            return_type="int"
        )
        
        assert function_info.name == "test_function"
        assert function_info.file_path == "test.c"
        assert function_info.start_line == 10
        assert function_info.end_line == 20
        assert function_info.parameters == ["int x", "char* str"]
        assert function_info.return_type == "int"
        assert function_info.calls == []
        assert function_info.called_by == []
        assert function_info.is_exported is False
        assert function_info.is_static is False
    
    def test_function_info_with_calls(self):
        """Test FunctionInfo with function calls."""
        function_info = FunctionInfo(
            name="main",
            file_path="main.c",
            start_line=1,
            end_line=50,
            parameters=[],
            return_type="int",
            calls=["printf", "malloc", "free"],
            called_by=[],
            is_exported=True
        )
        
        assert function_info.calls == ["printf", "malloc", "free"]
        assert function_info.is_exported is True
        assert function_info.is_static is False
    
    def test_function_info_static_function(self):
        """Test FunctionInfo for static function."""
        function_info = FunctionInfo(
            name="static_helper",
            file_path="helper.c",
            start_line=5,
            end_line=15,
            parameters=["int x"],
            return_type="void",
            is_static=True
        )
        
        assert function_info.is_static is True
        assert function_info.is_exported is False

