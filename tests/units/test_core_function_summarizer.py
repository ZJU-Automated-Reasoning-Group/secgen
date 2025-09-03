"""Unit tests for secgen.core.function_summary module."""

import pytest
import json
import tempfile
import os
from unittest.mock import Mock, patch
from secgen.core.summary import FunctionSummary
from secgen.core.models import FunctionInfo


class TestFunctionSummary:
    """Test FunctionSummary dataclass."""
    
    def test_creation_and_to_dict(self):
        """Test FunctionSummary creation and to_dict method."""
        summary = FunctionSummary(
            function_name="test_func",
            file_path="test.c",
            summary="Test function",
            purpose="Test purpose",
            inputs="Test inputs",
            outputs="Test outputs",
            security_concerns=["risk1"],
            complexity_score=3,
            analysis_confidence=0.8
        )
        
        assert summary.function_name == "test_func"
        assert summary.complexity_score == 3
        assert summary.analysis_confidence == 0.8
        
        result = summary.to_dict()
        assert result['function_name'] == 'test_func'
        assert result['complexity_score'] == 3


class TestFunctionSummaryGenerator:
    """Test FunctionSummaryGenerator class."""
    
    def test_init(self):
        """Test initialization."""
        generator = FunctionSummaryGenerator()
        assert generator.model is None
        assert generator.max_workers == 3
        assert generator.summaries == {}
    
    def test_generate_summary_without_model(self):
        """Test generate_summary without LLM model."""
        generator = FunctionSummaryGenerator()
        
        func_info = FunctionInfo(
            name="test_func",
            file_path="test.c",
            start_line=1,
            end_line=10,
            parameters=["arg1", "arg2"],
            calls=["malloc", "strcpy"]
        )
        
        summary = generator.generate_summary(func_info, "void test_func() {}")
        
        assert isinstance(summary, FunctionSummary)
        assert summary.function_name == "test_func"
        assert summary.analysis_confidence == 1.0
        assert "strcpy" in str(summary.security_concerns)
    
    def test_generate_summary_with_model(self):
        """Test generate_summary with LLM model."""
        model = Mock()
        model.generate.return_value = Mock()
        model.generate.return_value.content = '''
        {
            "summary": "Test function",
            "purpose": "Test purpose",
            "inputs": "Test inputs",
            "outputs": "Test outputs",
            "security_concerns": ["risk1"],
            "complexity_score": 2,
            "confidence": 0.9
        }
        '''
        
        generator = FunctionSummaryGenerator(model=model)
        
        func_info = FunctionInfo(
            name="test_func",
            file_path="test.c",
            start_line=1,
            end_line=5,
            parameters=["arg1"]
        )
        
        summary = generator.generate_summary(func_info, "void test_func() {}")
        
        assert summary.function_name == "test_func"
        assert summary.analysis_confidence == 0.9
        assert "risk1" in summary.security_concerns
    
    def test_analyze_function_statically(self):
        """Test _analyze_function_statically method."""
        generator = FunctionSummaryGenerator()
        
        func_info = FunctionInfo(
            name="complex_func",
            file_path="test.c",
            start_line=1,
            end_line=100,
            parameters=["arg1", "arg2", "arg3", "arg4", "arg5", "arg6"],
            calls=["malloc", "strcpy", "system"]
        )
        
        summary = generator._analyze_function_statically(func_info, "void complex_func() {}")
        
        assert summary.function_name == "complex_func"
        assert summary.complexity_score >= 3  # High due to many params and long function
        assert summary.analysis_confidence == 1.0
        assert len(summary.security_concerns) > 0
    
    def test_get_security_hotspots(self):
        """Test get_security_hotspots method."""
        generator = FunctionSummaryGenerator()
        
        summary1 = FunctionSummary(
            function_name="func1", file_path="test.c", summary="Test",
            purpose="Test", inputs="Test", outputs="Test",
            security_concerns=["risk1"], complexity_score=4, analysis_confidence=0.8
        )
        
        summary2 = FunctionSummary(
            function_name="func2", file_path="test.c", summary="Test",
            purpose="Test", inputs="Test", outputs="Test",
            security_concerns=[], complexity_score=2, analysis_confidence=0.8
        )
        
        generator.summaries = {"test.c:func1": summary1, "test.c:func2": summary2}
        
        hotspots = generator.get_security_hotspots(min_confidence=0.7)
        assert len(hotspots) == 1
        assert hotspots[0].function_name == "func1"
    
    def test_export_summaries(self):
        """Test export_summaries method."""
        generator = FunctionSummaryGenerator()
        
        summary = FunctionSummary(
            function_name="func1", file_path="test.c", summary="Test",
            purpose="Test", inputs="Test", outputs="Test",
            security_concerns=["risk1"], complexity_score=3, analysis_confidence=0.8
        )
        
        generator.summaries = {"test.c:func1": summary}
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            temp_file = f.name
        
        try:
            generator.export_summaries(temp_file)
            
            with open(temp_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            assert data['total_functions'] == 1
            assert 'test.c:func1' in data['functions']
            
        finally:
            os.unlink(temp_file)
    
    def test_generate_summary_report(self):
        """Test generate_summary_report method."""
        generator = FunctionSummaryGenerator()
        
        # Test empty report
        assert generator.generate_summary_report() == "No function summaries available."
        
        # Test with summaries
        summary = FunctionSummary(
            function_name="dangerous_func", file_path="test.c", summary="Dangerous",
            purpose="Test", inputs="Test", outputs="Test",
            security_concerns=["Buffer overflow"], complexity_score=5, analysis_confidence=0.9
        )
        
        generator.summaries = {"test.c:dangerous_func": summary}
        
        report = generator.generate_summary_report()
        assert "# Function Summary Report" in report
        assert "### dangerous_func" in report


if __name__ == "__main__":
    pytest.main()