"""Unit tests for secgen.core.function_summarizer module."""

import pytest
import json
import tempfile
import os
from unittest.mock import Mock, patch
from secgen.core.function_summarizer import LLMFunctionSummary, FunctionSummarizer
from secgen.core.models import FunctionInfo


class TestLLMFunctionSummary:
    """Test LLMFunctionSummary dataclass."""
    
    def test_creation_and_to_dict(self):
        """Test LLMFunctionSummary creation and to_dict method."""
        summary = LLMFunctionSummary(
            function_name="test_func",
            file_path="test.c",
            summary="Test function",
            purpose="Test purpose",
            inputs="Test inputs",
            outputs="Test outputs",
            security_concerns=["risk1"],
            complexity_score=3,
            confidence=0.8
        )
        
        assert summary.function_name == "test_func"
        assert summary.complexity_score == 3
        assert summary.confidence == 0.8
        
        result = summary.to_dict()
        assert result['function_name'] == 'test_func'
        assert result['complexity_score'] == 3


class TestFunctionSummarizer:
    """Test FunctionSummarizer class."""
    
    def test_init(self):
        """Test initialization."""
        summarizer = FunctionSummarizer()
        assert summarizer.model is None
        assert summarizer.max_workers == 3
        assert summarizer.summaries == {}
    
    def test_summarize_function_without_model(self):
        """Test summarize_function without LLM model."""
        summarizer = FunctionSummarizer()
        
        func_info = FunctionInfo(
            name="test_func",
            file_path="test.c",
            start_line=1,
            end_line=10,
            parameters=["arg1", "arg2"],
            calls=["malloc", "strcpy"]
        )
        
        summary = summarizer.summarize_function(func_info, "void test_func() {}")
        
        assert isinstance(summary, LLMFunctionSummary)
        assert summary.function_name == "test_func"
        assert summary.confidence == 0.5
        assert "strcpy" in str(summary.security_concerns)
    
    def test_summarize_function_with_model(self):
        """Test summarize_function with LLM model."""
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
        
        summarizer = FunctionSummarizer(model=model)
        
        func_info = FunctionInfo(
            name="test_func",
            file_path="test.c",
            start_line=1,
            end_line=5,
            parameters=["arg1"]
        )
        
        summary = summarizer.summarize_function(func_info, "void test_func() {}")
        
        assert summary.function_name == "test_func"
        assert summary.confidence == 0.9
        assert "risk1" in summary.security_concerns
    
    def test_generate_basic_summary(self):
        """Test _generate_basic_summary method."""
        summarizer = FunctionSummarizer()
        
        func_info = FunctionInfo(
            name="complex_func",
            file_path="test.c",
            start_line=1,
            end_line=100,
            parameters=["arg1", "arg2", "arg3", "arg4", "arg5", "arg6"],
            calls=["malloc", "strcpy", "system"]
        )
        
        summary = summarizer._generate_basic_summary(func_info)
        
        assert summary.function_name == "complex_func"
        assert summary.complexity_score >= 3  # High due to many params and long function
        assert summary.confidence == 0.5
        assert len(summary.security_concerns) > 0
    
    def test_get_security_hotspots(self):
        """Test get_security_hotspots method."""
        summarizer = FunctionSummarizer()
        
        summary1 = LLMFunctionSummary(
            function_name="func1", file_path="test.c", summary="Test",
            purpose="Test", inputs="Test", outputs="Test",
            security_concerns=["risk1"], complexity_score=4, confidence=0.8
        )
        
        summary2 = LLMFunctionSummary(
            function_name="func2", file_path="test.c", summary="Test",
            purpose="Test", inputs="Test", outputs="Test",
            security_concerns=[], complexity_score=2, confidence=0.8
        )
        
        summarizer.summaries = {"test.c:func1": summary1, "test.c:func2": summary2}
        
        hotspots = summarizer.get_security_hotspots(min_confidence=0.7)
        assert len(hotspots) == 1
        assert hotspots[0].function_name == "func1"
    
    def test_export_summaries(self):
        """Test export_summaries method."""
        summarizer = FunctionSummarizer()
        
        summary = LLMFunctionSummary(
            function_name="func1", file_path="test.c", summary="Test",
            purpose="Test", inputs="Test", outputs="Test",
            security_concerns=["risk1"], complexity_score=3, confidence=0.8
        )
        
        summarizer.summaries = {"test.c:func1": summary}
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            temp_file = f.name
        
        try:
            summarizer.export_summaries(temp_file)
            
            with open(temp_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            assert data['total_functions'] == 1
            assert 'test.c:func1' in data['functions']
            
        finally:
            os.unlink(temp_file)
    
    def test_generate_summary_report(self):
        """Test generate_summary_report method."""
        summarizer = FunctionSummarizer()
        
        # Test empty report
        assert summarizer.generate_summary_report() == "No function summaries available."
        
        # Test with summaries
        summary = LLMFunctionSummary(
            function_name="dangerous_func", file_path="test.c", summary="Dangerous",
            purpose="Test", inputs="Test", outputs="Test",
            security_concerns=["Buffer overflow"], complexity_score=5, confidence=0.9
        )
        
        summarizer.summaries = {"test.c:dangerous_func": summary}
        
        report = summarizer.generate_summary_report()
        assert "# Function Summary Report" in report
        assert "### dangerous_func" in report


if __name__ == "__main__":
    pytest.main()