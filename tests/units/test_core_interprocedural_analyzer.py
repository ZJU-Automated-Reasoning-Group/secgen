"""Unit tests for secgen.core.interprocedural_analyzer module."""

import pytest
from unittest.mock import Mock, patch
from secgen.core.interprocedural_analyzer import InterproceduralAnalyzer
from secgen.core.models import FunctionInfo, Vulnerability, VulnerabilityType, Severity, CodeLocation
from secgen.core.summary import FunctionSummary


class TestInterproceduralAnalyzer:
    """Test InterproceduralAnalyzer class."""
    
    def test_init(self):
        """Test initialization."""
        analyzer = InterproceduralAnalyzer()
        assert analyzer.model is None
        assert analyzer.logger is None
        assert analyzer.functions == {}
        assert analyzer.function_summaries == {}
    
    def test_build_call_graph(self):
        """Test build_call_graph method."""
        analyzer = InterproceduralAnalyzer()
        
        functions = {
            "func1": FunctionInfo(
                name="func1", file_path="test.c", start_line=1, end_line=5,
                parameters=[], calls=["func2"]
            ),
            "func2": FunctionInfo(
                name="func2", file_path="test.c", start_line=6, end_line=10,
                parameters=[], calls=[]
            )
        }
        
        with patch.object(analyzer.call_graph_builder, 'build_call_graph') as mock_build:
            mock_build.return_value = Mock()
            result = analyzer.build_call_graph(functions)
            
            assert analyzer.functions == functions
            mock_build.assert_called_once_with(functions)
    
    def test_build_function_summaries(self):
        """Test build_function_summaries method."""
        analyzer = InterproceduralAnalyzer()
        logger = Mock()
        analyzer.logger = logger
        
        functions = {
            "func1": FunctionInfo(
                name="func1", file_path="test.c", start_line=1, end_line=5,
                parameters=[]
            )
        }
        
        file_contents = {"test.c": "void func1() {}"}
        
        with patch.object(analyzer.summary_generator, 'compute_summary_for_call_graph') as mock_compute:
            mock_summaries = {"test.c:func1": Mock()}
            mock_compute.return_value = mock_summaries
            
            result = analyzer.build_function_summaries(functions, file_contents)
            
            assert result == mock_summaries
            assert analyzer.function_summaries == mock_summaries
            mock_compute.assert_called_once_with(functions, file_contents)
    
    def test_find_reachable_functions(self):
        """Test find_reachable_functions method."""
        analyzer = InterproceduralAnalyzer()
        
        with patch.object(analyzer.call_graph_builder, 'find_reachable_functions') as mock_find:
            mock_find.return_value = {"func1", "func2"}
            
            result = analyzer.find_reachable_functions("start_func")
            
            assert result == {"func1", "func2"}
            mock_find.assert_called_once_with("start_func")
    
    def test_find_call_paths(self):
        """Test find_call_paths method."""
        analyzer = InterproceduralAnalyzer()
        
        with patch.object(analyzer.call_graph_builder, 'find_call_paths') as mock_find:
            mock_find.return_value = [["func1", "func2", "func3"]]
            
            result = analyzer.find_call_paths("func1", "func3")
            
            assert result == [["func1", "func2", "func3"]]
            mock_find.assert_called_once_with("func1", "func3")
    
    def test_analyze_interprocedural_taint_flow(self):
        """Test analyze_interprocedural_taint_flow method."""
        analyzer = InterproceduralAnalyzer()
        
        # Test with no summaries
        result = analyzer.analyze_interprocedural_taint_flow()
        assert result == []
        
        # Test with summaries
        summary1 = FunctionSummary(
            function_name="source_func", file_path="test.c",
            side_effects=[Mock(type="user_input")]
        )
        summary2 = FunctionSummary(
            function_name="sink_func", file_path="test.c",
            security_sensitive=True
        )
        
        analyzer.function_summaries = {
            "test.c:source_func": summary1,
            "test.c:sink_func": summary2
        }
        
        with patch.object(analyzer, '_trace_taint_through_call_graph') as mock_trace:
            mock_trace.return_value = [Mock()]
            
            result = analyzer.analyze_interprocedural_taint_flow()
            
            assert len(result) == 1
            mock_trace.assert_called_once()
    
    def test_detect_interprocedural_vulnerabilities(self):
        """Test detect_interprocedural_vulnerabilities method."""
        analyzer = InterproceduralAnalyzer()
        
        file_contents = {"test.c": "void func1() {}"}
        
        with patch.object(analyzer, 'analyze_data_flow') as mock_analyze:
            mock_taint_path = Mock()
            mock_taint_path.vulnerability_type = VulnerabilityType.BUFFER_OVERFLOW
            mock_taint_path.sink.line_number = 10
            mock_taint_path.confidence = 0.8
            mock_analyze.return_value = [mock_taint_path]
            
            with patch.object(analyzer, '_analyze_call_graph_patterns') as mock_patterns:
                mock_patterns.return_value = []
                
                result = analyzer.detect_interprocedural_vulnerabilities(file_contents)
                
                assert len(result) == 1
                assert isinstance(result[0], Vulnerability)
                assert result[0].vuln_type == VulnerabilityType.BUFFER_OVERFLOW
                assert result[0].severity == Severity.HIGH
    
    def test_analyze_reachability(self):
        """Test analyze_reachability method."""
        analyzer = InterproceduralAnalyzer()
        
        with patch.object(analyzer.call_graph_builder, 'analyze_reachability') as mock_analyze:
            mock_analyze.return_value = {"target_func": ["entry1", "entry2"]}
            
            result = analyzer.analyze_reachability(["entry1", "entry2"], ["target_func"])
            
            assert result == {"target_func": ["entry1", "entry2"]}
            mock_analyze.assert_called_once_with(["entry1", "entry2"], ["target_func"])
    
    def test_get_call_graph_metrics(self):
        """Test get_call_graph_metrics method."""
        analyzer = InterproceduralAnalyzer()
        
        with patch.object(analyzer.call_graph_builder, 'get_call_graph_metrics') as mock_metrics:
            mock_metrics.return_value = Mock()
            
            result = analyzer.get_call_graph_metrics()
            
            assert result is not None
            mock_metrics.assert_called_once()


if __name__ == "__main__":
    pytest.main()