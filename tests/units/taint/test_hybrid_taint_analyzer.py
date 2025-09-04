"""Unit tests for HybridTaintAnalyzer."""

import pytest
from unittest.mock import Mock, MagicMock
from secgen.core.hybrid_taint_analyzer import (
    HybridTaintAnalyzer, 
    TaintPropagationResult, 
    TaintPath, 
    TaintComplexity
)
from secgen.core.summary import FunctionSummary, TaintPropagationType
from secgen.core.models import FunctionInfo


class TestHybridTaintAnalyzer:
    """Test cases for HybridTaintAnalyzer."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.analyzer = HybridTaintAnalyzer(logger=self.mock_logger)
    
    def test_initialization(self):
        """Test analyzer initialization."""
        assert self.analyzer.logger == self.mock_logger
        assert self.analyzer.alias_analyzer is not None
        assert isinstance(self.analyzer.propagation_cache, dict)
        assert isinstance(self.analyzer.path_cache, dict)
        assert len(self.analyzer.taint_preserving_functions) > 0
        assert len(self.analyzer.taint_sanitizing_functions) > 0
        assert len(self.analyzer.taint_introducing_functions) > 0
        assert len(self.analyzer.dangerous_sink_functions) > 0
    
    def test_static_taint_preserving_functions(self):
        """Test that taint-preserving functions are correctly identified."""
        # Create mock function summaries for taint-preserving functions
        caller_summary = self._create_mock_summary("caller")
        callee_summary = self._create_mock_summary("strcpy")
        
        result = self.analyzer.analyze_taint_propagation(
            caller_summary, callee_summary, {}
        )
        
        assert result.can_propagate is True
        assert result.propagation_type == TaintPropagationType.PRESERVES_TAINT
        assert result.complexity == TaintComplexity.SIMPLE
        assert result.llm_used is False
    
    def test_static_taint_sanitizing_functions(self):
        """Test that taint-sanitizing functions are correctly identified."""
        caller_summary = self._create_mock_summary("caller")
        callee_summary = self._create_mock_summary("strlen")
        
        result = self.analyzer.analyze_taint_propagation(
            caller_summary, callee_summary, {}
        )
        
        assert result.can_propagate is False
        assert result.propagation_type == TaintPropagationType.SANITIZES_TAINT
        assert result.complexity == TaintComplexity.SIMPLE
        assert result.llm_used is False
    
    def test_static_taint_introducing_functions(self):
        """Test that taint-introducing functions are correctly identified."""
        caller_summary = self._create_mock_summary("caller")
        callee_summary = self._create_mock_summary("scanf")
        
        result = self.analyzer.analyze_taint_propagation(
            caller_summary, callee_summary, {}
        )
        
        assert result.can_propagate is True
        assert result.propagation_type == TaintPropagationType.INTRODUCES_TAINT
        assert result.complexity == TaintComplexity.SIMPLE
        assert result.llm_used is False
    
    def test_dangerous_sink_functions(self):
        """Test that dangerous sink functions are correctly identified."""
        caller_summary = self._create_mock_summary("caller")
        callee_summary = self._create_mock_summary("system")
        
        result = self.analyzer.analyze_taint_propagation(
            caller_summary, callee_summary, {}
        )
        
        assert result.can_propagate is True
        assert result.propagation_type == TaintPropagationType.DANGEROUS_SINK
        assert result.complexity == TaintComplexity.SIMPLE
        assert result.llm_used is False
    
    def test_caching_behavior(self):
        """Test that analysis results are properly cached."""
        caller_summary = self._create_mock_summary("caller")
        callee_summary = self._create_mock_summary("strcpy")
        
        # First call should not be cached
        result1 = self.analyzer.analyze_taint_propagation(
            caller_summary, callee_summary, {}
        )
        
        # Second call should be cached
        result2 = self.analyzer.analyze_taint_propagation(
            caller_summary, callee_summary, {}
        )
        
        assert result1 == result2
        assert (caller_summary.function_name, callee_summary.function_name) in self.analyzer.propagation_cache
    
    def test_unknown_function_complexity(self):
        """Test that unknown functions are marked as complex."""
        caller_summary = self._create_mock_summary("caller")
        callee_summary = self._create_mock_summary("unknown_function")
        
        result = self.analyzer.analyze_taint_propagation(
            caller_summary, callee_summary, {}
        )
        
        assert result.complexity == TaintComplexity.COMPLEX
        assert result.llm_used is False  # No LLM tools available in test
    
    def test_taint_path_creation(self):
        """Test taint path creation and validation."""
        path = TaintPath(
            source_function="source",
            sink_function="sink",
            path=["source", "intermediate", "sink"],
            confidence=0.8,
            requires_llm_analysis=False
        )
        
        assert path.source_function == "source"
        assert path.sink_function == "sink"
        assert len(path.path) == 3
        assert path.confidence == 0.8
        assert path.requires_llm_analysis is False
    
    def test_taint_propagation_result_creation(self):
        """Test TaintPropagationResult creation and properties."""
        result = TaintPropagationResult(
            can_propagate=True,
            confidence=0.9,
            propagation_type=TaintPropagationType.PRESERVES_TAINT,
            complexity=TaintComplexity.SIMPLE,
            explanation="Test explanation",
            llm_used=False
        )
        
        assert result.can_propagate is True
        assert result.confidence == 0.9
        assert result.propagation_type == TaintPropagationType.PRESERVES_TAINT
        assert result.complexity == TaintComplexity.SIMPLE
        assert result.explanation == "Test explanation"
        assert result.llm_used is False
    
    def _create_mock_summary(self, function_name: str) -> FunctionSummary:
        """Create a mock FunctionSummary for testing."""
        return FunctionSummary(
            function_name=function_name,
            file_path="test.c",
            start_line=1,
            end_line=10
        )

