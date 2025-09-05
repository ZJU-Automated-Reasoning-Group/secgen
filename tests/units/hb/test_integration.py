"""Integration tests for happen-before analysis functionality.

This module imports and runs all the individual test modules to ensure
comprehensive coverage of the happen-before analysis system.
"""

import pytest
import test_event
import test_hb_graph
import test_hb_analyzer
import test_race_conditions


class TestHappenBeforeIntegration:
    """Integration tests for the complete happen-before analysis system."""
    
    def test_all_modules_importable(self):
        """Test that all test modules can be imported successfully."""
        # This test ensures all our divided test modules are properly structured
        assert test_event is not None
        assert test_hb_graph is not None
        assert test_hb_analyzer is not None
        assert test_race_conditions is not None

    def test_complete_analysis_workflow(self):
        """Test the complete analysis workflow from start to finish."""
        from secgen.checker.happen_before_analyzer import HappenBeforeAnalyzer
        from secgen.ir.hb_graph import HappenBeforeGraph
        from secgen.core.models import FunctionInfo
        
        # Create a comprehensive test scenario
        functions = {
            "main": FunctionInfo(
                name="main",
                file_path="test.cpp",
                start_line=1,
                end_line=50,
                parameters=[],
                calls=["pthread_create", "pthread_join"]
            ),
            "worker": FunctionInfo(
                name="worker_thread",
                file_path="test.cpp",
                start_line=10,
                end_line=30,
                parameters=["arg"],
                calls=["pthread_mutex_lock", "pthread_mutex_unlock"]
            )
        }
        
        analyzer = HappenBeforeAnalyzer()
        hb_graph = analyzer.analyze_functions(functions)
        
        # Verify the analysis produces expected results
        assert isinstance(hb_graph, HappenBeforeGraph)
        assert len(hb_graph.events) > 0
        
        # Get analysis results
        results = analyzer.get_analysis_results()
        assert 'graph' in results
        assert 'race_conditions' in results
        assert 'concurrency_patterns' in results
        assert 'metrics' in results
        
        # Verify metrics are calculated
        metrics = results['metrics']
        assert 'num_events' in metrics
        assert 'num_relations' in metrics
        assert 'num_race_conditions' in metrics


if __name__ == "__main__":
    pytest.main([__file__])
