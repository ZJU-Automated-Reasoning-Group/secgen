"""Unit tests for enhanced alias analysis with tree-sitter based variable identification.

This test suite verifies that the improved interface correctly handles variables with the same name
in different scopes, functions, and locations using precise variable references.
"""

import pytest

from secgen.core.variable_reference import VariableReference, VariableScope, VariableReferenceExtractor
from secgen.alias.alias_driver import ModularAliasAnalyzer, AnalysisConfig
from secgen.core.models import FunctionInfo
from secgen.tsanalyzer import CppSymbolAnalyzer


@pytest.fixture
def sample_cpp_code():
    """Sample C++ code with clear alias relationships for testing."""
    return """
#include <iostream>

int global_x = 10;  // Global variable

void function1(int x) {  // Parameter 'x'
    int local_x = x;     // Direct assignment - creates alias
    int y = local_x;     // Another alias relationship
    int z = y;           // Chain of aliases
    
    // Simple assignments that should be detected
    int a = 5;
    int b = a;           // b aliases a
    int c = b;           // c aliases b (and transitively a)
    
    global_x = local_x;  // Assignment to global
}

void function2() {
    int x = 20;          // Local variable
    int y = x;           // y aliases x
    int z = y;           // z aliases y (and transitively x)
    
    // More complex alias patterns
    int temp = x;
    x = temp;            // x aliases temp
    int result = x;      // result aliases x
}

int main() {
    int x = 5;           // Main function's 'x'
    int y = x;           // y aliases x
    int z = y;           // z aliases y (and transitively x)
    
    function1(x);        // Pass main's 'x' to function1
    function2();
    return x;            // Return main's 'x'
}
"""


@pytest.fixture
def analysis_config():
    """Standard analysis configuration for tests."""
    return AnalysisConfig(
        enable_basic_operations=True,
        enable_function_analysis=True,
        enable_interprocedural=True,
        enable_global_variables=True,
        max_call_depth=3,
        min_confidence=0.0
    )


@pytest.fixture
def analyzer(analysis_config):
    """ModularAliasAnalyzer instance for testing."""
    return ModularAliasAnalyzer(analysis_config)


@pytest.fixture
def symbol_analyzer():
    """CppSymbolAnalyzer instance for testing."""
    return CppSymbolAnalyzer()


@pytest.fixture
def functions(sample_cpp_code, symbol_analyzer):
    """Extracted functions from sample code."""
    analysis_results = symbol_analyzer.analyze_file(sample_cpp_code, "example.cpp")
    
    functions = []
    for func in analysis_results.functions:
        func_info = FunctionInfo(
            name=func.name,
            file_path="example.cpp",
            start_line=func.line_number,
            end_line=func.line_number + 10,  # Estimate
            parameters=func.parameters or []
        )
        functions.append(func_info)
    
    return functions


@pytest.fixture
def variable_references(sample_cpp_code, symbol_analyzer):
    """Variable references extracted from sample code."""
    tree = symbol_analyzer.parse_code(sample_cpp_code)
    variable_extractor = VariableReferenceExtractor("c", symbol_analyzer)
    return variable_extractor.extract_variable_references(tree, sample_cpp_code, "example.cpp")


@pytest.fixture
def analysis_results(analyzer, functions, sample_cpp_code):
    """Results from alias analysis."""
    return analyzer.analyze_functions(functions, sample_cpp_code)

class TestVariableReferenceExtraction:
    """Test variable reference extraction functionality."""
    
    def test_variable_references_extraction(self, variable_references):
        """Test that variable references are properly extracted."""
        assert len(variable_references) > 0, "Should extract variable references from sample code"
        
        # Test unique IDs and source locations
        unique_ids = set()
        for var_ref in variable_references.values():
            assert var_ref.unique_id not in unique_ids, f"Duplicate unique ID: {var_ref.unique_id}"
            unique_ids.add(var_ref.unique_id)
            assert var_ref.source_location is not None, f"Variable reference {var_ref} should have source location"
    
    def test_variable_name_disambiguation(self, variable_references):
        """Test that variables with same name in different scopes are properly disambiguated."""
        variables_by_name = {}
        for var_ref in variable_references.values():
            if var_ref.name not in variables_by_name:
                variables_by_name[var_ref.name] = []
            variables_by_name[var_ref.name].append(var_ref)
        
        # Test that 'x' appears in multiple contexts with unique IDs
        assert 'x' in variables_by_name, "Variable 'x' should be found"
        x_vars = variables_by_name['x']
        assert len(x_vars) > 1, "Variable 'x' should appear in multiple contexts"
        assert len({var.unique_id for var in x_vars}) == len(x_vars), "All 'x' variables should have unique IDs"


class TestFunctionExtraction:
    """Test function extraction functionality."""
    
    def test_functions_extraction(self, functions):
        """Test that functions are properly extracted from sample code."""
        assert len(functions) >= 3, "Should extract at least 3 functions (function1, function2, main)"
        
        function_names = {func.name for func in functions}
        expected_functions = {'function1', 'function2', 'main'}
        assert expected_functions.issubset(function_names), f"Should extract functions: {expected_functions}"
        
        # Test function1 parameters and source locations
        function1 = next((f for f in functions if f.name == 'function1'), None)
        assert function1 is not None, "Should find function1"
        assert len(function1.parameters) == 1, "function1 should have 1 parameter"
        assert 'x' in function1.parameters[0], f"function1 parameter should contain 'x', got: {function1.parameters[0]}"
        
        # Test source locations for all functions
        for func in functions:
            assert func.file_path == "example.cpp"
            assert func.start_line > 0
            assert func.end_line > func.start_line


class TestAliasAnalysis:
    """Test alias analysis functionality."""
    
    def test_alias_analysis_execution(self, analysis_results, analyzer, variable_references):
        """Test that alias analysis executes and works correctly."""
        assert 'modules' in analysis_results, "Analysis results should contain modules"
        assert len(analysis_results['modules']) > 0, "Should analyze at least one module"
        
        # Test local alias detection
        modules = analysis_results['modules']
        has_local_aliases = any(
            module_result.get('local_aliases', {}) 
            for module_result in modules.values()
        )
        assert has_local_aliases, "Should detect at least some local aliases"
        
        # Test get_aliases method
        test_vars = list(variable_references.values())[:3]
        for var_ref in test_vars:
            aliases = analyzer.get_aliases(var_ref)
            assert isinstance(aliases, (list, set)), f"get_aliases should return a list or set, got {type(aliases)}"
            assert var_ref in aliases, f"Variable {var_ref} should be an alias of itself"
        
        # Test analysis summary
        summary = analyzer.get_analysis_summary()
        assert 'total_functions' in summary, "Summary should contain total_functions"
        assert 'analysis_stats' in summary, "Summary should contain analysis_stats"


class TestIntegration:
    """Integration tests for the complete alias analysis workflow."""
    
    def test_complete_analysis_workflow(self, sample_cpp_code, symbol_analyzer, analyzer):
        """Test the complete analysis workflow from code to results."""
        # Parse code and extract functions
        analysis_results = symbol_analyzer.analyze_file(sample_cpp_code, "example.cpp")
        assert analysis_results is not None
        
        functions = []
        for func in analysis_results.functions:
            func_info = FunctionInfo(
                name=func.name,
                file_path="example.cpp",
                start_line=func.line_number,
                end_line=func.line_number + 10,
                parameters=func.parameters or []
            )
            functions.append(func_info)
        
        assert len(functions) > 0, "Should extract functions"
        
        # Run alias analysis
        results = analyzer.analyze_functions(functions, sample_cpp_code)
        assert results is not None
        assert 'modules' in results
        
        # Extract variable references and test alias queries
        tree = symbol_analyzer.parse_code(sample_cpp_code)
        variable_extractor = VariableReferenceExtractor("c", symbol_analyzer)
        variable_references = variable_extractor.extract_variable_references(tree, sample_cpp_code, "example.cpp")
        
        assert len(variable_references) > 0, "Should extract variable references"
        
        # Test alias queries work
        for var_ref in list(variable_references.values())[:3]:
            aliases = analyzer.get_aliases(var_ref)
            assert isinstance(aliases, (list, set)), f"Should be able to query aliases for any variable, got {type(aliases)}"
    
    def test_error_handling(self, analyzer):
        """Test error handling with invalid inputs."""
        # Test with empty function list
        results = analyzer.analyze_functions([], "")
        assert results is not None
        
        # Test with None inputs - this should raise an exception
        with pytest.raises(TypeError):
            analyzer.analyze_functions(None, None)


if __name__ == "__main__":
    pytest.main([__file__])
