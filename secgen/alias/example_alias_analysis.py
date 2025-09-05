#!/usr/bin/env python3
"""Example demonstrating the enhanced alias analysis with tree-sitter based variable identification.

This example shows how the improved interface handles variables with the same name
in different scopes, functions, and locations using precise variable references.
"""

import sys
import os

from secgen.core.variable_reference import VariableReference, VariableScope, VariableReferenceExtractor
from secgen.alias.alias_driver import ModularAliasAnalyzer, AnalysisConfig
from secgen.core.models import FunctionInfo
from secgen.tsanalyzer import CppSymbolAnalyzer


def demonstrate_enhanced_variable_identification():
    """Demonstrate how the enhanced system handles variable name conflicts."""
    
    # Sample C++ code with clear alias relationships
    sample_code = """
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
    
    print("=== Enhanced Alias Analysis with Tree-Sitter Variable Identification ===\n")
    
    # Initialize the enhanced analyzer
    config = AnalysisConfig(
        enable_basic_operations=True,
        enable_function_analysis=True,
        enable_interprocedural=True,
        enable_global_variables=True,
        max_call_depth=3,
        min_confidence=0.0
    )
    
    analyzer = ModularAliasAnalyzer(config)
    
    # Extract functions from the code
    symbol_analyzer = CppSymbolAnalyzer()
    analysis_results = symbol_analyzer.analyze_file(sample_code, "example.cpp")
    
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
    
    print(f"Found {len(functions)} functions: {[f.name for f in functions]}\n")
    
    # Analyze functions
    results = analyzer.analyze_functions(functions, sample_code)
    
    # Demonstrate precise variable identification
    print("=== Variable Reference Analysis ===\n")
    
    # Extract variable references using tree-sitter
    tree = symbol_analyzer.parse_code(sample_code)
    variable_extractor = VariableReferenceExtractor("c", symbol_analyzer)
    variable_references = variable_extractor.extract_variable_references(tree, sample_code, "example.cpp")
    
    print(f"Found {len(variable_references)} variable references:\n")
    
    # Group variables by name to show disambiguation
    variables_by_name = {}
    for var_ref in variable_references.values():
        if var_ref.name not in variables_by_name:
            variables_by_name[var_ref.name] = []
        variables_by_name[var_ref.name].append(var_ref)
    
    for var_name, var_refs in variables_by_name.items():
        print(f"Variable '{var_name}' appears in {len(var_refs)} different contexts:")
        for i, var_ref in enumerate(var_refs, 1):
            scope_info = f"{var_ref.scope.value}"
            if var_ref.function_name:
                scope_info += f" in function '{var_ref.function_name}'"
            if var_ref.block_id:
                scope_info += f" (block: {var_ref.block_id})"
            
            location_info = "unknown location"
            if var_ref.source_location:
                file_path, start_line, end_line, col = var_ref.source_location
                location_info = f"{file_path}:{start_line}:{col}"
            
            print(f"  {i}. {var_ref} - {scope_info} at {location_info}")
            print(f"     Unique ID: {var_ref.unique_id}")
            print(f"     Type: {var_ref.variable_type or 'unknown'}, Pointer: {var_ref.is_pointer}, Array: {var_ref.is_array}")
        print()
    
    # Demonstrate alias analysis with precise references
    print("=== Alias Analysis Results ===\n")
    
    # Show aliases for all variables, not just 'x'
    all_variables = list(variables_by_name.keys())
    print(f"Analyzing aliases for all variables: {all_variables}\n")
    
    for var_name, var_refs in variables_by_name.items():
        print(f"Variable '{var_name}' ({len(var_refs)} references):")
        for i, var_ref in enumerate(var_refs, 1):
            print(f"  {i}. {var_ref}")
            aliases = analyzer.get_aliases(var_ref)
            # Filter out self-references
            other_aliases = [alias for alias in aliases if alias.unique_id != var_ref.unique_id]
            if other_aliases:
                print(f"     Aliases: {[str(alias) for alias in other_aliases]}")
                # Show specific alias relationships
                for alias in other_aliases:
                    location_info = "unknown location"
                    if alias.source_location:
                        file_path, start_line, end_line, col = alias.source_location
                        location_info = f"{file_path}:{start_line}:{col}"
                    print(f"       -> {alias.name} at {location_info}")
            else:
                print(f"     Aliases: []")
        print()
    
    # Show some specific alias relationships
    print("=== Specific Alias Tests ===\n")
    
    # Test some expected alias relationships
    test_cases = []
    for var_name, var_refs in variables_by_name.items():
        if len(var_refs) >= 2:
            test_cases.append((var_refs[0], var_refs[1], f"Different {var_name} variables"))
    
    for var1, var2, description in test_cases[:3]:  # Test first 3 cases
        are_aliases = analyzer.are_aliases(var1, var2)
        print(f"{description}: {are_aliases}")
        print(f"  {var1}")
        print(f"  {var2}")
        print()
    
    # Show detailed alias relationships
    print("=== Detailed Alias Relationships ===\n")
    for func_name, module_result in results['modules'].items():
        print(f"Function '{func_name}':")
        
        # Show local aliases
        local_aliases = module_result['local_aliases']
        if local_aliases:
            print(f"  Local aliases ({len(local_aliases)} variable groups):")
            for var_id, aliases in local_aliases.items():
                if len(aliases) > 1:  # Only show groups with multiple aliases
                    print(f"    {', '.join(aliases)}")
        else:
            print("  No local aliases detected")
        
        # Show input aliases
        input_aliases = module_result['input_aliases']
        if input_aliases:
            print(f"  Input aliases ({len(input_aliases)} parameter groups):")
            for var_id, aliases in input_aliases.items():
                if len(aliases) > 1:
                    print(f"    {', '.join(aliases)}")
        
        # Show output aliases
        output_aliases = module_result['output_aliases']
        if output_aliases:
            print(f"  Output aliases ({len(output_aliases)} return groups):")
            for var_id, aliases in output_aliases.items():
                if len(aliases) > 1:
                    print(f"    {', '.join(aliases)}")
        
        print()
    
    # Show analysis summary
    print("=== Analysis Summary ===\n")
    summary = analyzer.get_analysis_summary()
    print(f"Total functions analyzed: {summary['total_functions']}")
    print(f"Analysis type: {summary['analysis_stats']['total_modules']} modules")
    print(f"Call graph: {summary['analysis_stats']['call_graph_nodes']} nodes, {summary['analysis_stats']['call_graph_edges']} edges")


if __name__ == "__main__":
    demonstrate_enhanced_variable_identification()
