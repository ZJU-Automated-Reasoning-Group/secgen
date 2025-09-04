"""Example usage of the interprocedural analyzer.

This module demonstrates how to use the interprocedural analyzer
with lightweight alias analysis, function summaries, hybrid taint propagation,
and specialized LLM tools.
"""

from typing import Dict, List
from secgen.core.interprocedural_analyzer import InterproceduralAnalyzer
from secgen.core.models import FunctionInfo


def example_usage():
    """Example of using the interprocedural analyzer."""
    
    # Mock LLM model (in real usage, this would be an actual LLM model)
    class MockLLMModel:
        def generate(self, prompt: str) -> str:
            # Mock response - in real usage, this would call the actual LLM
            return '''
            {
                "can_propagate": true,
                "confidence": 0.9,
                "propagation_type": "preserves_taint",
                "explanation": "Function preserves taint from input to output",
                "reasoning_steps": [
                    "Step 1: Input parameter is passed through",
                    "Step 2: No sanitization is performed",
                    "Step 3: Taint is preserved in return value"
                ]
            }
            '''
    
    # Initialize the analyzer
    model = MockLLMModel()
    analyzer = InterproceduralAnalyzer(model=model, logger=None)
    
    # Example function information
    functions = {
        "main": FunctionInfo(
            name="main",
            file_path="example.c",
            start_line=1,
            end_line=20,
            parameters=["argc", "argv"],
            calls=["process_input", "execute_command"]
        ),
        "process_input": FunctionInfo(
            name="process_input",
            file_path="example.c",
            start_line=21,
            end_line=35,
            parameters=["input"],
            calls=["strcpy", "validate_input"]
        ),
        "execute_command": FunctionInfo(
            name="execute_command",
            file_path="example.c",
            start_line=36,
            end_line=50,
            parameters=["command"],
            calls=["system"]
        )
    }
    
    # Example file contents
    file_contents = {
        "example.c": """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char input[100];
    char command[200];
    
    if (argc > 1) {
        strcpy(input, argv[1]);
        process_input(input);
    }
    
    strcpy(command, "echo ");
    strcat(command, input);
    execute_command(command);
    
    return 0;
}

void process_input(char *input) {
    char buffer[100];
    strcpy(buffer, input);
    validate_input(buffer);
}

void execute_command(char *command) {
    system(command);
}
"""
    }
    
    # Perform analysis
    result = analyzer.analyze_project(functions, file_contents)
    
    # Print results
    print("=== Interprocedural Analysis Results ===")
    print(f"Total functions analyzed: {len(result.function_summaries)}")
    print(f"Vulnerabilities found: {len(result.vulnerabilities)}")
    print(f"Taint paths found: {len(result.taint_paths)}")
    
    # Print vulnerabilities
    if result.vulnerabilities:
        print("\n=== Vulnerabilities ===")
        for i, vuln in enumerate(result.vulnerabilities, 1):
            print(f"{i}. {vuln.vuln_type.value} in {vuln.location}")
            print(f"   Description: {vuln.description}")
            print(f"   Confidence: {vuln.confidence:.2f}")
            print(f"   Evidence: {vuln.evidence}")
            print()
    
    # Print taint paths
    if result.taint_paths:
        print("=== Taint Paths ===")
        for i, path in enumerate(result.taint_paths, 1):
            print(f"{i}. {path.source_function} -> {path.sink_function}")
            print(f"   Path: {' -> '.join(path.path)}")
            print(f"   Confidence: {path.confidence:.2f}")
            print(f"   Requires LLM: {path.requires_llm_analysis}")
            print()
    
    # Print analysis statistics
    print("=== Analysis Statistics ===")
    stats = result.analysis_statistics
    print(f"Total functions: {stats['total_functions']}")
    print(f"Analyzed functions: {stats['analyzed_functions']}")
    print(f"Taint sources: {stats['taint_sources']}")
    print(f"Taint sinks: {stats['taint_sinks']}")
    
    # Print LLM usage statistics
    if result.llm_usage_stats.get('llm_available'):
        print("\n=== LLM Usage Statistics ===")
        llm_stats = result.llm_usage_stats
        print(f"LLM available: {llm_stats['llm_available']}")
        
        # Print tool statistics
        for tool_name, tool_stats in llm_stats['tool_stats'].items():
            print(f"{tool_name}:")
            print(f"  Total queries: {tool_stats['total_queries']}")
            print(f"  Cache hits: {tool_stats['cache_hits']}")
            print(f"  Cache hit ratio: {tool_stats['cache_hit_ratio']:.2f}")
    
    return result


def demonstrate_alias_analysis():
    """Demonstrate the lightweight alias analysis."""
    
    from secgen.core.alias_analyzer import LightweightAliasAnalyzer
    from secgen.core.models import FunctionInfo
    
    # Create analyzer
    analyzer = LightweightAliasAnalyzer()
    
    # Example function
    func_info = FunctionInfo(
        name="example_function",
        file_path="example.c",
        start_line=1,
        end_line=10,
        parameters=["ptr1", "ptr2"],
        calls=[]
    )
    
    # Example code with aliases
    code = """
void example_function(char *ptr1, char *ptr2) {
    char *temp = ptr1;        // temp aliases with ptr1
    char *alias = temp;       // alias aliases with temp (and ptr1)
    ptr2 = ptr1;              // ptr2 aliases with ptr1
    char *field = ptr1->data; // field aliases with ptr1.data
}
"""
    
    # Analyze aliases
    aliases = analyzer.analyze_function(func_info, code)
    
    print("=== Alias Analysis Results ===")
    for var, alias_set in aliases.items():
        if len(alias_set) > 1:  # Only show non-trivial aliases
            print(f"{var} aliases with: {', '.join(alias_set - {var})}")
    
    return aliases


def demonstrate_summary():
    """Demonstrate the function summary."""
    
    from secgen.core.summary import FunctionSummary, ParameterSummary
    from secgen.core.summary import TaintPropagationType, SideEffectType, SideEffect
    
    # Create a summary
    param1 = ParameterSummary(
        index=0,
        name="input",
        type="char*",
        aliases={"input", "user_input"},
        taint_propagation=TaintPropagationType.PRESERVES_TAINT,
        taint_confidence=0.9,
        may_be_modified=True,
        is_input_only=False,
        is_input_output=True
    )
    
    param2 = ParameterSummary(
        index=1,
        name="output",
        type="char*",
        aliases={"output", "result"},
        taint_propagation=TaintPropagationType.PRESERVES_TAINT,
        taint_confidence=0.8,
        may_be_modified=True,
        is_input_only=False,
        is_output_only=True
    )
    
    side_effect = SideEffect(
        effect_type=SideEffectType.SYSTEM_CALL,
        description="Calls system() with potentially tainted input",
        affected_params={0, 1},
        is_dangerous=True,
        risk_level=5,
        confidence=0.95
    )
    
    summary = FunctionSummary(
        function_name="process_user_input",
        file_path="example.c",
        start_line=10,
        end_line=25,
        parameters=[param1, param2],
        side_effects=[side_effect],
        security_sensitive=True,
        validates_input=False,
        sanitizes_output=False,
        security_concerns=["Command injection possible", "No input validation"],
        complexity_score=3,
        analysis_confidence=0.9,
        analysis_method="hybrid",
        llm_analysis_used=True,
        llm_confidence=0.9
    )
    
    print("=== Function Summary ===")
    print(f"Function: {summary.function_name}")
    print(f"Security sensitive: {summary.security_sensitive}")
    print(f"Validates input: {summary.validates_input}")
    print(f"Analysis method: {summary.analysis_method}")
    print(f"LLM confidence: {summary.llm_confidence}")
    
    # Show taint propagation paths
    taint_paths = summary.get_taint_propagation_paths()
    print(f"\nTaint propagation paths: {len(taint_paths)}")
    for i, path in enumerate(taint_paths, 1):
        print(f"  {i}. {path['source']} -> {path['sink']} (confidence: {path['confidence']:.2f})")
    
    return summary


if __name__ == "__main__":
    print("Running interprocedural analysis examples...\n")
    
    # Run examples
    demonstrate_alias_analysis()
    print()
    
    demonstrate_summary()
    print()
    
    example_usage()
