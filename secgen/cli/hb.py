"""CLI command for happen-before analysis."""

import argparse
import json
from typing import Dict, Any
from pathlib import Path

from secgen.checker.happen_before_analyzer import HappenBeforeAnalyzer
from secgen.core.models import FunctionInfo, CodeLocation
from secgen.tsanalyzer.parsers import CppSymbolAnalyzer


def analyze_happen_before(args) -> None:
    """Analyze happen-before relationships in C/C++ code."""
    parser = CppSymbolAnalyzer()
    
    # Parse source files
    functions = {}
    for file_path in args.files:
        if not Path(file_path).exists():
            print(f"Warning: File {file_path} does not exist, skipping...")
            continue
            
        try:
            with open(file_path, 'r') as f:
                source_code = f.read()
            analysis_result = parser.analyze_file(source_code, file_path)
            
            # Convert to FunctionInfo objects
            for func in analysis_result.functions:
                func_id = f"{file_path}:{func.name}:{func.line_number}"
                func_info = FunctionInfo(
                    name=func.name,
                    file_path=file_path,
                    start_line=func.line_number,
                    end_line=func.line_number + 10,  # Simplified
                    parameters=func.parameters or [],
                    return_type=func.return_type,
                    calls=[call.name for call in analysis_result.calls if call.caller_function == func.name],
                    variables=[var.name for var in analysis_result.variables if var.line_number >= func.line_number]
                )
                functions[func_id] = func_info
                
        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
            continue
    
    if not functions:
        print("No functions found to analyze.")
        return
    
    # Run happen-before analysis
    analyzer = HappenBeforeAnalyzer()
    hb_graph = analyzer.analyze_functions(functions)
    
    # Get results
    results = analyzer.get_analysis_results()
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump({
                'metrics': results['metrics'],
                'race_conditions': [
                    {
                        'variable': rc.variable_name,
                        'location1': str(rc.location1),
                        'location2': str(rc.location2),
                        'severity': rc.severity,
                        'description': rc.description,
                        'recommendation': rc.recommendation,
                        'confidence': rc.confidence
                    }
                    for rc in results['race_conditions']
                ],
                'concurrency_patterns': [
                    {
                        'pattern_type': cp.pattern_type,
                        'description': cp.description,
                        'severity': cp.severity,
                        'recommendation': cp.recommendation,
                        'locations': [str(loc) for loc in cp.locations]
                    }
                    for cp in results['concurrency_patterns']
                ]
            }, f, indent=2)
        print(f"Results written to {args.output}")
    else:
        # Print summary
        print(f"\nHappen-Before Analysis Results:")
        print(f"  Functions analyzed: {len(functions)}")
        print(f"  Events detected: {results['metrics']['num_events']}")
        print(f"  Race conditions: {results['metrics']['num_race_conditions']}")
        print(f"  Concurrency patterns: {results['metrics']['num_concurrency_patterns']}")
        
        # Print race conditions
        if results['race_conditions']:
            print(f"\nRace Conditions Found:")
            for i, rc in enumerate(results['race_conditions'], 1):
                print(f"  {i}. {rc.variable_name} ({rc.severity})")
                print(f"     Location 1: {rc.location1}")
                print(f"     Location 2: {rc.location2}")
                print(f"     Description: {rc.description}")
                print(f"     Recommendation: {rc.recommendation}")
                print()
        
        # Print concurrency patterns
        if results['concurrency_patterns']:
            print(f"\nConcurrency Patterns Found:")
            for i, cp in enumerate(results['concurrency_patterns'], 1):
                print(f"  {i}. {cp.pattern_type} ({cp.severity})")
                print(f"     Description: {cp.description}")
                print(f"     Recommendation: {cp.recommendation}")
                print(f"     Locations: {', '.join(str(loc) for loc in cp.locations)}")
                print()


def add_hb_parser(subparsers) -> None:
    """Add happen-before analysis subcommand to CLI."""
    hb_parser = subparsers.add_parser(
        'hb',
        help='Analyze happen-before relationships and concurrency issues'
    )
    
    hb_parser.add_argument(
        'files',
        nargs='+',
        help='C/C++ source files to analyze'
    )
    
    hb_parser.add_argument(
        '-o', '--output',
        help='Output file for detailed results (JSON format)'
    )
    
    hb_parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    hb_parser.set_defaults(func=analyze_happen_before)
