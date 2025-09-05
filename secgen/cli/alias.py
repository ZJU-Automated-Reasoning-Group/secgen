"""Command-line interface for alias analysis."""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import asdict

from secgen.alias.local_must_alias_analyzer import LocalMustAliasAnalyzer, AliasType
from secgen.core.models import FunctionInfo
from secgen.tsanalyzer import CodeMetadataExtractor
from secgen.agent.minotor import AgentLogger, LogLevel


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser for alias analysis."""
    parser = argparse.ArgumentParser(
        description="Alias analysis tool for detecting variable aliasing relationships",
        epilog="""Examples:
  secgen-alias file.c
  secgen-alias . --format json -o aliases.json
  secgen-alias file.cpp --query "ptr" --min-confidence 0.8
        """
    )
    
    parser.add_argument("target", help="File or directory to analyze")
    parser.add_argument("--extensions", nargs="+", default=[".c", ".cpp", ".h", ".hpp"], 
                       help="File extensions to analyze")
    parser.add_argument("--exclude", nargs="+", default=[".git", "node_modules", "build"], 
                       help="Patterns to exclude")
    parser.add_argument("--min-confidence", type=float, default=0.0,
                       help="Minimum confidence threshold")
    parser.add_argument("--type", choices=[t.value for t in AliasType], 
                       help="Filter by alias type")
    parser.add_argument("--query", help="Search for specific variables")
    parser.add_argument("--output", "-o", help="Output file")
    parser.add_argument("--format", "-f", choices=["text", "json", "summary"], 
                       default="text", help="Output format")
    parser.add_argument("--detailed", action="store_true", 
                       help="Include line numbers and confidence")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode")
    
    return parser


def setup_logging(args) -> AgentLogger:
    """Setup logging based on command line arguments."""
    level = LogLevel.OFF if args.quiet else (LogLevel.DEBUG if args.verbose else LogLevel.INFO)
    return AgentLogger(level=level)


def find_files(target: str, extensions: List[str], exclude_patterns: List[str]) -> List[Path]:
    """Find files to analyze based on target path and filters."""
    target_path = Path(target)
    
    if target_path.is_file():
        return [target_path]
    elif target_path.is_dir():
        files = [f for ext in extensions for f in target_path.rglob(f"*{ext}")]
        return [f for f in files if not any(p in str(f) for p in exclude_patterns)]
    else:
        raise ValueError(f"Target path does not exist: {target}")


def extract_functions(file_path: Path, extractor: CodeMetadataExtractor) -> List[FunctionInfo]:
    """Extract function information from a file."""
    try:
        metadata = extractor.analyze_file(str(file_path))
        functions = []
        
        for func_key, func_info in metadata.get('functions', {}).items():
            if isinstance(func_info, FunctionInfo):
                functions.append(func_info)
            elif isinstance(func_info, dict) and 'start_line' in func_info:
                functions.append(FunctionInfo(
                    name=func_info.get('name', func_key.split(':')[-1]),
                    file_path=str(file_path),
                    start_line=func_info['start_line'],
                    end_line=func_info['end_line'],
                    parameters=func_info.get('parameters', []),
                    return_type=func_info.get('return_type'),
                    calls=func_info.get('calls', []),
                    variables=func_info.get('variables', [])
                ))
        
        return functions
    except Exception:
        return []


def analyze_file(file_path: Path, analyzer: LocalMustAliasAnalyzer, 
                extractor: CodeMetadataExtractor, args) -> Dict[str, Any]:
    """Analyze a single file for alias relationships."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        functions = extract_functions(file_path, extractor)
        if args.verbose:
            print(f"  Found {len(functions)} functions")
        
        file_results = {
            'file_path': str(file_path),
            'functions': {},
            'total_relations': 0,
            'total_alias_sets': 0
        }
        
        for func in functions:
            if args.verbose:
                print(f"  Analyzing function: {func.name}")
            
            analyzer.analyze_function(func, content)
            
            # Filter and convert relations
            filtered_relations = [
                {**asdict(r), 'alias_type': r.alias_type.value}
                for r in analyzer.alias_relations
                if (r.confidence >= args.min_confidence and
                    (not args.type or r.alias_type.value == args.type) and
                    (not args.query or args.query.lower() in r.lhs.lower() or 
                     args.query.lower() in r.rhs.lower()))
            ]
            
            # Filter and convert alias sets
            filtered_sets = [
                {**asdict(s), 'variables': list(s.variables)}
                for s in analyzer.alias_sets
                if len(s.variables) > 1 and
                (not args.query or any(args.query.lower() in var.lower() for var in s.variables))
            ]
            
            if args.verbose and (filtered_relations or filtered_sets):
                print(f"    Found {len(filtered_relations)} relations, {len(filtered_sets)} alias sets")
            
            func_result = {
                'function_name': func.name,
                'relations': filtered_relations,
                'alias_sets': filtered_sets,
                'relation_count': len(filtered_relations),
                'alias_set_count': len(filtered_sets)
            }
            
            file_results['functions'][func.name] = func_result
            file_results['total_relations'] += len(filtered_relations)
            file_results['total_alias_sets'] += len(filtered_sets)
        
        return file_results
        
    except Exception as e:
        return {
            'file_path': str(file_path),
            'error': str(e),
            'functions': {},
            'total_relations': 0,
            'total_alias_sets': 0
        }


def format_text_output(results: List[Dict[str, Any]], args) -> str:
    """Format results as text output."""
    # Collect all relations and sets
    all_relations = [r for file_result in results if 'error' not in file_result
                    for func_result in file_result['functions'].values()
                    for r in func_result['relations']]
    all_sets = [s for file_result in results if 'error' not in file_result
               for func_result in file_result['functions'].values()
               for s in func_result['alias_sets']]
    
    output = []
    if all_relations:
        output.append("=== Alias Relations ===")
        for r in all_relations:
            conf = f" ({r['confidence']:.2f})" if args.detailed else ""
            line = f":{r['line_number']}" if args.detailed else ""
            output.append(f"{r['lhs']} = {r['rhs']} [{r['alias_type']}]{line}{conf}")
    
    if all_sets:
        output.append("\n=== Alias Sets ===")
        for s in all_sets:
            vars_str = ", ".join(sorted(s['variables']))
            conf = f" ({s['confidence']:.2f})" if args.detailed else ""
            output.append(f"{{{vars_str}}}{conf}")
    
    return "\n".join(output)


def format_json_output(results: List[Dict[str, Any]], args) -> str:
    """Format results as JSON output."""
    return json.dumps({
        'total_relations': sum(r.get('total_relations', 0) for r in results),
        'total_alias_sets': sum(r.get('total_alias_sets', 0) for r in results),
        'files': results
    }, indent=2 if args.detailed else None)




def format_summary_output(results: List[Dict[str, Any]], args) -> str:
    """Format results as summary output."""
    total_files = len(results)
    total_relations = sum(r.get('total_relations', 0) for r in results)
    total_sets = sum(r.get('total_alias_sets', 0) for r in results)
    
    # Count by type
    type_counts = {}
    for file_result in results:
        for func_result in file_result['functions'].values():
            for relation in func_result['relations']:
                alias_type = relation['alias_type']
                type_counts[alias_type] = type_counts.get(alias_type, 0) + 1
    
    output = [
        "=== Alias Analysis Summary ===",
        f"Files analyzed: {total_files}",
        f"Total alias relations: {total_relations}",
        f"Total alias sets: {total_sets}",
        "",
        "Relations by type:"
    ] + [f"  {alias_type}: {count}" for alias_type, count in sorted(type_counts.items())]
    
    return "\n".join(output)


def main():
    """Main CLI entry point for alias analysis."""
    parser = create_parser()
    args = parser.parse_args()
    logger = setup_logging(args)
    
    try:
        files = find_files(args.target, args.extensions, args.exclude)
        if not files:
            print("No files found to analyze", file=sys.stderr)
            return 1
        
        if args.verbose:
            print(f"Found {len(files)} files to analyze")
        
        analyzer = LocalMustAliasAnalyzer(logger=logger)
        extractor = CodeMetadataExtractor(logger=logger)
        
        results = []
        for file_path in files:
            if args.verbose:
                print(f"Analyzing {file_path}")
            results.append(analyze_file(file_path, analyzer, extractor, args))
        
        # Format output
        formatters = {
            "text": format_text_output,
            "json": format_json_output,
            "summary": format_summary_output
        }
        output = formatters[args.format](results, args)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            if args.verbose:
                print(f"Results written to {args.output}")
        else:
            print(output)
        
        return 0
        
    except KeyboardInterrupt:
        print("Analysis interrupted by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"Error during analysis: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
