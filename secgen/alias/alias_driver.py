"""Modular alias analyzer interface.

This module provides a clean interface for the modular, bottom-up alias analysis system,
delegating all core logic to the bottom_up_alias_analyzer module.
"""

from typing import Dict, List, Set, Optional, Any, Union
from dataclasses import dataclass
import json

from secgen.alias.bottom_up_alias_analyzer import BottomUpAliasAnalyzer
from secgen.core.models import FunctionInfo, CodeLocation
from secgen.core.variable_reference import VariableReference, VariableReferenceExtractor


@dataclass
class AnalysisConfig:
    """Configuration for alias analysis."""
    enable_basic_operations: bool = True
    enable_function_analysis: bool = True
    enable_interprocedural: bool = True
    enable_global_variables: bool = True
    max_call_depth: int = 3
    min_confidence: float = 0.0
    enable_caching: bool = True


class ModularAliasAnalyzer:
    """Clean interface for modular alias analysis with bottom-up approach."""
    
    def __init__(self, config: Optional[AnalysisConfig] = None):
        self.config = config or AnalysisConfig()
        
        # Initialize tree-sitter based tools
        from secgen.tsanalyzer import CppSymbolAnalyzer, CodeMetadataExtractor
        
        self.symbol_analyzer = CppSymbolAnalyzer()
        self.code_extractor = CodeMetadataExtractor()
        
        # Initialize true modular bottom-up analyzer
        self.bottom_up_analyzer = BottomUpAliasAnalyzer(
            symbol_analyzer=self.symbol_analyzer,
            code_extractor=self.code_extractor
        )
        
        # Analysis state
        self.analyzed_functions: Set[str] = set()
        self.analysis_results: Dict[str, Any] = {}
    
    def analyze_functions(self, functions: List[FunctionInfo], code: str) -> Dict[str, Any]:
        """Analyze functions using modular bottom-up approach."""
        # Add all functions as modules
        for func in functions:
            self.bottom_up_analyzer.add_function_module(func, code)
            self.analyzed_functions.add(func.name)
        
        # Perform bottom-up analysis
        analysis_results = self.bottom_up_analyzer.analyze_bottom_up()
        
        # Convert to interface format
        results = {
            'analysis_type': 'modular_bottom_up',
            'modules': {},
            'summary': self.bottom_up_analyzer.get_analysis_summary()
        }
        
        for func_name, result in analysis_results.items():
            module = result.module
            results['modules'][func_name] = {
                'function_info': module.function_info,
                'local_aliases': {var_id: [str(alias) for alias in aliases] for var_id, aliases in module.local_aliases.items()},
                'input_aliases': {var_id: [str(alias) for alias in aliases] for var_id, aliases in module.input_aliases.items()},
                'output_aliases': {var_id: [str(alias) for alias in aliases] for var_id, aliases in module.output_aliases.items()},
                'operations': [str(op) for op in module.operations],
                'analyzed': module.analyzed,
                'dependencies': list(module.dependencies),
                'variable_references': {var_id: {
                    'name': var_ref.name,
                    'scope': var_ref.scope.value,
                    'function_name': var_ref.function_name,
                    'variable_type': var_ref.variable_type,
                    'is_pointer': var_ref.is_pointer,
                    'is_array': var_ref.is_array,
                    'source_location': var_ref.source_location
                } for var_id, var_ref in module.variable_references.items()}
            }
        
        self.analysis_results = results
        return results
    
    
    def get_aliases(self, var_ref: VariableReference, function: str = None) -> Set[VariableReference]:
        """Get aliases for a variable reference."""
        # If no function specified, try to determine from variable reference
        if function is None and var_ref.function_name:
            function = var_ref.function_name
        return self.bottom_up_analyzer.get_aliases(var_ref, function)
    
    def are_aliases(self, var1: VariableReference, var2: VariableReference, function: str = None) -> bool:
        """Check if two variables are aliases."""
        return self.bottom_up_analyzer.are_aliases(var1, var2, function)
    
    def get_module_aliases(self, function: str) -> Dict[str, Set[VariableReference]]:
        """Get all aliases for a specific function module."""
        return self.bottom_up_analyzer.get_module_aliases(function)
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get analysis summary."""
        return {
            'config': {
                'enable_basic_operations': self.config.enable_basic_operations,
                'enable_function_analysis': self.config.enable_function_analysis,
                'enable_interprocedural': self.config.enable_interprocedural,
                'enable_global_variables': self.config.enable_global_variables,
                'max_call_depth': self.config.max_call_depth,
                'min_confidence': self.config.min_confidence
            },
            'analysis_stats': self.bottom_up_analyzer.get_analysis_summary(),
            'analyzed_functions': list(self.analyzed_functions),
            'total_functions': len(self.analyzed_functions)
        }
    
    def export_results(self, format: str = "json") -> str:
        """Export analysis results."""
        if format == "json":
            return json.dumps(self.analysis_results, indent=2, default=str)
        elif format == "summary":
            return json.dumps(self.get_analysis_summary(), indent=2, default=str)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def clear_analysis(self):
        """Clear all analysis results."""
        self.analyzed_functions.clear()
        self.analysis_results.clear()
        # Reinitialize the bottom-up analyzer
        self.bottom_up_analyzer = BottomUpAliasAnalyzer(
            symbol_analyzer=self.symbol_analyzer,
            code_extractor=self.code_extractor
        )
