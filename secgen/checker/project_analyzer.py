"""Project and directory-level analysis functionality."""

import time
from typing import Dict, List, Optional, Any
from pathlib import Path

from secgen.core.models import Vulnerability, VulnerabilityType
from secgen.core.interprocedural_analyzer import InterproceduralAnalyzer
from secgen.core.summary import FunctionSummary
from secgen.checker.file_analyzer_core import FileAnalyzerCore
from secgen.checker.report_generator import AnalysisReport, ReportGenerator


class ProjectAnalyzer:
    """Handles project and directory-level analysis."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, logger=None, model=None):
        """Initialize project analyzer.
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
            model: LLM model for intelligent analysis
        """
        self.config = config or {}
        self.logger = logger
        self.model = model
        
        # Initialize components
        self.file_analyzer = FileAnalyzerCore(config, logger)
        self.interprocedural_analyzer = InterproceduralAnalyzer(model, logger)
        self.function_summarizer = FunctionSummaryGenerator(model, logger)
        self.report_generator = ReportGenerator()
    
    def analyze_project(self, project_path: str, 
                       file_extensions: Optional[List[str]] = None,
                       exclude_patterns: Optional[List[str]] = None,
                       enabled_types: Optional[List[VulnerabilityType]] = None) -> AnalysisReport:
        """Analyze entire project with interprocedural analysis.
        
        Args:
            project_path: Path to project directory
            file_extensions: List of file extensions to include
            exclude_patterns: List of patterns to exclude
            enabled_types: List of vulnerability types to detect
            
        Returns:
            Comprehensive analysis report
        """
        start_time = time.time()
        
        # Set defaults
        file_extensions = file_extensions or ['.py', '.c', '.cpp', '.h', '.hpp', '.java', '.js', '.ts']
        exclude_patterns = exclude_patterns or ['__pycache__', '.git', 'node_modules', 'venv', '.venv']
        
        # Find files to analyze
        files_to_analyze = self._find_files(project_path, file_extensions, exclude_patterns)
        
        if self.logger:
            self.logger.log(f"Found {len(files_to_analyze)} files to analyze")
        
        # Load file contents
        file_contents = {}
        for file_path in files_to_analyze:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    file_contents[file_path] = f.read()
            except Exception as e:
                if self.logger:
                    self.logger.log(f"Error reading {file_path}: {e}", level="ERROR")
        
        # Build interprocedural analysis
        functions = self._extract_functions_from_files(file_contents)
        if functions:
            # Build call graph
            call_graph = self.interprocedural_analyzer.build_call_graph(functions)
            
            # Build function summaries
            function_summaries = self.interprocedural_analyzer.build_function_summaries(functions, file_contents)
            
            if self.logger:
                self.logger.log(f"Built call graph with {len(functions)} functions and {len(function_summaries)} summaries")
        else:
            call_graph = None
            function_summaries = {}
        
        # Analyze each file with interprocedural context
        all_vulnerabilities = []
        analysis_results = {
            'files_analyzed': [],
            'files_skipped': [],
            'vulnerabilities': [],
            'interprocedural_vulnerabilities': [],
            'statistics': {}
        }
        
        for file_path in files_to_analyze:
            try:
                content = file_contents[file_path]
                
                # Analyze file with interprocedural context
                file_vulnerabilities = self.file_analyzer.analyze_file(
                    file_path, content, enabled_types, 
                    functions, function_summaries, self.interprocedural_analyzer
                )
                
                all_vulnerabilities.extend(file_vulnerabilities)
                analysis_results['files_analyzed'].append(file_path)
                
            except Exception as e:
                if self.logger:
                    self.logger.log(f"Error analyzing {file_path}: {e}", level="ERROR")
                analysis_results['files_skipped'].append(file_path)
        
        # Run interprocedural analysis for cross-function vulnerabilities
        if call_graph and function_summaries:
            interprocedural_vulns = self.interprocedural_analyzer.detect_interprocedural_vulnerabilities(file_contents)
            all_vulnerabilities.extend(interprocedural_vulns)
            analysis_results['interprocedural_vulnerabilities'] = interprocedural_vulns
            
            if self.logger:
                self.logger.log(f"Found {len(interprocedural_vulns)} interprocedural vulnerabilities")
        
        # Final processing
        unique_vulns = self.file_analyzer.deduplicate_vulnerabilities(all_vulnerabilities)
        ranked_vulns = self.file_analyzer.rank_vulnerabilities(unique_vulns)
        
        # Generate comprehensive report
        return self.report_generator.generate_report(
            files_to_analyze, ranked_vulns, {}, 
            function_summaries if 'function_summaries' in locals() else {}, 
            time.time() - start_time
        )
    
    def analyze_directory(self, directory_path: str, 
                         file_extensions: Optional[List[str]] = None,
                         exclude_patterns: Optional[List[str]] = None,
                         enabled_types: Optional[List[VulnerabilityType]] = None) -> AnalysisReport:
        """Analyze all files in a directory.
        
        Args:
            directory_path: Path to directory to analyze
            file_extensions: List of file extensions to include (None for all supported)
            exclude_patterns: List of patterns to exclude
            enabled_types: List of vulnerability types to detect (None for all)
            
        Returns:
            Analysis results dictionary
        """
        start_time = time.time()
        
        # Set defaults
        file_extensions = file_extensions or ['.py', '.c', '.cpp', '.h', '.hpp', '.java', '.js', '.ts']
        exclude_patterns = exclude_patterns or ['__pycache__', '.git', 'node_modules', 'venv', '.venv']
        
        # Find files to analyze
        files_to_analyze = self._find_files(directory_path, file_extensions, exclude_patterns)
        
        if self.logger:
            self.logger.log(f"Found {len(files_to_analyze)} files to analyze")
        
        # Analyze each file
        all_vulnerabilities = []
        analysis_results = {
            'files_analyzed': [],
            'files_skipped': [],
            'vulnerabilities': [],
            'statistics': {}
        }
        
        for file_path in files_to_analyze:
            try:
                # Read file content
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Analyze file
                vulnerabilities = self.file_analyzer.analyze_file(file_path, content, enabled_types)
                all_vulnerabilities.extend(vulnerabilities)
                analysis_results['files_analyzed'].append(file_path)
                
            except Exception as e:
                if self.logger:
                    self.logger.log(f"Error analyzing {file_path}: {e}", level="ERROR")
                analysis_results['files_skipped'].append(file_path)
        
        # Final processing
        unique_vulns = self.file_analyzer.deduplicate_vulnerabilities(all_vulnerabilities)
        ranked_vulns = self.file_analyzer.rank_vulnerabilities(unique_vulns)
        
        # Generate comprehensive report
        return self.report_generator.generate_report(
            files_to_analyze, ranked_vulns, {}, 
            {}, time.time() - start_time
        )
    
    def _find_files(self, directory_path: str, extensions: List[str], 
                   exclude_patterns: List[str]) -> List[str]:
        """Find all files to analyze in a directory."""
        files = []
        directory = Path(directory_path)
        
        for ext in extensions:
            pattern = f"**/*{ext}"
            for file_path in directory.glob(pattern):
                file_str = str(file_path)
                
                # Check exclude patterns
                should_exclude = any(pattern in file_str for pattern in exclude_patterns)
                if not should_exclude:
                    files.append(file_str)
        
        return files
    
    def _extract_functions_from_files(self, file_contents: Dict[str, str]) -> Dict[str, Any]:
        """Extract function information from all files for interprocedural analysis."""
        functions = {}
        
        for file_path, content in file_contents.items():
            if file_path.endswith(('.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx')):
                # Use CppSymbolAnalyzer to extract functions
                from secgen.tsanalyzer.symbol_analyzer import CppSymbolAnalyzer
                analyzer = CppSymbolAnalyzer()
                analysis_results = analyzer.analyze_file(content, file_path)
                
                # Extract function information
                for func in analysis_results.get('functions', []):
                    func_key = f"{file_path}:{func.name}"
                    functions[func_key] = func
        
        return functions
