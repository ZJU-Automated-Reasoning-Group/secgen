"""Core file analysis functionality for vulnerability detection."""

import time
from typing import Dict, List, Optional, Any, Set
from pathlib import Path


from secgen.core.models import Vulnerability, VulnerabilityType, Severity
from secgen.core.interprocedural_analyzer import InterproceduralAnalyzer
from secgen.checker.report_generator import AnalysisReport, ReportGenerator
from secgen.checker.cpp_checker import CppChecker


class DetectionContext:
    """Context for vulnerability detection."""
    
    def __init__(self, file_path: str, lines: List[str], functions: Optional[Dict] = None,
                 function_summaries: Optional[Dict] = None, interprocedural_analyzer=None,
                 analysis_results: Optional[Dict] = None):
        self.file_path = file_path
        self.lines = lines
        self.functions = functions or {}
        self.function_summaries = function_summaries or {}
        self.interprocedural_analyzer = interprocedural_analyzer
        self.analysis_results = analysis_results or {}


class FileAnalyzerCore:
    """Core file analysis functionality."""
    
    # Supported file extensions by language
    LANGUAGE_EXTENSIONS = {
        'c_cpp': {'.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx'},
        'python': {'.py', '.pyw', '.pyi'}
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, logger=None):
        """Initialize file analyzer core.
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.config = config or {}
        self.logger = logger
        
        # Analysis statistics
        self.analysis_stats = {
            'files_analyzed': 0,
            'vulnerabilities_found': 0,
            'analysis_time': 0.0,
            'cache_hits': 0,
            'cache_misses': 0
        }
        
        # Detector cache and file contents
        self._detector_cache: Dict[str, List[CppChecker]] = {}
        self.file_contents: Dict[str, str] = {}
        
        # Report generator
        self.report_generator = ReportGenerator()
    
    def get_language_for_file(self, file_path: str) -> Optional[str]:
        """Get language type for a file based on its extension."""
        file_ext = '.' + file_path.split('.')[-1] if '.' in file_path else ''
        for language, extensions in self.LANGUAGE_EXTENSIONS.items():
            if file_ext in extensions:
                return language
        return None
    
    def create_detectors_for_language(self, language: str) -> List[CppChecker]:
        """Create detectors for a specific language."""
        if language in self._detector_cache:
            return self._detector_cache[language]
        
        detectors = []
        
        if language == 'c_cpp':
            # C/C++ detectors - using CppChecker for now
            detectors.append(CppChecker())
        elif language == 'python':
            # Python detectors - placeholder for now
            # TODO: Add Python-specific checker
            pass
        
        self._detector_cache[language] = detectors
        return detectors
    
    def get_analysis_results(self, file_path: str, content: str) -> Dict[str, Any]:
        """Get analysis results for a file."""
        # For C/C++ files, use CppSymbolAnalyzer
        if file_path.endswith(('.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx')):
            from secgen.tsanalyzer.symbol_analyzer import CppSymbolAnalyzer
            analyzer = CppSymbolAnalyzer()
            return analyzer.analyze_file(content, file_path)
        
        # For other file types, return empty results for now
        return {}
    
    def analyze_file(self, file_path: str, content: str, 
                    enabled_types: Optional[List[VulnerabilityType]] = None,
                    functions: Optional[Dict[str, Any]] = None,
                    function_summaries: Optional[Dict[str, Any]] = None,
                    interprocedural_analyzer: Optional[InterproceduralAnalyzer] = None) -> List[Vulnerability]:
        """Analyze a single file for vulnerabilities.
        
        Args:
            file_path: Path to the file to analyze
            content: File content
            enabled_types: List of vulnerability types to detect (None for all)
            functions: Function information for interprocedural analysis
            function_summaries: Function summaries for enhanced analysis
            interprocedural_analyzer: Interprocedural analyzer instance
            
        Returns:
            List of detected vulnerabilities
        """
        start_time = time.time()
        
        # Get language for this file type
        language = self.get_language_for_file(file_path)
        if not language:
            if self.logger:
                self.logger.log(f"No language support found for file: {file_path}", level="WARNING")
            return []
        
        # Get analysis results
        analysis_results = self.get_analysis_results(file_path, content)
        
        # Create detection context
        context = DetectionContext(
            file_path=file_path,
            lines=content.split('\n'),
            functions=functions,
            function_summaries=function_summaries,
            interprocedural_analyzer=interprocedural_analyzer,
            analysis_results=analysis_results
        )
        
        # Get detectors for this language
        detectors = self.create_detectors_for_language(language)
        
        # Run detection
        vulnerabilities = []
        for detector in detectors:
            try:
                # For CppChecker, use the check method
                if isinstance(detector, CppChecker):
                    result = detector.check(content)
                    # Convert result to Vulnerability objects if needed
                    # For now, just log the result
                    if self.logger:
                        self.logger.log(f"CppChecker result: {result}")
                else:
                    # Handle other detector types if they exist
                    detector_vulns = detector.detect(context)
                    vulnerabilities.extend(detector_vulns)
            except Exception as e:
                if self.logger:
                    self.logger.log(f"Error in detector {detector.__class__.__name__}: {e}", level="ERROR")
        
        # Deduplicate and rank vulnerabilities
        unique_vulns = self.deduplicate_vulnerabilities(vulnerabilities)
        ranked_vulns = self.rank_vulnerabilities(unique_vulns)
        
        # Update statistics
        analysis_time = time.time() - start_time
        self.analysis_stats['files_analyzed'] += 1
        self.analysis_stats['vulnerabilities_found'] += len(ranked_vulns)
        self.analysis_stats['analysis_time'] += analysis_time
        
        if self.logger:
            self.logger.log(f"Analyzed {file_path}: {len(ranked_vulns)} vulnerabilities in {analysis_time:.2f}s")
        
        return ranked_vulns
    
    def analyze_single_file(self, file_path: str, enabled_detectors: Optional[List[VulnerabilityType]] = None) -> AnalysisReport:
        """Analyze a single file for vulnerabilities."""
        start_time = time.time()
        
        # Validate file exists and is readable
        file_path_obj = Path(file_path)
        if not file_path_obj.exists() or not file_path_obj.is_file():
            raise ValueError(f"File does not exist or is not a file: {file_path}")
        
        # Load file content
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            self.file_contents[file_path] = content
        except Exception as e:
            raise ValueError(f"Error reading file {file_path}: {e}")
        
        # Analyze the file
        all_vulnerabilities = self.analyze_file(file_path, content, enabled_detectors)
        
        # Process results
        unique_vulnerabilities = self.deduplicate_vulnerabilities(all_vulnerabilities)
        ranked_vulnerabilities = self.rank_vulnerabilities(unique_vulnerabilities)
        
        return self.report_generator.generate_report(
            [file_path], ranked_vulnerabilities, {}, 
            {}, time.time() - start_time
        )
    
    def deduplicate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities."""
        seen = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            signature = (str(vuln.location), vuln.vuln_type.value, vuln.description)
            if signature not in seen:
                seen.add(signature)
                unique_vulns.append(vuln)
        
        return unique_vulns
    
    def rank_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Rank vulnerabilities by severity and confidence."""
        severity_weights = {Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3, 
                          Severity.LOW: 2, Severity.INFO: 1}
        
        def score(vuln):
            return severity_weights.get(vuln.severity, 1) * vuln.confidence
        
        return sorted(vulnerabilities, key=score, reverse=True)
    
    def get_supported_languages(self) -> List[str]:
        """Get list of supported programming languages."""
        return list(self.LANGUAGE_EXTENSIONS.keys())
    
    def get_supported_extensions(self) -> Set[str]:
        """Get all supported file extensions."""
        extensions = set()
        for lang_extensions in self.LANGUAGE_EXTENSIONS.values():
            extensions.update(lang_extensions)
        return extensions
    
    def clear_caches(self):
        """Clear all detector caches."""
        self._detector_cache.clear()
