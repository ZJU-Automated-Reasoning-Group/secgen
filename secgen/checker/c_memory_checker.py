"""C/C++ memory safety checker using modular detector architecture."""

from typing import Dict, List, Set, Optional, Any

from secgen.checker.base_checker import BaseChecker
from secgen.core.models import Vulnerability
from secgen.config import load_memory_config
from secgen.checker.detectors import DetectorFactory
from secgen.checker.detectors.base_detector import DetectionContext


class CMemoryChecker(BaseChecker):
    """C/C++ specific memory safety checker using modular detector architecture."""
    
    def __init__(self, model=None, logger=None, interprocedural_analyzer=None):
        super().__init__(model, logger, interprocedural_analyzer)
        
        # Load configuration from config file
        self.config = load_memory_config()
    
    def supports_file_type(self, file_path: str) -> bool:
        return file_path.endswith(('.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx'))
    
    def get_supported_extensions(self) -> Set[str]:
        return {'.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx'}
    
    def analyze_file(self, file_path: str, content: str) -> List[Vulnerability]:
        if not self.supports_file_type(file_path):
            return []
        
        vulnerabilities = []
        lines = content.split('\n')
        
        # Create detection context
        context = DetectionContext(
            file_path=file_path,
            lines=lines,
            functions=None,
            function_summaries=None,
            interprocedural_analyzer=self.interprocedural_analyzer
        )
        
        # Get detectors that support this file type
        file_detectors = DetectorFactory.create_detectors_for_file_type(
            file_path=file_path,
            config=self.config,
            logger=self.logger
        )
        
        # Run each detector
        for detector in file_detectors:
            try:
                detector_vulns = detector.detect(context)
                vulnerabilities.extend(detector_vulns)
            except Exception as e:
                if self.logger:
                    self.logger.log(f"Error in detector {detector.__class__.__name__}: {e}", level="ERROR")
        
        return self._deduplicate_vulnerabilities(vulnerabilities)
    
    def _analyze_with_interprocedural_data(self, file_contents: Dict[str, str], 
                                         functions: Dict[str, Any],
                                         function_summaries: Dict[str, Any]) -> List[Vulnerability]:
        """Analyze C/C++ memory safety using interprocedural context."""
        vulnerabilities = []
        
        if not self.interprocedural_analyzer:
            return super()._analyze_with_interprocedural_data(file_contents, functions, function_summaries)
        
        if self.logger:
            self.logger.log("Starting interprocedural C/C++ memory analysis...")
        
        # Build call graph and function summaries
        self.interprocedural_analyzer.build_call_graph(functions)
        if not function_summaries:
            function_summaries = self.interprocedural_analyzer.build_function_summaries(functions, file_contents)
        
        # Analyze each file with interprocedural context
        for file_path, content in file_contents.items():
            if not self.supports_file_type(file_path):
                continue
                
            lines = content.split('\n')
            
            # Create detection context with interprocedural data
            context = DetectionContext(
                file_path=file_path,
                lines=lines,
                functions=functions,
                function_summaries=function_summaries,
                interprocedural_analyzer=self.interprocedural_analyzer
            )
            
            # Get detectors that support this file type
            file_detectors = DetectorFactory.create_detectors_for_file_type(
                file_path=file_path,
                config=self.config,
                logger=self.logger
            )
            
            # Run each detector with interprocedural context
            for detector in file_detectors:
                try:
                    # Run basic detection
                    detector_vulns = detector.detect(context)
                    vulnerabilities.extend(detector_vulns)
                    
                    # Run interprocedural analysis if available
                    if hasattr(detector, 'analyze_interprocedural_uaf'):
                        interprocedural_vulns = detector.analyze_interprocedural_uaf(context)
                        vulnerabilities.extend(interprocedural_vulns)
                    elif hasattr(detector, 'analyze_interprocedural_npd'):
                        interprocedural_vulns = detector.analyze_interprocedural_npd(context)
                        vulnerabilities.extend(interprocedural_vulns)
                    elif hasattr(detector, 'analyze_interprocedural_memory_leaks'):
                        interprocedural_vulns = detector.analyze_interprocedural_memory_leaks(context)
                        vulnerabilities.extend(interprocedural_vulns)
                    elif hasattr(detector, 'analyze_interprocedural_double_free'):
                        interprocedural_vulns = detector.analyze_interprocedural_double_free(context)
                        vulnerabilities.extend(interprocedural_vulns)
                    elif hasattr(detector, 'analyze_interprocedural_buffer_overflow'):
                        interprocedural_vulns = detector.analyze_interprocedural_buffer_overflow(context)
                        vulnerabilities.extend(interprocedural_vulns)
                        
                except Exception as e:
                    if self.logger:
                        self.logger.log(f"Error in detector {detector.__class__.__name__}: {e}", level="ERROR")
        
        if self.logger:
            self.logger.log(f"Found {len(vulnerabilities)} total C/C++ memory vulnerabilities")
        
        return self._deduplicate_vulnerabilities(vulnerabilities)