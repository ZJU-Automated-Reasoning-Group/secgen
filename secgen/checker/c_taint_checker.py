"""C/C++ taint analysis checker using modular detector architecture."""

from typing import Dict, List, Set, Any

from secgen.checker.base_checker import BaseChecker
from secgen.core.models import Vulnerability, VulnerabilityType
from secgen.config import load_c_taint_config
from secgen.checker.detectors import DetectorFactory
from secgen.checker.detectors.base_detector import DetectionContext


class CTaintChecker(BaseChecker):
    """C/C++ specific taint analysis checker using modular detector architecture."""
    
    def __init__(self, model=None, logger=None, interprocedural_analyzer=None):
        super().__init__(model, logger, interprocedural_analyzer)
        
        # Load configuration from config file
        try:
            self.config = load_c_taint_config()
        except Exception as e:
            if self.logger:
                self.logger.log(f"Failed to load taint configuration: {e}", level="WARNING")
            self.config = {}
    
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
        
        # Create taint detector with C/C++ specific configuration
        taint_detector = DetectorFactory.create_detector(
            vuln_type=VulnerabilityType.COMMAND_INJECTION,  # Will be overridden by taint detector
            config=self.config,
            logger=self.logger
        )
        
        # Run taint analysis
        try:
            detector_vulns = taint_detector.detect(context)
            vulnerabilities.extend(detector_vulns)
        except Exception as e:
            if self.logger:
                self.logger.log(f"Error in taint detector: {e}", level="ERROR")
        
        return self._deduplicate_vulnerabilities(vulnerabilities)
    
    def _analyze_with_interprocedural_data(self, file_contents: Dict[str, str], 
                                         functions: Dict[str, Any],
                                         function_summaries: Dict[str, Any]) -> List[Vulnerability]:
        """Analyze C/C++ taint flows using interprocedural context."""
        vulnerabilities = []
        
        if not self.interprocedural_analyzer:
            return super()._analyze_with_interprocedural_data(file_contents, functions, function_summaries)
        
        if self.logger:
            self.logger.log("Starting interprocedural C/C++ taint analysis...")
        
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
            
            # Create taint detector
            taint_detector = DetectorFactory.create_detector(
                vuln_type=VulnerabilityType.COMMAND_INJECTION,
                config=self.config,
                logger=self.logger
            )
            
            try:
                # Run basic taint detection
                detector_vulns = taint_detector.detect(context)
                vulnerabilities.extend(detector_vulns)
                
                # Get interprocedural taint paths
                taint_paths = self.interprocedural_analyzer.analyze_interprocedural_taint_flow()
                
                # Convert taint paths to vulnerabilities
                for taint_path in taint_paths:
                    vuln = self._create_vulnerability_from_taint_path(taint_path, file_contents)
                    if vuln:
                        vulnerabilities.append(vuln)
                        
            except Exception as e:
                if self.logger:
                    self.logger.log(f"Error in taint detector: {e}", level="ERROR")
        
        if self.logger:
            self.logger.log(f"Found {len(vulnerabilities)} total C/C++ taint vulnerabilities")
        
        return self._deduplicate_vulnerabilities(vulnerabilities)
    
    def _create_vulnerability_from_taint_path(self, taint_path, file_contents: Dict[str, str]):
        """Create vulnerability from interprocedural taint path."""
        from secgen.core.interprocedural_analyzer import TaintPath
        from secgen.core.models import VulnerabilityType, Severity, CodeLocation, PathStep, VulnerabilityPath
        
        if not isinstance(taint_path, TaintPath):
            return None
        
        # Get file path from sink location
        sink_file = None
        sink_line = taint_path.sink.line_number
        
        # Try to determine file from path steps
        for step in taint_path.path:
            if hasattr(step, 'location') and hasattr(step.location, 'file_path'):
                sink_file = step.location.file_path
                break
        
        # Fallback: use first C/C++ file
        if not sink_file:
            for file_path in file_contents.keys():
                if file_path.endswith(('.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx')):
                    sink_file = file_path
                    break
        
        if not sink_file:
            return None
        
        # Create detailed path steps
        source_step = PathStep(
            location=CodeLocation(sink_file, taint_path.source.line_number, taint_path.source.line_number),
            description=f"Interprocedural taint source in function '{taint_path.source.function}': {taint_path.source.variable}",
            node_type='source',
            variable=taint_path.source.variable,
            function_name=taint_path.source.function
        )
        
        # Intermediate steps
        intermediate_steps = []
        for i, step in enumerate(taint_path.path):
            step_desc = f"Taint propagation through function '{step.function}'"
            if step.variable:
                step_desc += f" via variable '{step.variable}'"
            
            intermediate_steps.append(PathStep(
                location=CodeLocation(sink_file, step.line_number, step.line_number),
                description=step_desc,
                node_type='propagation',
                variable=step.variable,
                function_name=step.function
            ))
        
        # Sink step
        sink_step = PathStep(
            location=CodeLocation(sink_file, sink_line, sink_line),
            description=f"Interprocedural taint sink in function '{taint_path.sink.function}': {taint_path.sink.variable}",
            node_type='sink',
            variable=taint_path.sink.variable,
            function_name=taint_path.sink.function
        )
        
        vuln_path = VulnerabilityPath(
            source=source_step,
            sink=sink_step,
            intermediate_steps=intermediate_steps,
            sanitizers=[]
        )
        
        # Determine severity based on vulnerability type
        severity_map = {
            VulnerabilityType.SQL_INJECTION: Severity.HIGH,
            VulnerabilityType.COMMAND_INJECTION: Severity.CRITICAL,
            VulnerabilityType.BUFFER_OVERFLOW: Severity.CRITICAL,
            VulnerabilityType.PATH_TRAVERSAL: Severity.HIGH,
        }
        
        vuln_type = taint_path.vulnerability_type
        severity = severity_map.get(vuln_type, Severity.HIGH)
        
        return Vulnerability(
            vuln_type=vuln_type,
            severity=severity,
            location=CodeLocation(sink_file, sink_line, sink_line),
            description=f"Interprocedural C/C++ taint flow: {taint_path.vulnerability_type.value}",
            evidence=f"Taint flows from {taint_path.source.function}:{taint_path.source.variable} to {taint_path.sink.function}:{taint_path.sink.variable}",
            confidence=taint_path.confidence,
            recommendation=self._get_interprocedural_recommendation(vuln_type),
            path=vuln_path
        )
    
    def _get_interprocedural_recommendation(self, vuln_type: VulnerabilityType) -> str:
        """Get recommendation for interprocedural vulnerabilities."""
        recommendations = {
            VulnerabilityType.SQL_INJECTION: "Use parameterized queries and validate input at function boundaries",
            VulnerabilityType.COMMAND_INJECTION: "Avoid system() calls and sanitize input before passing to exec functions",
            VulnerabilityType.BUFFER_OVERFLOW: "Use safe string functions and validate buffer sizes at function interfaces",
            VulnerabilityType.PATH_TRAVERSAL: "Validate file paths at entry points and use secure file operations",
        }
        return recommendations.get(vuln_type, "Validate and sanitize input at function boundaries")