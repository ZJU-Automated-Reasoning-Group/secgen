"""Python taint analysis checker using modular detector architecture."""

import ast
from typing import Dict, List, Set, Any

from secgen.checker.base_checker import BaseChecker
from secgen.core.models import Vulnerability, VulnerabilityType
from secgen.config import load_python_taint_config
from secgen.checker.detectors import DetectorFactory
from secgen.checker.detectors.base_detector import DetectionContext


class PythonTaintChecker(BaseChecker):
    """Python specific taint analysis checker using modular detector architecture."""
    
    def __init__(self, model=None, logger=None, interprocedural_analyzer=None):
        super().__init__(model, logger, interprocedural_analyzer)
        
        # Load configuration from config file
        try:
            self.config = load_python_taint_config()
        except Exception as e:
            if self.logger:
                self.logger.log(f"Failed to load Python taint configuration: {e}", level="WARNING")
            self.config = {}
    
    def supports_file_type(self, file_path: str) -> bool:
        return file_path.endswith('.py')
    
    def get_supported_extensions(self) -> Set[str]:
        return {'.py'}
    
    def analyze_file(self, file_path: str, content: str) -> List[Vulnerability]:
        if not self.supports_file_type(file_path):
            return []
        
        try:
            tree = ast.parse(content)
            lines = content.split('\n')
            
            # Create detection context
            context = DetectionContext(
                file_path=file_path,
                lines=lines,
                functions=None,
                function_summaries=None,
                interprocedural_analyzer=self.interprocedural_analyzer
            )
            
            # Create taint detector with Python specific configuration
            taint_detector = DetectorFactory.create_detector(
                vuln_type=VulnerabilityType.COMMAND_INJECTION,  # Will be overridden by taint detector
                config=self.config,
                logger=self.logger
            )
            
            # Run taint analysis
            try:
                detector_vulns = taint_detector.detect(context)
                return self._deduplicate_vulnerabilities(detector_vulns)
            except Exception as e:
                if self.logger:
                    self.logger.log(f"Error in taint detector: {e}", level="ERROR")
                return []
                
        except SyntaxError as e:
            if self.logger:
                self.logger.log(f"Syntax error in {file_path}: {e}", level="ERROR")
            return []
    
    def _analyze_with_interprocedural_data(self, file_contents: Dict[str, str], 
                                         functions: Dict[str, Any],
                                         function_summaries: Dict[str, Any]) -> List[Vulnerability]:
        """Analyze Python taint flows using interprocedural context."""
        vulnerabilities = []
        
        if not self.interprocedural_analyzer:
            return super()._analyze_with_interprocedural_data(file_contents, functions, function_summaries)
        
        if self.logger:
            self.logger.log("Starting interprocedural Python taint analysis...")
        
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
            self.logger.log(f"Found {len(vulnerabilities)} total Python taint vulnerabilities")
        
        return self._deduplicate_vulnerabilities(vulnerabilities)
    
    def _create_vulnerability_from_taint_path(self, taint_path, file_contents: Dict[str, str]):
        """Create vulnerability from interprocedural taint path."""
        from secgen.core.interprocedural_analyzer import TaintPath
        from secgen.core.models import Severity, CodeLocation, PathStep, VulnerabilityPath
        
        if not isinstance(taint_path, TaintPath):
            return None
        
        # Get file path from sink location
        sink_file = next((step.location.file_path for step in taint_path.path 
                         if hasattr(step, 'location') and hasattr(step.location, 'file_path')), None)
        if not sink_file:
            sink_file = next((f for f in file_contents.keys() if f.endswith('.py')), None)
        if not sink_file:
            return None
        
        # Create path steps
        source_step = PathStep(
            location=CodeLocation(sink_file, taint_path.source.line_number, taint_path.source.line_number),
            description=f"Source: {taint_path.source.function}:{taint_path.source.variable}",
            node_type='source', 
            variable=taint_path.source.variable, 
            function_name=taint_path.source.function
        )
        
        intermediate_steps = [
            PathStep(
                location=CodeLocation(sink_file, step.line_number, step.line_number),
                description=f"Through {step.function}" + (f":{step.variable}" if step.variable else ""),
                node_type='propagation', 
                variable=step.variable, 
                function_name=step.function
            ) for step in taint_path.path
        ]
        
        sink_step = PathStep(
            location=CodeLocation(sink_file, taint_path.sink.line_number, taint_path.sink.line_number),
            description=f"Sink: {taint_path.sink.function}:{taint_path.sink.variable}",
            node_type='sink', 
            variable=taint_path.sink.variable, 
            function_name=taint_path.sink.function
        )
        
        # Determine severity based on vulnerability type
        severity_map = {
            VulnerabilityType.SQL_INJECTION: Severity.HIGH,
            VulnerabilityType.COMMAND_INJECTION: Severity.CRITICAL,
            VulnerabilityType.XSS: Severity.MEDIUM,
            VulnerabilityType.PATH_TRAVERSAL: Severity.HIGH,
        }
        
        vuln_type = taint_path.vulnerability_type
        severity = severity_map.get(vuln_type, Severity.MEDIUM)
        
        return Vulnerability(
            vuln_type=vuln_type,
            severity=severity,
            location=CodeLocation(sink_file, taint_path.sink.line_number, taint_path.sink.line_number),
            description=f"Interprocedural {vuln_type.value}",
            evidence=f"{taint_path.source.function}:{taint_path.source.variable} → {taint_path.sink.function}:{taint_path.sink.variable}",
            confidence=taint_path.confidence,
            recommendation=self._get_recommendation(vuln_type),
            path=VulnerabilityPath(source=source_step, sink=sink_step, intermediate_steps=intermediate_steps, sanitizers=[])
        )
    
    def _get_recommendation(self, vuln_type: VulnerabilityType) -> str:
        """Get recommendation for vulnerability type."""
        recommendations = {
            VulnerabilityType.SQL_INJECTION: "Use parameterized queries or prepared statements",
            VulnerabilityType.COMMAND_INJECTION: "Validate input and use subprocess with shell=False",
            VulnerabilityType.XSS: "Use auto-escaping templates or manually escape output",
            VulnerabilityType.PATH_TRAVERSAL: "Validate file paths and use allowlist of permitted locations"
        }
        return recommendations.get(vuln_type, "Validate and sanitize input data")