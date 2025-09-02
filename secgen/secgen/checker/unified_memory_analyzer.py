"""Unified memory safety analyzer that coordinates language-specific checkers."""

from typing import Dict, List, Any

from secgen.core.analyzer import Vulnerability
from secgen.checker.c_memory_checker import CMemoryChecker
from secgen.checker.python_memory_checker import PythonMemoryChecker


class UnifiedMemoryAnalyzer:
    """Unified memory analyzer that delegates to language-specific checkers."""
    
    def __init__(self, model=None, logger=None, interprocedural_analyzer=None):
        self.model = model
        self.logger = logger
        self.interprocedural_analyzer = interprocedural_analyzer
        
        # Initialize language-specific checkers
        self.checkers = [
            CMemoryChecker(model, logger, interprocedural_analyzer),
            PythonMemoryChecker(model, logger, interprocedural_analyzer)
        ]
    
    def analyze_file(self, file_path: str, content: str) -> List[Vulnerability]:
        """Analyze a file for memory safety issues using appropriate checker."""
        vulnerabilities = []
        
        for checker in self.checkers:
            if checker.supports_file_type(file_path):
                try:
                    vulnerabilities.extend(checker.analyze_file(file_path, content))
                except Exception as e:
                    if self.logger:
                        self.logger.log(f"Error in {checker.__class__.__name__} for {file_path}: {e}", level="ERROR")
        
        return self._deduplicate_vulnerabilities(vulnerabilities)
    
    def analyze_with_interprocedural_context(self, file_contents: Dict[str, str],
                                           functions: Dict[str, Any],
                                           function_summaries: Dict[str, Any]) -> List[Vulnerability]:
        """Analyze memory safety using interprocedural context."""
        vulnerabilities = []
        
        # Group files by checker type
        for checker in self.checkers:
            checker_files = {path: content for path, content in file_contents.items() 
                           if checker.supports_file_type(path)}
            
            if checker_files:
                try:
                    checker_vulns = checker.analyze_with_interprocedural_context(
                        checker_files, functions, function_summaries
                    )
                    vulnerabilities.extend(checker_vulns)
                except Exception as e:
                    if self.logger:
                        self.logger.log(f"Error in interprocedural {checker.__class__.__name__}: {e}", level="ERROR")
        
        return self._deduplicate_vulnerabilities(vulnerabilities)
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities."""
        seen = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            signature = (vuln.vuln_type, vuln.location.file_path, 
                        vuln.location.line_start, vuln.description[:50])
            if signature not in seen:
                seen.add(signature)
                unique_vulns.append(vuln)
        
        return unique_vulns
    
    def get_memory_statistics(self) -> Dict[str, Any]:
        """Get statistics about memory operations from all checkers."""
        statistics = {
            'total_checkers': len(self.checkers),
            'supported_extensions': list(set().union(*(c.get_supported_extensions() for c in self.checkers))),
            'checker_statistics': {}
        }
        
        for checker in self.checkers:
            checker_name = checker.__class__.__name__
            if hasattr(checker, 'allocations'):  # For C memory checker
                try:
                    total_allocations = len(checker.allocations)
                    freed_allocations = sum(1 for alloc in checker.allocations.values() if alloc.freed)
                    statistics['checker_statistics'][checker_name] = {
                        'total_allocations': total_allocations,
                        'freed_allocations': freed_allocations,
                        'potential_leaks': total_allocations - freed_allocations
                    }
                except:
                    pass
        
        return statistics
    
    async def enhance_with_llm(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Enhance vulnerability detection using LLM analysis."""
        if not self.model:
            return vulnerabilities
        
        enhanced_vulns = []
        for vuln in vulnerabilities:
            try:
                enhanced_vuln = await self._llm_validate_vulnerability(vuln)
                enhanced_vulns.append(enhanced_vuln or vuln)
            except Exception as e:
                if self.logger:
                    self.logger.log(f"Error enhancing vulnerability with LLM: {e}", level="ERROR")
                enhanced_vulns.append(vuln)
        
        return enhanced_vulns
    
    async def _llm_validate_vulnerability(self, vuln: Vulnerability):
        """Use LLM to validate and enhance a vulnerability."""
        from secgen.agent.models import ChatMessage, MessageRole
        
        prompt = f"""
        Analyze this memory safety vulnerability:
        
        Type: {vuln.vuln_type.value}
        Location: {vuln.location}
        Description: {vuln.description}
        Evidence: {vuln.evidence}
        
        Assess: 1) Is this real or false positive? 2) Appropriate severity? 3) Confidence? 4) Remediation advice?
        
        JSON response: {{"is_valid": true/false, "severity": "critical/high/medium/low", "confidence": 0.0-1.0, "description": "enhanced description", "recommendation": "specific advice"}}
        """
        
        messages = [
            ChatMessage(role=MessageRole.SYSTEM, content="You are a security expert analyzing memory safety vulnerabilities."),
            ChatMessage(role=MessageRole.USER, content=prompt)
        ]
        
        try:
            response = self.model.generate(messages)
            import json
            result = json.loads(response.content)
            
            if result.get('is_valid', True):
                vuln.confidence = result.get('confidence', vuln.confidence)
                vuln.description = result.get('description', vuln.description)
                vuln.recommendation = result.get('recommendation', vuln.recommendation)
                
                # Update severity if provided
                from secgen.core.analyzer import Severity
                severity_map = {'critical': Severity.CRITICAL, 'high': Severity.HIGH, 'medium': Severity.MEDIUM, 'low': Severity.LOW}
                new_severity = severity_map.get(result.get('severity', '').lower())
                if new_severity:
                    vuln.severity = new_severity
                
                return vuln
            else:
                return None  # False positive
                
        except Exception as e:
            if self.logger:
                self.logger.log(f"Error in LLM validation: {e}", level="ERROR")
            return vuln