"""Unified taint analyzer that coordinates language-specific checkers."""

from typing import Dict, List, Any
import json

from secgen.core.models import Vulnerability, Severity
from secgen.checker.c_taint_checker import CTaintChecker
from secgen.checker.python_taint_checker import PythonTaintChecker


class UnifiedTaintAnalyzer:
    """Unified taint analyzer that delegates to language-specific checkers."""
    
    def __init__(self, model=None, logger=None, interprocedural_analyzer=None):
        self.model = model
        self.logger = logger
        self.checkers = [
            CTaintChecker(model, logger, interprocedural_analyzer),
            PythonTaintChecker(model, logger, interprocedural_analyzer)
        ]
    
    def analyze_file(self, file_path: str, content: str) -> List[Vulnerability]:
        """Analyze a file for taint vulnerabilities using appropriate checker."""
        vulnerabilities = []
        for checker in self.checkers:
            if checker.supports_file_type(file_path):
                try:
                    vulnerabilities.extend(checker.analyze_file(file_path, content))
                except Exception as e:
                    self.logger and self.logger.log(f"Error in {checker.__class__.__name__} for {file_path}: {e}", level="ERROR")
        return self._deduplicate_vulnerabilities(vulnerabilities)
    
    def analyze_with_interprocedural_context(self, file_contents: Dict[str, str], 
                                           functions: Dict[str, Any],
                                           function_summaries: Dict[str, Any]) -> List[Vulnerability]:
        """Analyze taint flows using interprocedural context."""
        vulnerabilities = []
        for checker in self.checkers:
            checker_files = {path: content for path, content in file_contents.items() 
                           if checker.supports_file_type(path)}
            if checker_files:
                try:
                    vulnerabilities.extend(checker.analyze_with_interprocedural_context(
                        checker_files, functions, function_summaries))
                except Exception as e:
                    self.logger and self.logger.log(f"Error in interprocedural {checker.__class__.__name__}: {e}", level="ERROR")
        return self._deduplicate_vulnerabilities(vulnerabilities)
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities."""
        seen = set()
        return [vuln for vuln in vulnerabilities 
                if (signature := (vuln.vuln_type, vuln.location.file_path, vuln.location.line_start, vuln.description[:50])) 
                not in seen and not seen.add(signature)]
    
    def get_taint_summary(self) -> Dict[str, Any]:
        """Get summary of taint analysis results from all checkers."""
        return {
            'total_checkers': len(self.checkers),
            'supported_extensions': list(set().union(*(c.get_supported_extensions() for c in self.checkers))),
            'checker_summaries': {c.__class__.__name__: {} for c in self.checkers}
        }
    
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
                self.logger and self.logger.log(f"Error enhancing vulnerability with LLM: {e}", level="ERROR")
                enhanced_vulns.append(vuln)
        return enhanced_vulns
    
    async def _llm_validate_vulnerability(self, vuln: Vulnerability):
        """Use LLM to validate and enhance a vulnerability."""
        from secgen.agent.models import ChatMessage, MessageRole
        
        prompt = f"""Analyze this taint flow vulnerability:
Type: {vuln.vuln_type.value}
Location: {vuln.location}
Description: {vuln.description}
Evidence: {vuln.evidence}

Assess: 1) Is this real or false positive? 2) Appropriate severity? 3) Confidence? 4) Remediation advice?

JSON response: {{"is_valid": true/false, "severity": "critical/high/medium/low", "confidence": 0.0-1.0, "description": "enhanced description", "recommendation": "specific advice"}}"""
        
        messages = [
            ChatMessage(role=MessageRole.SYSTEM, content="You are a security expert analyzing taint flow vulnerabilities."),
            ChatMessage(role=MessageRole.USER, content=prompt)
        ]
        
        try:
            response = self.model.generate(messages)
            result = json.loads(response.content)
            
            if result.get('is_valid', True):
                vuln.confidence = result.get('confidence', vuln.confidence)
                vuln.description = result.get('description', vuln.description)
                vuln.recommendation = result.get('recommendation', vuln.recommendation)
                
                severity_map = {'critical': Severity.CRITICAL, 'high': Severity.HIGH, 'medium': Severity.MEDIUM, 'low': Severity.LOW}
                if new_severity := severity_map.get(result.get('severity', '').lower()):
                    vuln.severity = new_severity
                return vuln
            return None  # False positive
                
        except Exception as e:
            self.logger and self.logger.log(f"Error in LLM validation: {e}", level="ERROR")
            return vuln