"""Unified memory safety analyzer that coordinates language-specific checkers."""

from typing import Dict, List, Any
from secgen.core.models import Vulnerability
from secgen.checker.c_memory_checker import CMemoryChecker



class UnifiedMemoryAnalyzer:
    """Unified memory analyzer that delegates to language-specific checkers."""
    
    def __init__(self, model=None, logger=None, interprocedural_analyzer=None):
        self.model, self.logger, self.interprocedural_analyzer = model, logger, interprocedural_analyzer
        self.checkers = [
            CMemoryChecker(model, logger, interprocedural_analyzer)
        ]
    
    def analyze_file(self, file_path: str, content: str) -> List[Vulnerability]:
        """Analyze a file for memory safety issues using appropriate checker."""
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
        """Analyze memory safety using interprocedural context."""
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
        seen, unique_vulns = set(), []
        for vuln in vulnerabilities:
            signature = (vuln.vuln_type, vuln.location.file_path, vuln.location.line_start, vuln.description[:50])
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
            if hasattr(checker, 'allocations'):
                try:
                    total = len(checker.allocations)
                    freed = sum(1 for alloc in checker.allocations.values() if alloc.freed)
                    statistics['checker_statistics'][checker.__class__.__name__] = {
                        'total_allocations': total, 'freed_allocations': freed, 'potential_leaks': total - freed
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
                enhanced_vulns.append(await self._llm_validate_vulnerability(vuln) or vuln)
            except Exception as e:
                self.logger and self.logger.log(f"Error enhancing vulnerability with LLM: {e}", level="ERROR")
                enhanced_vulns.append(vuln)
        return enhanced_vulns
    
    async def _llm_validate_vulnerability(self, vuln: Vulnerability):
        """Use LLM to validate and enhance a vulnerability."""
        from secgen.agent.models import ChatMessage, MessageRole
        import json
        
        prompt = f"""Analyze this memory safety vulnerability:
Type: {vuln.vuln_type.value}
Location: {vuln.location}
Description: {vuln.description}
Evidence: {vuln.evidence}

Assess: 1) Is this real or false positive? 2) Appropriate severity? 3) Confidence? 4) Remediation advice?

JSON response: {{"is_valid": true/false, "severity": "critical/high/medium/low", "confidence": 0.0-1.0, "description": "enhanced description", "recommendation": "specific advice"}}"""
        
        messages = [
            ChatMessage(role=MessageRole.SYSTEM, content="You are a security expert analyzing memory safety vulnerabilities."),
            ChatMessage(role=MessageRole.USER, content=prompt)
        ]
        
        try:
            result = json.loads(self.model.generate(messages).content)
            if result.get('is_valid', True):
                vuln.confidence = result.get('confidence', vuln.confidence)
                vuln.description = result.get('description', vuln.description)
                vuln.recommendation = result.get('recommendation', vuln.recommendation)
                from secgen.core.models import Severity
                severity_map = {'critical': Severity.CRITICAL, 'high': Severity.HIGH, 'medium': Severity.MEDIUM, 'low': Severity.LOW}
                if new_severity := severity_map.get(result.get('severity', '').lower()):
                    vuln.severity = new_severity
                return vuln
            return None  # False positive
        except Exception as e:
            self.logger and self.logger.log(f"Error in LLM validation: {e}", level="ERROR")
            return vuln
        
        