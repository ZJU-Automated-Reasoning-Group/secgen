"""Report generation and export functionality for vulnerability analysis."""

from collections import Counter
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass

from secgen.core.models import Vulnerability, VulnerabilityType, Severity
from secgen.core.function_summarizer import LLMFunctionSummary


@dataclass
class AnalysisReport:
    """Comprehensive analysis report."""
    files_analyzed: List[str]
    total_vulnerabilities: int
    vulnerabilities_by_severity: Dict[str, int]
    vulnerabilities_by_type: Dict[str, int]
    vulnerabilities: List[Vulnerability]
    call_graph_metrics: Dict[str, Any]
    taint_analysis_summary: Dict[str, Any]
    memory_statistics: Dict[str, Any]
    function_summaries: Dict[str, LLMFunctionSummary]
    analysis_time: float
    confidence_distribution: Dict[str, int]


class ReportGenerator:
    """Handles report generation and export functionality."""
    
    def generate_report(self, files_analyzed: List[str], 
                       vulnerabilities: List[Vulnerability],
                       static_results: Dict[str, Any],
                       function_summaries: Dict[str, LLMFunctionSummary],
                       analysis_time: float) -> AnalysisReport:
        """Generate comprehensive analysis report."""
        
        # Count vulnerabilities by severity and type
        severity_counts = Counter(vuln.severity.value for vuln in vulnerabilities)
        type_counts = Counter(vuln.vuln_type.value for vuln in vulnerabilities)
        
        # Confidence distribution
        confidence_ranges = {'0.9-1.0': 0, '0.8-0.9': 0, '0.7-0.8': 0, '0.6-0.7': 0, '0.0-0.6': 0}
        for vuln in vulnerabilities:
            conf = vuln.confidence
            if conf >= 0.9: confidence_ranges['0.9-1.0'] += 1
            elif conf >= 0.8: confidence_ranges['0.8-0.9'] += 1
            elif conf >= 0.7: confidence_ranges['0.7-0.8'] += 1
            elif conf >= 0.6: confidence_ranges['0.6-0.7'] += 1
            else: confidence_ranges['0.0-0.6'] += 1
        
        return AnalysisReport(
            files_analyzed=files_analyzed,
            total_vulnerabilities=len(vulnerabilities),
            vulnerabilities_by_severity=dict(severity_counts),
            vulnerabilities_by_type=dict(type_counts),
            vulnerabilities=vulnerabilities,
            call_graph_metrics={},
            taint_analysis_summary={},
            memory_statistics={},
            function_summaries=function_summaries,
            analysis_time=analysis_time,
            confidence_distribution=confidence_ranges
        )
    
    def filter_vulnerabilities(self, vulnerabilities: List[Vulnerability], 
                             min_severity: Severity = Severity.LOW,
                             min_confidence: float = 0.0,
                             vuln_types: Optional[Set[VulnerabilityType]] = None) -> List[Vulnerability]:
        """Filter vulnerabilities based on criteria."""
        severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        min_severity_idx = severity_order.index(min_severity)
        
        return [vuln for vuln in vulnerabilities 
                if severity_order.index(vuln.severity) >= min_severity_idx
                and vuln.confidence >= min_confidence
                and (not vuln_types or vuln.vuln_type in vuln_types)]
    
    def export_json_report(self, report: AnalysisReport) -> Dict[str, Any]:
        """Export report as JSON-serializable dictionary."""
        return {
            'summary': {
                'files_analyzed': len(report.files_analyzed),
                'total_vulnerabilities': report.total_vulnerabilities,
                'analysis_time': report.analysis_time,
                'vulnerabilities_by_severity': report.vulnerabilities_by_severity,
                'vulnerabilities_by_type': report.vulnerabilities_by_type,
                'confidence_distribution': report.confidence_distribution
            },
            'vulnerabilities': [vuln.to_dict() for vuln in report.vulnerabilities],
            'analysis_metrics': {
                'call_graph': report.call_graph_metrics.to_dict() if hasattr(report.call_graph_metrics, 'to_dict') else report.call_graph_metrics,
                'taint_analysis': report.taint_analysis_summary,
                'memory_analysis': report.memory_statistics
            },
            'files_analyzed': report.files_analyzed
        }
    
    def generate_summary_report(self, report: AnalysisReport) -> str:
        """Generate a human-readable summary report."""
        summary = f"""# Security Analysis Report

## Overview
- **Files Analyzed**: {len(report.files_analyzed)}
- **Total Vulnerabilities**: {report.total_vulnerabilities}
- **Analysis Time**: {report.analysis_time:.2f} seconds

## Vulnerability Breakdown by Severity
"""
        
        for severity, count in sorted(report.vulnerabilities_by_severity.items()):
            summary += f"- **{severity.upper()}**: {count}\n"
        
        summary += "\n## Vulnerability Types\n"
        for vuln_type, count in sorted(report.vulnerabilities_by_type.items()):
            summary += f"- **{vuln_type.replace('_', ' ').title()}**: {count}\n"
        
        summary += "\n## Confidence Distribution\n"
        for conf_range, count in report.confidence_distribution.items():
            summary += f"- **{conf_range}**: {count}\n"
        
        # Add top vulnerabilities
        if report.vulnerabilities:
            summary += "\n## Top Vulnerabilities\n"
            for i, vuln in enumerate(report.vulnerabilities[:10], 1):
                summary += f"""
### {i}. {vuln.vuln_type.value.replace('_', ' ').title()}
- **Location**: {vuln.location}
- **Severity**: {vuln.severity.value.upper()}
- **Confidence**: {vuln.confidence:.1%}
- **Description**: {vuln.description}
- **Recommendation**: {vuln.recommendation or 'No specific recommendation provided'}
"""
        
        return summary
    
    def generate_statistics(self, vulnerabilities: List[Vulnerability], 
                           total_time: float) -> Dict[str, Any]:
        """Generate analysis statistics."""
        severity_counts = Counter(vuln.severity.value for vuln in vulnerabilities)
        type_counts = Counter(vuln.vuln_type.value for vuln in vulnerabilities)
        
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'vulnerabilities_by_severity': dict(severity_counts),
            'vulnerabilities_by_type': dict(type_counts),
            'analysis_time': total_time,
            'average_confidence': sum(vuln.confidence for vuln in vulnerabilities) / len(vulnerabilities) if vulnerabilities else 0.0
        }
