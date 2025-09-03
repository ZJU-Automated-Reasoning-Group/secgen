"""Function summarization module for generating intelligent function summaries."""

from __future__ import annotations

# import asyncio
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

from secgen.core.models import FunctionInfo
from secgen.agent.models import ChatMessage, MessageRole


@dataclass
class LLMFunctionSummary:
    """Represents an LLM-generated function summary."""
    function_name: str
    file_path: str
    summary: str
    purpose: str
    inputs: str
    outputs: str
    security_concerns: List[str]
    complexity_score: int  # 1-5 scale
    confidence: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'function_name': self.function_name,
            'file_path': self.file_path,
            'summary': self.summary,
            'purpose': self.purpose,
            'inputs': self.inputs,
            'outputs': self.outputs,
            'security_concerns': self.security_concerns,
            'complexity_score': self.complexity_score,
            'confidence': self.confidence
        }


class FunctionSummarizer:
    """Generates intelligent summaries of functions using LLM analysis."""
    
    def __init__(self, model=None, logger=None, max_workers: int = 3):
        """Initialize function summarizer.
        
        Args:
            model: LLM model for generating summaries
            logger: Logger instance
            max_workers: Maximum number of parallel workers
        """
        self.model = model
        self.logger = logger
        self.max_workers = max_workers
        self.summaries: Dict[str, 'LLMFunctionSummary'] = {}
    
    def summarize_function(self, function_info: FunctionInfo, content: str) -> Optional['LLMFunctionSummary']:
        """Generate summary for a single function.
        
        Args:
            function_info: Function information
            content: File content containing the function
            
        Returns:
            Function summary or None if generation fails
        """
        if not self.model:
            return self._generate_basic_summary(function_info)
        
        try:
            # Extract function code
            lines = content.split('\n')
            func_lines = lines[function_info.start_line-1:function_info.end_line]
            func_code = '\n'.join(func_lines)
            
            # Generate LLM-based summary
            summary_data = self._generate_llm_summary(function_info.name, func_code)
            
            if summary_data:
                summary = LLMFunctionSummary(
                    function_name=function_info.name,
                    file_path=function_info.file_path,
                    **summary_data
                )
                
                # Cache the summary
                func_key = f"{function_info.file_path}:{function_info.name}"
                self.summaries[func_key] = summary
                
                return summary
        
        except Exception as e:
            if self.logger:
                self.logger.log(f"Error generating summary for {function_info.name}: {e}", level="ERROR")
        
        return self._generate_basic_summary(function_info)
    
    def _generate_llm_summary(self, function_name: str, func_code: str) -> Optional[Dict[str, Any]]:
        """Generate LLM-based function summary."""
        
        prompt = f"""Analyze this function and provide a structured summary in JSON format:

Function: {function_name}
```
{func_code}
```

Please provide a JSON response with the following structure:
{{
    "summary": "One sentence description of what the function does",
    "purpose": "Detailed explanation of the function's purpose and role",
    "inputs": "Description of input parameters and their types",
    "outputs": "Description of return values and side effects",
    "security_concerns": ["List of potential security issues or concerns"],
    "complexity_score": 1-5 (1=very simple, 5=very complex),
    "confidence": 0.0-1.0 (confidence in the analysis)
}}

Focus on:
1. What the function does
2. Input/output behavior
3. Potential security vulnerabilities
4. Code complexity and maintainability issues
5. Dependencies and side effects"""

        messages = [
            ChatMessage(
                role=MessageRole.SYSTEM,
                content="You are an expert code analyst. Analyze functions and provide structured, accurate summaries focusing on functionality and security implications."
            ),
            ChatMessage(
                role=MessageRole.USER,
                content=prompt
            )
        ]
        
        try:
            response = self.model.generate(messages)
            if response.content:
                import json
                
                # Try to extract JSON from response
                content = response.content.strip()
                if content.startswith('```json'):
                    content = content[7:]
                if content.endswith('```'):
                    content = content[:-3]
                
                summary_data = json.loads(content.strip())
                
                # Validate required fields
                required_fields = ['summary', 'purpose', 'inputs', 'outputs', 'security_concerns', 'complexity_score', 'confidence']
                if all(field in summary_data for field in required_fields):
                    return summary_data
                
        except Exception as e:
            if self.logger:
                self.logger.log(f"Error parsing LLM response for {function_name}: {e}", level="ERROR")
        
        return None
    
    def _generate_basic_summary(self, function_info: FunctionInfo) -> LLMFunctionSummary:
        """Generate basic summary without LLM."""
        
        # Basic heuristics for summary generation
        param_count = len(function_info.parameters)
        call_count = len(function_info.calls)
        
        # Determine complexity based on heuristics
        complexity = 1
        if param_count > 5:
            complexity += 1
        if call_count > 10:
            complexity += 1
        if function_info.end_line - function_info.start_line > 50:
            complexity += 1
        if function_info.end_line - function_info.start_line > 100:
            complexity += 1
        
        complexity = min(complexity, 5)
        
        # Basic security concern detection
        security_concerns = []
        dangerous_calls = {'malloc', 'strcpy', 'strcat', 'sprintf', 'system', 'exec', 'eval'}
        for call in function_info.calls:
            if call in dangerous_calls:
                security_concerns.append(f"Calls potentially dangerous function: {call}")
        
        return LLMFunctionSummary(
            function_name=function_info.name,
            file_path=function_info.file_path,
            summary=f"Function {function_info.name} with {param_count} parameters",
            purpose=f"Function defined at lines {function_info.start_line}-{function_info.end_line}",
            inputs=f"Takes {param_count} parameters: {', '.join(function_info.parameters)}",
            outputs="Return value not analyzed",
            security_concerns=security_concerns,
            complexity_score=complexity,
            confidence=0.5  # Lower confidence for basic analysis
        )
    
    def summarize_functions_batch(self, functions: Dict[str, FunctionInfo], 
                                file_contents: Dict[str, str]) -> Dict[str, 'LLMFunctionSummary']:
        """Generate summaries for multiple functions in parallel.
        
        Args:
            functions: Dictionary of function information
            file_contents: Dictionary mapping file paths to content
            
        Returns:
            Dictionary mapping function keys to summaries
        """
        summaries = {}
        
        if not self.model:
            # Generate basic summaries without LLM
            for func_key, func_info in functions.items():
                summary = self._generate_basic_summary(func_info)
                summaries[func_key] = summary
            return summaries
        
        # Parallel processing with LLM
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_func = {}
            
            for func_key, func_info in functions.items():
                if func_info.file_path in file_contents:
                    future = executor.submit(
                        self.summarize_function,
                        func_info,
                        file_contents[func_info.file_path]
                    )
                    future_to_func[future] = func_key
            
            for future in as_completed(future_to_func):
                func_key = future_to_func[future]
                try:
                    summary = future.result()
                    if summary:
                        summaries[func_key] = summary
                        if self.logger:
                            self.logger.log(f"Generated summary for {summary.function_name}")
                except Exception as e:
                    if self.logger:
                        self.logger.log(f"Error generating summary for {func_key}: {e}", level="ERROR")
        
        return summaries
    
    def get_function_summary(self, func_key: str) -> Optional[LLMFunctionSummary]:
        """Get cached function summary.
        
        Args:
            func_key: Function key (file_path:function_name)
            
        Returns:
            Function summary if available
        """
        return self.summaries.get(func_key)
    
    def get_security_hotspots(self, min_confidence: float = 0.7) -> List[LLMFunctionSummary]:
        """Get functions with potential security concerns.
        
        Args:
            min_confidence: Minimum confidence threshold
            
        Returns:
            List of functions with security concerns
        """
        hotspots = []
        for summary in self.summaries.values():
            if (summary.confidence >= min_confidence and 
                summary.security_concerns and 
                len(summary.security_concerns) > 0):
                hotspots.append(summary)
        
        # Sort by number of security concerns and complexity
        hotspots.sort(key=lambda s: (len(s.security_concerns), s.complexity_score), reverse=True)
        return hotspots
    
    def get_complex_functions(self, min_complexity: int = 4) -> List[LLMFunctionSummary]:
        """Get functions with high complexity scores.
        
        Args:
            min_complexity: Minimum complexity threshold
            
        Returns:
            List of complex functions
        """
        complex_funcs = [
            summary for summary in self.summaries.values()
            if summary.complexity_score >= min_complexity
        ]
        
        # Sort by complexity score
        complex_funcs.sort(key=lambda s: s.complexity_score, reverse=True)
        return complex_funcs
    
    def export_summaries(self, output_file: str):
        """Export all function summaries to JSON file.
        
        Args:
            output_file: Output file path
        """
        import json
        
        export_data = {
            'total_functions': len(self.summaries),
            'functions': {
                func_key: summary.to_dict()
                for func_key, summary in self.summaries.items()
            },
            'statistics': {
                'security_hotspots': len(self.get_security_hotspots()),
                'complex_functions': len(self.get_complex_functions()),
                'avg_complexity': sum(s.complexity_score for s in self.summaries.values()) / len(self.summaries) if self.summaries else 0
            }
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        if self.logger:
            self.logger.log(f"Exported {len(self.summaries)} function summaries to {output_file}")
    
    def generate_summary_report(self) -> str:
        """Generate a text report of function summaries.
        
        Returns:
            Formatted text report
        """
        if not self.summaries:
            return "No function summaries available."
        
        report = f"# Function Summary Report\n\n"
        report += f"**Total Functions Analyzed**: {len(self.summaries)}\n\n"
        
        # Security hotspots
        hotspots = self.get_security_hotspots()
        if hotspots:
            report += f"## Security Hotspots ({len(hotspots)} functions)\n\n"
            for summary in hotspots[:10]:  # Top 10
                report += f"### {summary.function_name}\n"
                report += f"- **File**: {summary.file_path}\n"
                report += f"- **Summary**: {summary.summary}\n"
                report += f"- **Security Concerns**: {', '.join(summary.security_concerns)}\n"
                report += f"- **Complexity**: {summary.complexity_score}/5\n\n"
        
        # Complex functions
        complex_funcs = self.get_complex_functions()
        if complex_funcs:
            report += f"## Complex Functions ({len(complex_funcs)} functions)\n\n"
            for summary in complex_funcs[:10]:  # Top 10
                report += f"### {summary.function_name}\n"
                report += f"- **File**: {summary.file_path}\n"
                report += f"- **Summary**: {summary.summary}\n"
                report += f"- **Complexity**: {summary.complexity_score}/5\n"
                report += f"- **Purpose**: {summary.purpose}\n\n"
        
        return report
