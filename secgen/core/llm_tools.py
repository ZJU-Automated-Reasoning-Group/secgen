"""LLM tools for interprocedural analysis."""

import json
import re
from typing import Dict, List, Optional, Any, Type
from dataclasses import dataclass, field
from abc import ABC, abstractmethod


@dataclass
class LLMToolInput(ABC):
    """Base class for LLM tool inputs with caching support."""
    
    @abstractmethod
    def __hash__(self) -> int:
        pass
    
    def __eq__(self, other) -> bool:
        return self.__hash__() == other.__hash__()


@dataclass
class LLMToolOutput(ABC):
    """Base class for LLM tool outputs."""
    pass


class LLMTool(ABC):
    """Base class for LLM tools with caching."""
    
    def __init__(self, model, logger=None):
        self.model = model
        self.logger = logger
        self.cache: Dict[LLMToolInput, LLMToolOutput] = {}
        self.query_count = 0
        self.cache_hits = 0
    
    def invoke(self, input: LLMToolInput, output_class: Type[LLMToolOutput]) -> Optional[LLMToolOutput]:
        """Invoke tool with caching."""
        if input in self.cache:
            self.cache_hits += 1
            return self.cache[input]
        
        try:
            prompt = self._generate_prompt(input)
            response = self.model.generate(prompt)
            self.query_count += 1
            
            output = self._parse_response(response, input)
            if output and isinstance(output, output_class):
                self.cache[input] = output
                return output
        except Exception as e:
            if self.logger:
                self.logger.log(f"Error in {type(self).__name__}: {e}", level="ERROR")
        
        return None
    
    @abstractmethod
    def _generate_prompt(self, input: LLMToolInput) -> str:
        pass
    
    @abstractmethod
    def _parse_response(self, response: str, input: LLMToolInput) -> Optional[LLMToolOutput]:
        pass
    
    def get_cache_stats(self) -> Dict[str, Any]:
        return {
            'total_queries': self.query_count,
            'cache_hits': self.cache_hits,
            'cache_hit_ratio': self.cache_hits / max(self.query_count, 1),
            'cache_size': len(self.cache)
        }


# Analysis Tools

@dataclass
class AnalysisInput(LLMToolInput):
    """Input for analysis tools."""
    caller_summary: Dict[str, Any]
    callee_summary: Dict[str, Any]
    call_site: Dict[str, Any]
    alias_relationships: Dict[str, Any] = field(default_factory=dict)
    
    def __hash__(self) -> int:
        return hash((
            json.dumps(self.caller_summary, sort_keys=True),
            json.dumps(self.callee_summary, sort_keys=True),
            json.dumps(self.call_site, sort_keys=True)
        ))


@dataclass
class AnalysisOutput(LLMToolOutput):
    """Output for analysis tools."""
    can_propagate: bool
    confidence: float
    propagation_type: str
    explanation: str
    reasoning_steps: List[str] = field(default_factory=list)


class TaintAnalyzerTool(LLMTool):
    """LLM tool for taint propagation analysis."""
    
    def _generate_prompt(self, input: LLMToolInput) -> str:
        if not isinstance(input, AnalysisInput):
            raise TypeError("Expected AnalysisInput")
        
        return f"""Analyze taint propagation between functions:

CALLER: {input.caller_summary['function_name']} ({input.caller_summary['file_path']})
CALLEE: {input.callee_summary['function_name']} ({input.callee_summary['file_path']})
CALL SITE: {json.dumps(input.call_site)}

Consider parameter flow, return values, side effects, and aliases.

Respond in JSON:
{{
    "can_propagate": true/false,
    "confidence": 0.0-1.0,
    "propagation_type": "preserves_taint|sanitizes|introduces_taint|no_effect",
    "explanation": "Brief explanation",
    "reasoning_steps": ["Step 1", "Step 2"]
}}"""
    
    def _parse_response(self, response: str, input: LLMToolInput) -> Optional[AnalysisOutput]:
        try:
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if not json_match:
                return None
            
            data = json.loads(json_match.group())
            return AnalysisOutput(
                can_propagate=data.get('can_propagate', False),
                confidence=data.get('confidence', 0.0),
                propagation_type=data.get('propagation_type', 'no_effect'),
                explanation=data.get('explanation', ''),
                reasoning_steps=data.get('reasoning_steps', [])
            )
        except (json.JSONDecodeError, KeyError):
            return None


@dataclass
class PathAnalysisInput(LLMToolInput):
    """Input for path analysis tool."""
    call_path: List[str]
    function_summaries: Dict[str, Dict[str, Any]]
    taint_sources: List[str]
    taint_sinks: List[str]
    
    def __hash__(self) -> int:
        return hash((
            tuple(self.call_path),
            json.dumps(self.function_summaries, sort_keys=True),
            tuple(self.taint_sources),
            tuple(self.taint_sinks)
        ))


@dataclass
class PathAnalysisOutput(LLMToolOutput):
    """Output for path analysis tool."""
    is_feasible: bool
    confidence: float
    explanation: str
    critical_points: List[Dict[str, Any]] = field(default_factory=list)
    sanitization_points: List[str] = field(default_factory=list)


class PathAnalyzerTool(LLMTool):
    """LLM tool for analyzing call path feasibility."""
    
    def _generate_prompt(self, input: LLMToolInput) -> str:
        if not isinstance(input, PathAnalysisInput):
            raise TypeError("Expected PathAnalysisInput")
        
        path_str = " -> ".join(input.call_path)
        return f"""Analyze taint propagation path feasibility:

PATH: {path_str}
SOURCES: {', '.join(input.taint_sources)}
SINKS: {', '.join(input.taint_sinks)}

Consider taint handling, parameter flow, validation, and side effects.

Respond in JSON:
{{
    "is_feasible": true/false,
    "confidence": 0.0-1.0,
    "explanation": "Brief explanation",
    "critical_points": [{{"function": "name", "type": "source|sink|propagation|sanitization", "description": "..."}}],
    "sanitization_points": ["func1", "func2"]
}}"""
    
    def _parse_response(self, response: str, input: LLMToolInput) -> Optional[PathAnalysisOutput]:
        try:
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if not json_match:
                return None
            
            data = json.loads(json_match.group())
            return PathAnalysisOutput(
                is_feasible=data.get('is_feasible', False),
                confidence=data.get('confidence', 0.0),
                explanation=data.get('explanation', ''),
                critical_points=data.get('critical_points', []),
                sanitization_points=data.get('sanitization_points', [])
            )
        except (json.JSONDecodeError, KeyError):
            return None


@dataclass
class FunctionSummaryInput(LLMToolInput):
    """Input for function summary tool."""
    function_name: str
    function_code: str
    file_path: str
    parameters: List[str]
    calls: List[str]
    
    def __hash__(self) -> int:
        return hash((
            self.function_name,
            self.function_code,
            self.file_path,
            tuple(self.parameters),
            tuple(self.calls)
        ))


@dataclass
class FunctionSummaryOutput(LLMToolOutput):
    """Output for function summary tool."""
    summary: Dict[str, Any]
    confidence: float
    analysis_method: str


class FunctionSummaryTool(LLMTool):
    """LLM tool for generating function summaries."""
    
    def _generate_prompt(self, input: LLMToolInput) -> str:
        if not isinstance(input, FunctionSummaryInput):
            raise TypeError("Expected FunctionSummaryInput")
        
        return f"""Analyze this C/C++ function for interprocedural analysis:

FUNCTION: {input.function_name} ({input.file_path})
PARAMETERS: {', '.join(input.parameters)}
CALLS: {', '.join(input.calls)}

CODE:
```c
{input.function_code}
```

Analyze parameter effects, return values, side effects, taint flow, aliases, and security.

Respond in JSON:
{{
    "parameters": [{{"index": 0, "name": "param", "taint_propagation": "preserves_taint|sanitizes|introduces_taint|no_effect", "may_be_modified": true}}],
    "return_value": {{"type": "int*", "depends_on_params": [0], "can_introduce_taint": false}},
    "side_effects": [{{"effect_type": "memory_operation|file_io|system_call", "description": "..."}}],
    "memory_safe": false,
    "security_sensitive": true,
    "analysis_confidence": 0.9
}}"""
    
    def _parse_response(self, response: str, input: LLMToolInput) -> Optional[FunctionSummaryOutput]:
        try:
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if not json_match:
                return None
            
            data = json.loads(json_match.group())
            return FunctionSummaryOutput(
                summary=data,
                confidence=data.get('analysis_confidence', 0.8),
                analysis_method='llm'
            )
        except (json.JSONDecodeError, KeyError):
            return None


class LLMToolsManager:
    """Manager for LLM tools."""
    
    def __init__(self, model, logger=None):
        self.model = model
        self.logger = logger
        self.tools = {
            'taint_analyzer': TaintAnalyzerTool(model, logger),
            'path_analyzer': PathAnalyzerTool(model, logger),
            'function_summarizer': FunctionSummaryTool(model, logger)
        }
    
    def get_tool(self, tool_name: str) -> Optional[LLMTool]:
        return self.tools.get(tool_name)
    
    def get_all_stats(self) -> Dict[str, Dict[str, Any]]:
        return {name: tool.get_cache_stats() for name, tool in self.tools.items()}
    
    def clear_all_caches(self):
        for tool in self.tools.values():
            tool.cache.clear()
