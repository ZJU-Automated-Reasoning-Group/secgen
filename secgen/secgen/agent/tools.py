"""Basic tool definitions for SecGen."""

from typing import Dict, Any


class Tool:
    """Basic tool class for SecGen."""
    
    def __init__(self, name: str, description: str, inputs: Dict[str, Any] = None):
        self.name = name
        self.description = description
        self.inputs = inputs or {}
    
    def __call__(self, *args, **kwargs):
        """Execute the tool."""
        raise NotImplementedError("Tool execution not implemented")
