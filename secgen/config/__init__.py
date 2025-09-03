"""Configuration management for secgen."""

import json
import os
from typing import Dict, Any, Optional
from pathlib import Path


class ConfigLoader:
    """Loads configuration from JSON files."""
    
    def __init__(self, config_dir: Optional[str] = None):
        """Initialize config loader.
        
        Args:
            config_dir: Directory containing config files. If None, uses default config directory.
        """
        if config_dir is None:
            # Get the directory where this __init__.py file is located
            self.config_dir = Path(__file__).parent
        else:
            self.config_dir = Path(config_dir)
    
    def load_config(self, config_name: str) -> Dict[str, Any]:
        """Load configuration from a JSON file.
        
        Args:
            config_name: Name of the config file (without .json extension)
            
        Returns:
            Dictionary containing the configuration data
            
        Raises:
            FileNotFoundError: If the config file doesn't exist
            json.JSONDecodeError: If the config file contains invalid JSON
        """
        config_path = self.config_dir / f"{config_name}.json"
        
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def get_memory_config(self) -> Dict[str, Any]:
        """Load memory-related configuration."""
        # Memory detectors now use hardcoded configurations
        return {}
    

    def get_c_taint_config(self) -> Dict[str, Any]:
        """Load C/C++ taint analysis configuration."""
        return self.load_config("c_taint")
    
    def get_python_taint_config(self) -> Dict[str, Any]:
        """Load Python taint analysis configuration."""
        return self.load_config("python_taint")


# Global config loader instance
_config_loader = None


def get_config_loader() -> ConfigLoader:
    """Get the global configuration loader instance."""
    global _config_loader
    if _config_loader is None:
        _config_loader = ConfigLoader()
    return _config_loader


def load_memory_config() -> Dict[str, Any]:
    """Load memory configuration using the global config loader."""
    return get_config_loader().get_memory_config()


def load_c_taint_config() -> Dict[str, Any]:
    """Load C/C++ taint configuration using the global config loader."""
    return get_config_loader().get_c_taint_config()


def load_python_taint_config() -> Dict[str, Any]:
    """Load Python taint configuration using the global config loader."""
    return get_config_loader().get_python_taint_config()


def load_detector_config(detector_name: str) -> Dict[str, Any]:
    """Load configuration for a specific detector.
    
    Args:
        detector_name: Name of the detector (e.g., 'uaf', 'npd', 'buffer_overflow')
        
    Returns:
        Configuration dictionary for the detector
    """
    config_loader = get_config_loader()
    
    # Memory-related detectors now use hardcoded configurations
    if detector_name in ['uaf', 'npd', 'memory_leak', 'double_free', 'buffer_overflow', 'format_string', 'integer_overflow']:
        return {}
    
    # Taint analysis detectors still use configuration files
    if detector_name in ['taint', 'c_taint']:
        try:
            return config_loader.get_c_taint_config()
        except FileNotFoundError:
            return {}
    elif detector_name == 'python_taint':
        try:
            return config_loader.get_python_taint_config()
        except FileNotFoundError:
            return {}
    
    return {}


def get_detector_configs() -> Dict[str, Dict[str, Any]]:
    """Get all available detector configurations.
    
    Returns:
        Dictionary mapping detector names to their configurations
    """
    config_loader = get_config_loader()
    
    detector_configs = {}
    
    # Memory-related detectors now use hardcoded configurations
    memory_detectors = ['uaf', 'npd', 'memory_leak', 'double_free', 'buffer_overflow', 'format_string', 'integer_overflow']
    for detector in memory_detectors:
        detector_configs[detector] = {}
    
    # C/C++ specific taint
    try:
        c_taint_config = config_loader.get_c_taint_config()
        detector_configs['c_taint'] = c_taint_config
        detector_configs['taint'] = c_taint_config  # Fallback for generic taint
    except FileNotFoundError:
        detector_configs['c_taint'] = {}
        detector_configs['taint'] = {}
    
    # Python specific taint
    try:
        python_taint_config = config_loader.get_python_taint_config()
        detector_configs['python_taint'] = python_taint_config
    except FileNotFoundError:
        detector_configs['python_taint'] = {}
    
    return detector_configs
