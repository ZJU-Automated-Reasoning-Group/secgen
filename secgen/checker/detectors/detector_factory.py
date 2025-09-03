"""Factory for creating and managing vulnerability detectors."""

from typing import Dict, List, Optional, Any, Type
from secgen.core.models import VulnerabilityType

from .base_detector import BaseVulnerabilityDetector
from .uaf_detector import UAFDetector
from .npd_detector import NPDDetector
from .buffer_overflow_detector import BufferOverflowDetector
from .memory_leak_detector import MemoryLeakDetector
from .double_free_detector import DoubleFreeDetector
from .format_string_detector import FormatStringDetector
from .integer_overflow_detector import IntegerOverflowDetector
from .taint_detector import TaintDetector


class DetectorFactory:
    """Factory for creating and managing vulnerability detectors."""
    
    # Registry of available detectors
    _detector_registry: Dict[VulnerabilityType, Type[BaseVulnerabilityDetector]] = {
        VulnerabilityType.USE_AFTER_FREE: UAFDetector,
        VulnerabilityType.NULL_POINTER_DEREF: NPDDetector,
        VulnerabilityType.BUFFER_OVERFLOW: BufferOverflowDetector,
        VulnerabilityType.MEMORY_LEAK: MemoryLeakDetector,
        VulnerabilityType.COMMAND_INJECTION: TaintDetector,  # Can be taint-based
        VulnerabilityType.SQL_INJECTION: TaintDetector,      # Can be taint-based
        VulnerabilityType.XSS: TaintDetector,                # Can be taint-based
        VulnerabilityType.PATH_TRAVERSAL: TaintDetector,     # Can be taint-based
        VulnerabilityType.INTEGER_OVERFLOW: IntegerOverflowDetector,
    }
    
    # Special detectors for specific patterns
    _special_detectors = {
        'double_free': DoubleFreeDetector,
        'format_string': FormatStringDetector,
    }
    
    @classmethod
    def create_detector(cls, 
                       vuln_type: VulnerabilityType, 
                       config: Optional[Dict[str, Any]] = None,
                       logger=None) -> BaseVulnerabilityDetector:
        """Create a detector for the specified vulnerability type.
        
        Args:
            vuln_type: Type of vulnerability to detect
            config: Configuration dictionary for the detector
            logger: Logger instance
            
        Returns:
            Configured detector instance
            
        Raises:
            ValueError: If no detector is available for the vulnerability type
        """
        detector_class = cls._detector_registry.get(vuln_type)
        if not detector_class:
            raise ValueError(f"No detector available for vulnerability type: {vuln_type}")
        
        return detector_class(config, logger)
    
    @classmethod
    def create_special_detector(cls,
                               detector_name: str,
                               config: Optional[Dict[str, Any]] = None,
                               logger=None) -> BaseVulnerabilityDetector:
        """Create a special detector by name.
        
        Args:
            detector_name: Name of the special detector
            config: Configuration dictionary for the detector
            logger: Logger instance
            
        Returns:
            Configured detector instance
            
        Raises:
            ValueError: If no special detector is available with the given name
        """
        detector_class = cls._special_detectors.get(detector_name)
        if not detector_class:
            raise ValueError(f"No special detector available with name: {detector_name}")
        
        return detector_class(config, logger)
    
    @classmethod
    def create_all_detectors(cls,
                           config: Optional[Dict[str, Any]] = None,
                           logger=None,
                           enabled_types: Optional[List[VulnerabilityType]] = None) -> List[BaseVulnerabilityDetector]:
        """Create all available detectors.
        
        Args:
            config: Configuration dictionary for all detectors
            logger: Logger instance
            enabled_types: List of vulnerability types to enable (None for all)
            
        Returns:
            List of configured detector instances
        """
        detectors = []
        
        # Create main detectors
        for vuln_type, detector_class in cls._detector_registry.items():
            if enabled_types is None or vuln_type in enabled_types:
                try:
                    detector = detector_class(config, logger)
                    detectors.append(detector)
                except Exception as e:
                    if logger:
                        logger.log(f"Failed to create detector for {vuln_type}: {e}", level="WARNING")
        
        # Create special detectors
        for detector_name, detector_class in cls._special_detectors.items():
            try:
                detector = detector_class(config, logger)
                detectors.append(detector)
            except Exception as e:
                if logger:
                    logger.log(f"Failed to create special detector {detector_name}: {e}", level="WARNING")
        
        return detectors
    
    @classmethod
    def create_detectors_for_file_type(cls,
                                     file_path: str,
                                     config: Optional[Dict[str, Any]] = None,
                                     logger=None) -> List[BaseVulnerabilityDetector]:
        """Create detectors that support the given file type.
        
        Args:
            file_path: Path to the file to analyze
            config: Configuration dictionary for detectors
            logger: Logger instance
            
        Returns:
            List of detectors that support the file type
        """
        detectors = []
        
        # Create all detectors and filter by file type support
        all_detectors = cls.create_all_detectors(config, logger)
        
        for detector in all_detectors:
            if detector.supports_file_type(file_path):
                detectors.append(detector)
        
        return detectors
    
    @classmethod
    def register_detector(cls,
                         vuln_type: VulnerabilityType,
                         detector_class: Type[BaseVulnerabilityDetector]) -> None:
        """Register a new detector for a vulnerability type.
        
        Args:
            vuln_type: Vulnerability type to register for
            detector_class: Detector class to register
        """
        cls._detector_registry[vuln_type] = detector_class
    
    @classmethod
    def register_special_detector(cls,
                                 detector_name: str,
                                 detector_class: Type[BaseVulnerabilityDetector]) -> None:
        """Register a new special detector.
        
        Args:
            detector_name: Name of the special detector
            detector_class: Detector class to register
        """
        cls._special_detectors[detector_name] = detector_class
    
    @classmethod
    def get_available_detectors(cls) -> Dict[str, List[str]]:
        """Get information about available detectors.
        
        Returns:
            Dictionary with detector information
        """
        return {
            'vulnerability_types': [vuln_type.value for vuln_type in cls._detector_registry.keys()],
            'special_detectors': list(cls._special_detectors.keys())
        }
    
    @classmethod
    def create_detector_suite(cls,
                            file_path: str,
                            config: Optional[Dict[str, Any]] = None,
                            logger=None,
                            memory_analysis: bool = True,
                            taint_analysis: bool = True,
                            buffer_analysis: bool = True) -> List[BaseVulnerabilityDetector]:
        """Create a comprehensive detector suite for a file.
        
        Args:
            file_path: Path to the file to analyze
            config: Configuration dictionary
            logger: Logger instance
            memory_analysis: Enable memory-related detectors
            taint_analysis: Enable taint analysis detectors
            buffer_analysis: Enable buffer overflow detectors
            
        Returns:
            List of configured detectors
        """
        detectors = []
        
        # Memory-related detectors
        if memory_analysis:
            if file_path.endswith(('.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx')):
                detectors.append(UAFDetector(config, logger))
                detectors.append(NPDDetector(config, logger))
                detectors.append(MemoryLeakDetector(config, logger))
                detectors.append(DoubleFreeDetector(config, logger))
        
        # Buffer overflow detectors
        if buffer_analysis:
            if file_path.endswith(('.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx')):
                detectors.append(BufferOverflowDetector(config, logger))
                detectors.append(FormatStringDetector(config, logger))
                detectors.append(IntegerOverflowDetector(config, logger))
        
        # Taint analysis detectors
        if taint_analysis:
            detectors.append(TaintDetector(config, logger))
        
        return detectors
