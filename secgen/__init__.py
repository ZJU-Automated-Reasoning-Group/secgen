"""SecGen-New: Ultra-concise vulnerability report generator."""

__version__ = "1.0.0"
__author__ = "SecGen Team"

from .main import SecGen
from .utils import Vulnerability

__all__ = ['SecGen', 'Vulnerability']
