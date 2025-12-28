"""Core components for honeypot detection."""

from .base import BaseDetector, register_detector
from .result import DetectionResult, Indicator, Confidence
from .registry import DetectorRegistry

__all__ = [
    "BaseDetector",
    "register_detector",
    "DetectionResult",
    "Indicator",
    "Confidence",
    "DetectorRegistry",
]
