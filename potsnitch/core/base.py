"""Base detector class and registration decorator."""

from abc import ABC
from enum import Enum
from typing import Optional

from .result import DetectionResult


class DetectionMode(Enum):
    """Detection mode for controlling probe aggressiveness.

    PASSIVE: Static signatures only (banners, headers, certificates).
             No commands sent, minimal interaction. Stealthier.
    ACTIVE:  Dynamic probing (send commands, analyze responses).
             More accurate but detectable by honeypot operators.
    FULL:    Both passive and active detection combined.
    """
    PASSIVE = "passive"
    ACTIVE = "active"
    FULL = "full"


class BaseDetector(ABC):
    """Abstract base class for honeypot detectors."""

    # Detector metadata - override in subclasses
    name: str = "base"
    description: str = "Base detector"
    honeypot_types: list[str] = []  # Types this detector can identify
    default_ports: list[int] = []  # Default ports to scan

    def __init__(
        self,
        timeout: float = 5.0,
        verbose: bool = False,
        mode: DetectionMode = DetectionMode.FULL,
    ):
        """Initialize detector.

        Args:
            timeout: Connection timeout in seconds
            verbose: Enable verbose output
            mode: Detection mode (PASSIVE, ACTIVE, or FULL)
        """
        self.timeout = timeout
        self.verbose = verbose
        self.mode = mode

    def detect(self, target: str, port: int) -> DetectionResult:
        """Run detection against target based on configured mode.

        Args:
            target: IP address or hostname
            port: Port number to probe

        Returns:
            DetectionResult with findings
        """
        result = DetectionResult(target=target, port=port)

        if self.mode in (DetectionMode.PASSIVE, DetectionMode.FULL):
            passive_result = self.detect_passive(target, port)
            for indicator in passive_result.indicators:
                result.add_indicator(indicator)
            if passive_result.honeypot_type:
                result.honeypot_type = passive_result.honeypot_type

        if self.mode in (DetectionMode.ACTIVE, DetectionMode.FULL):
            active_result = self.detect_active(target, port)
            for indicator in active_result.indicators:
                result.add_indicator(indicator)
            if active_result.honeypot_type and not result.honeypot_type:
                result.honeypot_type = active_result.honeypot_type

        return result

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive/static detection only.

        Static signatures include:
        - Banners received on connection
        - HTTP headers and certificates
        - Default ports and port combinations
        - TLS/SSL fingerprints (JA3S)
        - HASSH fingerprints

        Override in subclasses. Default returns empty result.

        Args:
            target: IP address or hostname
            port: Port number

        Returns:
            DetectionResult with passive findings
        """
        return DetectionResult(target=target, port=port)

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active/dynamic probing.

        Dynamic probes include:
        - Sending specific commands and analyzing responses
        - Protocol-specific queries (e.g., INFO for Redis)
        - Error message analysis from invalid inputs
        - Timing-based detection
        - Behavioral fingerprinting

        Override in subclasses. Default returns empty result.

        Args:
            target: IP address or hostname
            port: Port number

        Returns:
            DetectionResult with active findings
        """
        return DetectionResult(target=target, port=port)

    def validate(self, target: str, port: int) -> DetectionResult:
        """Run all validation tests for defensive checking.

        This runs more comprehensive tests than detect() and provides
        remediation recommendations. Override in subclasses for
        honeypot-specific validation.

        Args:
            target: IP address or hostname
            port: Port number to probe

        Returns:
            DetectionResult with detailed validation findings
        """
        return self.detect(target, port)

    def get_recommendations(self, result: DetectionResult) -> list[str]:
        """Get remediation recommendations based on detection result.

        Override in subclasses to provide specific recommendations.

        Args:
            result: Detection result to analyze

        Returns:
            List of recommendation strings
        """
        return []

    @classmethod
    def get_info(cls) -> dict:
        """Get detector information."""
        return {
            "name": cls.name,
            "description": cls.description,
            "honeypot_types": cls.honeypot_types,
            "default_ports": cls.default_ports,
        }


# Registry for detectors
_detector_registry: dict[str, type[BaseDetector]] = {}


def register_detector(cls: type[BaseDetector]) -> type[BaseDetector]:
    """Decorator to register a detector class.

    Usage:
        @register_detector
        class MyDetector(BaseDetector):
            name = "my_detector"
            ...
    """
    if not issubclass(cls, BaseDetector):
        raise TypeError(f"{cls.__name__} must inherit from BaseDetector")

    _detector_registry[cls.name] = cls
    return cls


def get_detector(name: str) -> Optional[type[BaseDetector]]:
    """Get a detector class by name."""
    return _detector_registry.get(name)


def get_all_detectors() -> dict[str, type[BaseDetector]]:
    """Get all registered detectors."""
    return _detector_registry.copy()
