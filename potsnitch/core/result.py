"""Detection result models."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Confidence(Enum):
    """Confidence level for honeypot detection."""

    LOW = "low"  # Single weak indicator
    MEDIUM = "medium"  # Multiple weak indicators or one strong
    HIGH = "high"  # Multiple strong indicators
    DEFINITE = "definite"  # Conclusive proof (e.g., default signatures)

    @property
    def score(self) -> float:
        """Numeric score for confidence level."""
        return {
            Confidence.LOW: 0.25,
            Confidence.MEDIUM: 0.50,
            Confidence.HIGH: 0.75,
            Confidence.DEFINITE: 0.95,
        }[self]


@dataclass
class Indicator:
    """Single detection indicator."""

    name: str
    description: str
    severity: Confidence
    details: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "details": self.details,
        }


@dataclass
class DetectionResult:
    """Result of honeypot detection scan."""

    target: str
    port: int
    honeypot_type: Optional[str] = None
    is_honeypot: bool = False
    confidence: Confidence = Confidence.LOW
    indicators: list[Indicator] = field(default_factory=list)
    scan_time: datetime = field(default_factory=datetime.utcnow)
    error: Optional[str] = None

    def add_indicator(self, indicator: Indicator) -> None:
        """Add an indicator and update confidence."""
        self.indicators.append(indicator)
        self._update_confidence()

    def _update_confidence(self) -> None:
        """Update overall confidence based on indicators."""
        if not self.indicators:
            self.confidence = Confidence.LOW
            return

        # Check for definite indicators
        if any(i.severity == Confidence.DEFINITE for i in self.indicators):
            self.confidence = Confidence.DEFINITE
            self.is_honeypot = True
            return

        # Count high severity indicators
        high_count = sum(1 for i in self.indicators if i.severity == Confidence.HIGH)
        medium_count = sum(1 for i in self.indicators if i.severity == Confidence.MEDIUM)

        if high_count >= 2 or (high_count >= 1 and medium_count >= 2):
            self.confidence = Confidence.HIGH
            self.is_honeypot = True
        elif high_count >= 1 or medium_count >= 2:
            self.confidence = Confidence.MEDIUM
            self.is_honeypot = True
        elif medium_count >= 1 or len(self.indicators) >= 2:
            self.confidence = Confidence.LOW
            self.is_honeypot = True

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON output."""
        return {
            "target": self.target,
            "port": self.port,
            "honeypot_type": self.honeypot_type,
            "is_honeypot": self.is_honeypot,
            "confidence": self.confidence.value,
            "confidence_score": self.confidence.score,
            "indicators": [i.to_dict() for i in self.indicators],
            "scan_time": self.scan_time.isoformat(),
            "error": self.error,
        }


@dataclass
class ScanReport:
    """Complete scan report for a target."""

    target: str
    scan_time: datetime = field(default_factory=datetime.utcnow)
    detections: list[DetectionResult] = field(default_factory=list)

    @property
    def has_honeypot(self) -> bool:
        """Check if any honeypot was detected."""
        return any(d.is_honeypot for d in self.detections)

    @property
    def highest_confidence(self) -> Optional[Confidence]:
        """Get highest confidence detection."""
        honeypots = [d for d in self.detections if d.is_honeypot]
        if not honeypots:
            return None
        return max(honeypots, key=lambda d: d.confidence.score).confidence

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON output."""
        return {
            "target": self.target,
            "scan_time": self.scan_time.isoformat(),
            "has_honeypot": self.has_honeypot,
            "highest_confidence": self.highest_confidence.value if self.highest_confidence else None,
            "detections": [d.to_dict() for d in self.detections],
        }
