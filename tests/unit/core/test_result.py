"""Unit tests for potsnitch.core.result module."""

import pytest
from datetime import datetime

from potsnitch.core.result import (
    Confidence,
    Indicator,
    DetectionResult,
    ScanReport,
)


class TestConfidence:
    """Tests for Confidence enum."""

    @pytest.mark.parametrize(
        "confidence,expected_score",
        [
            (Confidence.DEFINITE, 0.95),
            (Confidence.HIGH, 0.75),
            (Confidence.MEDIUM, 0.50),
            (Confidence.LOW, 0.25),
        ],
    )
    def test_confidence_scores(self, confidence, expected_score):
        """Test that confidence levels have correct numeric scores."""
        assert confidence.score == expected_score

    @pytest.mark.parametrize(
        "confidence,expected_value",
        [
            (Confidence.DEFINITE, "definite"),
            (Confidence.HIGH, "high"),
            (Confidence.MEDIUM, "medium"),
            (Confidence.LOW, "low"),
        ],
    )
    def test_confidence_values(self, confidence, expected_value):
        """Test that confidence levels have correct string values."""
        assert confidence.value == expected_value

    def test_all_confidence_levels_exist(self):
        """Test that all expected confidence levels are defined."""
        levels = [c for c in Confidence]
        assert len(levels) == 4
        assert Confidence.LOW in levels
        assert Confidence.MEDIUM in levels
        assert Confidence.HIGH in levels
        assert Confidence.DEFINITE in levels


class TestIndicator:
    """Tests for Indicator dataclass."""

    def test_indicator_creation(self):
        """Test basic indicator creation."""
        indicator = Indicator(
            name="test_indicator",
            description="A test indicator",
            severity=Confidence.HIGH,
        )
        assert indicator.name == "test_indicator"
        assert indicator.description == "A test indicator"
        assert indicator.severity == Confidence.HIGH
        assert indicator.details is None

    def test_indicator_with_details(self):
        """Test indicator creation with optional details."""
        indicator = Indicator(
            name="detailed_indicator",
            description="An indicator with details",
            severity=Confidence.MEDIUM,
            details="Extra information here",
        )
        assert indicator.details == "Extra information here"

    def test_indicator_to_dict(self):
        """Test indicator serialization to dictionary."""
        indicator = Indicator(
            name="serializable",
            description="Can be serialized",
            severity=Confidence.LOW,
            details="Some details",
        )
        result = indicator.to_dict()
        assert result == {
            "name": "serializable",
            "description": "Can be serialized",
            "severity": "low",
            "details": "Some details",
        }

    def test_indicator_to_dict_without_details(self):
        """Test indicator serialization when details is None."""
        indicator = Indicator(
            name="no_details",
            description="No details provided",
            severity=Confidence.HIGH,
        )
        result = indicator.to_dict()
        assert result["details"] is None


class TestDetectionResult:
    """Tests for DetectionResult dataclass."""

    def test_detection_result_creation(self):
        """Test basic detection result creation."""
        result = DetectionResult(target="192.168.1.1", port=22)
        assert result.target == "192.168.1.1"
        assert result.port == 22
        assert result.honeypot_type is None
        assert result.is_honeypot is False
        assert result.confidence == Confidence.LOW
        assert result.indicators == []
        assert result.error is None

    def test_detection_result_with_all_fields(self):
        """Test detection result with all fields populated."""
        scan_time = datetime(2024, 1, 1, 12, 0, 0)
        result = DetectionResult(
            target="10.0.0.1",
            port=6379,
            honeypot_type="redis-honeypot",
            is_honeypot=True,
            confidence=Confidence.HIGH,
            scan_time=scan_time,
            error=None,
        )
        assert result.honeypot_type == "redis-honeypot"
        assert result.is_honeypot is True
        assert result.confidence == Confidence.HIGH
        assert result.scan_time == scan_time

    def test_add_indicator_updates_confidence(self):
        """Test that adding indicators updates confidence level."""
        result = DetectionResult(target="test", port=80)
        indicator = Indicator(
            name="test",
            description="Test indicator",
            severity=Confidence.MEDIUM,
        )
        result.add_indicator(indicator)
        assert len(result.indicators) == 1
        assert result.is_honeypot is True
        assert result.confidence == Confidence.LOW

    def test_definite_indicator_sets_definite_confidence(self):
        """Test that a DEFINITE severity indicator sets DEFINITE confidence."""
        result = DetectionResult(target="test", port=80)
        indicator = Indicator(
            name="definite_proof",
            description="Conclusive evidence",
            severity=Confidence.DEFINITE,
        )
        result.add_indicator(indicator)
        assert result.confidence == Confidence.DEFINITE
        assert result.is_honeypot is True

    def test_two_high_indicators_set_high_confidence(self):
        """Test that two HIGH indicators set HIGH confidence."""
        result = DetectionResult(target="test", port=80)
        for i in range(2):
            result.add_indicator(
                Indicator(
                    name=f"high_{i}",
                    description="High severity",
                    severity=Confidence.HIGH,
                )
            )
        assert result.confidence == Confidence.HIGH
        assert result.is_honeypot is True

    def test_one_high_two_medium_set_high_confidence(self):
        """Test that one HIGH + two MEDIUM indicators set HIGH confidence."""
        result = DetectionResult(target="test", port=80)
        result.add_indicator(
            Indicator(name="high", description="High", severity=Confidence.HIGH)
        )
        for i in range(2):
            result.add_indicator(
                Indicator(name=f"med_{i}", description="Medium", severity=Confidence.MEDIUM)
            )
        assert result.confidence == Confidence.HIGH

    def test_two_medium_indicators_set_medium_confidence(self):
        """Test that two MEDIUM indicators set MEDIUM confidence."""
        result = DetectionResult(target="test", port=80)
        for i in range(2):
            result.add_indicator(
                Indicator(name=f"med_{i}", description="Med", severity=Confidence.MEDIUM)
            )
        assert result.confidence == Confidence.MEDIUM
        assert result.is_honeypot is True

    def test_empty_indicators_keeps_low_confidence(self):
        """Test that empty indicators maintain LOW confidence."""
        result = DetectionResult(target="test", port=80)
        result._update_confidence()
        assert result.confidence == Confidence.LOW
        assert result.is_honeypot is False

    def test_detection_result_to_dict(self):
        """Test detection result serialization."""
        result = DetectionResult(target="test.com", port=443)
        result.add_indicator(
            Indicator(name="test", description="Test", severity=Confidence.MEDIUM)
        )
        data = result.to_dict()
        assert data["target"] == "test.com"
        assert data["port"] == 443
        assert data["is_honeypot"] is True
        assert data["confidence"] == "low"
        assert data["confidence_score"] == 0.25
        assert len(data["indicators"]) == 1
        assert "scan_time" in data

    def test_detection_result_with_error(self):
        """Test detection result with error message."""
        result = DetectionResult(target="test", port=80, error="Connection refused")
        assert result.error == "Connection refused"
        data = result.to_dict()
        assert data["error"] == "Connection refused"


class TestScanReport:
    """Tests for ScanReport dataclass."""

    def test_scan_report_creation(self):
        """Test basic scan report creation."""
        report = ScanReport(target="192.168.1.0/24")
        assert report.target == "192.168.1.0/24"
        assert report.detections == []
        assert report.has_honeypot is False

    def test_has_honeypot_property(self):
        """Test has_honeypot returns True when honeypots detected."""
        report = ScanReport(target="test")
        detection = DetectionResult(target="test", port=22, is_honeypot=True)
        report.detections.append(detection)
        assert report.has_honeypot is True

    def test_highest_confidence_with_no_honeypots(self):
        """Test highest_confidence returns None when no honeypots."""
        report = ScanReport(target="test")
        report.detections.append(DetectionResult(target="test", port=22))
        assert report.highest_confidence is None

    def test_highest_confidence_returns_max(self):
        """Test highest_confidence returns the maximum confidence."""
        report = ScanReport(target="test")
        report.detections.append(
            DetectionResult(
                target="test", port=22, is_honeypot=True, confidence=Confidence.LOW
            )
        )
        report.detections.append(
            DetectionResult(
                target="test", port=80, is_honeypot=True, confidence=Confidence.HIGH
            )
        )
        assert report.highest_confidence == Confidence.HIGH

    def test_scan_report_to_dict(self):
        """Test scan report serialization."""
        report = ScanReport(target="test.com")
        report.detections.append(
            DetectionResult(
                target="test.com", port=22, is_honeypot=True, confidence=Confidence.MEDIUM
            )
        )
        data = report.to_dict()
        assert data["target"] == "test.com"
        assert data["has_honeypot"] is True
        assert data["highest_confidence"] == "medium"
        assert len(data["detections"]) == 1
