"""Unit tests for potsnitch.core.base module."""

import pytest
from unittest.mock import MagicMock, patch

from potsnitch.core.base import (
    BaseDetector,
    DetectionMode,
    register_detector,
    get_detector,
    get_all_detectors,
    _detector_registry,
)
from potsnitch.core.result import DetectionResult, Indicator, Confidence


class TestDetectionMode:
    """Tests for DetectionMode enum."""

    def test_detection_modes_exist(self):
        """Test that all detection modes are defined."""
        assert DetectionMode.PASSIVE.value == "passive"
        assert DetectionMode.ACTIVE.value == "active"
        assert DetectionMode.FULL.value == "full"

    def test_detection_mode_count(self):
        """Test that exactly three modes exist."""
        modes = list(DetectionMode)
        assert len(modes) == 3


class TestBaseDetector:
    """Tests for BaseDetector class."""

    def test_default_initialization(self):
        """Test detector initializes with default values."""
        detector = BaseDetector()
        assert detector.timeout == 5.0
        assert detector.verbose is False
        assert detector.mode == DetectionMode.FULL

    def test_custom_initialization(self):
        """Test detector initializes with custom values."""
        detector = BaseDetector(
            timeout=10.0,
            verbose=True,
            mode=DetectionMode.PASSIVE,
        )
        assert detector.timeout == 10.0
        assert detector.verbose is True
        assert detector.mode == DetectionMode.PASSIVE

    def test_class_attributes(self):
        """Test default class attributes."""
        assert BaseDetector.name == "base"
        assert BaseDetector.description == "Base detector"
        assert BaseDetector.honeypot_types == []
        assert BaseDetector.default_ports == []

    def test_detect_passive_returns_empty_result(self):
        """Test default detect_passive returns empty result."""
        detector = BaseDetector()
        result = detector.detect_passive("127.0.0.1", 22)
        assert isinstance(result, DetectionResult)
        assert result.target == "127.0.0.1"
        assert result.port == 22
        assert result.indicators == []

    def test_detect_active_returns_empty_result(self):
        """Test default detect_active returns empty result."""
        detector = BaseDetector()
        result = detector.detect_active("127.0.0.1", 22)
        assert isinstance(result, DetectionResult)
        assert result.target == "127.0.0.1"
        assert result.port == 22
        assert result.indicators == []

    def test_detect_in_passive_mode(self):
        """Test detect calls only passive detection in PASSIVE mode."""
        detector = BaseDetector(mode=DetectionMode.PASSIVE)
        detector.detect_passive = MagicMock(
            return_value=DetectionResult(target="test", port=22)
        )
        detector.detect_active = MagicMock(
            return_value=DetectionResult(target="test", port=22)
        )

        detector.detect("test", 22)

        detector.detect_passive.assert_called_once_with("test", 22)
        detector.detect_active.assert_not_called()

    def test_detect_in_active_mode(self):
        """Test detect calls only active detection in ACTIVE mode."""
        detector = BaseDetector(mode=DetectionMode.ACTIVE)
        detector.detect_passive = MagicMock(
            return_value=DetectionResult(target="test", port=22)
        )
        detector.detect_active = MagicMock(
            return_value=DetectionResult(target="test", port=22)
        )

        detector.detect("test", 22)

        detector.detect_passive.assert_not_called()
        detector.detect_active.assert_called_once_with("test", 22)

    def test_detect_in_full_mode(self):
        """Test detect calls both passive and active in FULL mode."""
        detector = BaseDetector(mode=DetectionMode.FULL)
        detector.detect_passive = MagicMock(
            return_value=DetectionResult(target="test", port=22)
        )
        detector.detect_active = MagicMock(
            return_value=DetectionResult(target="test", port=22)
        )

        detector.detect("test", 22)

        detector.detect_passive.assert_called_once_with("test", 22)
        detector.detect_active.assert_called_once_with("test", 22)

    def test_detect_combines_indicators(self):
        """Test detect combines indicators from passive and active."""
        detector = BaseDetector(mode=DetectionMode.FULL)

        passive_result = DetectionResult(target="test", port=22)
        passive_result.indicators = [
            Indicator(name="passive", description="Passive indicator", severity=Confidence.LOW)
        ]

        active_result = DetectionResult(target="test", port=22)
        active_result.indicators = [
            Indicator(name="active", description="Active indicator", severity=Confidence.HIGH)
        ]

        detector.detect_passive = MagicMock(return_value=passive_result)
        detector.detect_active = MagicMock(return_value=active_result)

        result = detector.detect("test", 22)

        assert len(result.indicators) == 2
        names = [i.name for i in result.indicators]
        assert "passive" in names
        assert "active" in names

    def test_detect_uses_first_honeypot_type(self):
        """Test detect uses honeypot_type from passive if set."""
        detector = BaseDetector(mode=DetectionMode.FULL)

        passive_result = DetectionResult(target="test", port=22, honeypot_type="cowrie")
        active_result = DetectionResult(target="test", port=22, honeypot_type="kippo")

        detector.detect_passive = MagicMock(return_value=passive_result)
        detector.detect_active = MagicMock(return_value=active_result)

        result = detector.detect("test", 22)
        assert result.honeypot_type == "cowrie"

    def test_detect_falls_back_to_active_honeypot_type(self):
        """Test detect uses honeypot_type from active if passive is None."""
        detector = BaseDetector(mode=DetectionMode.FULL)

        passive_result = DetectionResult(target="test", port=22)
        active_result = DetectionResult(target="test", port=22, honeypot_type="kippo")

        detector.detect_passive = MagicMock(return_value=passive_result)
        detector.detect_active = MagicMock(return_value=active_result)

        result = detector.detect("test", 22)
        assert result.honeypot_type == "kippo"

    def test_validate_calls_detect(self):
        """Test validate method calls detect by default."""
        detector = BaseDetector()
        detector.detect = MagicMock(
            return_value=DetectionResult(target="test", port=22)
        )

        detector.validate("test", 22)

        detector.detect.assert_called_once_with("test", 22)

    def test_get_recommendations_returns_empty_list(self):
        """Test default get_recommendations returns empty list."""
        detector = BaseDetector()
        result = DetectionResult(target="test", port=22)
        recommendations = detector.get_recommendations(result)
        assert recommendations == []

    def test_get_info_class_method(self):
        """Test get_info returns detector information."""
        info = BaseDetector.get_info()
        assert info == {
            "name": "base",
            "description": "Base detector",
            "honeypot_types": [],
            "default_ports": [],
        }


class TestCustomDetector:
    """Tests for custom detector subclasses."""

    def test_subclass_with_custom_attributes(self):
        """Test subclass can override class attributes."""

        class CustomDetector(BaseDetector):
            name = "custom"
            description = "Custom detector"
            honeypot_types = ["custom-pot"]
            default_ports = [8080, 9090]

        detector = CustomDetector()
        info = detector.get_info()

        assert info["name"] == "custom"
        assert info["description"] == "Custom detector"
        assert info["honeypot_types"] == ["custom-pot"]
        assert info["default_ports"] == [8080, 9090]

    def test_subclass_can_override_detect_passive(self):
        """Test subclass can override detect_passive."""

        class CustomDetector(BaseDetector):
            def detect_passive(self, target, port):
                result = DetectionResult(target=target, port=port)
                result.add_indicator(
                    Indicator(
                        name="custom_passive",
                        description="Custom passive check",
                        severity=Confidence.MEDIUM,
                    )
                )
                return result

        detector = CustomDetector(mode=DetectionMode.PASSIVE)
        result = detector.detect("test", 22)

        assert len(result.indicators) == 1
        assert result.indicators[0].name == "custom_passive"

    def test_subclass_can_override_detect_active(self):
        """Test subclass can override detect_active."""

        class CustomDetector(BaseDetector):
            def detect_active(self, target, port):
                result = DetectionResult(target=target, port=port)
                result.add_indicator(
                    Indicator(
                        name="custom_active",
                        description="Custom active check",
                        severity=Confidence.HIGH,
                    )
                )
                return result

        detector = CustomDetector(mode=DetectionMode.ACTIVE)
        result = detector.detect("test", 22)

        assert len(result.indicators) == 1
        assert result.indicators[0].name == "custom_active"
