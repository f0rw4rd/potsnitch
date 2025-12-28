"""Unit tests for potsnitch.core.registry module."""

import pytest
from unittest.mock import patch, MagicMock

from potsnitch.core.base import (
    BaseDetector,
    register_detector,
    get_detector,
    get_all_detectors,
    _detector_registry,
)
from potsnitch.core.registry import DetectorRegistry


class TestRegisterDetector:
    """Tests for the register_detector decorator."""

    def setup_method(self):
        """Clear registry before each test."""
        _detector_registry.clear()

    def teardown_method(self):
        """Clear registry after each test."""
        _detector_registry.clear()

    def test_register_detector_adds_to_registry(self):
        """Test that register_detector adds class to registry."""

        @register_detector
        class TestDetector(BaseDetector):
            name = "test_detector"

        assert "test_detector" in _detector_registry
        assert _detector_registry["test_detector"] is TestDetector

    def test_register_detector_returns_class(self):
        """Test that register_detector returns the original class."""

        @register_detector
        class TestDetector(BaseDetector):
            name = "return_test"

        assert TestDetector.name == "return_test"

    def test_register_multiple_detectors(self):
        """Test registering multiple different detectors."""

        @register_detector
        class Detector1(BaseDetector):
            name = "detector1"

        @register_detector
        class Detector2(BaseDetector):
            name = "detector2"

        assert len(_detector_registry) == 2
        assert "detector1" in _detector_registry
        assert "detector2" in _detector_registry

    def test_register_detector_overwrites_duplicate(self):
        """Test that duplicate registration overwrites existing."""

        @register_detector
        class Detector1(BaseDetector):
            name = "duplicate"
            description = "First"

        @register_detector
        class Detector2(BaseDetector):
            name = "duplicate"
            description = "Second"

        assert len([k for k in _detector_registry if k == "duplicate"]) == 1
        assert _detector_registry["duplicate"].description == "Second"

    def test_register_non_subclass_raises_error(self):
        """Test that registering non-BaseDetector raises TypeError."""

        class NotADetector:
            name = "invalid"

        with pytest.raises(TypeError, match="must inherit from BaseDetector"):
            register_detector(NotADetector)


class TestGetDetector:
    """Tests for the get_detector function."""

    def setup_method(self):
        """Clear registry before each test."""
        _detector_registry.clear()

    def teardown_method(self):
        """Clear registry after each test."""
        _detector_registry.clear()

    def test_get_existing_detector(self):
        """Test getting an existing detector by name."""

        @register_detector
        class MyDetector(BaseDetector):
            name = "my_detector"

        result = get_detector("my_detector")
        assert result is MyDetector

    def test_get_nonexistent_detector_returns_none(self):
        """Test getting a nonexistent detector returns None."""
        result = get_detector("nonexistent")
        assert result is None

    def test_get_detector_after_multiple_registrations(self):
        """Test getting specific detector among multiple."""

        @register_detector
        class DetectorA(BaseDetector):
            name = "a"

        @register_detector
        class DetectorB(BaseDetector):
            name = "b"

        assert get_detector("a") is DetectorA
        assert get_detector("b") is DetectorB


class TestGetAllDetectors:
    """Tests for the get_all_detectors function."""

    def setup_method(self):
        """Clear registry before each test."""
        _detector_registry.clear()

    def teardown_method(self):
        """Clear registry after each test."""
        _detector_registry.clear()

    def test_get_all_detectors_empty(self):
        """Test get_all_detectors with empty registry."""
        result = get_all_detectors()
        assert result == {}

    def test_get_all_detectors_returns_copy(self):
        """Test get_all_detectors returns a copy of registry."""

        @register_detector
        class TestDetector(BaseDetector):
            name = "test"

        result = get_all_detectors()
        result["modified"] = None

        assert "modified" not in _detector_registry

    def test_get_all_detectors_contains_all(self):
        """Test get_all_detectors returns all registered detectors."""

        @register_detector
        class D1(BaseDetector):
            name = "d1"

        @register_detector
        class D2(BaseDetector):
            name = "d2"

        result = get_all_detectors()
        assert len(result) == 2
        assert "d1" in result
        assert "d2" in result


class TestDetectorRegistry:
    """Tests for DetectorRegistry class."""

    def setup_method(self):
        """Reset registry state before each test."""
        _detector_registry.clear()
        DetectorRegistry._loaded = False

    def teardown_method(self):
        """Reset registry state after each test."""
        _detector_registry.clear()
        DetectorRegistry._loaded = False

    def test_load_detectors_imports_modules(self):
        """Test load_detectors successfully loads detector modules."""
        # Reset to ensure fresh load
        DetectorRegistry._loaded = False

        # Call load_detectors - this should work since potsnitch.detectors exists
        DetectorRegistry.load_detectors()

        # After loading, _loaded should be True
        assert DetectorRegistry._loaded is True

    def test_load_detectors_only_loads_once(self):
        """Test load_detectors is idempotent."""
        DetectorRegistry._loaded = True

        with patch("potsnitch.core.registry.importlib") as mock_import:
            DetectorRegistry.load_detectors()
            mock_import.import_module.assert_not_called()

    def test_get_detector_calls_load(self):
        """Test get_detector triggers load_detectors."""
        DetectorRegistry.load_detectors = MagicMock()
        DetectorRegistry.get_detector("test")
        DetectorRegistry.load_detectors.assert_called_once()

    def test_get_all_detectors_calls_load(self):
        """Test get_all_detectors triggers load_detectors."""
        DetectorRegistry.load_detectors = MagicMock()
        DetectorRegistry.get_all_detectors()
        DetectorRegistry.load_detectors.assert_called_once()

    def test_get_detectors_for_port(self):
        """Test getting detectors by port number."""

        @register_detector
        class SSHDetector(BaseDetector):
            name = "ssh"
            default_ports = [22]

        @register_detector
        class HTTPDetector(BaseDetector):
            name = "http"
            default_ports = [80, 443]

        DetectorRegistry._loaded = True

        ssh_detectors = DetectorRegistry.get_detectors_for_port(22)
        http_detectors = DetectorRegistry.get_detectors_for_port(80)
        no_detectors = DetectorRegistry.get_detectors_for_port(9999)

        assert len(ssh_detectors) == 1
        assert ssh_detectors[0].name == "ssh"
        assert len(http_detectors) == 1
        assert http_detectors[0].name == "http"
        assert len(no_detectors) == 0

    def test_get_detectors_for_honeypot(self):
        """Test getting detectors by honeypot type."""

        @register_detector
        class CowrieDetector(BaseDetector):
            name = "cowrie"
            honeypot_types = ["cowrie", "kippo"]

        @register_detector
        class RedisDetector(BaseDetector):
            name = "redis"
            honeypot_types = ["redis-honeypot"]

        DetectorRegistry._loaded = True

        cowrie = DetectorRegistry.get_detectors_for_honeypot("cowrie")
        kippo = DetectorRegistry.get_detectors_for_honeypot("KIPPO")
        redis = DetectorRegistry.get_detectors_for_honeypot("redis-honeypot")
        none = DetectorRegistry.get_detectors_for_honeypot("unknown")

        assert len(cowrie) == 1
        assert len(kippo) == 1  # Case insensitive
        assert len(redis) == 1
        assert len(none) == 0

    def test_list_detectors(self):
        """Test list_detectors returns detector info."""

        @register_detector
        class TestDetector(BaseDetector):
            name = "list_test"
            description = "Test detector for listing"
            honeypot_types = ["test-pot"]
            default_ports = [1234]

        DetectorRegistry._loaded = True

        detectors = DetectorRegistry.list_detectors()

        assert len(detectors) == 1
        assert detectors[0]["name"] == "list_test"
        assert detectors[0]["description"] == "Test detector for listing"
        assert detectors[0]["honeypot_types"] == ["test-pot"]
        assert detectors[0]["default_ports"] == [1234]

    def test_list_detectors_multiple(self):
        """Test list_detectors with multiple detectors."""

        @register_detector
        class D1(BaseDetector):
            name = "d1"
            description = "First"

        @register_detector
        class D2(BaseDetector):
            name = "d2"
            description = "Second"

        DetectorRegistry._loaded = True

        detectors = DetectorRegistry.list_detectors()

        assert len(detectors) == 2
        names = [d["name"] for d in detectors]
        assert "d1" in names
        assert "d2" in names
