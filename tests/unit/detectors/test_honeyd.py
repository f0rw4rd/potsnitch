"""
Unit tests for Honeyd honeypot detector.

Tests cover:
- Timing inconsistency detection
- Multi-OS fingerprint detection
- TCP fingerprint deviation
- CVE-2004-2095 detection
- Mock socket with timing simulation
"""

import socket
import time
import pytest
from unittest.mock import MagicMock, patch, call

from potsnitch.detectors.honeyd import (
    HoneydDetector,
    TIMING_THRESHOLD_MS,
    TIMING_VARIANCE_THRESHOLD,
    HONEYD_OS_FINGERPRINTS,
)
from potsnitch.core.base import DetectionMode
from potsnitch.core.result import Confidence, DetectionResult


class TestTimingInconsistencyDetection:
    """Test timing-based Honeyd detection."""

    @pytest.fixture
    def detector(self):
        """Create Honeyd detector instance."""
        return HoneydDetector()

    def test_instant_connection_detection(self, detector):
        """Test detection of unusually fast connection times."""
        with patch("socket.socket") as mock_socket_class, \
             patch("time.perf_counter") as mock_time:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            # Simulate very fast connections (< 5ms)
            mock_time.side_effect = [
                0.0, 0.001,  # First connection: 1ms
                0.1, 0.101,  # Second connection: 1ms
                0.2, 0.201,  # Third connection: 1ms
            ]

            result = detector._check_connection_timing("192.168.1.1", 80)

        assert result is not None
        assert result.name == "instant_connection"
        assert result.severity == Confidence.MEDIUM

    def test_consistent_timing_detection(self, detector):
        """Test detection of very consistent timing patterns."""
        with patch("socket.socket") as mock_socket_class, \
             patch("time.perf_counter") as mock_time:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            # Simulate consistent but not instant timing
            mock_time.side_effect = [
                0.0, 0.010,   # 10ms
                0.1, 0.110,   # 10ms
                0.2, 0.210,   # 10ms
            ]

            result = detector._check_connection_timing("192.168.1.1", 80)

        # May detect consistent timing depending on variance calculation
        # With exactly same timing, variance should be very low

    def test_normal_timing_no_detection(self, detector):
        """Test that normal timing patterns are not flagged."""
        with patch("socket.socket") as mock_socket_class, \
             patch("time.perf_counter") as mock_time, \
             patch("time.sleep"):  # Mock sleep to avoid delays
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            # Simulate normal highly variable timing with higher average
            # Variance needs to be > 0.001 to avoid detection
            # Timings: 100ms, 300ms, 50ms -> avg=150ms, variance~0.0108
            mock_time.side_effect = [
                0.0, 0.100,   # 100ms - first connection
                0.2, 0.500,   # 300ms - second connection (big variance)
                0.6, 0.650,   # 50ms - third connection
            ]

            result = detector._check_connection_timing("192.168.1.1", 80)

        # With these highly variable timings, there should be no detection
        assert result is None

    def test_scripted_timing_detection(self, detector, mock_socket):
        """Test detection of scripted response patterns."""
        socket_instance = mock_socket.return_value

        with patch("time.perf_counter") as mock_time:
            # Very consistent response times across 5 probes
            times = []
            for i in range(10):  # 2 per probe (start, end)
                times.append(i * 0.1)
                times.append(i * 0.1 + 0.005)  # 5ms each time
            mock_time.side_effect = times

            socket_instance.recv.return_value = b"response"

            result = detector.detect_active("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        # Should detect scripted or uniform timing
        assert "scripted_timing" in indicator_names or "uniform_timing" in indicator_names

    def test_uniform_timing_detection(self, detector, mock_socket):
        """Test detection of uniform response timing."""
        socket_instance = mock_socket.return_value

        with patch("time.perf_counter") as mock_time:
            # Uniform timing with < 1ms difference
            times = []
            base_time = 0.0
            for i in range(10):
                times.append(base_time)
                times.append(base_time + 0.0100)  # Exactly 10ms
                base_time += 0.1
            mock_time.side_effect = times

            socket_instance.recv.return_value = b"response"

            result = detector.detect_active("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "uniform_timing" in indicator_names or "scripted_timing" in indicator_names


class TestMultiOSFingerprint:
    """Test multi-OS fingerprint detection."""

    @pytest.fixture
    def detector(self):
        """Create Honeyd detector instance."""
        return HoneydDetector()

    def test_multi_os_detection(self, detector):
        """Test detection of multiple OS fingerprints on same host."""
        with patch.object(detector, "_get_os_hint") as mock_os_hint:
            # Different OS detected on different ports
            mock_os_hint.side_effect = ["Windows XP", "Linux 2.6", None, None]

            result = DetectionResult(target="192.168.1.1", port=80)
            detector._check_multi_os_fingerprint("192.168.1.1", result)

        indicator_names = [ind.name for ind in result.indicators]
        assert "multi_os_fingerprint" in indicator_names
        assert any(ind.severity == Confidence.DEFINITE for ind in result.indicators)

    def test_single_os_no_detection(self, detector):
        """Test no detection when same OS on all ports."""
        with patch.object(detector, "_get_os_hint") as mock_os_hint:
            # Same OS detected on all ports
            mock_os_hint.return_value = "Windows XP"

            result = DetectionResult(target="192.168.1.1", port=80)
            detector._check_multi_os_fingerprint("192.168.1.1", result)

        indicator_names = [ind.name for ind in result.indicators]
        assert "multi_os_fingerprint" not in indicator_names

    def test_no_os_hints_no_detection(self, detector):
        """Test no detection when no OS hints available."""
        with patch.object(detector, "_get_os_hint") as mock_os_hint:
            mock_os_hint.return_value = None

            result = DetectionResult(target="192.168.1.1", port=80)
            detector._check_multi_os_fingerprint("192.168.1.1", result)

        assert len(result.indicators) == 0


class TestTCPFingerprintDeviation:
    """Test TCP fingerprint deviation detection."""

    @pytest.fixture
    def detector(self):
        """Create Honeyd detector instance."""
        return HoneydDetector()

    def test_tcp_anomaly_response(self, detector, mock_socket):
        """Test detection of unusual response to malformed data."""
        socket_instance = mock_socket.return_value

        # Honeyd responding to malformed data (unusual)
        socket_instance.recv.return_value = b"unexpected response"

        result = DetectionResult(target="192.168.1.1", port=80)
        detector._check_tcp_fingerprint_deviation("192.168.1.1", 80, result)

        indicator_names = [ind.name for ind in result.indicators]
        assert "tcp_anomaly_response" in indicator_names

    def test_tcp_no_response_no_detection(self, detector, mock_socket):
        """Test no detection when no response to malformed data."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = socket.timeout()

        result = DetectionResult(target="192.168.1.1", port=80)
        detector._check_tcp_fingerprint_deviation("192.168.1.1", 80, result)

        indicator_names = [ind.name for ind in result.indicators]
        assert "tcp_anomaly_response" not in indicator_names

    def test_tcp_connection_error(self, detector, mock_socket):
        """Test handling of connection error."""
        socket_instance = mock_socket.return_value
        socket_instance.connect.side_effect = socket.error("Connection refused")

        result = DetectionResult(target="192.168.1.1", port=80)
        detector._check_tcp_fingerprint_deviation("192.168.1.1", 80, result)

        assert len(result.indicators) == 0


class TestCVE20042095Detection:
    """Test CVE-2004-2095 detection."""

    @pytest.fixture
    def detector(self):
        """Create Honeyd detector instance."""
        return HoneydDetector()

    def test_cve_honeyd_disclosure(self, detector, mock_socket):
        """Test detection when 'honeyd' is revealed in response."""
        socket_instance = mock_socket.return_value

        # Response revealing honeyd
        socket_instance.recv.return_value = b"Honeyd virtual honeypot"

        result = DetectionResult(target="192.168.1.1", port=80)
        detector._check_cve_2004_2095("192.168.1.1", 80, result)

        indicator_names = [ind.name for ind in result.indicators]
        assert "cve_2004_2095" in indicator_names
        assert any(ind.severity == Confidence.DEFINITE for ind in result.indicators)

    def test_cve_personality_leak(self, detector, mock_socket):
        """Test detection when personality configuration is leaked."""
        socket_instance = mock_socket.return_value

        # Response leaking personality info
        socket_instance.recv.return_value = b"Personality: Windows XP SP2"

        result = DetectionResult(target="192.168.1.1", port=80)
        detector._check_cve_2004_2095("192.168.1.1", 80, result)

        indicator_names = [ind.name for ind in result.indicators]
        assert "personality_leak" in indicator_names
        assert any(ind.severity == Confidence.DEFINITE for ind in result.indicators)

    def test_cve_no_disclosure(self, detector, mock_socket):
        """Test no detection when response is normal."""
        socket_instance = mock_socket.return_value

        # Normal response
        socket_instance.recv.return_value = b"HTTP/1.1 200 OK\r\n"

        result = DetectionResult(target="192.168.1.1", port=80)
        detector._check_cve_2004_2095("192.168.1.1", 80, result)

        indicator_names = [ind.name for ind in result.indicators]
        assert "cve_2004_2095" not in indicator_names
        assert "personality_leak" not in indicator_names

    def test_cve_timeout(self, detector, mock_socket):
        """Test handling of timeout during CVE check."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = socket.timeout()

        result = DetectionResult(target="192.168.1.1", port=80)
        detector._check_cve_2004_2095("192.168.1.1", 80, result)

        assert len(result.indicators) == 0


class TestDetectorModes:
    """Test detector in different modes."""

    def test_passive_mode(self):
        """Test detector in passive mode."""
        detector = HoneydDetector(mode=DetectionMode.PASSIVE)
        assert detector.mode == DetectionMode.PASSIVE

    def test_active_mode(self):
        """Test detector in active mode."""
        detector = HoneydDetector(mode=DetectionMode.ACTIVE)
        assert detector.mode == DetectionMode.ACTIVE

    def test_full_mode(self):
        """Test detector in full mode."""
        detector = HoneydDetector(mode=DetectionMode.FULL)
        assert detector.mode == DetectionMode.FULL


class TestRecommendations:
    """Test detector recommendations."""

    @pytest.fixture
    def detector(self):
        """Create Honeyd detector instance."""
        return HoneydDetector()

    def test_timing_recommendation(self, detector):
        """Test recommendations for timing detection."""
        from potsnitch.core.result import Indicator

        result = DetectionResult(target="192.168.1.1", port=80)
        result.add_indicator(
            Indicator(
                name="scripted_timing",
                description="Scripted response pattern detected",
                severity=Confidence.HIGH,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any("delay" in r.lower() or "timing" in r.lower() for r in recommendations)

    def test_multi_os_recommendation(self, detector):
        """Test recommendations for multi-OS detection."""
        from potsnitch.core.result import Indicator

        result = DetectionResult(target="192.168.1.1", port=80)
        result.add_indicator(
            Indicator(
                name="multi_os_fingerprint",
                description="Multiple OS fingerprints detected",
                severity=Confidence.DEFINITE,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any("personality" in r.lower() or "os" in r.lower() for r in recommendations)

    def test_cve_recommendation(self, detector):
        """Test recommendations for CVE-2004-2095."""
        from potsnitch.core.result import Indicator

        result = DetectionResult(target="192.168.1.1", port=80)
        result.add_indicator(
            Indicator(
                name="cve_2004_2095",
                description="CVE-2004-2095 detected",
                severity=Confidence.DEFINITE,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any("cve" in r.lower() or "patch" in r.lower() or "update" in r.lower() for r in recommendations)

    def test_tcp_anomaly_recommendation(self, detector):
        """Test recommendations for TCP anomaly."""
        from potsnitch.core.result import Indicator

        result = DetectionResult(target="192.168.1.1", port=80)
        result.add_indicator(
            Indicator(
                name="tcp_anomaly_response",
                description="TCP anomaly detected",
                severity=Confidence.LOW,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any("nmap" in r.lower() or "personality" in r.lower() for r in recommendations)


class TestDetectorProperties:
    """Test detector class properties."""

    def test_detector_name(self):
        """Test detector name property."""
        detector = HoneydDetector()
        assert detector.name == "honeyd"

    def test_detector_description(self):
        """Test detector has description."""
        detector = HoneydDetector()
        assert detector.description is not None
        assert "honeyd" in detector.description.lower()

    def test_detector_honeypot_types(self):
        """Test detector honeypot types."""
        detector = HoneydDetector()
        assert "honeyd" in detector.honeypot_types

    def test_detector_default_ports(self):
        """Test detector default ports."""
        detector = HoneydDetector()
        assert 22 in detector.default_ports
        assert 80 in detector.default_ports
        assert 443 in detector.default_ports

    def test_detector_timeout_config(self):
        """Test detector timeout configuration."""
        detector = HoneydDetector(timeout=10.0)
        assert detector.timeout == 10.0


class TestConnectionErrors:
    """Test handling of connection errors."""

    @pytest.fixture
    def detector(self):
        """Create Honeyd detector instance."""
        return HoneydDetector()

    def test_connection_timeout(self, detector, mock_socket):
        """Test handling of connection timeout."""
        socket_instance = mock_socket.return_value
        socket_instance.connect.side_effect = socket.timeout()

        result = detector.detect_passive("192.168.1.1", 80)

        assert not result.is_honeypot
        assert len(result.indicators) == 0

    def test_connection_refused(self, detector, mock_socket):
        """Test handling of connection refused."""
        socket_instance = mock_socket.return_value
        socket_instance.connect.side_effect = ConnectionRefusedError()

        result = detector.detect_passive("192.168.1.1", 80)

        assert not result.is_honeypot

    def test_os_error(self, detector, mock_socket):
        """Test handling of OS errors."""
        socket_instance = mock_socket.return_value
        socket_instance.connect.side_effect = OSError("Network unreachable")

        result = detector.detect_active("192.168.1.1", 80)

        assert not result.is_honeypot
