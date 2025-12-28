"""
Unit tests for Tarpit honeypot detectors (Endlessh and HellPot).

Tests cover:
- Endlessh detection (slow banner, partial SSH banner)
- HellPot infinite response detection
- Timing analysis for tarpit behavior
- Delayed response detection
"""

import socket
import time
import pytest
from unittest.mock import MagicMock, patch

from potsnitch.detectors.tarpit import (
    EndlesshDetector,
    HellPotDetector,
    TarpitDetector,
    ENDLESSH_DETECTION_THRESHOLD_S,
    HELLPOT_TARPIT_PATHS,
    HELLPOT_SERVER_HEADER,
)
from potsnitch.core.base import DetectionMode
from potsnitch.core.result import Confidence


class TestEndlesshBannerDetection:
    """Test Endlessh banner-based detection."""

    def test_partial_ssh_banner_detection(self):
        """Test detection of partial SSH banner without newline."""
        detector = EndlesshDetector()
        # Partial banner - no newline (Endlessh behavior)
        partial_banner = b"SSH-2.0-OpenSSH_7.9"

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.recv.return_value = partial_banner

            result = detector.detect_passive("192.168.1.1", 22)

        assert result.is_honeypot
        indicator_names = [ind.name for ind in result.indicators]
        assert "endlessh_partial_banner" in indicator_names
        assert result.honeypot_type == "endlessh"

    def test_complete_ssh_banner_no_detection(self):
        """Test that complete SSH banners don't trigger detection."""
        detector = EndlesshDetector()
        # Complete banner with newline
        complete_banner = b"SSH-2.0-OpenSSH_7.9\r\n"

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.recv.return_value = complete_banner

            result = detector.detect_passive("192.168.1.1", 22)

        indicator_names = [ind.name for ind in result.indicators]
        assert "endlessh_partial_banner" not in indicator_names

    def test_default_endlessh_port_detection(self):
        """Test detection of default Endlessh port 22222."""
        detector = EndlesshDetector()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.recv.return_value = b"SSH-2.0-Test\r\n"

            result = detector.detect_passive("192.168.1.1", 22222)

        indicator_names = [ind.name for ind in result.indicators]
        assert "endlessh_default_port" in indicator_names


class TestEndlesshTimingAnalysis:
    """Test Endlessh timing-based detection."""

    def test_delayed_banner_detection(self):
        """Test detection of delayed SSH banner (> 5 seconds)."""
        detector = EndlesshDetector()

        # Simulate delayed first byte
        with patch.object(detector, "_measure_banner_timing") as mock_timing:
            # first_byte_time > 5 seconds
            mock_timing.return_value = (6.0, 20, 10.0)

            result = detector.detect_active("192.168.1.1", 22)

        assert result.is_honeypot
        indicator_names = [ind.name for ind in result.indicators]
        assert "endlessh_delayed_banner" in indicator_names

    def test_slow_data_rate_detection(self):
        """Test detection of extremely slow data rate (tarpit behavior)."""
        detector = EndlesshDetector()

        with patch.object(detector, "_measure_banner_timing") as mock_timing:
            # 10 bytes in 10 seconds = 1 byte/second (very slow)
            mock_timing.return_value = (0.5, 10, 10.0)

            result = detector.detect_active("192.168.1.1", 22)

        assert result.is_honeypot
        indicator_names = [ind.name for ind in result.indicators]
        assert "endlessh_slow_rate" in indicator_names
        # Slow rate is DEFINITE indicator
        slow_ind = [ind for ind in result.indicators if ind.name == "endlessh_slow_rate"]
        assert slow_ind[0].severity == Confidence.DEFINITE

    def test_incomplete_banner_after_wait(self):
        """Test detection of incomplete banner after long wait."""
        detector = EndlesshDetector()

        with patch.object(detector, "_measure_banner_timing") as mock_timing:
            # Only 30 bytes after 12 seconds
            mock_timing.return_value = (0.5, 30, 12.0)

            result = detector.detect_active("192.168.1.1", 22)

        indicator_names = [ind.name for ind in result.indicators]
        assert "endlessh_incomplete_banner" in indicator_names

    def test_normal_ssh_timing(self):
        """Test that normal SSH timing doesn't trigger detection."""
        detector = EndlesshDetector()

        with patch.object(detector, "_measure_banner_timing") as mock_timing:
            # Fast response, complete banner
            mock_timing.return_value = (0.05, 100, 0.1)

            result = detector.detect_active("192.168.1.1", 22)

        indicator_names = [ind.name for ind in result.indicators]
        assert "endlessh_delayed_banner" not in indicator_names
        assert "endlessh_slow_rate" not in indicator_names


class TestEndlesshMeasureBannerTiming:
    """Test the _measure_banner_timing method."""

    def test_timing_measurement_success(self):
        """Test successful timing measurement."""
        detector = EndlesshDetector()

        with patch("socket.socket") as mock_socket_class, patch(
            "select.select"
        ) as mock_select:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            # Simulate data being ready
            mock_select.return_value = ([mock_socket], [], [])

            # Return complete SSH banner
            mock_socket.recv.return_value = b"SSH-2.0-Test\r\n"

            result = detector._measure_banner_timing("192.168.1.1", 22)

        assert result is not None
        first_byte_time, total_bytes, duration = result
        assert total_bytes > 0

    def test_timing_measurement_timeout(self):
        """Test timing measurement with connection timeout."""
        detector = EndlesshDetector()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.connect.side_effect = socket.timeout()

            result = detector._measure_banner_timing("192.168.1.1", 22)

        assert result is None


class TestHellPotDetection:
    """Test HellPot HTTP tarpit detection."""

    def test_hellpot_nginx_header(self):
        """Test detection of HellPot default nginx Server header."""
        detector = HellPotDetector()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            response = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nHello"
            mock_socket.recv.return_value = response

            result = detector.detect_passive("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "hellpot_nginx_header" in indicator_names

    @pytest.mark.parametrize(
        "tarpit_path",
        [
            "/wp-login.php",
            "/wp-admin/",
            "/.git/",
            "/.env",
            "/admin/",
            "/phpmyadmin/",
        ],
    )
    def test_tarpit_path_detection(self, tarpit_path):
        """Test detection of infinite data stream on tarpit paths."""
        detector = HellPotDetector()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            # Simulate infinite data stream (many chunks, lots of data)
            chunk_data = b"A" * 4096
            # Return many chunks then timeout
            mock_socket.recv.side_effect = [chunk_data] * 10 + [socket.timeout()]

            indicator = detector._check_tarpit_path("192.168.1.1", 80, tarpit_path)

        assert indicator is not None
        assert indicator.name == "hellpot_infinite_response"
        assert indicator.severity == Confidence.DEFINITE

    def test_normal_response_no_tarpit(self):
        """Test that normal responses don't trigger tarpit detection."""
        detector = HellPotDetector()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            # Normal small response, then connection closes
            mock_socket.recv.side_effect = [b"404 Not Found", b""]

            indicator = detector._check_tarpit_path(
                "192.168.1.1", 80, "/wp-login.php"
            )

        assert indicator is None

    def test_large_response_detection(self):
        """Test detection of unusually large response."""
        detector = HellPotDetector()

        with patch("socket.socket") as mock_socket_class, patch(
            "potsnitch.detectors.tarpit.time"
        ) as mock_time_module:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            # Simulate time passing
            start_time = 1000.0
            mock_time_module.time.side_effect = [
                start_time,  # Start time
                start_time + 1,  # First loop iteration
                start_time + 2,  # Second loop iteration
                start_time + 3,  # Third loop iteration
                start_time + 4,  # Fourth loop iteration
                start_time + 6,  # After connection closes (>5 seconds)
            ]

            # Large response over time (>50KB)
            chunk = b"X" * 20000
            mock_socket.recv.side_effect = [chunk, chunk, chunk, b""]

            indicator = detector._check_tarpit_path(
                "192.168.1.1", 80, "/wp-admin/"
            )

        assert indicator is not None
        assert indicator.name in ("hellpot_infinite_response", "hellpot_large_response")


class TestHellPotActiveDetection:
    """Test HellPot active probing."""

    def test_detect_active_finds_tarpit(self):
        """Test active detection finds tarpit on first path."""
        detector = HellPotDetector()

        with patch.object(detector, "_check_tarpit_path") as mock_check:
            from potsnitch.core.result import Indicator

            mock_check.return_value = Indicator(
                name="hellpot_infinite_response",
                description="Infinite stream detected",
                severity=Confidence.DEFINITE,
            )

            result = detector.detect_active("192.168.1.1", 80)

        assert result.is_honeypot
        assert result.honeypot_type == "hellpot"

    def test_detect_active_no_tarpit(self):
        """Test active detection when no tarpit behavior."""
        detector = HellPotDetector()

        with patch.object(detector, "_check_tarpit_path") as mock_check:
            mock_check.return_value = None  # No tarpit indicators

            result = detector.detect_active("192.168.1.1", 80)

        assert not result.is_honeypot


class TestTarpitDetector:
    """Test combined Tarpit detector."""

    def test_ssh_port_uses_endlessh(self):
        """Test that SSH ports use Endlessh detection."""
        detector = TarpitDetector()

        with patch.object(
            detector._endlessh, "detect_passive"
        ) as mock_endlessh, patch.object(
            detector._hellpot, "detect_passive"
        ) as mock_hellpot:
            from potsnitch.core.result import DetectionResult, Indicator

            endlessh_result = DetectionResult(target="192.168.1.1", port=22)
            endlessh_result.add_indicator(
                Indicator(
                    name="endlessh_partial_banner",
                    description="Partial banner",
                    severity=Confidence.HIGH,
                )
            )
            endlessh_result.honeypot_type = "endlessh"

            mock_endlessh.return_value = endlessh_result
            mock_hellpot.return_value = DetectionResult(
                target="192.168.1.1", port=22
            )

            result = detector.detect_passive("192.168.1.1", 22)

        mock_endlessh.assert_called_once()
        mock_hellpot.assert_not_called()
        assert result.honeypot_type == "endlessh"

    def test_http_port_uses_hellpot(self):
        """Test that HTTP ports use HellPot detection."""
        detector = TarpitDetector()

        with patch.object(
            detector._endlessh, "detect_passive"
        ) as mock_endlessh, patch.object(
            detector._hellpot, "detect_passive"
        ) as mock_hellpot:
            from potsnitch.core.result import DetectionResult, Indicator

            hellpot_result = DetectionResult(target="192.168.1.1", port=80)
            hellpot_result.add_indicator(
                Indicator(
                    name="hellpot_nginx_header",
                    description="Nginx header",
                    severity=Confidence.LOW,
                )
            )
            hellpot_result.honeypot_type = "hellpot"

            mock_hellpot.return_value = hellpot_result
            mock_endlessh.return_value = DetectionResult(
                target="192.168.1.1", port=80
            )

            result = detector.detect_passive("192.168.1.1", 80)

        mock_hellpot.assert_called_once()
        mock_endlessh.assert_not_called()

    @pytest.mark.parametrize(
        "port",
        [22, 2222, 22222],
    )
    def test_ssh_ports_active(self, port):
        """Test active detection on SSH ports."""
        detector = TarpitDetector()

        with patch.object(
            detector._endlessh, "detect_active"
        ) as mock_endlessh:
            from potsnitch.core.result import DetectionResult

            mock_endlessh.return_value = DetectionResult(
                target="192.168.1.1", port=port
            )

            detector.detect_active("192.168.1.1", port)

        mock_endlessh.assert_called_once()

    @pytest.mark.parametrize(
        "port",
        [80, 443, 8080, 8443],
    )
    def test_http_ports_active(self, port):
        """Test active detection on HTTP ports."""
        detector = TarpitDetector()

        with patch.object(
            detector._hellpot, "detect_active"
        ) as mock_hellpot:
            from potsnitch.core.result import DetectionResult

            mock_hellpot.return_value = DetectionResult(
                target="192.168.1.1", port=port
            )

            detector.detect_active("192.168.1.1", port)

        mock_hellpot.assert_called_once()


class TestTarpitDetectorModes:
    """Test Tarpit detector mode handling."""

    def test_passive_mode(self):
        """Test detector in passive mode."""
        detector = EndlesshDetector(mode=DetectionMode.PASSIVE)

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.recv.return_value = b"SSH-2.0-Partial"  # No newline

            result = detector.detect("192.168.1.1", 22)

        assert result.is_honeypot

    def test_active_mode(self):
        """Test detector in active mode."""
        detector = EndlesshDetector(mode=DetectionMode.ACTIVE)

        with patch.object(detector, "_measure_banner_timing") as mock_timing:
            # Simulate slow tarpit behavior
            mock_timing.return_value = (6.0, 10, 10.0)

            result = detector.detect("192.168.1.1", 22)

        assert result.is_honeypot


class TestTarpitConnectionErrors:
    """Test tarpit detector error handling."""

    def test_endlessh_connection_timeout(self):
        """Test Endlessh handling of connection timeout."""
        detector = EndlesshDetector(timeout=1.0)

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.connect.side_effect = socket.timeout()

            result = detector.detect_passive("192.168.1.1", 22)

        assert not result.is_honeypot

    def test_hellpot_connection_error(self):
        """Test HellPot handling of connection error."""
        detector = HellPotDetector()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.connect.side_effect = ConnectionRefusedError()

            result = detector.detect_passive("192.168.1.1", 80)

        assert not result.is_honeypot


class TestTarpitRecommendations:
    """Test tarpit detector recommendations."""

    def test_endlessh_recommendations(self):
        """Test Endlessh recommendations."""
        detector = EndlesshDetector()
        from potsnitch.core.result import DetectionResult

        result = DetectionResult(target="192.168.1.1", port=22)
        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        # Endlessh is designed to be detectable
        assert any(
            "tarpit" in r.lower() or "detectable" in r.lower()
            for r in recommendations
        )

    def test_hellpot_recommendations(self):
        """Test HellPot recommendations."""
        detector = HellPotDetector()
        from potsnitch.core.result import DetectionResult

        result = DetectionResult(target="192.168.1.1", port=80)
        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
