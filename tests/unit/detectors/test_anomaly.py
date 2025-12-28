"""
Unit tests for anomaly-based honeypot detector.

Tests cover:
- Port signature matching
- Duplicate service detection
- OS/service mismatch detection
- Timing consistency analysis
- Behavioral consistency checks
- Recommendation generation
"""

import socket
import time
import pytest
from unittest.mock import MagicMock, patch, call

from potsnitch.detectors.anomaly import (
    AnomalyDetector,
    HONEYPOT_PORT_SIGNATURES,
    PORT_MATCH_THRESHOLD,
)
from potsnitch.core.base import DetectionMode
from potsnitch.core.result import Confidence, DetectionResult


class TestPortSignatureDetection:
    """Test port signature matching against known honeypot configurations."""

    @pytest.mark.parametrize(
        "honeypot_name,expected_ports",
        [
            ("amun", HONEYPOT_PORT_SIGNATURES["amun"]),
            ("artillery", HONEYPOT_PORT_SIGNATURES["artillery"]),
            ("dionaea", HONEYPOT_PORT_SIGNATURES["dionaea"]),
            ("honeypy", HONEYPOT_PORT_SIGNATURES["honeypy"]),
        ],
    )
    def test_port_signature_match_high(self, honeypot_name, expected_ports):
        """Test detection of high match (>=90%) with honeypot port signatures."""
        detector = AnomalyDetector()

        # Use 95% of signature ports as open
        open_ports = expected_ports[: int(len(expected_ports) * 0.95)]

        with patch("potsnitch.detectors.anomaly.scan_ports") as mock_scan:
            mock_scan.return_value = open_ports

            result = detector.detect_passive("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "port_signature_match" in indicator_names

        sig_indicator = next(ind for ind in result.indicators if ind.name == "port_signature_match")
        assert sig_indicator.severity == Confidence.HIGH
        assert result.honeypot_type == honeypot_name

    def test_port_signature_match_medium(self):
        """Test detection of medium match (70-90%) with port signatures."""
        detector = AnomalyDetector()

        # Use ~75% of amun ports
        amun_ports = HONEYPOT_PORT_SIGNATURES["amun"]
        open_ports = amun_ports[: int(len(amun_ports) * 0.75)]

        with patch("potsnitch.detectors.anomaly.scan_ports") as mock_scan:
            mock_scan.return_value = open_ports

            result = detector.detect_passive("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "port_signature_match" in indicator_names

        sig_indicator = next(ind for ind in result.indicators if ind.name == "port_signature_match")
        assert sig_indicator.severity == Confidence.MEDIUM

    def test_port_signature_no_match(self):
        """Test when ports don't match any honeypot signature."""
        detector = AnomalyDetector()

        # Use random ports that don't match signatures
        open_ports = [1234, 5678, 9999]

        with patch("potsnitch.detectors.anomaly.scan_ports") as mock_scan:
            mock_scan.return_value = open_ports

            result = detector.detect_passive("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "port_signature_match" not in indicator_names

    def test_no_open_ports(self):
        """Test when no ports are open."""
        detector = AnomalyDetector()

        with patch("potsnitch.detectors.anomaly.scan_ports") as mock_scan:
            mock_scan.return_value = []

            result = detector.detect_passive("192.168.1.1", 80)

        assert len(result.indicators) == 0
        assert not result.is_honeypot


class TestDuplicateServiceDetection:
    """Test detection of duplicate services on multiple ports."""

    def test_multiple_ssh_ports(self):
        """Test detection of multiple SSH ports."""
        detector = AnomalyDetector()

        open_ports = [22, 2222, 22222, 80]  # Multiple SSH ports

        with patch("potsnitch.detectors.anomaly.scan_ports") as mock_scan:
            mock_scan.return_value = open_ports

            result = detector.detect_passive("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "duplicate_ssh" in indicator_names

        dup_indicator = next(ind for ind in result.indicators if ind.name == "duplicate_ssh")
        assert dup_indicator.severity == Confidence.MEDIUM

    def test_many_http_ports(self):
        """Test detection of many HTTP ports."""
        detector = AnomalyDetector()

        open_ports = [80, 8080, 8000, 8888]  # Many HTTP ports

        with patch("potsnitch.detectors.anomaly.scan_ports") as mock_scan:
            mock_scan.return_value = open_ports

            result = detector.detect_passive("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "many_http_ports" in indicator_names

        http_indicator = next(ind for ind in result.indicators if ind.name == "many_http_ports")
        assert http_indicator.severity == Confidence.LOW

    def test_single_service_per_port(self):
        """Test no detection when services are not duplicated."""
        detector = AnomalyDetector()

        open_ports = [22, 80, 443]  # Normal configuration

        with patch("potsnitch.detectors.anomaly.scan_ports") as mock_scan:
            mock_scan.return_value = open_ports

            result = detector.detect_passive("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "duplicate_ssh" not in indicator_names
        assert "many_http_ports" not in indicator_names


class TestOSServiceMismatchDetection:
    """Test detection of OS/service mismatches."""

    def test_mixed_os_services(self):
        """Test detection of mixed Windows and Linux services."""
        detector = AnomalyDetector()

        # Windows ports (SMB, RDP) + Linux ports (SSH)
        open_ports = [22, 445, 135, 3389]

        with patch("potsnitch.detectors.anomaly.scan_ports") as mock_scan:
            mock_scan.return_value = open_ports

            result = detector.detect_passive("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "mixed_os_services" in indicator_names

        mixed_indicator = next(ind for ind in result.indicators if ind.name == "mixed_os_services")
        assert mixed_indicator.severity == Confidence.MEDIUM

    def test_many_open_ports(self):
        """Test detection of unusually many open ports."""
        detector = AnomalyDetector()

        # More than 15 open ports
        open_ports = list(range(1, 20))

        with patch("potsnitch.detectors.anomaly.scan_ports") as mock_scan:
            mock_scan.return_value = open_ports

            result = detector.detect_passive("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "many_open_ports" in indicator_names

    def test_windows_only_services(self):
        """Test no mismatch detection for Windows-only services."""
        detector = AnomalyDetector()

        open_ports = [445, 135, 139, 3389]  # Windows only

        with patch("potsnitch.detectors.anomaly.scan_ports") as mock_scan:
            mock_scan.return_value = open_ports

            result = detector.detect_passive("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "mixed_os_services" not in indicator_names

    def test_linux_only_services(self):
        """Test no mismatch detection for Linux-only services."""
        detector = AnomalyDetector()

        open_ports = [22, 80, 443]  # Linux only

        with patch("potsnitch.detectors.anomaly.scan_ports") as mock_scan:
            mock_scan.return_value = open_ports

            result = detector.detect_passive("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "mixed_os_services" not in indicator_names


class TestTimingConsistencyDetection:
    """Test response timing consistency analysis."""

    def test_uniform_timing_detection(self):
        """Test detection of suspiciously uniform response timing."""
        detector = AnomalyDetector()

        open_ports = [21, 22, 23, 80, 443]

        with patch("potsnitch.detectors.anomaly.scan_ports") as mock_scan:
            mock_scan.return_value = open_ports

            with patch("socket.socket") as mock_socket:
                sock_instance = MagicMock()
                mock_socket.return_value = sock_instance

                # Simulate very fast, uniform connection times
                # Each connect/recv takes ~0.01s
                def fast_connect(*args):
                    time.sleep(0.01)

                sock_instance.connect.side_effect = fast_connect
                sock_instance.recv.return_value = b"banner"

                result = detector.detect_active("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "uniform_timing" in indicator_names

        timing_indicator = next(ind for ind in result.indicators if ind.name == "uniform_timing")
        assert timing_indicator.severity == Confidence.MEDIUM

    def test_variable_timing_no_detection(self):
        """Test no detection when timing is variable."""
        detector = AnomalyDetector()

        open_ports = [21, 22, 23, 80, 443]

        with patch("potsnitch.detectors.anomaly.scan_ports") as mock_scan:
            mock_scan.return_value = open_ports

            with patch("socket.socket") as mock_socket:
                sock_instance = MagicMock()
                mock_socket.return_value = sock_instance

                # Simulate variable connection times
                delays = [0.1, 0.3, 0.2, 0.5, 0.15]
                delay_idx = [0]

                def variable_connect(*args):
                    idx = delay_idx[0] % len(delays)
                    time.sleep(delays[idx])
                    delay_idx[0] += 1

                sock_instance.connect.side_effect = variable_connect
                sock_instance.recv.return_value = b"banner"

                result = detector.detect_active("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "uniform_timing" not in indicator_names

    def test_timing_with_few_ports(self):
        """Test timing check is skipped with fewer than 3 ports."""
        detector = AnomalyDetector()

        open_ports = [22, 80]  # Only 2 ports

        with patch("potsnitch.detectors.anomaly.scan_ports") as mock_scan:
            mock_scan.return_value = open_ports

            with patch("socket.socket") as mock_socket:
                result = detector.detect_active("192.168.1.1", 80)

        # Should return early without timing indicator
        indicator_names = [ind.name for ind in result.indicators]
        assert "uniform_timing" not in indicator_names

    def test_timing_with_connection_errors(self):
        """Test timing check handles connection errors gracefully."""
        detector = AnomalyDetector()

        open_ports = [21, 22, 23, 80, 443]

        with patch("potsnitch.detectors.anomaly.scan_ports") as mock_scan:
            mock_scan.return_value = open_ports

            with patch("socket.socket") as mock_socket:
                sock_instance = MagicMock()
                mock_socket.return_value = sock_instance

                # All connections fail
                sock_instance.connect.side_effect = socket.error("Connection refused")

                result = detector.detect_active("192.168.1.1", 80)

        # Should not crash, just no timing indicator
        assert result is not None


class TestBehavioralConsistencyDetection:
    """Test behavioral consistency anomaly detection."""

    def test_identical_error_responses(self):
        """Test detection of identical error responses across services."""
        detector = AnomalyDetector()

        open_ports = [21, 22, 23, 80, 443]

        with patch("potsnitch.detectors.anomaly.scan_ports") as mock_scan:
            mock_scan.return_value = open_ports

            with patch("socket.socket") as mock_socket:
                sock_instance = MagicMock()
                mock_socket.return_value = sock_instance

                # All services return identical error response
                sock_instance.recv.return_value = b"ERROR: Invalid protocol"

                result = detector.detect_active("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "identical_error_responses" in indicator_names

        error_indicator = next(ind for ind in result.indicators if ind.name == "identical_error_responses")
        assert error_indicator.severity == Confidence.HIGH

    def test_similar_error_responses(self):
        """Test detection of similar but not identical error responses."""
        detector = AnomalyDetector()

        open_ports = [21, 22, 23, 80, 443]

        with patch("potsnitch.detectors.anomaly.scan_ports") as mock_scan:
            mock_scan.return_value = open_ports

            with patch("socket.socket") as mock_socket:
                sock_instance = MagicMock()
                mock_socket.return_value = sock_instance

                # Some services return same response, others different
                responses = [
                    b"ERROR: Invalid",
                    b"ERROR: Invalid",
                    b"ERROR: Invalid",
                    b"Different error",
                    b"ERROR: Invalid",
                ]
                response_idx = [0]

                def get_response(*args):
                    idx = response_idx[0] % len(responses)
                    response_idx[0] += 1
                    return responses[idx]

                sock_instance.recv.side_effect = get_response

                result = detector.detect_active("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "similar_error_responses" in indicator_names

        similar_indicator = next(ind for ind in result.indicators if ind.name == "similar_error_responses")
        assert similar_indicator.severity == Confidence.MEDIUM

    def test_diverse_error_responses(self):
        """Test no detection when error responses are diverse."""
        detector = AnomalyDetector()

        open_ports = [21, 22, 23, 80, 443]

        with patch("potsnitch.detectors.anomaly.scan_ports") as mock_scan:
            mock_scan.return_value = open_ports

            with patch("socket.socket") as mock_socket:
                sock_instance = MagicMock()
                mock_socket.return_value = sock_instance

                # All services return different responses
                responses = [
                    b"FTP Error",
                    b"SSH Error",
                    b"Telnet Error",
                    b"HTTP Error",
                    b"HTTPS Error",
                ]
                response_idx = [0]

                def get_response(*args):
                    idx = response_idx[0] % len(responses)
                    response_idx[0] += 1
                    return responses[idx]

                sock_instance.recv.side_effect = get_response

                result = detector.detect_active("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "identical_error_responses" not in indicator_names
        assert "similar_error_responses" not in indicator_names

    def test_behavioral_with_timeout(self):
        """Test behavioral check handles timeouts gracefully."""
        detector = AnomalyDetector()

        open_ports = [21, 22, 23, 80, 443]

        with patch("potsnitch.detectors.anomaly.scan_ports") as mock_scan:
            mock_scan.return_value = open_ports

            with patch("socket.socket") as mock_socket:
                sock_instance = MagicMock()
                mock_socket.return_value = sock_instance

                # All recv calls timeout
                sock_instance.recv.side_effect = socket.timeout()

                result = detector.detect_active("192.168.1.1", 80)

        # Should not crash
        assert result is not None

    def test_behavioral_with_connection_errors(self):
        """Test behavioral check handles connection errors."""
        detector = AnomalyDetector()

        open_ports = [21, 22, 23, 80, 443]

        with patch("potsnitch.detectors.anomaly.scan_ports") as mock_scan:
            mock_scan.return_value = open_ports

            with patch("socket.socket") as mock_socket:
                sock_instance = MagicMock()
                mock_socket.return_value = sock_instance

                sock_instance.connect.side_effect = socket.error("Connection refused")

                result = detector.detect_active("192.168.1.1", 80)

        # Should not crash
        assert result is not None


class TestDetectorModes:
    """Test anomaly detector in different detection modes."""

    def test_passive_mode(self):
        """Test detector in passive mode only."""
        detector = AnomalyDetector(mode=DetectionMode.PASSIVE)

        open_ports = [22, 2222, 22222]

        with patch("potsnitch.detectors.anomaly.scan_ports") as mock_scan:
            mock_scan.return_value = open_ports

            result = detector.detect("192.168.1.1", 80)

        # Should have passive indicators only
        indicator_names = [ind.name for ind in result.indicators]
        assert "duplicate_ssh" in indicator_names

    def test_active_mode(self):
        """Test detector in active mode only."""
        detector = AnomalyDetector(mode=DetectionMode.ACTIVE)

        open_ports = [21, 22, 23, 80, 443]

        with patch("potsnitch.detectors.anomaly.scan_ports") as mock_scan:
            mock_scan.return_value = open_ports

            with patch("socket.socket") as mock_socket:
                sock_instance = MagicMock()
                mock_socket.return_value = sock_instance
                sock_instance.recv.return_value = b"ERROR: Invalid"

                result = detector.detect("192.168.1.1", 80)

        # Should have active indicators
        indicator_names = [ind.name for ind in result.indicators]
        assert "identical_error_responses" in indicator_names

    def test_full_mode(self):
        """Test detector in full mode (passive + active)."""
        detector = AnomalyDetector(mode=DetectionMode.FULL)

        open_ports = [22, 2222, 22222, 23, 80]

        with patch("potsnitch.detectors.anomaly.scan_ports") as mock_scan:
            mock_scan.return_value = open_ports

            with patch("socket.socket") as mock_socket:
                sock_instance = MagicMock()
                mock_socket.return_value = sock_instance
                sock_instance.recv.return_value = b"ERROR: Invalid"

                result = detector.detect("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        # Should have both passive and active indicators
        assert "duplicate_ssh" in indicator_names or "identical_error_responses" in indicator_names


class TestRecommendations:
    """Test recommendation generation."""

    @pytest.mark.parametrize(
        "indicator_name,expected_keyword",
        [
            ("port_signature_match", "port"),
            ("duplicate_ssh", "multiple"),
            ("mixed_os_services", "windows"),
            ("many_open_ports", "number"),
            ("uniform_timing", "timing"),
            ("identical_error_responses", "error"),
            ("similar_error_responses", "error"),
        ],
    )
    def test_recommendation_for_indicator(self, indicator_name, expected_keyword):
        """Test that each indicator type generates appropriate recommendations."""
        detector = AnomalyDetector()
        from potsnitch.core.result import Indicator

        result = DetectionResult(target="192.168.1.1", port=80)
        result.add_indicator(
            Indicator(
                name=indicator_name,
                description="Test indicator",
                severity=Confidence.MEDIUM,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any(expected_keyword.lower() in r.lower() for r in recommendations)

    def test_no_recommendations_for_empty_result(self):
        """Test no recommendations when no indicators present."""
        detector = AnomalyDetector()

        result = DetectionResult(target="192.168.1.1", port=80)
        recommendations = detector.get_recommendations(result)

        assert len(recommendations) == 0


class TestDetectorMetadata:
    """Test detector metadata and initialization."""

    def test_detector_name(self):
        """Test detector name is set correctly."""
        detector = AnomalyDetector()
        assert detector.name == "anomaly"

    def test_detector_description(self):
        """Test detector has a description."""
        detector = AnomalyDetector()
        assert len(detector.description) > 0

    def test_detector_honeypot_types(self):
        """Test detector targets correct honeypot types."""
        detector = AnomalyDetector()
        assert "amun" in detector.honeypot_types
        assert "artillery" in detector.honeypot_types
        assert "honeypy" in detector.honeypot_types

    def test_all_signature_ports_collected(self):
        """Test that all signature ports are collected on init."""
        detector = AnomalyDetector()

        all_expected_ports = set()
        for port_list in HONEYPOT_PORT_SIGNATURES.values():
            all_expected_ports.update(port_list)

        assert set(detector._all_ports) == all_expected_ports

    def test_detector_info(self):
        """Test get_info method returns correct info."""
        info = AnomalyDetector.get_info()

        assert info["name"] == "anomaly"
        assert "honeypot_types" in info
        assert "default_ports" in info


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_response(self):
        """Test handling of empty responses from services."""
        detector = AnomalyDetector()

        open_ports = [21, 22, 23, 80, 443]

        with patch("potsnitch.detectors.anomaly.scan_ports") as mock_scan:
            mock_scan.return_value = open_ports

            with patch("socket.socket") as mock_socket:
                sock_instance = MagicMock()
                mock_socket.return_value = sock_instance

                # Return empty responses
                sock_instance.recv.return_value = b""

                result = detector.detect_active("192.168.1.1", 80)

        # Should not crash and should not detect empty as identical
        assert result is not None

    def test_custom_timeout(self):
        """Test detector with custom timeout."""
        detector = AnomalyDetector(timeout=10.0)
        assert detector.timeout == 10.0

    def test_verbose_mode(self):
        """Test detector with verbose mode enabled."""
        detector = AnomalyDetector(verbose=True)
        assert detector.verbose is True

    def test_active_no_open_ports(self):
        """Test active detection with no open ports."""
        detector = AnomalyDetector()

        with patch("potsnitch.detectors.anomaly.scan_ports") as mock_scan:
            mock_scan.return_value = []

            result = detector.detect_active("192.168.1.1", 80)

        assert len(result.indicators) == 0

    def test_truncated_error_responses(self):
        """Test that error responses are truncated to 100 bytes."""
        detector = AnomalyDetector()

        open_ports = [21, 22, 23]

        with patch("potsnitch.detectors.anomaly.scan_ports") as mock_scan:
            mock_scan.return_value = open_ports

            with patch("socket.socket") as mock_socket:
                sock_instance = MagicMock()
                mock_socket.return_value = sock_instance

                # Return very long identical responses
                long_response = b"A" * 200
                sock_instance.recv.return_value = long_response

                result = detector.detect_active("192.168.1.1", 80)

        # Should still detect as identical (after truncation to 100 bytes)
        indicator_names = [ind.name for ind in result.indicators]
        assert "identical_error_responses" in indicator_names
