"""
Unit tests for ADB honeypot detection (adbhoney via T-Pot detector).

Tests ADB banner detection, limited command implementation,
static device response detection, and ADB protocol mocking.
"""

import socket
import pytest
from unittest.mock import MagicMock, patch

from potsnitch.detectors.tpot import (
    TPotDetector,
    TPOT_STANDARD_PORTS,
    TPOT_SIGNATURES,
)
from potsnitch.core.result import DetectionResult, Indicator, Confidence


class TestADBBannerDetection:
    """Tests for ADB banner and connection detection."""

    @pytest.fixture
    def detector(self):
        return TPotDetector()

    def test_detect_adb_port_5555_passive(self, detector, mock_socket):
        """Test passive detection of ADB on port 5555."""
        mock_socket.return_value.connect_ex.return_value = 0
        result = detector.detect_passive("192.168.1.100", 5555)
        assert any(i.name == "tpot_adb_port" for i in result.indicators)

    def test_no_adb_indicator_on_non_adb_port(self, detector, mock_socket):
        """Test no ADB indicator on non-ADB port."""
        mock_socket.return_value.recv.return_value = b"+PONG\r\n"
        result = detector.detect_passive("192.168.1.100", 6379)
        assert not any(i.name == "tpot_adb_port" for i in result.indicators)


class TestADBActiveProbing:
    """Tests for ADB active connection probing."""

    @pytest.fixture
    def detector(self):
        return TPotDetector()

    def test_check_adb_cnxn_response(self, detector, mock_socket):
        """Test ADB CNXN handshake response detection."""
        mock_socket.return_value.recv.return_value = b"CNXN\x00\x00\x00\x01\x00\x10\x00\x00response"
        result = detector.detect_active("192.168.1.100", 5555)
        assert any(i.name == "adb_honeypot" for i in result.indicators)
        assert result.honeypot_type == "adbhoney"

    def test_check_adb_socket_timeout(self, detector, mock_socket):
        """Test ADB detection handles socket timeout gracefully."""
        mock_socket.return_value.recv.side_effect = socket.timeout()
        result = detector.detect_active("192.168.1.100", 5555)
        assert result.error is None


class TestADBLimitedCommandDetection:
    """Tests for detecting limited ADB command implementation."""

    @pytest.fixture
    def detector(self):
        return TPotDetector()

    @pytest.mark.parametrize("response,expected", [
        (b"CNXN\x00\x00\x00\x01device::features", True),
        (b"OKAY\x00\x00\x00\x01", True),
        (b"", False),
    ])
    def test_adb_response_variations(self, detector, response, expected, mock_socket):
        """Test various ADB response patterns."""
        mock_socket.return_value.recv.return_value = response
        result = detector.detect_active("192.168.1.100", 5555)
        has_adb_indicator = any(i.name == "adb_honeypot" for i in result.indicators)
        assert has_adb_indicator == expected

    def test_adb_signature_cnxn(self):
        """Test TPOT_SIGNATURES contains CNXN for ADB."""
        assert "adbhoney" in TPOT_SIGNATURES
        assert b"CNXN" in TPOT_SIGNATURES["adbhoney"]


class TestADBPortConfiguration:
    """Tests for ADB port configuration in T-Pot."""

    def test_adbhoney_default_port(self):
        """Test that adbhoney has port 5555 configured."""
        assert "adbhoney" in TPOT_STANDARD_PORTS
        assert 5555 in TPOT_STANDARD_PORTS["adbhoney"]

    def test_adb_in_default_ports(self):
        """Test that 5555 is in T-Pot default ports."""
        detector = TPotDetector()
        assert 5555 in detector.default_ports

    def test_adbhoney_in_honeypot_types(self):
        """Test that adbhoney is in detected honeypot types."""
        detector = TPotDetector()
        assert "adbhoney" in detector.honeypot_types


class TestADBProtocolMocking:
    """Tests for ADB protocol mocking in honeypots."""

    @pytest.fixture
    def detector(self):
        return TPotDetector()

    def test_adb_handshake_packet_structure(self, mock_socket):
        """Test the ADB handshake packet that is sent."""
        detector = TPotDetector()
        mock_socket.return_value.recv.return_value = b"CNXN"
        detector._check_adb("192.168.1.100", 5555, DetectionResult(target="192.168.1.100", port=5555))
        calls = mock_socket.return_value.send.call_args_list
        if calls:
            assert calls[0][0][0].startswith(b"CNXN")
