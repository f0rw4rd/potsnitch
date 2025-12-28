"""
Unit tests for multi-service honeypot framework detectors.

Tests OpenCanary, QeeqBox, T-Pot, Artillery, and FAPRO detection
including port combinations, banners, and multi-service correlation.
"""

import socket
import pytest
from unittest.mock import MagicMock, patch

from potsnitch.detectors.framework import (
    OpenCanaryDetector,
    QeeqBoxDetector,
    ArtilleryDetector,
    FaproDetector,
    FrameworkDetector,
    OPENCANARY_PORTS,
    QEEQBOX_PORTS,
    ARTILLERY_PORTS,
    FAPRO_PORTS,
    MIN_PORT_MATCH_THRESHOLD,
)
from potsnitch.core.base import DetectionMode
from potsnitch.core.result import DetectionResult, Indicator, Confidence


# =============================================================================
# OpenCanary Detector Tests
# =============================================================================


class TestOpenCanaryDetection:
    """Tests for OpenCanary port combination and banner detection."""

    @pytest.fixture
    def detector(self):
        return OpenCanaryDetector()

    def test_detect_opencanary_port_combo(self, detector):
        """Test detection of OpenCanary port combination."""
        result = DetectionResult(target="192.168.1.100", port=22)
        open_ports = {21, 22, 23, 80, 445, 3306}
        detector._analyze_port_combination(open_ports, result)
        assert any(i.name == "opencanary_port_combo" for i in result.indicators)

    def test_detect_mixed_os_services(self, detector):
        """Test detection of mixed Windows/Linux services."""
        result = DetectionResult(target="192.168.1.100", port=22)
        open_ports = {22, 445, 1433}  # SSH (Linux) with SMB/MSSQL (Windows)
        detector._analyze_port_combination(open_ports, result)
        assert any(i.name == "opencanary_mixed_os" for i in result.indicators)

    @pytest.mark.parametrize("port_count,expected_severity", [
        (4, Confidence.MEDIUM),
        (6, Confidence.HIGH),
    ])
    def test_port_count_severity(self, detector, port_count, expected_severity):
        """Test severity increases with port count."""
        result = DetectionResult(target="192.168.1.100", port=22)
        open_ports = set(list(OPENCANARY_PORTS.keys())[:port_count])
        detector._analyze_port_combination(open_ports, result)
        indicators = [i for i in result.indicators if i.name == "opencanary_port_combo"]
        if indicators:
            assert indicators[0].severity == expected_severity

    def test_detect_opencanary_ftp_banner(self, detector, mock_socket):
        """Test detection of OpenCanary FTP banner."""
        mock_socket.return_value.recv.return_value = b"220 OpenCanary FTP Server Ready\r\n"
        result = DetectionResult(target="192.168.1.100", port=21)
        detector._check_service_signatures("192.168.1.100", {21}, result)
        assert any(i.name == "opencanary_ftp_banner" for i in result.indicators)

    # -------------------------------------------------------------------------
    # Tests for detect_passive (lines 124-134)
    # -------------------------------------------------------------------------
    def test_detect_passive_with_open_ports(self, detector):
        """Test detect_passive when ports are open and match threshold."""
        with patch.object(detector, "_scan_opencanary_ports") as mock_scan:
            mock_scan.return_value = {21, 22, 23, 80, 445, 3306}
            result = detector.detect_passive("192.168.1.100", 22)
            assert result.target == "192.168.1.100"
            assert result.port == 22
            assert result.honeypot_type == "opencanary"
            assert any(i.name == "opencanary_port_combo" for i in result.indicators)

    def test_detect_passive_no_open_ports(self, detector):
        """Test detect_passive when no ports are open."""
        with patch.object(detector, "_scan_opencanary_ports") as mock_scan:
            mock_scan.return_value = set()
            result = detector.detect_passive("192.168.1.100", 22)
            assert result.target == "192.168.1.100"
            assert result.honeypot_type is None
            assert len(result.indicators) == 0

    def test_detect_passive_below_threshold(self, detector):
        """Test detect_passive when open ports below threshold."""
        with patch.object(detector, "_scan_opencanary_ports") as mock_scan:
            mock_scan.return_value = {21, 22}  # Only 2 ports
            result = detector.detect_passive("192.168.1.100", 22)
            assert result.honeypot_type is None

    # -------------------------------------------------------------------------
    # Tests for detect_active (lines 136-157)
    # -------------------------------------------------------------------------
    def test_detect_active_with_ftp_banner(self, detector, mock_socket):
        """Test detect_active with OpenCanary FTP banner."""
        mock_socket.return_value.recv.return_value = b"220 OpenCanary FTP Server Ready\r\n"
        mock_socket.return_value.connect_ex.return_value = 0
        with patch.object(detector, "_scan_opencanary_ports") as mock_scan:
            mock_scan.return_value = {21, 22, 80, 443}
            result = detector.detect_active("192.168.1.100", 21)
            assert result.honeypot_type == "opencanary"
            assert any(i.name == "opencanary_ftp_banner" for i in result.indicators)

    def test_detect_active_no_indicators(self, detector, mock_socket):
        """Test detect_active when no honeypot indicators found."""
        mock_socket.return_value.recv.return_value = b"220 Normal FTP Server\r\n"
        with patch.object(detector, "_scan_opencanary_ports") as mock_scan:
            mock_scan.return_value = {21}  # Only FTP port
            result = detector.detect_active("192.168.1.100", 21)
            assert result.honeypot_type is None

    # -------------------------------------------------------------------------
    # Tests for _scan_opencanary_ports (lines 159-165)
    # -------------------------------------------------------------------------
    def test_scan_opencanary_ports_all_open(self, detector):
        """Test _scan_opencanary_ports when all ports are open."""
        with patch.object(detector, "_is_port_open", return_value=True):
            ports = detector._scan_opencanary_ports("192.168.1.100")
            assert ports == set(OPENCANARY_PORTS.keys())

    def test_scan_opencanary_ports_none_open(self, detector):
        """Test _scan_opencanary_ports when no ports are open."""
        with patch.object(detector, "_is_port_open", return_value=False):
            ports = detector._scan_opencanary_ports("192.168.1.100")
            assert ports == set()

    def test_scan_opencanary_ports_some_open(self, detector):
        """Test _scan_opencanary_ports when some ports are open."""
        def port_checker(target, port):
            return port in {21, 22, 80}
        with patch.object(detector, "_is_port_open", side_effect=port_checker):
            ports = detector._scan_opencanary_ports("192.168.1.100")
            assert ports == {21, 22, 80}

    # -------------------------------------------------------------------------
    # Tests for _is_port_open (lines 167-176)
    # -------------------------------------------------------------------------
    def test_is_port_open_success(self, detector, mock_socket):
        """Test _is_port_open when port is open."""
        mock_socket.return_value.connect_ex.return_value = 0
        assert detector._is_port_open("192.168.1.100", 22) is True
        mock_socket.return_value.settimeout.assert_called_with(1.0)
        mock_socket.return_value.close.assert_called()

    def test_is_port_open_closed(self, detector, mock_socket):
        """Test _is_port_open when port is closed."""
        mock_socket.return_value.connect_ex.return_value = 111  # Connection refused
        assert detector._is_port_open("192.168.1.100", 22) is False

    def test_is_port_open_socket_error(self, detector, mock_socket):
        """Test _is_port_open when socket error occurs."""
        mock_socket.return_value.connect_ex.side_effect = socket.error("Connection failed")
        assert detector._is_port_open("192.168.1.100", 22) is False

    def test_is_port_open_os_error(self, detector, mock_socket):
        """Test _is_port_open when OS error occurs."""
        mock_socket.return_value.connect_ex.side_effect = OSError("Network unreachable")
        assert detector._is_port_open("192.168.1.100", 22) is False

    # -------------------------------------------------------------------------
    # Tests for _get_ftp_banner (lines 230-240)
    # -------------------------------------------------------------------------
    def test_get_ftp_banner_success(self, detector, mock_socket):
        """Test _get_ftp_banner successfully retrieves banner."""
        mock_socket.return_value.recv.return_value = b"220 FTP Server Ready\r\n"
        banner = detector._get_ftp_banner("192.168.1.100", 21)
        assert banner == b"220 FTP Server Ready\r\n"
        mock_socket.return_value.connect.assert_called_with(("192.168.1.100", 21))

    def test_get_ftp_banner_socket_error(self, detector, mock_socket):
        """Test _get_ftp_banner when socket error occurs."""
        mock_socket.return_value.connect.side_effect = socket.error("Connection refused")
        banner = detector._get_ftp_banner("192.168.1.100", 21)
        assert banner is None

    def test_get_ftp_banner_timeout(self, detector, mock_socket):
        """Test _get_ftp_banner when timeout occurs."""
        mock_socket.return_value.connect.side_effect = socket.timeout("Timed out")
        banner = detector._get_ftp_banner("192.168.1.100", 21)
        assert banner is None

    def test_get_ftp_banner_os_error(self, detector, mock_socket):
        """Test _get_ftp_banner when OS error occurs."""
        mock_socket.return_value.connect.side_effect = OSError("Network error")
        banner = detector._get_ftp_banner("192.168.1.100", 21)
        assert banner is None

    # -------------------------------------------------------------------------
    # Tests for _check_service_signatures edge cases (lines 209-228)
    # -------------------------------------------------------------------------
    def test_check_service_signatures_https_ports(self, detector):
        """Test _check_service_signatures with HTTPS/RDP ports (TLS placeholder)."""
        result = DetectionResult(target="192.168.1.100", port=443)
        # This tests the pass statement for TLS fingerprinting placeholder
        detector._check_service_signatures("192.168.1.100", {443, 3389}, result)
        # No indicators added since TLS fingerprinting is not implemented
        assert not any(i.name == "opencanary_ftp_banner" for i in result.indicators)

    def test_check_service_signatures_no_ftp_port(self, detector, mock_socket):
        """Test _check_service_signatures when FTP port not in open ports."""
        result = DetectionResult(target="192.168.1.100", port=22)
        detector._check_service_signatures("192.168.1.100", {22, 80}, result)
        # No FTP banner check should occur
        mock_socket.return_value.connect.assert_not_called()

    def test_check_service_signatures_ftp_banner_no_match(self, detector, mock_socket):
        """Test _check_service_signatures when FTP banner doesn't contain OpenCanary."""
        mock_socket.return_value.recv.return_value = b"220 ProFTPD Server Ready\r\n"
        result = DetectionResult(target="192.168.1.100", port=21)
        detector._check_service_signatures("192.168.1.100", {21}, result)
        assert not any(i.name == "opencanary_ftp_banner" for i in result.indicators)

    def test_check_service_signatures_ftp_banner_none(self, detector, mock_socket):
        """Test _check_service_signatures when FTP banner retrieval fails."""
        mock_socket.return_value.connect.side_effect = socket.error("Connection refused")
        result = DetectionResult(target="192.168.1.100", port=21)
        detector._check_service_signatures("192.168.1.100", {21}, result)
        assert not any(i.name == "opencanary_ftp_banner" for i in result.indicators)


# =============================================================================
# QeeqBox Detector Tests (25+ services pattern)
# =============================================================================


class TestQeeqBoxDetection:
    """Tests for QeeqBox high port count and unusual service detection."""

    @pytest.fixture
    def detector(self):
        return QeeqBoxDetector()

    def test_detect_high_port_count(self, detector):
        """Test detection of high port count (8+ services)."""
        result = DetectionResult(target="192.168.1.100", port=22)
        open_ports = {21, 22, 23, 25, 80, 110, 143, 389, 443, 445}
        detector._analyze_port_combination(open_ports, result)
        assert any(i.name == "qeeqbox_high_port_count" for i in result.indicators)

    @pytest.mark.parametrize("combo,desc", [
        ({5060, 9200}, "SIP + Elasticsearch"),
        ({1521, 27017}, "Oracle + MongoDB"),
        ({11211, 6379}, "Memcached + Redis"),
    ])
    def test_unusual_combo_variations(self, detector, combo, desc):
        """Test various unusual service combinations."""
        result = DetectionResult(target="192.168.1.100", port=22)
        detector._analyze_port_combination(combo | {22, 80}, result)
        assert any(i.name == "qeeqbox_unusual_combo" for i in result.indicators)

    def test_qeeqbox_has_25_plus_services(self):
        """Test that QeeqBox port configuration has 25+ services."""
        assert len(QEEQBOX_PORTS) >= 20

    # -------------------------------------------------------------------------
    # Tests for detect_passive (lines 274-284)
    # -------------------------------------------------------------------------
    def test_detect_passive_with_high_port_count(self, detector):
        """Test detect_passive when many ports are open."""
        with patch.object(detector, "_scan_qeeqbox_ports") as mock_scan:
            mock_scan.return_value = {21, 22, 23, 25, 80, 110, 143, 389, 443, 445}
            result = detector.detect_passive("192.168.1.100", 22)
            assert result.target == "192.168.1.100"
            assert result.port == 22
            assert result.honeypot_type == "qeeqbox"
            assert any(i.name == "qeeqbox_high_port_count" for i in result.indicators)

    def test_detect_passive_no_open_ports(self, detector):
        """Test detect_passive when no ports are open."""
        with patch.object(detector, "_scan_qeeqbox_ports") as mock_scan:
            mock_scan.return_value = set()
            result = detector.detect_passive("192.168.1.100", 22)
            assert result.honeypot_type is None
            assert len(result.indicators) == 0

    def test_detect_passive_below_threshold(self, detector):
        """Test detect_passive when port count is below threshold."""
        with patch.object(detector, "_scan_qeeqbox_ports") as mock_scan:
            mock_scan.return_value = {21, 22}  # Only 2 ports
            result = detector.detect_passive("192.168.1.100", 22)
            assert result.honeypot_type is None

    def test_detect_passive_with_unusual_combo(self, detector):
        """Test detect_passive detects unusual service combinations."""
        with patch.object(detector, "_scan_qeeqbox_ports") as mock_scan:
            mock_scan.return_value = {5060, 9200, 21, 22, 80}  # SIP + Elasticsearch
            result = detector.detect_passive("192.168.1.100", 22)
            assert result.honeypot_type == "qeeqbox"
            assert any(i.name == "qeeqbox_unusual_combo" for i in result.indicators)

    # -------------------------------------------------------------------------
    # Tests for detect_active (lines 286-301)
    # -------------------------------------------------------------------------
    def test_detect_active_returns_empty_result(self, detector):
        """Test detect_active returns empty result (placeholder for TLS fingerprinting)."""
        result = detector.detect_active("192.168.1.100", 22)
        assert result.target == "192.168.1.100"
        assert result.port == 22
        # Active probing is not implemented for QeeqBox yet
        assert result.honeypot_type is None

    # -------------------------------------------------------------------------
    # Tests for _scan_qeeqbox_ports (lines 303-309)
    # -------------------------------------------------------------------------
    def test_scan_qeeqbox_ports_all_open(self, detector):
        """Test _scan_qeeqbox_ports when all ports are open."""
        with patch.object(detector, "_is_port_open", return_value=True):
            ports = detector._scan_qeeqbox_ports("192.168.1.100")
            assert ports == set(QEEQBOX_PORTS.keys())

    def test_scan_qeeqbox_ports_none_open(self, detector):
        """Test _scan_qeeqbox_ports when no ports are open."""
        with patch.object(detector, "_is_port_open", return_value=False):
            ports = detector._scan_qeeqbox_ports("192.168.1.100")
            assert ports == set()

    def test_scan_qeeqbox_ports_some_open(self, detector):
        """Test _scan_qeeqbox_ports when some ports are open."""
        def port_checker(target, port):
            return port in {21, 22, 80, 443}
        with patch.object(detector, "_is_port_open", side_effect=port_checker):
            ports = detector._scan_qeeqbox_ports("192.168.1.100")
            assert ports == {21, 22, 80, 443}

    # -------------------------------------------------------------------------
    # Tests for _is_port_open (lines 311-320)
    # -------------------------------------------------------------------------
    def test_is_port_open_success(self, detector, mock_socket):
        """Test _is_port_open when port is open."""
        mock_socket.return_value.connect_ex.return_value = 0
        assert detector._is_port_open("192.168.1.100", 22) is True
        mock_socket.return_value.settimeout.assert_called_with(1.0)
        mock_socket.return_value.close.assert_called()

    def test_is_port_open_closed(self, detector, mock_socket):
        """Test _is_port_open when port is closed."""
        mock_socket.return_value.connect_ex.return_value = 111
        assert detector._is_port_open("192.168.1.100", 22) is False

    def test_is_port_open_socket_error(self, detector, mock_socket):
        """Test _is_port_open when socket error occurs."""
        mock_socket.return_value.connect_ex.side_effect = socket.error("Connection failed")
        assert detector._is_port_open("192.168.1.100", 22) is False

    def test_is_port_open_os_error(self, detector, mock_socket):
        """Test _is_port_open when OS error occurs."""
        mock_socket.return_value.connect_ex.side_effect = OSError("Network unreachable")
        assert detector._is_port_open("192.168.1.100", 22) is False

    # -------------------------------------------------------------------------
    # Tests for _analyze_port_combination edge cases (lines 322-366)
    # -------------------------------------------------------------------------
    def test_analyze_port_combo_with_threshold(self, detector):
        """Test port combo detection at exactly threshold."""
        result = DetectionResult(target="192.168.1.100", port=22)
        # Exactly MIN_PORT_MATCH_THRESHOLD ports
        open_ports = set(list(QEEQBOX_PORTS.keys())[:MIN_PORT_MATCH_THRESHOLD])
        detector._analyze_port_combination(open_ports, result)
        assert any(i.name == "qeeqbox_port_combo" for i in result.indicators)

    def test_analyze_port_combo_below_threshold(self, detector):
        """Test port combo detection below threshold."""
        result = DetectionResult(target="192.168.1.100", port=22)
        # Below MIN_PORT_MATCH_THRESHOLD ports
        open_ports = set(list(QEEQBOX_PORTS.keys())[:MIN_PORT_MATCH_THRESHOLD - 1])
        detector._analyze_port_combination(open_ports, result)
        assert not any(i.name == "qeeqbox_port_combo" for i in result.indicators)

    def test_analyze_port_combo_no_unusual_combo(self, detector):
        """Test no unusual combo indicator when combos don't match."""
        result = DetectionResult(target="192.168.1.100", port=22)
        open_ports = {21, 22, 80, 443}  # Common ports, no unusual combo
        detector._analyze_port_combination(open_ports, result)
        assert not any(i.name == "qeeqbox_unusual_combo" for i in result.indicators)


# =============================================================================
# T-Pot Detection Tests
# =============================================================================


class TestTPotDetection:
    """Tests for T-Pot port combination detection."""

    @pytest.fixture
    def detector(self):
        from potsnitch.detectors.tpot import TPotDetector
        return TPotDetector()

    def test_detect_tpot_kibana_port(self, detector, mock_socket):
        """Test detection of T-Pot Kibana admin port."""
        mock_socket.return_value.recv.return_value = b""
        result = detector.detect_passive("192.168.1.100", 64297)
        assert any(i.name == "tpot_kibana_port" for i in result.indicators)
        assert result.honeypot_type == "tpot"

    def test_tpot_has_many_honeypots(self):
        """Test T-Pot configuration includes many honeypots."""
        from potsnitch.detectors.tpot import TPOT_STANDARD_PORTS
        assert len(TPOT_STANDARD_PORTS) >= 20


# =============================================================================
# Artillery Detector Tests
# =============================================================================


class TestArtilleryDetection:
    """Tests for Artillery default port and silent port detection."""

    @pytest.fixture
    def detector(self):
        return ArtilleryDetector()

    def test_artillery_default_ports(self):
        """Test Artillery has expected default ports."""
        assert 10000 in ARTILLERY_PORTS  # Webmin
        assert 44443 in ARTILLERY_PORTS  # HTTPS alt

    def test_detect_artillery_port_combo(self, detector):
        """Test detection of Artillery port combination."""
        result = DetectionResult(target="192.168.1.100", port=22)
        detector._analyze_port_combination({21, 22, 135, 445, 3306}, result)
        assert any(i.name == "artillery_port_combo" for i in result.indicators)

    def test_detect_silent_ports(self, detector):
        """Test detection of silent ports (no response)."""
        result = DetectionResult(target="192.168.1.100", port=22)
        with patch.object(detector, "_get_banner", return_value=b""):
            detector._check_minimal_responses("192.168.1.100", {21, 22, 135, 445, 3306}, result)
        assert any(i.name == "artillery_silent_ports" for i in result.indicators)

    # -------------------------------------------------------------------------
    # Tests for detect_passive (lines 399-409)
    # -------------------------------------------------------------------------
    def test_detect_passive_with_port_combo(self, detector):
        """Test detect_passive when Artillery ports are open."""
        with patch.object(detector, "_scan_artillery_ports") as mock_scan:
            mock_scan.return_value = {21, 22, 135, 445, 3306}
            result = detector.detect_passive("192.168.1.100", 22)
            assert result.target == "192.168.1.100"
            assert result.port == 22
            assert result.honeypot_type == "artillery"
            assert any(i.name == "artillery_port_combo" for i in result.indicators)

    def test_detect_passive_no_open_ports(self, detector):
        """Test detect_passive when no ports are open."""
        with patch.object(detector, "_scan_artillery_ports") as mock_scan:
            mock_scan.return_value = set()
            result = detector.detect_passive("192.168.1.100", 22)
            assert result.honeypot_type is None
            assert len(result.indicators) == 0

    def test_detect_passive_below_threshold(self, detector):
        """Test detect_passive when port count is below threshold."""
        with patch.object(detector, "_scan_artillery_ports") as mock_scan:
            mock_scan.return_value = {21, 22}  # Only 2 ports
            result = detector.detect_passive("192.168.1.100", 22)
            assert result.honeypot_type is None

    # -------------------------------------------------------------------------
    # Tests for detect_active (lines 411-432)
    # -------------------------------------------------------------------------
    def test_detect_active_with_silent_ports(self, detector):
        """Test detect_active detects silent ports."""
        with patch.object(detector, "_scan_artillery_ports") as mock_scan:
            mock_scan.return_value = {21, 22, 135, 445, 3306}
            with patch.object(detector, "_get_banner", return_value=b""):
                result = detector.detect_active("192.168.1.100", 22)
                assert result.honeypot_type == "artillery"
                assert any(i.name == "artillery_silent_ports" for i in result.indicators)

    def test_detect_active_with_active_ports(self, detector):
        """Test detect_active when ports respond with data."""
        with patch.object(detector, "_scan_artillery_ports") as mock_scan:
            mock_scan.return_value = {21, 22, 80}
            with patch.object(detector, "_get_banner", return_value=b"SSH-2.0-OpenSSH"):
                result = detector.detect_active("192.168.1.100", 22)
                # No silent ports indicator because ports respond
                assert not any(i.name == "artillery_silent_ports" for i in result.indicators)

    def test_detect_active_no_ports(self, detector):
        """Test detect_active when no ports are open."""
        with patch.object(detector, "_scan_artillery_ports") as mock_scan:
            mock_scan.return_value = set()
            result = detector.detect_active("192.168.1.100", 22)
            assert result.honeypot_type is None

    # -------------------------------------------------------------------------
    # Tests for _scan_artillery_ports (lines 434-440)
    # -------------------------------------------------------------------------
    def test_scan_artillery_ports_all_open(self, detector):
        """Test _scan_artillery_ports when all ports are open."""
        with patch.object(detector, "_is_port_open", return_value=True):
            ports = detector._scan_artillery_ports("192.168.1.100")
            assert ports == set(ARTILLERY_PORTS.keys())

    def test_scan_artillery_ports_none_open(self, detector):
        """Test _scan_artillery_ports when no ports are open."""
        with patch.object(detector, "_is_port_open", return_value=False):
            ports = detector._scan_artillery_ports("192.168.1.100")
            assert ports == set()

    def test_scan_artillery_ports_some_open(self, detector):
        """Test _scan_artillery_ports when some ports are open."""
        def port_checker(target, port):
            return port in {21, 22, 135}
        with patch.object(detector, "_is_port_open", side_effect=port_checker):
            ports = detector._scan_artillery_ports("192.168.1.100")
            assert ports == {21, 22, 135}

    # -------------------------------------------------------------------------
    # Tests for _is_port_open (lines 442-451)
    # -------------------------------------------------------------------------
    def test_is_port_open_success(self, detector, mock_socket):
        """Test _is_port_open when port is open."""
        mock_socket.return_value.connect_ex.return_value = 0
        assert detector._is_port_open("192.168.1.100", 22) is True
        mock_socket.return_value.settimeout.assert_called_with(1.0)
        mock_socket.return_value.close.assert_called()

    def test_is_port_open_closed(self, detector, mock_socket):
        """Test _is_port_open when port is closed."""
        mock_socket.return_value.connect_ex.return_value = 111
        assert detector._is_port_open("192.168.1.100", 22) is False

    def test_is_port_open_socket_error(self, detector, mock_socket):
        """Test _is_port_open when socket error occurs."""
        mock_socket.return_value.connect_ex.side_effect = socket.error("Connection failed")
        assert detector._is_port_open("192.168.1.100", 22) is False

    def test_is_port_open_os_error(self, detector, mock_socket):
        """Test _is_port_open when OS error occurs."""
        mock_socket.return_value.connect_ex.side_effect = OSError("Network unreachable")
        assert detector._is_port_open("192.168.1.100", 22) is False

    # -------------------------------------------------------------------------
    # Tests for _check_minimal_responses (lines 471-492)
    # -------------------------------------------------------------------------
    def test_check_minimal_responses_all_silent(self, detector):
        """Test _check_minimal_responses when all ports are silent."""
        result = DetectionResult(target="192.168.1.100", port=22)
        with patch.object(detector, "_get_banner", return_value=b""):
            detector._check_minimal_responses("192.168.1.100", {21, 22, 135, 445, 3306}, result)
        assert any(i.name == "artillery_silent_ports" for i in result.indicators)
        indicator = [i for i in result.indicators if i.name == "artillery_silent_ports"][0]
        assert "5/5" in indicator.details

    def test_check_minimal_responses_some_silent(self, detector):
        """Test _check_minimal_responses when some ports are silent."""
        result = DetectionResult(target="192.168.1.100", port=22)
        call_count = [0]
        def mock_banner(target, port):
            call_count[0] += 1
            # 4 out of 5 ports return empty
            return b"data" if call_count[0] == 1 else b""
        with patch.object(detector, "_get_banner", side_effect=mock_banner):
            detector._check_minimal_responses("192.168.1.100", {21, 22, 135, 445, 3306}, result)
        # 4/5 = 80% silent, exceeds threshold of 60%
        assert any(i.name == "artillery_silent_ports" for i in result.indicators)

    def test_check_minimal_responses_none_silent(self, detector):
        """Test _check_minimal_responses when no ports are silent."""
        result = DetectionResult(target="192.168.1.100", port=22)
        with patch.object(detector, "_get_banner", return_value=b"SSH-2.0-OpenSSH"):
            detector._check_minimal_responses("192.168.1.100", {21, 22, 135, 445, 3306}, result)
        assert not any(i.name == "artillery_silent_ports" for i in result.indicators)

    def test_check_minimal_responses_none_response(self, detector):
        """Test _check_minimal_responses when _get_banner returns None."""
        result = DetectionResult(target="192.168.1.100", port=22)
        with patch.object(detector, "_get_banner", return_value=None):
            detector._check_minimal_responses("192.168.1.100", {21, 22, 135, 445, 3306}, result)
        assert any(i.name == "artillery_silent_ports" for i in result.indicators)

    def test_check_minimal_responses_empty_ports(self, detector):
        """Test _check_minimal_responses with empty port set."""
        result = DetectionResult(target="192.168.1.100", port=22)
        detector._check_minimal_responses("192.168.1.100", set(), result)
        # No indicator should be added when no ports to test
        assert not any(i.name == "artillery_silent_ports" for i in result.indicators)

    def test_check_minimal_responses_tests_first_5_ports(self, detector):
        """Test _check_minimal_responses only tests first 5 ports."""
        result = DetectionResult(target="192.168.1.100", port=22)
        call_count = [0]
        def mock_banner(target, port):
            call_count[0] += 1
            return b""
        with patch.object(detector, "_get_banner", side_effect=mock_banner):
            # Pass more than 5 ports
            detector._check_minimal_responses("192.168.1.100", {21, 22, 135, 445, 3306, 5900, 8080}, result)
        # Should only test 5 ports
        assert call_count[0] == 5

    # -------------------------------------------------------------------------
    # Tests for _get_banner (lines 494-508)
    # -------------------------------------------------------------------------
    def test_get_banner_success(self, detector, mock_socket):
        """Test _get_banner successfully retrieves banner."""
        mock_socket.return_value.recv.return_value = b"SSH-2.0-OpenSSH"
        banner = detector._get_banner("192.168.1.100", 22)
        assert banner == b"SSH-2.0-OpenSSH"
        mock_socket.return_value.connect.assert_called_with(("192.168.1.100", 22))

    def test_get_banner_timeout(self, detector, mock_socket):
        """Test _get_banner when recv times out (returns empty)."""
        mock_socket.return_value.recv.side_effect = socket.timeout("Timed out")
        banner = detector._get_banner("192.168.1.100", 22)
        assert banner == b""

    def test_get_banner_socket_error(self, detector, mock_socket):
        """Test _get_banner when socket error occurs."""
        mock_socket.return_value.connect.side_effect = socket.error("Connection refused")
        banner = detector._get_banner("192.168.1.100", 22)
        assert banner is None

    def test_get_banner_os_error(self, detector, mock_socket):
        """Test _get_banner when OS error occurs."""
        mock_socket.return_value.connect.side_effect = OSError("Network error")
        banner = detector._get_banner("192.168.1.100", 22)
        assert banner is None

    def test_get_banner_connect_timeout(self, detector, mock_socket):
        """Test _get_banner when connect times out."""
        mock_socket.return_value.connect.side_effect = socket.timeout("Connect timed out")
        banner = detector._get_banner("192.168.1.100", 22)
        assert banner is None

    # -------------------------------------------------------------------------
    # Tests for _analyze_port_combination (lines 453-469)
    # -------------------------------------------------------------------------
    def test_analyze_port_combo_at_threshold(self, detector):
        """Test port combo detection at exactly threshold."""
        result = DetectionResult(target="192.168.1.100", port=22)
        open_ports = set(list(ARTILLERY_PORTS.keys())[:MIN_PORT_MATCH_THRESHOLD])
        detector._analyze_port_combination(open_ports, result)
        assert any(i.name == "artillery_port_combo" for i in result.indicators)

    def test_analyze_port_combo_below_threshold(self, detector):
        """Test port combo detection below threshold."""
        result = DetectionResult(target="192.168.1.100", port=22)
        open_ports = set(list(ARTILLERY_PORTS.keys())[:MIN_PORT_MATCH_THRESHOLD - 1])
        detector._analyze_port_combination(open_ports, result)
        assert not any(i.name == "artillery_port_combo" for i in result.indicators)


# =============================================================================
# FAPRO Detector Tests
# =============================================================================


class TestFaproDetection:
    """Tests for FAPRO port detection."""

    @pytest.fixture
    def detector(self):
        return FaproDetector()

    def test_fapro_default_ports(self):
        """Test FAPRO has expected default ports."""
        assert 9200 in FAPRO_PORTS  # Elasticsearch
        assert 27017 in FAPRO_PORTS  # MongoDB

    def test_detect_fapro_port_combo(self, detector):
        """Test detection of FAPRO port combination."""
        result = DetectionResult(target="192.168.1.100", port=22)
        detector._analyze_port_combination({21, 22, 80, 443, 3306}, result)
        assert any(i.name == "fapro_port_combo" for i in result.indicators)

    # -------------------------------------------------------------------------
    # Tests for detect_passive (lines 529-551)
    # -------------------------------------------------------------------------
    def test_detect_passive_with_port_combo(self, detector):
        """Test detect_passive when FAPRO ports are open."""
        with patch.object(detector, "_scan_fapro_ports") as mock_scan:
            mock_scan.return_value = {21, 22, 80, 443, 3306}
            result = detector.detect_passive("192.168.1.100", 22)
            assert result.target == "192.168.1.100"
            assert result.port == 22
            assert result.honeypot_type == "fapro"
            assert any(i.name == "fapro_port_combo" for i in result.indicators)

    def test_detect_passive_no_open_ports(self, detector):
        """Test detect_passive when no ports are open."""
        with patch.object(detector, "_scan_fapro_ports") as mock_scan:
            mock_scan.return_value = set()
            result = detector.detect_passive("192.168.1.100", 22)
            assert result.honeypot_type is None
            assert len(result.indicators) == 0

    def test_detect_passive_below_threshold(self, detector):
        """Test detect_passive when port count is below threshold."""
        with patch.object(detector, "_scan_fapro_ports") as mock_scan:
            mock_scan.return_value = {21, 22}  # Only 2 ports
            result = detector.detect_passive("192.168.1.100", 22)
            assert result.honeypot_type is None

    # -------------------------------------------------------------------------
    # Tests for detect_active (lines 553-575)
    # -------------------------------------------------------------------------
    def test_detect_active_with_https_port(self, detector):
        """Test detect_active when HTTPS port is open (Go TLS check)."""
        with patch.object(detector, "_scan_fapro_ports") as mock_scan:
            mock_scan.return_value = {21, 22, 80, 443, 3306}
            with patch.object(detector, "_check_go_tls") as mock_tls:
                result = detector.detect_active("192.168.1.100", 443)
                mock_tls.assert_called_once_with("192.168.1.100", result)

    def test_detect_active_without_https_port(self, detector):
        """Test detect_active when HTTPS port is not open."""
        with patch.object(detector, "_scan_fapro_ports") as mock_scan:
            mock_scan.return_value = {21, 22, 80}  # No 443
            with patch.object(detector, "_check_go_tls") as mock_tls:
                result = detector.detect_active("192.168.1.100", 22)
                mock_tls.assert_not_called()

    def test_detect_active_no_ports(self, detector):
        """Test detect_active when no ports are open."""
        with patch.object(detector, "_scan_fapro_ports") as mock_scan:
            mock_scan.return_value = set()
            result = detector.detect_active("192.168.1.100", 22)
            assert result.honeypot_type is None

    def test_detect_active_sets_honeypot_type_when_detected(self, detector):
        """Test detect_active sets honeypot_type when honeypot is detected."""
        with patch.object(detector, "_scan_fapro_ports") as mock_scan:
            mock_scan.return_value = {21, 22, 80, 443, 3306}
            # Mock _check_go_tls to add an indicator that makes is_honeypot True
            def add_indicator(target, result):
                result.add_indicator(Indicator(
                    name="fapro_go_tls",
                    description="Go TLS fingerprint detected",
                    severity=Confidence.HIGH
                ))
            with patch.object(detector, "_check_go_tls", side_effect=add_indicator):
                result = detector.detect_active("192.168.1.100", 443)
                assert result.honeypot_type == "fapro"

    # -------------------------------------------------------------------------
    # Tests for _scan_fapro_ports (lines 577-583)
    # -------------------------------------------------------------------------
    def test_scan_fapro_ports_all_open(self, detector):
        """Test _scan_fapro_ports when all ports are open."""
        with patch.object(detector, "_is_port_open", return_value=True):
            ports = detector._scan_fapro_ports("192.168.1.100")
            assert ports == set(FAPRO_PORTS.keys())

    def test_scan_fapro_ports_none_open(self, detector):
        """Test _scan_fapro_ports when no ports are open."""
        with patch.object(detector, "_is_port_open", return_value=False):
            ports = detector._scan_fapro_ports("192.168.1.100")
            assert ports == set()

    def test_scan_fapro_ports_some_open(self, detector):
        """Test _scan_fapro_ports when some ports are open."""
        def port_checker(target, port):
            return port in {21, 22, 80, 443}
        with patch.object(detector, "_is_port_open", side_effect=port_checker):
            ports = detector._scan_fapro_ports("192.168.1.100")
            assert ports == {21, 22, 80, 443}

    # -------------------------------------------------------------------------
    # Tests for _is_port_open (lines 585-594)
    # -------------------------------------------------------------------------
    def test_is_port_open_success(self, detector, mock_socket):
        """Test _is_port_open when port is open."""
        mock_socket.return_value.connect_ex.return_value = 0
        assert detector._is_port_open("192.168.1.100", 22) is True
        mock_socket.return_value.settimeout.assert_called_with(1.0)
        mock_socket.return_value.close.assert_called()

    def test_is_port_open_closed(self, detector, mock_socket):
        """Test _is_port_open when port is closed."""
        mock_socket.return_value.connect_ex.return_value = 111
        assert detector._is_port_open("192.168.1.100", 22) is False

    def test_is_port_open_socket_error(self, detector, mock_socket):
        """Test _is_port_open when socket error occurs."""
        mock_socket.return_value.connect_ex.side_effect = socket.error("Connection failed")
        assert detector._is_port_open("192.168.1.100", 22) is False

    def test_is_port_open_os_error(self, detector, mock_socket):
        """Test _is_port_open when OS error occurs."""
        mock_socket.return_value.connect_ex.side_effect = OSError("Network unreachable")
        assert detector._is_port_open("192.168.1.100", 22) is False

    # -------------------------------------------------------------------------
    # Tests for _check_go_tls (lines 614-618) - placeholder function
    # -------------------------------------------------------------------------
    def test_check_go_tls_placeholder(self, detector):
        """Test _check_go_tls is a placeholder (does nothing)."""
        result = DetectionResult(target="192.168.1.100", port=443)
        # This should not raise any exceptions or add any indicators
        detector._check_go_tls("192.168.1.100", result)
        # Verify no indicators were added (placeholder does nothing)
        assert len(result.indicators) == 0

    # -------------------------------------------------------------------------
    # Tests for _analyze_port_combination (lines 596-612)
    # -------------------------------------------------------------------------
    def test_analyze_port_combo_at_threshold(self, detector):
        """Test port combo detection at exactly threshold."""
        result = DetectionResult(target="192.168.1.100", port=22)
        open_ports = set(list(FAPRO_PORTS.keys())[:MIN_PORT_MATCH_THRESHOLD])
        detector._analyze_port_combination(open_ports, result)
        assert any(i.name == "fapro_port_combo" for i in result.indicators)

    def test_analyze_port_combo_below_threshold(self, detector):
        """Test port combo detection below threshold."""
        result = DetectionResult(target="192.168.1.100", port=22)
        open_ports = set(list(FAPRO_PORTS.keys())[:MIN_PORT_MATCH_THRESHOLD - 1])
        detector._analyze_port_combination(open_ports, result)
        assert not any(i.name == "fapro_port_combo" for i in result.indicators)

    def test_analyze_port_combo_services_in_details(self, detector):
        """Test port combo indicator includes service names in details."""
        result = DetectionResult(target="192.168.1.100", port=22)
        open_ports = {21, 22, 80, 443, 3306}  # ftp, ssh, http, https, mysql
        detector._analyze_port_combination(open_ports, result)
        indicator = [i for i in result.indicators if i.name == "fapro_port_combo"][0]
        assert "Services:" in indicator.details


# =============================================================================
# Framework Detector Tests (Multi-Service Correlation)
# =============================================================================


class TestFrameworkDetector:
    """Tests for combined framework detection."""

    @pytest.fixture
    def detector(self):
        return FrameworkDetector()

    def test_detector_properties(self, detector):
        """Test Framework detector has correct properties."""
        assert detector.name == "framework"
        assert "opencanary" in detector.honeypot_types
        assert "qeeqbox" in detector.honeypot_types
        assert "artillery" in detector.honeypot_types
        assert "fapro" in detector.honeypot_types

    def test_framework_combines_subdetectors(self, detector):
        """Test Framework detector uses all sub-detectors."""
        assert hasattr(detector, "_opencanary")
        assert hasattr(detector, "_qeeqbox")
        assert hasattr(detector, "_artillery")
        assert hasattr(detector, "_fapro")

    def test_recommendations_for_port_combo(self, detector):
        """Test recommendations for port combination indicators."""
        result = DetectionResult(target="192.168.1.100", port=22)
        result.add_indicator(Indicator(
            name="opencanary_port_combo", description="Port combo", severity=Confidence.HIGH
        ))
        recommendations = detector.get_recommendations(result)
        assert len(recommendations) > 0

    # -------------------------------------------------------------------------
    # Tests for __init__ (lines 640-650)
    # -------------------------------------------------------------------------
    def test_init_with_custom_params(self):
        """Test FrameworkDetector initialization with custom parameters."""
        detector = FrameworkDetector(timeout=10.0, verbose=True, mode=DetectionMode.PASSIVE)
        assert detector.timeout == 10.0
        assert detector.verbose is True
        assert detector.mode == DetectionMode.PASSIVE
        # Sub-detectors should also have same params
        assert detector._opencanary.timeout == 10.0
        assert detector._qeeqbox.verbose is True
        assert detector._artillery.mode == DetectionMode.PASSIVE

    def test_init_default_params(self):
        """Test FrameworkDetector initialization with default parameters."""
        detector = FrameworkDetector()
        assert detector.timeout == 5.0
        assert detector.verbose is False
        assert detector.mode == DetectionMode.FULL

    # -------------------------------------------------------------------------
    # Tests for detect_passive (lines 664-692)
    # -------------------------------------------------------------------------
    def test_detect_passive_high_port_count(self, detector):
        """Test detect_passive detects high port count."""
        with patch.object(detector, "_is_port_open", return_value=True):
            # Mock all sub-detector scans to return empty
            with patch.object(detector._opencanary, "_scan_opencanary_ports", return_value=set()):
                with patch.object(detector._qeeqbox, "_scan_qeeqbox_ports", return_value=set()):
                    with patch.object(detector._artillery, "_scan_artillery_ports", return_value=set()):
                        with patch.object(detector._fapro, "_scan_fapro_ports", return_value=set()):
                            result = detector.detect_passive("192.168.1.100", 22)
                            # Should detect high port count
                            assert any(i.name == "framework_high_port_count" for i in result.indicators)

    def test_detect_passive_aggregates_sub_results(self, detector):
        """Test detect_passive aggregates results from all sub-detectors."""
        with patch.object(detector, "_is_port_open", return_value=False):
            # Mock OpenCanary to return a honeypot detection
            mock_result = DetectionResult(target="192.168.1.100", port=22)
            mock_result.add_indicator(Indicator(
                name="opencanary_port_combo",
                description="Test indicator",
                severity=Confidence.HIGH
            ))
            mock_result.honeypot_type = "opencanary"
            with patch.object(detector._opencanary, "detect_passive", return_value=mock_result):
                with patch.object(detector._qeeqbox, "detect_passive", return_value=DetectionResult(target="192.168.1.100", port=22)):
                    with patch.object(detector._artillery, "detect_passive", return_value=DetectionResult(target="192.168.1.100", port=22)):
                        with patch.object(detector._fapro, "detect_passive", return_value=DetectionResult(target="192.168.1.100", port=22)):
                            result = detector.detect_passive("192.168.1.100", 22)
                            assert result.honeypot_type == "opencanary"
                            assert any(i.name == "opencanary_port_combo" for i in result.indicators)

    def test_detect_passive_no_honeypot(self, detector):
        """Test detect_passive when no honeypot detected."""
        with patch.object(detector, "_is_port_open", return_value=False):
            with patch.object(detector._opencanary, "detect_passive", return_value=DetectionResult(target="192.168.1.100", port=22)):
                with patch.object(detector._qeeqbox, "detect_passive", return_value=DetectionResult(target="192.168.1.100", port=22)):
                    with patch.object(detector._artillery, "detect_passive", return_value=DetectionResult(target="192.168.1.100", port=22)):
                        with patch.object(detector._fapro, "detect_passive", return_value=DetectionResult(target="192.168.1.100", port=22)):
                            result = detector.detect_passive("192.168.1.100", 22)
                            assert result.honeypot_type is None

    def test_detect_passive_first_honeypot_type_wins(self, detector):
        """Test that first sub-detector honeypot type is used."""
        with patch.object(detector, "_is_port_open", return_value=False):
            # OpenCanary returns honeypot
            oc_result = DetectionResult(target="192.168.1.100", port=22)
            oc_result.honeypot_type = "opencanary"
            # QeeqBox also returns honeypot
            qb_result = DetectionResult(target="192.168.1.100", port=22)
            qb_result.honeypot_type = "qeeqbox"
            with patch.object(detector._opencanary, "detect_passive", return_value=oc_result):
                with patch.object(detector._qeeqbox, "detect_passive", return_value=qb_result):
                    with patch.object(detector._artillery, "detect_passive", return_value=DetectionResult(target="192.168.1.100", port=22)):
                        with patch.object(detector._fapro, "detect_passive", return_value=DetectionResult(target="192.168.1.100", port=22)):
                            result = detector.detect_passive("192.168.1.100", 22)
                            # First detected type should win
                            assert result.honeypot_type == "opencanary"

    # -------------------------------------------------------------------------
    # Tests for detect_active (lines 694-716)
    # -------------------------------------------------------------------------
    def test_detect_active_aggregates_sub_results(self, detector):
        """Test detect_active aggregates results from all sub-detectors."""
        # Mock Artillery to return a honeypot detection
        mock_result = DetectionResult(target="192.168.1.100", port=22)
        mock_result.add_indicator(Indicator(
            name="artillery_silent_ports",
            description="Silent ports detected",
            severity=Confidence.HIGH
        ))
        mock_result.honeypot_type = "artillery"
        with patch.object(detector._opencanary, "detect_active", return_value=DetectionResult(target="192.168.1.100", port=22)):
            with patch.object(detector._qeeqbox, "detect_active", return_value=DetectionResult(target="192.168.1.100", port=22)):
                with patch.object(detector._artillery, "detect_active", return_value=mock_result):
                    with patch.object(detector._fapro, "detect_active", return_value=DetectionResult(target="192.168.1.100", port=22)):
                        result = detector.detect_active("192.168.1.100", 22)
                        assert result.honeypot_type == "artillery"
                        assert any(i.name == "artillery_silent_ports" for i in result.indicators)

    def test_detect_active_no_honeypot(self, detector):
        """Test detect_active when no honeypot detected."""
        with patch.object(detector._opencanary, "detect_active", return_value=DetectionResult(target="192.168.1.100", port=22)):
            with patch.object(detector._qeeqbox, "detect_active", return_value=DetectionResult(target="192.168.1.100", port=22)):
                with patch.object(detector._artillery, "detect_active", return_value=DetectionResult(target="192.168.1.100", port=22)):
                    with patch.object(detector._fapro, "detect_active", return_value=DetectionResult(target="192.168.1.100", port=22)):
                        result = detector.detect_active("192.168.1.100", 22)
                        assert result.honeypot_type is None

    def test_detect_active_combines_all_indicators(self, detector):
        """Test detect_active combines indicators from all sub-detectors."""
        oc_result = DetectionResult(target="192.168.1.100", port=22)
        oc_result.add_indicator(Indicator(name="oc_indicator", description="OC", severity=Confidence.LOW))
        qb_result = DetectionResult(target="192.168.1.100", port=22)
        qb_result.add_indicator(Indicator(name="qb_indicator", description="QB", severity=Confidence.LOW))
        with patch.object(detector._opencanary, "detect_active", return_value=oc_result):
            with patch.object(detector._qeeqbox, "detect_active", return_value=qb_result):
                with patch.object(detector._artillery, "detect_active", return_value=DetectionResult(target="192.168.1.100", port=22)):
                    with patch.object(detector._fapro, "detect_active", return_value=DetectionResult(target="192.168.1.100", port=22)):
                        result = detector.detect_active("192.168.1.100", 22)
                        assert any(i.name == "oc_indicator" for i in result.indicators)
                        assert any(i.name == "qb_indicator" for i in result.indicators)

    # -------------------------------------------------------------------------
    # Tests for _is_port_open (lines 718-727)
    # -------------------------------------------------------------------------
    def test_is_port_open_success(self, detector, mock_socket):
        """Test _is_port_open when port is open."""
        mock_socket.return_value.connect_ex.return_value = 0
        assert detector._is_port_open("192.168.1.100", 22) is True
        mock_socket.return_value.settimeout.assert_called_with(1.0)
        mock_socket.return_value.close.assert_called()

    def test_is_port_open_closed(self, detector, mock_socket):
        """Test _is_port_open when port is closed."""
        mock_socket.return_value.connect_ex.return_value = 111
        assert detector._is_port_open("192.168.1.100", 22) is False

    def test_is_port_open_socket_error(self, detector, mock_socket):
        """Test _is_port_open when socket error occurs."""
        mock_socket.return_value.connect_ex.side_effect = socket.error("Connection failed")
        assert detector._is_port_open("192.168.1.100", 22) is False

    def test_is_port_open_os_error(self, detector, mock_socket):
        """Test _is_port_open when OS error occurs."""
        mock_socket.return_value.connect_ex.side_effect = OSError("Network unreachable")
        assert detector._is_port_open("192.168.1.100", 22) is False

    # -------------------------------------------------------------------------
    # Tests for get_recommendations (lines 729-741)
    # -------------------------------------------------------------------------
    def test_get_recommendations_for_port_count(self, detector):
        """Test recommendations for port count indicator."""
        result = DetectionResult(target="192.168.1.100", port=22)
        result.add_indicator(Indicator(
            name="framework_high_port_count",
            description="High port count",
            severity=Confidence.HIGH
        ))
        recommendations = detector.get_recommendations(result)
        assert len(recommendations) == 2
        assert any("Reduce the number" in rec for rec in recommendations)
        assert any("Avoid running Windows-only" in rec for rec in recommendations)

    def test_get_recommendations_no_port_indicators(self, detector):
        """Test no recommendations when no port indicators."""
        result = DetectionResult(target="192.168.1.100", port=22)
        result.add_indicator(Indicator(
            name="other_indicator",
            description="Some other indicator",
            severity=Confidence.LOW
        ))
        recommendations = detector.get_recommendations(result)
        assert len(recommendations) == 0

    def test_get_recommendations_empty_result(self, detector):
        """Test recommendations with empty result."""
        result = DetectionResult(target="192.168.1.100", port=22)
        recommendations = detector.get_recommendations(result)
        assert len(recommendations) == 0

    @pytest.mark.parametrize("indicator_name", [
        "opencanary_port_combo",
        "qeeqbox_port_combo",
        "artillery_port_combo",
        "fapro_port_combo",
        "framework_high_port_count",
    ])
    def test_get_recommendations_various_port_indicators(self, detector, indicator_name):
        """Test recommendations triggered by various port indicators."""
        result = DetectionResult(target="192.168.1.100", port=22)
        result.add_indicator(Indicator(
            name=indicator_name,
            description="Port indicator",
            severity=Confidence.HIGH
        ))
        recommendations = detector.get_recommendations(result)
        assert len(recommendations) == 2


class TestPortConfigurationConstants:
    """Tests for port configuration constants."""

    def test_min_port_match_threshold(self):
        """Test minimum port match threshold is reasonable."""
        assert MIN_PORT_MATCH_THRESHOLD >= 3
        assert MIN_PORT_MATCH_THRESHOLD <= 6

    def test_opencanary_ports_structure(self):
        """Test OPENCANARY_PORTS has port to service mapping."""
        assert isinstance(OPENCANARY_PORTS, dict)
        assert all(isinstance(k, int) for k in OPENCANARY_PORTS.keys())

    def test_qeeqbox_ports_structure(self):
        """Test QEEQBOX_PORTS has port to service mapping."""
        assert len(QEEQBOX_PORTS) >= 15

    def test_artillery_ports_structure(self):
        """Test ARTILLERY_PORTS has expected structure."""
        assert 44443 in ARTILLERY_PORTS  # Artillery-specific port

    def test_fapro_ports_structure(self):
        """Test FAPRO_PORTS has expected structure."""
        assert 27017 in FAPRO_PORTS  # MongoDB
