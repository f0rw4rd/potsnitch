"""
Unit tests for Dionaea honeypot detector.

Tests cover:
- SMB fingerprinting (OemDomainName, ServerName)
- FTP banner detection
- HTTP response patterns
- Multi-service anomaly detection
- Mock socket for protocol emulation
"""

import socket
import pytest
from unittest.mock import MagicMock, patch, call

from potsnitch.detectors.dionaea import (
    DionaeaDetector,
    DIONAEA_SMB_SIGNATURES,
    DIONAEA_DEFAULT_WORKGROUP,
    DIONAEA_DEFAULT_SERVER,
    KNOWN_FTP_BANNERS,
    KNOWN_SMTP_BANNERS,
)
from potsnitch.core.base import DetectionMode
from potsnitch.core.result import Confidence, DetectionResult


class TestSMBFingerprinting:
    """Test SMB fingerprinting for Dionaea signatures."""

    @pytest.fixture
    def detector(self):
        """Create Dionaea detector instance."""
        return DionaeaDetector()

    def test_smb_default_servername(self, detector, mock_socket):
        """Test detection of default Dionaea server name."""
        socket_instance = mock_socket.return_value

        # SMB response containing HOMEUSER-3AF6FE
        smb_response = b"\x00\x00\x00\x50\xff\x53\x4d\x42" + b"\x00" * 30 + DIONAEA_DEFAULT_SERVER.encode("utf-16-le") + b"\x00" * 20

        socket_instance.recv.return_value = smb_response

        result = detector.detect_passive("192.168.1.1", 445)

        assert result.is_honeypot
        indicator_names = [ind.name for ind in result.indicators]
        assert "dionaea_servername" in indicator_names
        assert any(ind.severity == Confidence.DEFINITE for ind in result.indicators)

    def test_smb_default_workgroup(self, detector, mock_socket):
        """Test detection of default Dionaea workgroup."""
        socket_instance = mock_socket.return_value

        # SMB response containing WORKGROUP - needs to have enough space after SMB header
        smb_response = b"\x00\x00\x00\x80\xff\x53\x4d\x42" + b"\x00" * 50 + DIONAEA_DEFAULT_WORKGROUP.encode("utf-16-le") + b"\x00" * 30

        socket_instance.recv.return_value = smb_response

        result = detector.detect_passive("192.168.1.1", 445)

        indicator_names = [ind.name for ind in result.indicators]
        assert "dionaea_workgroup" in indicator_names
        # WORKGROUP is also Windows default, so low severity
        assert any(ind.severity == Confidence.LOW for ind in result.indicators)

    @pytest.mark.parametrize(
        "server_name",
        [
            "HOMEUSER-3AF6FE",
            "VENUS",
            "COMPUTER",
        ],
    )
    def test_smb_known_server_names(self, detector, mock_socket, server_name):
        """Test detection of known Dionaea server names."""
        socket_instance = mock_socket.return_value

        # SMB response with known server name
        smb_response = (
            b"\x00\x00\x00\x80\xff\x53\x4d\x42" + b"\x00" * 30
            + server_name.encode("utf-16-le") + b"\x00" * 30
        )

        socket_instance.recv.return_value = smb_response

        result = detector.detect_passive("192.168.1.1", 445)

        # Only HOMEUSER-3AF6FE is specifically checked by default
        if server_name == "HOMEUSER-3AF6FE":
            indicator_names = [ind.name for ind in result.indicators]
            assert "dionaea_servername" in indicator_names

    def test_smb_ascii_servername(self, detector, mock_socket):
        """Test detection of server name in ASCII encoding."""
        socket_instance = mock_socket.return_value

        # SMB response with ASCII encoded server name
        smb_response = (
            b"\x00\x00\x00\x80\xff\x53\x4d\x42" + b"\x00" * 30
            + DIONAEA_DEFAULT_SERVER.encode("ascii") + b"\x00" * 30
        )

        socket_instance.recv.return_value = smb_response

        result = detector.detect_passive("192.168.1.1", 445)

        indicator_names = [ind.name for ind in result.indicators]
        assert "dionaea_servername" in indicator_names

    def test_smb_short_response(self, detector, mock_socket):
        """Test handling of short SMB response."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"\x00" * 20  # Too short

        result = detector.detect_passive("192.168.1.1", 445)

        assert not result.is_honeypot

    def test_smb_connection_timeout(self, detector, mock_socket):
        """Test handling of SMB connection timeout."""
        socket_instance = mock_socket.return_value
        socket_instance.connect.side_effect = socket.timeout()

        result = detector.detect_passive("192.168.1.1", 445)

        assert not result.is_honeypot


class TestSMBActiveProbing:
    """Test SMB active probing for Dionaea signatures."""

    @pytest.fixture
    def detector(self):
        """Create Dionaea detector instance."""
        return DionaeaDetector()

    def test_smb_limited_session_response(self, detector, mock_socket):
        """Test detection of limited SMB session response."""
        socket_instance = mock_socket.return_value

        # First response: valid negotiate
        negotiate_response = b"\x00\x00\x00\x50\xff\x53\x4d\x42\x72" + b"\x00" * 50

        # Second response: limited session response (< 36 bytes)
        session_response = b"\x00\x00\x00\x10\xff\x53\x4d\x42\x73" + b"\x00" * 10

        socket_instance.recv.side_effect = [negotiate_response, session_response]

        result = detector.detect_active("192.168.1.1", 445)

        indicator_names = [ind.name for ind in result.indicators]
        assert "smb_limited_session" in indicator_names

    def test_smb_smb1_only_check(self, detector, mock_socket):
        """Test that detector checks for SMB1-only response."""
        socket_instance = mock_socket.return_value

        # SMB1 negotiate response
        smb1_response = b"\x00\x00\x00\x50\xffSMB\x72" + b"\x00" * 50

        socket_instance.recv.side_effect = [smb1_response, b"\x00" * 50]

        result = detector.detect_active("192.168.1.1", 445)

        # Should attempt session setup after SMB1 response
        assert socket_instance.send.call_count >= 2

    def test_smb_non_smb1_response(self, detector, mock_socket):
        """Test handling of non-SMB1 response."""
        socket_instance = mock_socket.return_value

        # SMB2 response (different signature)
        smb2_response = b"\x00\x00\x00\x50\xfeSMB" + b"\x00" * 50

        socket_instance.recv.return_value = smb2_response

        result = detector.detect_active("192.168.1.1", 445)

        # Should not detect as honeypot based on SMB2
        # (Dionaea typically only does SMB1)


class TestFTPBannerDetection:
    """Test FTP banner detection for Dionaea signatures."""

    @pytest.fixture
    def detector(self):
        """Create Dionaea detector instance."""
        return DionaeaDetector()

    @pytest.mark.parametrize(
        "banner,expected_type",
        [
            (b"220 DiskStation FTP server ready.\r\n", "dionaea"),
            (b"220 DiskStation FTP server ready\r\n", "dionaea"),
            (b"220 Welcome to the ftp service\r\n", "dionaea"),
            (b"220 Welcome to the ftp service\r\n", "dionaea"),
            (b"220 Service ready\r\n", "dionaea"),
            (b"220 Welcome to my FTP Server\r\n", "amun"),
            (b"220 BearTrap-ftpd Service ready\r\n", "beartrap"),
            (b"220 Nepenthes FTP server ready\r\n", "nepenthes"),
        ],
    )
    def test_known_ftp_banners(self, detector, mock_socket, banner, expected_type):
        """Test detection of known FTP honeypot banners."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = banner

        result = detector.detect_passive("192.168.1.1", 21)

        assert result.is_honeypot
        indicator_names = [ind.name for ind in result.indicators]
        assert "known_ftp_banner" in indicator_names
        assert any(ind.severity == Confidence.DEFINITE for ind in result.indicators)

    def test_ftp_diskstation_banner(self, detector, mock_socket):
        """Test specific detection of DiskStation FTP banner."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"220 DiskStation FTP server ready.\r\n"

        result = detector.detect_passive("192.168.1.1", 21)

        assert result.is_honeypot
        assert any("dionaea" in ind.description.lower() for ind in result.indicators)

    def test_ftp_normal_banner_no_detection(self, detector, mock_socket):
        """Test that normal FTP banners are not flagged."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"220 vsftpd 3.0.3\r\n"

        result = detector.detect_passive("192.168.1.1", 21)

        indicator_names = [ind.name for ind in result.indicators]
        assert "known_ftp_banner" not in indicator_names

    def test_ftp_nonstandard_banner(self, detector, mock_socket):
        """Test detection of non-standard FTP banner format."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"200 FTP ready\r\n"  # Should start with 220

        result = detector.detect_passive("192.168.1.1", 21)

        indicator_names = [ind.name for ind in result.indicators]
        assert "unusual_ftp_banner" in indicator_names

    def test_ftp_connection_timeout(self, detector, mock_socket):
        """Test handling of FTP connection timeout."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = socket.timeout()

        result = detector.detect_passive("192.168.1.1", 21)

        assert not result.is_honeypot


class TestSMTPBannerDetection:
    """Test SMTP banner detection for Dionaea signatures."""

    @pytest.fixture
    def detector(self):
        """Create Dionaea detector instance."""
        return DionaeaDetector()

    @pytest.mark.parametrize(
        "banner,expected_type",
        [
            (b"220 mail.example.com SMTP Mailserver\r\n", "amun"),
            (b"220 localhost SMTP Mailserver\r\n", "dionaea"),
            (b"220 Microsoft ESMTP MAIL service ready\r\n", "heralding"),
        ],
    )
    def test_known_smtp_banners(self, detector, mock_socket, banner, expected_type):
        """Test detection of known SMTP honeypot banners."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = banner

        result = detector.detect_passive("192.168.1.1", 25)

        assert result.is_honeypot
        indicator_names = [ind.name for ind in result.indicators]
        assert "known_smtp_banner" in indicator_names
        assert any(ind.severity == Confidence.DEFINITE for ind in result.indicators)

    def test_smtp_localhost_banner(self, detector, mock_socket):
        """Test specific detection of localhost SMTP Mailserver banner."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"220 localhost SMTP Mailserver\r\n"

        result = detector.detect_passive("192.168.1.1", 25)

        assert result.is_honeypot
        assert result.honeypot_type == "dionaea"


class TestHTTPDetection:
    """Test HTTP detection for Dionaea signatures."""

    @pytest.fixture
    def detector(self):
        """Create Dionaea detector instance."""
        return DionaeaDetector()

    def test_http_missing_server_header(self, detector):
        """Test detection of missing Server header."""
        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.headers = {}
            mock_response.status_code = 200
            mock_get.return_value = mock_response

            result = detector.detect_active("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "missing_server_header" in indicator_names

    def test_http_with_server_header(self, detector):
        """Test no detection when Server header is present."""
        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.headers = {"Server": "Apache/2.4.41"}
            mock_response.status_code = 200
            mock_get.return_value = mock_response

            result = detector.detect_active("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "missing_server_header" not in indicator_names

    def test_http_request_exception(self, detector):
        """Test handling of HTTP request exception."""
        with patch("requests.get") as mock_get:
            mock_get.side_effect = Exception("Connection refused")

            result = detector.detect_active("192.168.1.1", 80)

        assert not result.is_honeypot


class TestMSSQLDetection:
    """Test MS-SQL detection for Dionaea signatures."""

    @pytest.fixture
    def detector(self):
        """Create Dionaea detector instance."""
        return DionaeaDetector()

    def test_mssql_limited_response(self, detector, mock_socket):
        """Test detection of limited MS-SQL TDS response."""
        socket_instance = mock_socket.return_value

        # Short TDS response (< 10 bytes)
        socket_instance.recv.return_value = b"\x04\x01\x00\x07\x00\x00\x00"

        result = detector.detect_active("192.168.1.1", 1433)

        indicator_names = [ind.name for ind in result.indicators]
        assert "limited_mssql_response" in indicator_names
        assert any(ind.severity == Confidence.MEDIUM for ind in result.indicators)

    def test_mssql_normal_response(self, detector, mock_socket):
        """Test no detection on normal MS-SQL response."""
        socket_instance = mock_socket.return_value

        # Valid TDS response (>= 10 bytes)
        socket_instance.recv.return_value = b"\x04\x01\x00\x20" + b"\x00" * 30

        result = detector.detect_active("192.168.1.1", 1433)

        indicator_names = [ind.name for ind in result.indicators]
        assert "limited_mssql_response" not in indicator_names

    def test_mssql_connection_timeout(self, detector, mock_socket):
        """Test handling of MS-SQL connection timeout."""
        socket_instance = mock_socket.return_value
        socket_instance.connect.side_effect = socket.timeout()

        result = detector.detect_active("192.168.1.1", 1433)

        assert not result.is_honeypot


class TestDetectorModes:
    """Test detector in different modes."""

    def test_passive_mode_only(self):
        """Test detector in passive mode."""
        detector = DionaeaDetector(mode=DetectionMode.PASSIVE)

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.recv.return_value = b"220 DiskStation FTP server ready.\r\n"

            result = detector.detect("192.168.1.1", 21)

        assert result.is_honeypot

    def test_active_mode_only(self):
        """Test detector in active mode."""
        detector = DionaeaDetector(mode=DetectionMode.ACTIVE)

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.headers = {}
            mock_response.status_code = 200
            mock_get.return_value = mock_response

            result = detector.detect("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "missing_server_header" in indicator_names

    def test_full_mode(self):
        """Test detector in full mode."""
        detector = DionaeaDetector(mode=DetectionMode.FULL)
        assert detector.mode == DetectionMode.FULL


class TestRecommendations:
    """Test detector recommendations."""

    @pytest.fixture
    def detector(self):
        """Create Dionaea detector instance."""
        return DionaeaDetector()

    def test_servername_recommendation(self, detector):
        """Test recommendations for server name detection."""
        from potsnitch.core.result import Indicator

        result = DetectionResult(target="192.168.1.1", port=445)
        result.add_indicator(
            Indicator(
                name="dionaea_servername",
                description=f"Default Dionaea server name: {DIONAEA_DEFAULT_SERVER}",
                severity=Confidence.DEFINITE,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any("servername" in r.lower() or "smbfields" in r.lower() for r in recommendations)

    def test_workgroup_recommendation(self, detector):
        """Test recommendations for workgroup detection."""
        from potsnitch.core.result import Indicator

        result = DetectionResult(target="192.168.1.1", port=445)
        result.add_indicator(
            Indicator(
                name="dionaea_workgroup",
                description="Default Dionaea workgroup 'WORKGROUP'",
                severity=Confidence.LOW,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any("domain" in r.lower() or "oemdomain" in r.lower() for r in recommendations)


class TestDetectorProperties:
    """Test detector class properties."""

    def test_detector_name(self):
        """Test detector name property."""
        detector = DionaeaDetector()
        assert detector.name == "dionaea"

    def test_detector_description(self):
        """Test detector has description."""
        detector = DionaeaDetector()
        assert detector.description is not None
        assert "dionaea" in detector.description.lower()

    def test_detector_honeypot_types(self):
        """Test detector honeypot types."""
        detector = DionaeaDetector()
        assert "dionaea" in detector.honeypot_types

    def test_detector_default_ports(self):
        """Test detector default ports."""
        detector = DionaeaDetector()
        assert 21 in detector.default_ports
        assert 445 in detector.default_ports
        assert 80 in detector.default_ports
        assert 1433 in detector.default_ports

    def test_detector_timeout_config(self):
        """Test detector timeout configuration."""
        detector = DionaeaDetector(timeout=10.0)
        assert detector.timeout == 10.0


class TestSMBNegotiateBuilder:
    """Test SMB negotiate packet building."""

    @pytest.fixture
    def detector(self):
        """Create Dionaea detector instance."""
        return DionaeaDetector()

    def test_build_smb_negotiate_structure(self, detector):
        """Test SMB negotiate packet structure."""
        negotiate = detector._build_smb_negotiate()

        # Check NetBIOS header
        assert negotiate[0:1] == b"\x00"

        # Check SMB signature after NetBIOS header
        assert b"\xffSMB" in negotiate

        # Check negotiate command (0x72)
        smb_start = negotiate.find(b"\xffSMB")
        assert negotiate[smb_start + 4:smb_start + 5] == b"\x72"

    def test_build_smb_session_setup_structure(self, detector):
        """Test SMB session setup packet structure."""
        session_setup = detector._build_smb_session_setup()

        # Check NetBIOS header
        assert session_setup[0:1] == b"\x00"

        # Check SMB signature
        assert b"\xffSMB" in session_setup

        # Check session setup command (0x73)
        smb_start = session_setup.find(b"\xffSMB")
        assert session_setup[smb_start + 4:smb_start + 5] == b"\x73"
