"""
Unit tests for FTP honeypot detector.

Tests cover:
- Banner detection (dionaea, cowrie FTP, qeeqbox)
- FEAT command response analysis
- Anonymous login detection
- Passive mode detection
- Credential testing
- Accept-all behavior detection
"""

import socket
import pytest
from unittest.mock import MagicMock, patch, call

from potsnitch.detectors.ftp import (
    FTPDetector,
    FTP_HONEYPOT_BANNERS,
    FTP_PROBE_COMMANDS,
)
from potsnitch.core.base import DetectionMode
from potsnitch.core.result import Confidence


class TestFTPBannerDetection:
    """Test FTP banner-based detection."""

    @pytest.mark.parametrize(
        "banner,expected_indicator",
        [
            (b"220 DiskStation FTP server ready\r\n", "ftp_honeypot_banner"),
            (b"220 Dionaea FTP\r\n", "ftp_honeypot_banner"),
            (b"220 Welcome to FTP server\r\n", "ftp_honeypot_banner"),
            (b"220 FTP Server Ready\r\n", "ftp_honeypot_banner"),
            (b"220 qeeqbox FTP service\r\n", "ftp_honeypot_banner"),
        ],
    )
    def test_known_honeypot_banners(self, banner, expected_indicator):
        """Test detection of known FTP honeypot banners."""
        detector = FTPDetector()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.recv.return_value = banner

            with patch(
                "potsnitch.detectors.ftp.measure_connection_time"
            ) as mock_timing:
                mock_timing.return_value = MagicMock(success=True, elapsed=0.1)

                result = detector.detect_passive("192.168.1.1", 21)

        assert result.is_honeypot
        indicator_names = [ind.name for ind in result.indicators]
        assert expected_indicator in indicator_names

    def test_dionaea_signature_detection(self):
        """Test explicit Dionaea signature in banner (not matching known banners)."""
        detector = FTPDetector()
        # Use a banner that contains 'dionaea' but doesn't match known honeypot banners exactly
        banner = b"220 Some FTP server - powered by dionaea\r\n"

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.recv.return_value = banner

            with patch(
                "potsnitch.detectors.ftp.measure_connection_time"
            ) as mock_timing:
                mock_timing.return_value = MagicMock(success=True, elapsed=0.1)

                result = detector.detect_passive("192.168.1.1", 21)

        assert result.is_honeypot
        indicator_names = [ind.name for ind in result.indicators]
        assert "ftp_dionaea_signature" in indicator_names
        assert any(
            ind.severity == Confidence.DEFINITE for ind in result.indicators
        )

    def test_instant_banner_detection(self):
        """Test detection of instant banner response."""
        detector = FTPDetector()
        banner = b"220 Normal FTP Server\r\n"

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.recv.return_value = banner

            with patch(
                "potsnitch.detectors.ftp.measure_connection_time"
            ) as mock_timing:
                # Simulate instant response (< 5ms)
                mock_timing.return_value = MagicMock(success=True, elapsed=0.003)

                result = detector.detect_passive("192.168.1.1", 21)

        indicator_names = [ind.name for ind in result.indicators]
        assert "ftp_instant_banner" in indicator_names

    def test_normal_banner_no_detection(self):
        """Test that normal FTP banners don't trigger detection."""
        detector = FTPDetector()
        banner = b"220 vsftpd 3.0.3\r\n"

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.recv.return_value = banner

            with patch(
                "potsnitch.detectors.ftp.measure_connection_time"
            ) as mock_timing:
                mock_timing.return_value = MagicMock(success=True, elapsed=0.1)

                result = detector.detect_passive("192.168.1.1", 21)

        assert not result.is_honeypot


class TestFTPFEATAnalysis:
    """Test FEAT command response analysis."""

    def test_few_features_detection(self):
        """Test detection of minimal FEAT response."""
        detector = FTPDetector()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            # Simulate login success and minimal FEAT response
            mock_socket.recv.side_effect = [
                b"220 FTP ready\r\n",  # Banner
                b"331 Password required\r\n",  # USER response
                b"230 Login successful\r\n",  # PASS response
                b"502 MLSD not implemented\r\n",  # MLSD
                b"502 MLST not implemented\r\n",  # MLST
                b"502 EPSV not implemented\r\n",  # EPSV
                b"502 EPRT not implemented\r\n",  # EPRT
                b"502 AUTH not implemented\r\n",  # AUTH TLS
                b"502 SITE not implemented\r\n",  # SITE CHMOD
                b"502 MFMT not implemented\r\n",  # MFMT
                b"211-Features:\r\n SIZE\r\n211 End\r\n",  # FEAT (1 feature)
                b"215 UNIX Type: L8\r\n",  # SYST
                b"257 \"/\" is current directory\r\n",  # PWD
                b"221 Bye\r\n",  # QUIT
            ]

            # Mock the login test and other probe methods to avoid complex mocking
            with patch.object(
                detector, "_try_login", return_value=(True, 0.1)
            ), patch.object(
                detector, "_probe_commands", return_value=[]
            ), patch.object(
                detector, "_probe_invalid_payloads", return_value=[]
            ):
                result = detector.detect_active("192.168.1.1", 21)

        indicator_names = [ind.name for ind in result.indicators]
        assert "ftp_few_features" in indicator_names or "ftp_limited_implementation" in indicator_names

    def test_no_feat_detection(self):
        """Test detection when FEAT command is not supported."""
        detector = FTPDetector()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            mock_socket.recv.side_effect = [
                b"220 FTP ready\r\n",  # Banner
                b"331 Password required\r\n",  # USER response
                b"230 Login successful\r\n",  # PASS response
                b"502 Not implemented\r\n",  # MLSD
                b"502 Not implemented\r\n",  # MLST
                b"502 Not implemented\r\n",  # EPSV
                b"502 Not implemented\r\n",  # EPRT
                b"502 Not implemented\r\n",  # AUTH TLS
                b"502 Not implemented\r\n",  # SITE CHMOD
                b"502 Not implemented\r\n",  # MFMT
                b"500 FEAT not implemented\r\n",  # FEAT
                b"215 UNIX Type: L8\r\n",  # SYST
                b"257 \"/\"\r\n",  # PWD
                b"221 Bye\r\n",  # QUIT
            ]

            with patch.object(
                detector, "_try_login", return_value=(True, 0.1)
            ), patch.object(
                detector, "_probe_commands", return_value=[]
            ), patch.object(
                detector, "_probe_invalid_payloads", return_value=[]
            ):
                result = detector.detect_active("192.168.1.1", 21)

        indicator_names = [ind.name for ind in result.indicators]
        assert "ftp_no_feat" in indicator_names or "ftp_limited_implementation" in indicator_names


class TestFTPAnonymousLogin:
    """Test anonymous login detection."""

    def test_anonymous_login_accepted(self):
        """Test detection when anonymous login is accepted."""
        detector = FTPDetector()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            # Anonymous login succeeds
            mock_socket.recv.side_effect = [
                b"220 FTP ready\r\n",
                b"331 Password required for anonymous\r\n",
                b"230 Login successful\r\n",
            ]

            result = detector._probe_credentials("192.168.1.1", 21)

        assert len(result) > 0
        assert result[0].name == "ftp_default_cred_accepted"
        assert "anonymous" in result[0].description.lower()


class TestFTPAcceptAllDetection:
    """Test accept-all credential behavior detection."""

    def test_garbage_credentials_accepted(self):
        """Test detection when garbage credentials are accepted."""
        detector = FTPDetector()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            # All garbage credentials succeed
            mock_socket.recv.side_effect = [
                b"220 FTP ready\r\n",
                b"331 Password required\r\n",
                b"230 Login successful\r\n",
            ]

            result = detector._probe_accept_all("192.168.1.1", 21)

        assert len(result) > 0
        assert result[0].name == "ftp_accept_all"
        assert result[0].severity == Confidence.DEFINITE


class TestFTPCommandProbing:
    """Test FTP command support probing."""

    def test_limited_command_support(self):
        """Test detection of limited FTP command support."""
        detector = FTPDetector()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            # Most commands return 500/502
            mock_socket.recv.side_effect = [
                b"220 FTP ready\r\n",  # Banner for SYST
                b"500 Command not implemented\r\n",
                b"220 FTP ready\r\n",  # Banner for FEAT
                b"502 Command not implemented\r\n",
                b"220 FTP ready\r\n",  # Banner for STAT
                b"500 Command not implemented\r\n",
                b"220 FTP ready\r\n",  # Banner for HELP
                b"502 Command not implemented\r\n",
                b"220 FTP ready\r\n",  # Banner for SITE HELP
                b"500 Command not implemented\r\n",
            ]

            result = detector._probe_commands("192.168.1.1", 21)

        indicator_names = [ind.name for ind in result]
        assert "ftp_limited_commands" in indicator_names

    def test_uniform_response_detection(self):
        """Test detection of uniform responses to all commands."""
        detector = FTPDetector()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            # All commands return identical response
            identical_response = b"500 Error\r\n"
            responses = []
            for _ in FTP_PROBE_COMMANDS:
                responses.extend([b"220 FTP ready\r\n", identical_response])

            mock_socket.recv.side_effect = responses

            result = detector._probe_commands("192.168.1.1", 21)

        indicator_names = [ind.name for ind in result]
        assert "ftp_uniform_response" in indicator_names


class TestFTPInvalidPayloads:
    """Test FTP response to invalid payloads."""

    def test_uniform_error_responses(self):
        """Test detection of uniform error responses."""
        detector = FTPDetector()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            # All invalid payloads get identical response
            mock_socket.recv.side_effect = [
                b"220 FTP ready\r\n",
                b"500 Syntax error\r\n",
                b"220 FTP ready\r\n",
                b"500 Syntax error\r\n",
                b"220 FTP ready\r\n",
                b"500 Syntax error\r\n",
                b"220 FTP ready\r\n",
                b"500 Syntax error\r\n",
                b"220 FTP ready\r\n",
                b"500 Syntax error\r\n",
            ]

            result = detector._probe_invalid_payloads("192.168.1.1", 21)

        indicator_names = [ind.name for ind in result]
        assert "ftp_uniform_error" in indicator_names


class TestFTPPostLoginProbes:
    """Test post-login FTP probing for advanced honeypot detection."""

    def test_no_epsv_support(self):
        """Test detection of missing EPSV command support."""
        detector = FTPDetector()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            mock_socket.recv.side_effect = [
                b"220 FTP ready\r\n",  # Banner
                b"331 Password\r\n",  # USER
                b"230 Login OK\r\n",  # PASS
                b"200 MLSD OK\r\n",  # MLSD
                b"200 MLST OK\r\n",  # MLST
                b"502 EPSV not implemented\r\n",  # EPSV - not supported
                b"200 EPRT OK\r\n",  # EPRT
                b"502 AUTH not implemented\r\n",  # AUTH TLS
                b"200 SITE OK\r\n",  # SITE CHMOD
                b"200 MFMT OK\r\n",  # MFMT
                b"211-Features:\r\n SIZE\r\n MLSD\r\n MLST\r\n211 End\r\n",  # FEAT
                b"215 UNIX Type: L8\r\n",  # SYST
                b"257 \"/\"\r\n",  # PWD
                b"221 Bye\r\n",  # QUIT
            ]

            result = detector._probe_ftp_post_login(
                "192.168.1.1", 21, "test", "test"
            )

        indicator_names = [ind.name for ind in result]
        assert "ftp_no_epsv" in indicator_names

    def test_no_auth_tls_support(self):
        """Test detection of missing AUTH TLS support."""
        detector = FTPDetector()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            mock_socket.recv.side_effect = [
                b"220 FTP ready\r\n",
                b"331 Password\r\n",
                b"230 Login OK\r\n",
                b"200 OK\r\n",  # MLSD
                b"200 OK\r\n",  # MLST
                b"200 OK\r\n",  # EPSV
                b"200 OK\r\n",  # EPRT
                b"502 AUTH TLS not implemented\r\n",  # AUTH TLS
                b"200 OK\r\n",  # SITE CHMOD
                b"200 OK\r\n",  # MFMT
                b"211-Features:\r\n SIZE\r\n211 End\r\n",  # FEAT
                b"215 UNIX Type: L8\r\n",  # SYST
                b"257 \"/\"\r\n",  # PWD
                b"221 Bye\r\n",  # QUIT
            ]

            result = detector._probe_ftp_post_login(
                "192.168.1.1", 21, "test", "test"
            )

        indicator_names = [ind.name for ind in result]
        assert "ftp_no_auth_tls" in indicator_names


class TestFTPDetectorModes:
    """Test FTP detector in different modes."""

    def test_passive_mode_only(self):
        """Test detector in passive mode."""
        detector = FTPDetector(mode=DetectionMode.PASSIVE)

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.recv.return_value = b"220 Dionaea FTP\r\n"

            with patch(
                "potsnitch.detectors.ftp.measure_connection_time"
            ) as mock_timing:
                mock_timing.return_value = MagicMock(success=True, elapsed=0.1)

                result = detector.detect("192.168.1.1", 21)

        assert result.is_honeypot

    def test_active_mode_only(self):
        """Test detector in active mode."""
        detector = FTPDetector(mode=DetectionMode.ACTIVE)

        # Mock accept-all behavior detection
        with patch.object(
            detector, "_probe_credentials_with_postlogin"
        ) as mock_creds, patch.object(
            detector, "_probe_accept_all_with_postlogin"
        ) as mock_accept, patch.object(
            detector, "_probe_commands", return_value=[]
        ), patch.object(
            detector, "_probe_invalid_payloads", return_value=[]
        ):
            from potsnitch.core.result import Indicator

            # Simulate accept-all detection
            mock_creds.return_value = ([], None)
            mock_accept.return_value = (
                [
                    Indicator(
                        name="ftp_accept_all",
                        description="FTP accepts garbage credentials",
                        severity=Confidence.DEFINITE,
                        details="Accepted: garbage:creds",
                    )
                ],
                ("garbage", "creds"),
            )

            result = detector.detect("192.168.1.1", 21)

        assert result.is_honeypot


class TestFTPConnectionErrors:
    """Test FTP detector error handling."""

    def test_connection_timeout(self):
        """Test handling of connection timeout."""
        detector = FTPDetector(timeout=1.0)

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.connect.side_effect = socket.timeout()

            with patch(
                "potsnitch.detectors.ftp.measure_connection_time"
            ) as mock_timing:
                mock_timing.return_value = MagicMock(success=False, elapsed=1.0)

                result = detector.detect_passive("192.168.1.1", 21)

        assert not result.is_honeypot
        assert len(result.indicators) == 0

    def test_connection_refused(self):
        """Test handling of connection refused."""
        detector = FTPDetector()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.connect.side_effect = ConnectionRefusedError()

            with patch(
                "potsnitch.detectors.ftp.measure_connection_time"
            ) as mock_timing:
                mock_timing.return_value = MagicMock(success=False, elapsed=0.0)

                result = detector.detect_passive("192.168.1.1", 21)

        assert not result.is_honeypot
