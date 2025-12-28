"""
Unit tests for SMTP honeypot detector.

Tests cover:
- Banner detection (mailoney, heralding)
- EHLO response analysis
- Open relay detection
- AUTH mechanism probing
- VRFY/EXPN command testing
"""

import socket
import pytest
from unittest.mock import MagicMock, patch

from potsnitch.detectors.smtp import (
    SMTPDetector,
    SMTP_HONEYPOT_BANNERS,
    HONEYPOT_HOSTNAMES,
    SMTP_PROBE_COMMANDS,
)
from potsnitch.core.base import DetectionMode
from potsnitch.core.result import Confidence


class TestSMTPBannerDetection:
    """Test SMTP banner-based detection."""

    @pytest.mark.parametrize(
        "banner,expected_indicator",
        [
            (b"220 mail.example.com SMTP ready\r\n", "smtp_honeypot_banner"),
            (b"220 Microsoft ESMTP MAIL Service\r\n", "smtp_honeypot_banner"),
            (b"220 mail.honeypot.local ready\r\n", "smtp_honeypot_banner"),
            (b"220 qeeqbox SMTP service\r\n", "smtp_honeypot_banner"),
            (b"220 SMTP Honeypot ready\r\n", "smtp_honeypot_banner"),
        ],
    )
    def test_known_honeypot_banners(self, banner, expected_indicator):
        """Test detection of known SMTP honeypot banners."""
        detector = SMTPDetector()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.recv.return_value = banner

            with patch(
                "potsnitch.detectors.smtp.measure_connection_time"
            ) as mock_timing:
                mock_timing.return_value = MagicMock(success=True, elapsed=0.1)

                result = detector.detect_passive("192.168.1.1", 25)

        assert result.is_honeypot
        indicator_names = [ind.name for ind in result.indicators]
        assert expected_indicator in indicator_names

    @pytest.mark.parametrize(
        "hostname",
        [
            "mail.example.com",
            "mail.honeypot.local",
            "localhost",
            "example.com",
            "mail.test.local",
        ],
    )
    def test_default_hostname_detection(self, hostname):
        """Test detection of default/example hostnames."""
        detector = SMTPDetector()
        banner = f"220 {hostname} ESMTP ready\r\n".encode()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.recv.return_value = banner

            with patch(
                "potsnitch.detectors.smtp.measure_connection_time"
            ) as mock_timing:
                mock_timing.return_value = MagicMock(success=True, elapsed=0.1)

                result = detector.detect_passive("192.168.1.1", 25)

        indicator_names = [ind.name for ind in result.indicators]
        assert (
            "smtp_default_hostname" in indicator_names
            or "smtp_honeypot_banner" in indicator_names
        )

    def test_mailoney_signature_detection(self):
        """Test explicit Mailoney signature in banner."""
        detector = SMTPDetector()
        banner = b"220 mailoney SMTP honeypot\r\n"

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.recv.return_value = banner

            with patch(
                "potsnitch.detectors.smtp.measure_connection_time"
            ) as mock_timing:
                mock_timing.return_value = MagicMock(success=True, elapsed=0.1)

                result = detector.detect_passive("192.168.1.1", 25)

        assert result.is_honeypot
        indicator_names = [ind.name for ind in result.indicators]
        assert "smtp_mailoney_signature" in indicator_names
        assert any(
            ind.severity == Confidence.DEFINITE for ind in result.indicators
        )

    def test_instant_banner_detection(self):
        """Test detection of instant banner response."""
        detector = SMTPDetector()
        banner = b"220 mail.legitimate.com ESMTP Postfix\r\n"

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.recv.return_value = banner

            with patch(
                "potsnitch.detectors.smtp.measure_connection_time"
            ) as mock_timing:
                # Simulate instant response (< 5ms)
                mock_timing.return_value = MagicMock(success=True, elapsed=0.003)

                result = detector.detect_passive("192.168.1.1", 25)

        indicator_names = [ind.name for ind in result.indicators]
        assert "smtp_instant_banner" in indicator_names

    def test_normal_banner_no_detection(self):
        """Test that normal SMTP banners don't trigger detection."""
        detector = SMTPDetector()
        banner = b"220 mail.company.com ESMTP Postfix (Ubuntu)\r\n"

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.recv.return_value = banner

            with patch(
                "potsnitch.detectors.smtp.measure_connection_time"
            ) as mock_timing:
                mock_timing.return_value = MagicMock(success=True, elapsed=0.1)

                result = detector.detect_passive("192.168.1.1", 25)

        assert not result.is_honeypot


class TestSMTPEHLOAnalysis:
    """Test EHLO response analysis."""

    def test_limited_extensions_detection(self):
        """Test detection of limited SMTP extensions."""
        detector = SMTPDetector()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            # EHLO response missing most standard extensions
            mock_socket.recv.side_effect = [
                b"220 mail ESMTP ready\r\n",  # Banner
                b"250 mail.example.com\r\n",  # EHLO - no extensions
            ]

            result = detector._probe_ehlo("192.168.1.1", 25)

        indicator_names = [ind.name for ind in result]
        assert "smtp_limited_extensions" in indicator_names

    def test_weak_auth_only_detection(self):
        """Test detection of only weak AUTH mechanisms."""
        detector = SMTPDetector()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            # EHLO response with only LOGIN/PLAIN auth
            ehlo_response = (
                b"250-mail.example.com\r\n"
                b"250-SIZE 10240000\r\n"
                b"250-AUTH LOGIN PLAIN\r\n"
                b"250-PIPELINING\r\n"
                b"250-8BITMIME\r\n"
                b"250 STARTTLS\r\n"
            )
            mock_socket.recv.side_effect = [
                b"220 mail ESMTP ready\r\n",
                ehlo_response,
            ]

            result = detector._probe_ehlo("192.168.1.1", 25)

        indicator_names = [ind.name for ind in result]
        assert "smtp_weak_auth_only" in indicator_names


class TestSMTPVRFYProbing:
    """Test VRFY command behavior probing."""

    def test_vrfy_uniform_response(self):
        """Test detection of uniform VRFY responses."""
        detector = SMTPDetector()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            # All VRFY commands return identical response
            identical_response = b"252 User exists\r\n"
            responses = []
            for _ in range(4):  # 4 test users
                responses.extend([b"220 SMTP\r\n", identical_response])

            mock_socket.recv.side_effect = responses

            result = detector._probe_vrfy("192.168.1.1", 25)

        indicator_names = [ind.name for ind in result]
        assert "smtp_vrfy_uniform" in indicator_names

    def test_vrfy_accept_all(self):
        """Test detection when VRFY accepts all users."""
        detector = SMTPDetector()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            # All users are "valid" (250 response)
            responses = []
            for _ in range(4):
                responses.extend([b"220 SMTP\r\n", b"250 User OK\r\n"])

            mock_socket.recv.side_effect = responses

            result = detector._probe_vrfy("192.168.1.1", 25)

        indicator_names = [ind.name for ind in result]
        assert "smtp_vrfy_accept_all" in indicator_names
        # Check it has high severity
        accept_all = [ind for ind in result if ind.name == "smtp_vrfy_accept_all"]
        assert accept_all[0].severity == Confidence.HIGH


class TestSMTPOpenRelayDetection:
    """Test open relay behavior detection."""

    def test_open_relay_detected(self):
        """Test detection of open relay behavior."""
        detector = SMTPDetector()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            # Server accepts relaying from external to external
            mock_socket.recv.side_effect = [
                b"220 SMTP ready\r\n",  # Banner
                b"250 OK\r\n",  # EHLO
                b"250 Sender OK\r\n",  # MAIL FROM
                b"250 Recipient OK\r\n",  # RCPT TO - accepts external!
            ]

            result = detector._probe_open_relay("192.168.1.1", 25)

        indicator_names = [ind.name for ind in result]
        assert "smtp_open_relay" in indicator_names
        # Open relay is definite honeypot indicator
        relay_ind = [ind for ind in result if ind.name == "smtp_open_relay"]
        assert relay_ind[0].severity == Confidence.DEFINITE

    def test_relay_rejected(self):
        """Test when relay is properly rejected."""
        detector = SMTPDetector()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            # Server rejects relaying
            mock_socket.recv.side_effect = [
                b"220 SMTP ready\r\n",
                b"250 OK\r\n",
                b"250 Sender OK\r\n",
                b"550 Relay access denied\r\n",  # Properly rejects
            ]

            result = detector._probe_open_relay("192.168.1.1", 25)

        assert len(result) == 0


class TestSMTPAuthProbing:
    """Test SMTP AUTH mechanism probing."""

    def test_default_credentials_accepted(self):
        """Test detection when default credentials are accepted."""
        detector = SMTPDetector()

        # Mock _try_auth to simulate successful auth with default credentials
        with patch.object(detector, "_try_auth") as mock_try_auth:
            # First default credential succeeds
            mock_try_auth.return_value = True

            result = detector._probe_auth("192.168.1.1", 25)

        indicator_names = [ind.name for ind in result]
        assert "smtp_default_cred_accepted" in indicator_names

    def test_garbage_credentials_accepted(self):
        """Test detection when garbage credentials are accepted."""
        detector = SMTPDetector()

        # Mock _try_auth to simulate garbage credentials being accepted
        with patch.object(detector, "_try_auth") as mock_try_auth:
            # First 3 default creds fail, garbage succeeds
            mock_try_auth.side_effect = [False, False, False, True]

            result = detector._probe_auth("192.168.1.1", 25)

        indicator_names = [ind.name for ind in result]
        assert "smtp_accept_all_auth" in indicator_names


class TestSMTPInvalidPayloads:
    """Test SMTP response to invalid payloads."""

    def test_uniform_error_responses(self):
        """Test detection of uniform error responses."""
        detector = SMTPDetector()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            # All invalid payloads get identical response
            responses = []
            for _ in range(5):  # 5 invalid payloads
                responses.extend([b"220 SMTP\r\n", b"500 Syntax error\r\n"])

            mock_socket.recv.side_effect = responses

            result = detector._probe_invalid_payloads("192.168.1.1", 25)

        indicator_names = [ind.name for ind in result]
        assert "smtp_uniform_error" in indicator_names


class TestSMTPDetectorModes:
    """Test SMTP detector in different modes."""

    def test_passive_mode(self):
        """Test detector in passive mode only."""
        detector = SMTPDetector(mode=DetectionMode.PASSIVE)

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.recv.return_value = b"220 mailoney SMTP\r\n"

            with patch(
                "potsnitch.detectors.smtp.measure_connection_time"
            ) as mock_timing:
                mock_timing.return_value = MagicMock(success=True, elapsed=0.1)

                result = detector.detect("192.168.1.1", 25)

        assert result.is_honeypot

    def test_active_mode(self):
        """Test detector in active mode only."""
        detector = SMTPDetector(mode=DetectionMode.ACTIVE)

        with patch.object(
            detector, "_probe_ehlo", return_value=[]
        ), patch.object(
            detector, "_probe_vrfy", return_value=[]
        ), patch.object(
            detector, "_probe_open_relay"
        ) as mock_relay, patch.object(
            detector, "_probe_auth", return_value=[]
        ), patch.object(
            detector, "_probe_invalid_payloads", return_value=[]
        ):
            # Simulate open relay detection
            from potsnitch.core.result import Indicator

            mock_relay.return_value = [
                Indicator(
                    name="smtp_open_relay",
                    description="Open relay detected",
                    severity=Confidence.DEFINITE,
                )
            ]

            result = detector.detect("192.168.1.1", 25)

        assert result.is_honeypot
        assert result.honeypot_type == "smtp_honeypot"


class TestSMTPConnectionErrors:
    """Test SMTP detector error handling."""

    def test_connection_timeout(self):
        """Test handling of connection timeout."""
        detector = SMTPDetector(timeout=1.0)

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.connect.side_effect = socket.timeout()

            with patch(
                "potsnitch.detectors.smtp.measure_connection_time"
            ) as mock_timing:
                mock_timing.return_value = MagicMock(success=False, elapsed=1.0)

                result = detector.detect_passive("192.168.1.1", 25)

        assert not result.is_honeypot

    def test_connection_refused(self):
        """Test handling of connection refused."""
        detector = SMTPDetector()

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.connect.side_effect = ConnectionRefusedError()

            with patch(
                "potsnitch.detectors.smtp.measure_connection_time"
            ) as mock_timing:
                mock_timing.return_value = MagicMock(success=False, elapsed=0.0)

                result = detector.detect_passive("192.168.1.1", 25)

        assert not result.is_honeypot


class TestSMTPRecommendations:
    """Test SMTP detector recommendations."""

    def test_recommendations_for_indicators(self):
        """Test that appropriate recommendations are generated."""
        detector = SMTPDetector()
        from potsnitch.core.result import DetectionResult, Indicator

        result = DetectionResult(target="192.168.1.1", port=25)
        result.add_indicator(
            Indicator(
                name="smtp_default_hostname",
                description="Default hostname",
                severity=Confidence.MEDIUM,
            )
        )
        result.add_indicator(
            Indicator(
                name="smtp_open_relay",
                description="Open relay",
                severity=Confidence.DEFINITE,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) >= 2
        assert any("hostname" in r.lower() for r in recommendations)
        assert any("relay" in r.lower() for r in recommendations)
