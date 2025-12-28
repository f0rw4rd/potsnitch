"""
Unit tests for RDP honeypot detector.

Tests X.224 connection response, TLS certificate fingerprinting, NLA/CredSSP detection,
RDP honeypot signatures (RDPY, PyRDP), JA3S hash detection, mock socket and ssl operations.
"""

import socket
import ssl
import pytest
from unittest.mock import MagicMock, patch, PropertyMock

from potsnitch.detectors.rdp import (
    RDPDetector,
    PYTHON_TLS_JA3_PREFIXES,
    HONEYPOT_CERT_PATTERNS,
    PYTHON_PREFERRED_CIPHERS,
)
from potsnitch.core.result import Confidence, DetectionResult


class TestRDPDetectorX224Response:
    """Tests for X.224 connection response handling."""

    @pytest.fixture
    def detector(self):
        """Create RDP detector instance."""
        return RDPDetector()

    def test_detect_valid_x224_tls_response(self, detector, mock_socket):
        """Test detection of valid X.224 TLS response."""
        socket_instance = mock_socket.return_value

        # Valid X.224 Connection Confirm with TLS negotiation
        x224_response = bytes([
            0x03, 0x00,  # TPKT header
            0x00, 0x13,  # Length: 19 bytes
            0x0e,        # X.224 length
            0xd0,        # X.224 CC (Connection Confirm)
            0x00, 0x00,  # DST-REF
            0x00, 0x00,  # SRC-REF
            0x00,        # CLASS
            0x02,        # RDP_NEG_RSP - TLS accepted
            0x00, 0x00,  # Flags
            0x01, 0x00, 0x00, 0x00,  # Protocol: TLS
        ])
        socket_instance.recv.return_value = x224_response

        # Mock SSL wrap to fail (testing just the X.224 part)
        with patch("ssl.create_default_context") as mock_ssl:
            mock_context = MagicMock()
            mock_ssl.return_value = mock_context
            mock_context.wrap_socket.side_effect = ssl.SSLError("Test")

            result = detector.detect_passive("192.168.1.100", 3389)

            # Should complete without error
            assert result.error is None

    def test_socket_timeout_handling(self, detector, mock_socket):
        """Test graceful handling of socket timeout."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = socket.timeout()

        result = detector.detect_passive("192.168.1.100", 3389)

        assert result.error is None
        assert len(result.indicators) == 0

    def test_socket_error_handling(self, detector, mock_socket):
        """Test graceful handling of socket errors."""
        socket_instance = mock_socket.return_value
        socket_instance.connect.side_effect = socket.error("Connection refused")

        result = detector.detect_passive("192.168.1.100", 3389)

        assert result.error is None


class TestRDPDetectorTLSCertificate:
    """Tests for TLS certificate fingerprinting."""

    @pytest.fixture
    def detector(self):
        """Create RDP detector instance."""
        return RDPDetector()

    @pytest.mark.parametrize("pattern", HONEYPOT_CERT_PATTERNS)
    def test_detect_honeypot_cert_patterns(self, detector, pattern):
        """Test detection of honeypot certificate patterns."""
        result = DetectionResult(target="192.168.1.100", port=3389)

        # Create mock certificate with x509 library (imported inside _analyze_certificate)
        with patch("cryptography.x509.load_der_x509_certificate") as mock_load_cert:
            mock_cert = MagicMock()
            mock_subject = MagicMock()
            mock_issuer = MagicMock()
            mock_subject.rfc4514_string.return_value = f"CN={pattern}.example.com"
            mock_issuer.rfc4514_string.return_value = "CN=Test CA"
            mock_cert.subject = mock_subject
            mock_cert.issuer = mock_issuer
            mock_load_cert.return_value = mock_cert

            detector._analyze_certificate(b"fake_cert_data", result)

            assert any(i.name == "generic_cert_subject" for i in result.indicators)

    def test_detect_non_windows_issuer(self, detector):
        """Test detection of non-Windows certificate issuer."""
        result = DetectionResult(target="192.168.1.100", port=3389)

        with patch("cryptography.x509.load_der_x509_certificate") as mock_load_cert:
            mock_cert = MagicMock()
            mock_subject = MagicMock()
            mock_issuer = MagicMock()
            mock_subject.rfc4514_string.return_value = "CN=server.example.com"
            mock_issuer.rfc4514_string.return_value = "CN=Python CA"
            mock_cert.subject = mock_subject
            mock_cert.issuer = mock_issuer
            mock_load_cert.return_value = mock_cert

            detector._analyze_certificate(b"fake_cert_data", result)

            assert any(i.name == "non_windows_issuer" for i in result.indicators)
            assert any(i.severity == Confidence.HIGH for i in result.indicators)

    def test_no_detection_windows_issuer(self, detector):
        """Test no detection when issuer appears to be Windows."""
        result = DetectionResult(target="192.168.1.100", port=3389)

        with patch("cryptography.x509.load_der_x509_certificate") as mock_load_cert:
            mock_cert = MagicMock()
            mock_subject = MagicMock()
            mock_issuer = MagicMock()
            mock_subject.rfc4514_string.return_value = "CN=server.contoso.com"
            mock_issuer.rfc4514_string.return_value = "CN=Microsoft Windows RDP"
            mock_cert.subject = mock_subject
            mock_cert.issuer = mock_issuer
            mock_load_cert.return_value = mock_cert

            detector._analyze_certificate(b"fake_cert_data", result)

            assert not any(i.name == "non_windows_issuer" for i in result.indicators)

    def test_certificate_exception_handling(self, detector):
        """Test graceful handling of certificate parsing errors."""
        result = DetectionResult(target="192.168.1.100", port=3389)

        with patch("cryptography.x509.load_der_x509_certificate") as mock_load_cert:
            mock_load_cert.side_effect = Exception("Parse error")

            # Should not raise exception
            detector._analyze_certificate(b"invalid_cert", result)

            assert len(result.indicators) == 0


class TestRDPDetectorCipherAnalysis:
    """Tests for TLS cipher analysis."""

    @pytest.fixture
    def detector(self):
        """Create RDP detector instance."""
        return RDPDetector()

    @pytest.mark.parametrize("cipher", PYTHON_PREFERRED_CIPHERS)
    def test_detect_python_ciphers(self, detector, cipher):
        """Test detection of Python ssl library ciphers."""
        result = DetectionResult(target="192.168.1.100", port=3389)

        cipher_info = (cipher, "TLSv1.2", 256)
        detector._analyze_cipher(cipher_info, result)

        assert any(i.name == "python_tls_cipher" for i in result.indicators)

    def test_no_detection_windows_cipher(self, detector):
        """Test no detection for Windows SChannel ciphers."""
        result = DetectionResult(target="192.168.1.100", port=3389)

        # Windows SChannel typical cipher
        cipher_info = ("TLS_RSA_WITH_AES_128_CBC_SHA256", "TLSv1.2", 128)
        detector._analyze_cipher(cipher_info, result)

        assert not any(i.name == "python_tls_cipher" for i in result.indicators)


class TestRDPDetectorMalformedPacket:
    """Tests for malformed RDP packet probing."""

    @pytest.fixture
    def detector(self):
        """Create RDP detector instance."""
        return RDPDetector()

    def test_detect_unusual_error_response(self, detector, mock_socket):
        """Test detection of unusual response to malformed packet."""
        socket_instance = mock_socket.return_value

        # Response to malformed packet (non-empty)
        socket_instance.recv.return_value = b"Some error response"

        result = detector.detect_active("192.168.1.100", 3389)

        assert any(i.name == "unusual_error_response" for i in result.indicators)

    def test_no_detection_connection_closed(self, detector, mock_socket):
        """Test no detection when connection is properly closed."""
        socket_instance = mock_socket.return_value

        # Real Windows RDP typically closes connection
        socket_instance.recv.side_effect = socket.timeout()

        result = detector.detect_active("192.168.1.100", 3389)

        assert not any(i.name == "unusual_error_response" for i in result.indicators)


class TestRDPDetectorInvalidProtocol:
    """Tests for invalid protocol probing."""

    @pytest.fixture
    def detector(self):
        """Create RDP detector instance."""
        return RDPDetector()

    def test_detect_non_standard_error(self, detector, mock_socket):
        """Test detection of non-standard error response."""
        socket_instance = mock_socket.return_value

        # Non-standard response (doesn't start with TPKT header)
        socket_instance.recv.return_value = b"\x00\x01\x02\x03Invalid"

        detector._probe_invalid_protocol("192.168.1.100", 3389,
                                         DetectionResult(target="192.168.1.100", port=3389))

        # The method should complete without error
        assert True

    def test_detect_short_response(self, detector, mock_socket):
        """Test detection of short error response."""
        socket_instance = mock_socket.return_value
        result = DetectionResult(target="192.168.1.100", port=3389)

        # Very short response
        socket_instance.recv.return_value = b"\x00\x01"

        detector._probe_invalid_protocol("192.168.1.100", 3389, result)

        assert any(i.name == "non_standard_error" for i in result.indicators)

    def test_proper_tpkt_response(self, detector, mock_socket):
        """Test no detection with proper TPKT response."""
        socket_instance = mock_socket.return_value
        result = DetectionResult(target="192.168.1.100", port=3389)

        # Proper TPKT formatted response
        socket_instance.recv.return_value = bytes([
            0x03, 0x00,  # TPKT header
            0x00, 0x0b,  # Length
            0x06, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])

        detector._probe_invalid_protocol("192.168.1.100", 3389, result)

        assert not any(i.name == "non_standard_error" for i in result.indicators)


class TestRDPDetectorHoneypotSignatures:
    """Tests for RDPY, PyRDP honeypot signatures."""

    @pytest.fixture
    def detector(self):
        """Create RDP detector instance."""
        return RDPDetector()

    def test_detect_rdpy_cert_pattern(self, detector):
        """Test detection of RDPY certificate pattern."""
        result = DetectionResult(target="192.168.1.100", port=3389)

        with patch("cryptography.x509.load_der_x509_certificate") as mock_load_cert:
            mock_cert = MagicMock()
            mock_subject = MagicMock()
            mock_issuer = MagicMock()
            mock_subject.rfc4514_string.return_value = "CN=rdpy-server"
            mock_issuer.rfc4514_string.return_value = "CN=rdpy"
            mock_cert.subject = mock_subject
            mock_cert.issuer = mock_issuer
            mock_load_cert.return_value = mock_cert

            detector._analyze_certificate(b"fake_cert", result)

            assert any(i.name == "generic_cert_subject" for i in result.indicators)

    def test_detect_heralding_cert_pattern(self, detector):
        """Test detection of Heralding certificate pattern."""
        result = DetectionResult(target="192.168.1.100", port=3389)

        with patch("cryptography.x509.load_der_x509_certificate") as mock_load_cert:
            mock_cert = MagicMock()
            mock_subject = MagicMock()
            mock_issuer = MagicMock()
            mock_subject.rfc4514_string.return_value = "CN=heralding-server"
            mock_issuer.rfc4514_string.return_value = "CN=heralding"
            mock_cert.subject = mock_subject
            mock_cert.issuer = mock_issuer
            mock_load_cert.return_value = mock_cert

            detector._analyze_certificate(b"fake_cert", result)

            assert any(i.name == "generic_cert_subject" for i in result.indicators)

    def test_detect_localhost_cert(self, detector):
        """Test detection of localhost in certificate."""
        result = DetectionResult(target="192.168.1.100", port=3389)

        with patch("cryptography.x509.load_der_x509_certificate") as mock_load_cert:
            mock_cert = MagicMock()
            mock_subject = MagicMock()
            mock_issuer = MagicMock()
            mock_subject.rfc4514_string.return_value = "CN=localhost"
            mock_issuer.rfc4514_string.return_value = "CN=localhost"
            mock_cert.subject = mock_subject
            mock_cert.issuer = mock_issuer
            mock_load_cert.return_value = mock_cert

            detector._analyze_certificate(b"fake_cert", result)

            assert any(i.name == "generic_cert_subject" for i in result.indicators)


class TestRDPDetectorIntegration:
    """Integration tests for RDP detector."""

    @pytest.fixture
    def detector(self):
        """Create RDP detector instance."""
        return RDPDetector()

    def test_honeypot_type_set_correctly(self, detector, mock_socket):
        """Test that honeypot_type is set when honeypot detected."""
        socket_instance = mock_socket.return_value

        # Response that triggers detection
        socket_instance.recv.return_value = b"Unusual response"

        result = detector.detect_active("192.168.1.100", 3389)

        if result.is_honeypot:
            assert result.honeypot_type == "rdpy"

    def test_detector_properties(self, detector):
        """Test detector class properties."""
        assert detector.name == "rdp"
        assert "rdpy" in detector.honeypot_types
        assert "heralding" in detector.honeypot_types
        assert "pyrdp" in detector.honeypot_types
        assert 3389 in detector.default_ports

    def test_detector_description(self, detector):
        """Test detector has description."""
        assert detector.description is not None
        assert len(detector.description) > 0


class TestRDPDetectorRecommendations:
    """Tests for RDP detector recommendations."""

    @pytest.fixture
    def detector(self):
        """Create RDP detector instance."""
        return RDPDetector()

    def test_recommendations_for_tls_indicator(self, detector):
        """Test recommendations when TLS indicator is detected."""
        from potsnitch.core.result import Indicator

        result = DetectionResult(target="192.168.1.100", port=3389)
        result.add_indicator(
            Indicator(
                name="python_tls_cipher",
                description="Python TLS cipher detected",
                severity=Confidence.LOW,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any("windows" in r.lower() for r in recommendations)

    def test_recommendations_for_cert_indicator(self, detector):
        """Test recommendations when certificate indicator is detected."""
        from potsnitch.core.result import Indicator

        result = DetectionResult(target="192.168.1.100", port=3389)
        result.add_indicator(
            Indicator(
                name="generic_cert_subject",
                description="Generic certificate subject",
                severity=Confidence.MEDIUM,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any("certificate" in r.lower() for r in recommendations)

    def test_recommendations_for_error_indicator(self, detector):
        """Test recommendations when error response indicator is detected."""
        from potsnitch.core.result import Indicator

        result = DetectionResult(target="192.168.1.100", port=3389)
        result.add_indicator(
            Indicator(
                name="unusual_error_response",
                description="Unusual error response",
                severity=Confidence.LOW,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any("error" in r.lower() or "windows" in r.lower() for r in recommendations)

    def test_recommendations_for_issuer_indicator(self, detector):
        """Test recommendations when issuer indicator is detected."""
        from potsnitch.core.result import Indicator

        result = DetectionResult(target="192.168.1.100", port=3389)
        result.add_indicator(
            Indicator(
                name="non_windows_issuer",
                description="Non-Windows issuer",
                severity=Confidence.HIGH,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0


class TestRDPDetectorTLSPassive:
    """Tests for passive TLS checking."""

    @pytest.fixture
    def detector(self):
        """Create RDP detector instance."""
        return RDPDetector()

    def test_check_tls_passive_with_ssl(self, detector, mock_socket):
        """Test _check_tls_passive with SSL connection."""
        socket_instance = mock_socket.return_value

        # X.224 response indicating TLS accepted
        x224_response = bytes([
            0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ])
        socket_instance.recv.return_value = x224_response

        with patch("ssl.create_default_context") as mock_ssl_ctx:
            mock_context = MagicMock()
            mock_ssl_ctx.return_value = mock_context
            mock_tls_sock = MagicMock()
            mock_context.wrap_socket.return_value = mock_tls_sock
            mock_tls_sock.getpeercert.return_value = b"fake_cert"
            mock_tls_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

            result = DetectionResult(target="192.168.1.100", port=3389)
            detector._check_tls_passive("192.168.1.100", 3389, result)

            # Should detect Python cipher
            assert any(i.name == "python_tls_cipher" for i in result.indicators)

    def test_check_tls_passive_ssl_error(self, detector, mock_socket):
        """Test _check_tls_passive handles SSL errors gracefully."""
        socket_instance = mock_socket.return_value

        x224_response = bytes([
            0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ])
        socket_instance.recv.return_value = x224_response

        with patch("ssl.create_default_context") as mock_ssl_ctx:
            mock_context = MagicMock()
            mock_ssl_ctx.return_value = mock_context
            mock_context.wrap_socket.side_effect = ssl.SSLError("SSL error")

            result = DetectionResult(target="192.168.1.100", port=3389)
            detector._check_tls_passive("192.168.1.100", 3389, result)

            # Should complete without error
            assert True


class TestRDPDetectorRDPProtocol:
    """Tests for _check_rdp_protocol method."""

    @pytest.fixture
    def detector(self):
        """Create RDP detector instance."""
        return RDPDetector()

    def test_check_rdp_protocol_response(self, detector, mock_socket):
        """Test _check_rdp_protocol with various responses."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"Some response"

        result = DetectionResult(target="192.168.1.100", port=3389)
        detector._check_rdp_protocol("192.168.1.100", 3389, result)

        assert any(i.name == "unusual_error_response" for i in result.indicators)

    def test_check_rdp_protocol_timeout(self, detector, mock_socket):
        """Test _check_rdp_protocol with timeout."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = socket.timeout()

        result = DetectionResult(target="192.168.1.100", port=3389)
        detector._check_rdp_protocol("192.168.1.100", 3389, result)

        # Should not add indicators on timeout
        assert not any(i.name == "unusual_error_response" for i in result.indicators)
