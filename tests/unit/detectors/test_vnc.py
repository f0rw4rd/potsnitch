"""
Unit tests for VNC honeypot detector.

Tests RFB version detection, security type enumeration, static challenge detection,
no-auth detection, VNC honeypot banner patterns, and mock socket operations.
"""

import socket
import pytest
from unittest.mock import MagicMock, patch

from potsnitch.detectors.vnc import (
    VNCDetector,
    VNC_HONEYPOT_VERSIONS,
    REAL_VNC_PATTERNS,
    SECURITY_TYPE_NONE,
    SECURITY_TYPE_VNC_AUTH,
    SECURITY_TYPE_TIGHT,
)
from potsnitch.core.result import Confidence, DetectionResult


class TestVNCDetectorVersionDetection:
    """Tests for RFB version detection."""

    @pytest.fixture
    def detector(self):
        """Create VNC detector instance."""
        return VNCDetector()

    @pytest.mark.parametrize("version", VNC_HONEYPOT_VERSIONS)
    def test_detect_honeypot_versions(self, detector, mock_socket, version):
        """Test detection of known honeypot RFB versions."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = version + b"\n"

        result = detector.detect_passive("192.168.1.100", 5900)

        assert any(i.name == "vnc_old_protocol" for i in result.indicators)

    def test_detect_rfb_003003_version(self, detector, mock_socket):
        """Test detection of RFB 003.003 (common in honeypots)."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"RFB 003.003\n"

        result = detector.detect_passive("192.168.1.100", 5900)

        assert any(i.name == "vnc_old_protocol" for i in result.indicators)
        assert any("003.003" in i.description for i in result.indicators)

    def test_detect_rfb_003007_version(self, detector, mock_socket):
        """Test detection of RFB 003.007 (common in honeypots)."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"RFB 003.007\n"

        result = detector.detect_passive("192.168.1.100", 5900)

        assert any(i.name == "vnc_old_protocol" for i in result.indicators)

    def test_no_detection_modern_rfb(self, detector, mock_socket):
        """Test that modern RFB versions are not flagged."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"RFB 003.008\n"

        result = detector.detect_passive("192.168.1.100", 5900)

        assert not any(i.name == "vnc_old_protocol" for i in result.indicators)

    def test_socket_timeout_handling(self, detector, mock_socket):
        """Test graceful handling of socket timeout."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = socket.timeout()

        result = detector.detect_passive("192.168.1.100", 5900)

        assert result.error is None
        assert len(result.indicators) == 0

    def test_socket_error_handling(self, detector, mock_socket):
        """Test graceful handling of socket errors."""
        socket_instance = mock_socket.return_value
        socket_instance.connect.side_effect = socket.error("Connection refused")

        result = detector.detect_passive("192.168.1.100", 5900)

        assert result.error is None


class TestVNCDetectorSecurityTypes:
    """Tests for VNC security type enumeration."""

    @pytest.fixture
    def detector(self):
        """Create VNC detector instance."""
        return VNCDetector()

    def test_detect_no_auth_only(self, detector, mock_socket):
        """Test detection of no-auth VNC servers."""
        socket_instance = mock_socket.return_value
        # detect_passive calls _get_protocol_version (recv 12 bytes)
        # then _get_security_types (recv 12 for version, recv 1 for count, recv count for types)
        # then measure_connection_time (recv 1024 bytes)
        socket_instance.recv.side_effect = [
            b"RFB 003.008\n",  # For _get_protocol_version
            b"RFB 003.008\n",  # For _get_security_types: server version
            b"\x01",  # Count: 1 security type
            bytes([SECURITY_TYPE_NONE]),  # Security type: None
            b"RFB 003.008\n",  # For measure_connection_time
        ]

        result = detector.detect_passive("192.168.1.100", 5900)

        assert any(i.name == "vnc_no_auth" for i in result.indicators)
        assert any(i.severity == Confidence.HIGH for i in result.indicators)

    def test_detect_basic_auth_only(self, detector, mock_socket):
        """Test detection of basic VNC auth only."""
        socket_instance = mock_socket.return_value
        # detect_passive calls _get_protocol_version (recv 12 bytes)
        # then _get_security_types (recv 12 for version, recv 1 for count, recv count for types)
        # then measure_connection_time (recv 1024 bytes)
        socket_instance.recv.side_effect = [
            b"RFB 003.008\n",  # For _get_protocol_version
            b"RFB 003.008\n",  # For _get_security_types: server version
            b"\x01",  # Count: 1 security type
            bytes([SECURITY_TYPE_VNC_AUTH]),  # Security type: VNC Auth
            b"RFB 003.008\n",  # For measure_connection_time
        ]

        result = detector.detect_passive("192.168.1.100", 5900)

        assert any(i.name == "vnc_basic_auth_only" for i in result.indicators)

    def test_no_detection_multiple_auth_types(self, detector, mock_socket):
        """Test no detection when multiple auth types are available."""
        socket_instance = mock_socket.return_value
        # detect_passive calls _get_protocol_version (recv 12 bytes)
        # then _get_security_types (recv 12 for version, recv 1 for count, recv count for types)
        # then measure_connection_time (recv 1024 bytes)
        socket_instance.recv.side_effect = [
            b"RFB 003.008\n",  # For _get_protocol_version
            b"RFB 003.008\n",  # For _get_security_types: server version
            b"\x03",  # Count: 3 security types
            bytes([SECURITY_TYPE_NONE, SECURITY_TYPE_VNC_AUTH, SECURITY_TYPE_TIGHT]),
            b"RFB 003.008\n",  # For measure_connection_time
        ]

        result = detector.detect_passive("192.168.1.100", 5900)

        assert not any(i.name == "vnc_basic_auth_only" for i in result.indicators)

    def test_check_security_types_method(self, detector):
        """Test _check_security_types method directly."""
        result = DetectionResult(target="192.168.1.100", port=5900)

        # Test no-auth only
        detector._check_security_types([SECURITY_TYPE_NONE], result)

        assert any(i.name == "vnc_no_auth" for i in result.indicators)

    def test_check_security_types_vnc_auth_only(self, detector):
        """Test _check_security_types with VNC auth only."""
        result = DetectionResult(target="192.168.1.100", port=5900)

        detector._check_security_types([SECURITY_TYPE_VNC_AUTH], result)

        assert any(i.name == "vnc_basic_auth_only" for i in result.indicators)


class TestVNCDetectorStaticChallenge:
    """Tests for static VNC challenge detection."""

    @pytest.fixture
    def detector(self):
        """Create VNC detector instance."""
        return VNCDetector()

    def test_detect_static_challenge(self, detector, mock_socket):
        """Test detection of static VNC challenge."""
        socket_instance = mock_socket.return_value
        static_challenge = b"\x00" * 16  # Same challenge every time

        # Three connections, same challenge each time
        socket_instance.recv.side_effect = [
            b"RFB 003.008\n",
            b"\x01",
            bytes([SECURITY_TYPE_VNC_AUTH]),
            static_challenge,
            b"RFB 003.008\n",
            b"\x01",
            bytes([SECURITY_TYPE_VNC_AUTH]),
            static_challenge,
            b"RFB 003.008\n",
            b"\x01",
            bytes([SECURITY_TYPE_VNC_AUTH]),
            static_challenge,
        ]

        indicators = detector._probe_challenge("192.168.1.100", 5900)

        assert any(i.name == "vnc_static_challenge" for i in indicators)
        assert any(i.severity == Confidence.DEFINITE for i in indicators)

    def test_no_detection_random_challenge(self, detector, mock_socket):
        """Test no detection when challenges are random."""
        socket_instance = mock_socket.return_value

        # Three connections, different challenges each time
        socket_instance.recv.side_effect = [
            b"RFB 003.008\n",
            b"\x01",
            bytes([SECURITY_TYPE_VNC_AUTH]),
            b"\x01" * 16,
            b"RFB 003.008\n",
            b"\x01",
            bytes([SECURITY_TYPE_VNC_AUTH]),
            b"\x02" * 16,
            b"RFB 003.008\n",
            b"\x01",
            bytes([SECURITY_TYPE_VNC_AUTH]),
            b"\x03" * 16,
        ]

        indicators = detector._probe_challenge("192.168.1.100", 5900)

        assert not any(i.name == "vnc_static_challenge" for i in indicators)


class TestVNCDetectorPasswordProbing:
    """Tests for VNC password probing."""

    @pytest.fixture
    def detector(self):
        """Create VNC detector instance."""
        return VNCDetector()

    def test_detect_default_password_accepted(self, detector, mock_socket):
        """Test detection when default password is accepted."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = [
            b"RFB 003.008\n",
            b"\x01",
            bytes([SECURITY_TYPE_VNC_AUTH]),
            b"\x00" * 16,  # Challenge
            b"\x00\x00\x00\x00",  # Success response
        ]

        indicators = detector._probe_passwords("192.168.1.100", 5900)

        assert any(i.name == "vnc_default_password_accepted" for i in indicators)

    def test_detect_instant_auth_rejection(self, detector, mock_socket):
        """Test detection of instant authentication rejection."""
        socket_instance = mock_socket.return_value
        # _probe_passwords loops through multiple passwords (up to 5).
        # Each call to _try_auth needs: version(12), count(1), sec_types(count), challenge(16), result(4)
        # After first failure with instant timing, test should get indicator.
        # We need to provide enough data for subsequent password attempts as well.
        socket_instance.recv.side_effect = [
            b"RFB 003.008\n",  # Password 1: version
            b"\x01",           # Password 1: count
            bytes([SECURITY_TYPE_VNC_AUTH]),  # Password 1: sec types
            b"\x00" * 16,      # Password 1: challenge
            b"\x00\x00\x00\x01",  # Password 1: failure response
            b"RFB 003.008\n",  # Password 2: version
            b"\x01",           # Password 2: count
            bytes([SECURITY_TYPE_VNC_AUTH]),  # Password 2: sec types
            b"\x00" * 16,      # Password 2: challenge
            b"\x00\x00\x00\x01",  # Password 2: failure response
            b"RFB 003.008\n",  # Password 3: version
            b"\x01",           # Password 3: count
            bytes([SECURITY_TYPE_VNC_AUTH]),  # Password 3: sec types
            b"\x00" * 16,      # Password 3: challenge
            b"\x00\x00\x00\x01",  # Password 3: failure response
            b"RFB 003.008\n",  # Password 4: version
            b"\x01",           # Password 4: count
            bytes([SECURITY_TYPE_VNC_AUTH]),  # Password 4: sec types
            b"\x00" * 16,      # Password 4: challenge
            b"\x00\x00\x00\x01",  # Password 4: failure response
            b"RFB 003.008\n",  # Password 5: version
            b"\x01",           # Password 5: count
            bytes([SECURITY_TYPE_VNC_AUTH]),  # Password 5: sec types
            b"\x00" * 16,      # Password 5: challenge
            b"\x00\x00\x00\x01",  # Password 5: failure response
        ]

        # The timing check is internal, mock perf_counter for instant response
        # Need to patch where it's used (in potsnitch.detectors.vnc)
        with patch("potsnitch.detectors.vnc.time.perf_counter") as mock_time:
            # Each _try_auth call uses perf_counter twice (start and after recv result)
            mock_time.side_effect = [0.0, 0.001] * 5  # 1ms response for each password attempt
            indicators = detector._probe_passwords("192.168.1.100", 5900)

        # This test checks the timing detection (< 10ms)
        assert any(i.name == "vnc_instant_auth_rejection" for i in indicators)


class TestVNCDetectorAcceptAll:
    """Tests for VNC accept-all password detection."""

    @pytest.fixture
    def detector(self):
        """Create VNC detector instance."""
        return VNCDetector()

    def test_detect_accept_all(self, detector, mock_socket):
        """Test detection of VNC that accepts any password."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = [
            b"RFB 003.008\n",
            b"\x01",
            bytes([SECURITY_TYPE_VNC_AUTH]),
            b"\x00" * 16,  # Challenge
            b"\x00\x00\x00\x00",  # Success for garbage password
        ]

        indicators = detector._probe_accept_all("192.168.1.100", 5900)

        assert any(i.name == "vnc_accept_all" for i in indicators)
        assert any(i.severity == Confidence.DEFINITE for i in indicators)

    def test_no_detection_proper_auth(self, detector, mock_socket):
        """Test no detection when garbage passwords are rejected."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = [
            b"RFB 003.008\n",
            b"\x01",
            bytes([SECURITY_TYPE_VNC_AUTH]),
            b"\x00" * 16,
            b"\x00\x00\x00\x01",  # Reject first garbage
            b"RFB 003.008\n",
            b"\x01",
            bytes([SECURITY_TYPE_VNC_AUTH]),
            b"\x00" * 16,
            b"\x00\x00\x00\x01",  # Reject second garbage
            b"RFB 003.008\n",
            b"\x01",
            bytes([SECURITY_TYPE_VNC_AUTH]),
            b"\x00" * 16,
            b"\x00\x00\x00\x01",  # Reject third garbage
        ]

        indicators = detector._probe_accept_all("192.168.1.100", 5900)

        assert not any(i.name == "vnc_accept_all" for i in indicators)


class TestVNCDetectorInvalidPayloads:
    """Tests for VNC invalid payload detection."""

    @pytest.fixture
    def detector(self):
        """Create VNC detector instance."""
        return VNCDetector()

    def test_detect_uniform_error_response(self, detector, mock_socket):
        """Test detection of uniform error responses to invalid payloads."""
        socket_instance = mock_socket.return_value

        # All invalid payloads get the same response
        uniform_response = b"RFB 003.008\n"
        socket_instance.recv.return_value = uniform_response

        indicators = detector._probe_invalid_payloads("192.168.1.100", 5900)

        assert any(i.name == "vnc_uniform_error" for i in indicators)

    def test_no_detection_varied_responses(self, detector, mock_socket):
        """Test no detection when responses vary."""
        socket_instance = mock_socket.return_value

        # Different responses for different payloads
        socket_instance.recv.side_effect = [
            b"Error 1",
            b"Error 2",
            b"Error 3",
        ]

        indicators = detector._probe_invalid_payloads("192.168.1.100", 5900)

        assert not any(i.name == "vnc_uniform_error" for i in indicators)


class TestVNCDetectorTiming:
    """Tests for VNC connection timing detection."""

    @pytest.fixture
    def detector(self):
        """Create VNC detector instance."""
        return VNCDetector()

    def test_detect_instant_response(self, detector, mock_socket):
        """Test detection of instant VNC response."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"RFB 003.008\n"

        with patch("potsnitch.detectors.vnc.measure_connection_time") as mock_timing:
            mock_result = MagicMock()
            mock_result.success = True
            mock_result.elapsed = 0.001  # 1ms - very fast
            mock_timing.return_value = mock_result

            result = detector.detect_passive("192.168.1.100", 5900)

            assert any(i.name == "vnc_instant_response" for i in result.indicators)


class TestVNCDetectorIntegration:
    """Integration tests for VNC detector."""

    @pytest.fixture
    def detector(self):
        """Create VNC detector instance."""
        return VNCDetector()

    def test_honeypot_type_set_correctly(self, detector, mock_socket):
        """Test that honeypot_type is set when honeypot detected."""
        socket_instance = mock_socket.return_value
        # detect_passive calls _get_protocol_version (recv 12 bytes)
        # then _get_security_types (recv 12 for version, recv 1 for count, recv count for types)
        # then measure_connection_time (recv 1024 bytes)
        socket_instance.recv.side_effect = [
            b"RFB 003.003\n",  # For _get_protocol_version (old version triggers honeypot)
            b"RFB 003.003\n",  # For _get_security_types: server version
            b"\x01",          # Count: 1 security type
            bytes([SECURITY_TYPE_NONE]),  # No auth (high severity indicator)
            b"RFB 003.003\n",  # For measure_connection_time
        ]

        result = detector.detect_passive("192.168.1.100", 5900)

        assert result.is_honeypot
        assert result.honeypot_type == "vnc_honeypot"

    def test_detector_properties(self, detector):
        """Test detector class properties."""
        assert detector.name == "vnc"
        assert "vnclowpot" in detector.honeypot_types
        assert "qeeqbox-vnc" in detector.honeypot_types
        assert 5900 in detector.default_ports
        assert 5901 in detector.default_ports

    def test_detector_description(self, detector):
        """Test detector has description."""
        assert detector.description is not None
        assert len(detector.description) > 0


class TestVNCDetectorRecommendations:
    """Tests for VNC detector recommendations."""

    @pytest.fixture
    def detector(self):
        """Create VNC detector instance."""
        return VNCDetector()

    def test_recommendations_for_static_challenge(self, detector):
        """Test recommendations when static challenge is detected."""
        from potsnitch.core.result import Indicator

        result = DetectionResult(target="192.168.1.100", port=5900)
        result.add_indicator(
            Indicator(
                name="vnc_static_challenge",
                description="Static challenge detected",
                severity=Confidence.DEFINITE,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any("random" in r.lower() for r in recommendations)

    def test_recommendations_for_accept_all(self, detector):
        """Test recommendations when accept-all is detected."""
        from potsnitch.core.result import Indicator

        result = DetectionResult(target="192.168.1.100", port=5900)
        result.add_indicator(
            Indicator(
                name="vnc_accept_all",
                description="Accepts all passwords",
                severity=Confidence.DEFINITE,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any("password" in r.lower() for r in recommendations)

    def test_recommendations_for_old_protocol(self, detector):
        """Test recommendations when old protocol is detected."""
        from potsnitch.core.result import Indicator

        result = DetectionResult(target="192.168.1.100", port=5900)
        result.add_indicator(
            Indicator(
                name="vnc_old_protocol",
                description="Old RFB protocol",
                severity=Confidence.LOW,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any("3.8" in r or "modern" in r.lower() for r in recommendations)


class TestVNCDetectorVersionCheck:
    """Tests for the _check_version method."""

    @pytest.fixture
    def detector(self):
        """Create VNC detector instance."""
        return VNCDetector()

    @pytest.mark.parametrize(
        "version,should_detect",
        [
            (b"RFB 003.003\n", True),
            (b"RFB 003.007\n", True),
            (b"RFB 003.008\n", False),
            (b"RFB 004.001\n", False),
        ],
    )
    def test_check_version(self, detector, version, should_detect):
        """Test _check_version with various RFB versions."""
        result = DetectionResult(target="192.168.1.100", port=5900)
        detector._check_version(version, result)

        if should_detect:
            assert any(i.name == "vnc_old_protocol" for i in result.indicators)
        else:
            assert not any(i.name == "vnc_old_protocol" for i in result.indicators)


class TestVNCDetectorNoAuthDetection:
    """Tests for no-auth VNC detection via _try_auth."""

    @pytest.fixture
    def detector(self):
        """Create VNC detector instance."""
        return VNCDetector()

    def test_try_auth_no_auth_success(self, detector, mock_socket):
        """Test _try_auth when no-auth is accepted."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = [
            b"RFB 003.008\n",
            b"\x01",  # Count: 1
            bytes([SECURITY_TYPE_NONE]),  # No auth
            b"\x00\x00\x00\x00",  # Success
        ]

        success, timing = detector._try_auth("192.168.1.100", 5900, "")

        assert success is True

    def test_try_auth_failure(self, detector, mock_socket):
        """Test _try_auth when authentication fails."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = [
            b"RFB 003.008\n",
            b"\x01",
            bytes([SECURITY_TYPE_VNC_AUTH]),
            b"\x00" * 16,  # Challenge
            b"\x00\x00\x00\x01",  # Failure
        ]

        success, timing = detector._try_auth("192.168.1.100", 5900, "wrongpass")

        assert success is False
