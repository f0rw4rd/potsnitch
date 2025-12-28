"""
Unit tests for Conpot ICS/SCADA honeypot detector.

Tests cover:
- S7Comm default values detection (Technodrome, Mouser)
- Modbus probe detection
- HTTP response fingerprinting
- SNMP default community detection
- Multi-ICS-port correlation
- Mock socket for ICS protocols
"""

import socket
import pytest
from unittest.mock import MagicMock, patch, call

from potsnitch.detectors.conpot import (
    ConpotDetector,
    CONPOT_S7_SIGNATURES,
    CONPOT_MODBUS_SIGNATURES,
    CONPOT_SNMP_SIGNATURES,
    CONPOT_DEFAULT_PORTS,
)
from potsnitch.core.base import DetectionMode
from potsnitch.core.result import Confidence, DetectionResult


class TestS7CommDetection:
    """Test S7Comm protocol detection for Conpot signatures."""

    @pytest.fixture
    def detector(self):
        """Create Conpot detector instance."""
        return ConpotDetector()

    @pytest.mark.parametrize(
        "signature_category,signature_value",
        [
            ("system_names", b"Technodrome"),
            ("system_names", b"S7-200"),
            ("system_names", b"SIMATIC"),
            ("facility_names", b"Mouser"),
            ("facility_names", b"Mouser Factory"),
            ("serials", b"88111222"),
            ("locations", b"Venus"),
            ("module_types", b"IM151-8 PN/DP CPU"),
            ("module_types", b"CPU 315-2 PN/DP"),
            ("contacts", b"Siemens AG"),
        ],
    )
    def test_s7comm_default_signatures(self, detector, mock_socket, signature_category, signature_value):
        """Test detection of Conpot default S7Comm signatures."""
        socket_instance = mock_socket.return_value

        # Build response containing the signature
        response_with_signature = b"\x03\x00\x00\x50" + b"\x00" * 30 + signature_value + b"\x00" * 50

        socket_instance.recv.side_effect = [
            b"\x03\x00\x00\x16\x11\xd0\x00\x01\x00\x00\x00\x00",  # COTP CC
            b"\x03\x00\x00\x1b\x02\xf0\x80\x32\x03\x00\x00\x00\x00\x00\x08\x00\x00\xf0\x00\x00\x01\x00\x01\x01\xe0",  # S7 setup response
            response_with_signature,  # SZL response with signature
        ]

        result = detector.detect_active("192.168.1.1", 102)

        assert result.is_honeypot
        indicator_names = [ind.name for ind in result.indicators]
        assert "conpot_s7_signature" in indicator_names
        assert any(ind.severity == Confidence.DEFINITE for ind in result.indicators)

    def test_s7comm_technodrome_detection(self, detector, mock_socket):
        """Test specific detection of Technodrome system name."""
        socket_instance = mock_socket.return_value

        # S7 response containing Technodrome
        response = b"\x03\x00\x00\x80\x02\xf0\x80\x32\x07" + b"\x00" * 20 + b"Technodrome" + b"\x00" * 50

        socket_instance.recv.side_effect = [
            b"\x03\x00\x00\x16\x11\xd0\x00\x01\x00\x00\x00\x00",  # COTP CC
            b"\x03\x00\x00\x1b\x02\xf0\x80\x32\x03\x00\x00",  # S7 setup
            response,
        ]

        result = detector.detect_active("192.168.1.1", 102)

        assert result.is_honeypot
        assert any("Technodrome" in ind.description for ind in result.indicators)

    def test_s7comm_mouser_factory_detection(self, detector, mock_socket):
        """Test specific detection of Mouser Factory facility name."""
        socket_instance = mock_socket.return_value

        response = b"\x03\x00\x00\x80" + b"\x00" * 30 + b"Mouser Factory" + b"\x00" * 50

        socket_instance.recv.side_effect = [
            b"\x03\x00\x00\x16\x11\xd0\x00\x01\x00\x00\x00\x00",
            b"\x03\x00\x00\x1b\x02\xf0\x80\x32\x03\x00\x00",
            response,
        ]

        result = detector.detect_active("192.168.1.1", 102)

        assert result.is_honeypot
        assert any("Mouser Factory" in ind.description for ind in result.indicators)

    def test_s7comm_connection_timeout(self, detector, mock_socket):
        """Test handling of S7Comm connection timeout."""
        socket_instance = mock_socket.return_value
        socket_instance.connect.side_effect = socket.timeout()

        result = detector.detect_active("192.168.1.1", 102)

        assert not result.is_honeypot
        assert len(result.indicators) == 0

    def test_s7comm_short_response(self, detector, mock_socket):
        """Test handling of short S7Comm response."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"\x03\x00"  # Too short

        result = detector.detect_active("192.168.1.1", 102)

        assert not result.is_honeypot


class TestModbusDetection:
    """Test Modbus protocol detection for Conpot signatures."""

    @pytest.fixture
    def detector(self):
        """Create Conpot detector instance."""
        return ConpotDetector()

    @pytest.mark.parametrize(
        "signature_category,signature_value",
        [
            ("vendor_names", "Siemens"),
            ("product_codes", "SIMATIC"),
            ("revisions", "S7-200"),
            ("revisions", "S7-300"),
            ("revisions", "S7-400"),
            ("descriptions", "Siemens, SIMATIC, S7-200"),
        ],
    )
    def test_modbus_default_signatures(self, detector, mock_socket, signature_category, signature_value):
        """Test detection of Conpot default Modbus device ID signatures."""
        socket_instance = mock_socket.return_value

        # Modbus response containing the signature
        response = (
            b"\x00\x01\x00\x00\x00\x20\x01\x2b\x0e\x01\x00\x00\x01\x00"
            + signature_value.encode()
            + b"\x00"
        )

        socket_instance.recv.return_value = response

        result = detector.detect_active("192.168.1.1", 502)

        assert result.is_honeypot
        indicator_names = [ind.name for ind in result.indicators]
        assert "conpot_modbus_signature" in indicator_names

    def test_modbus_disconnect_detection(self, detector, mock_socket):
        """Test detection when server disconnects on Modbus request."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"\x00\x01\x00"  # Short response < 9 bytes

        result = detector.detect_active("192.168.1.1", 502)

        indicator_names = [ind.name for ind in result.indicators]
        assert "modbus_disconnect" in indicator_names
        assert any(ind.severity == Confidence.MEDIUM for ind in result.indicators)

    def test_modbus_connection_reset(self, detector, mock_socket):
        """Test detection of Modbus connection reset."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = socket.error("Connection reset by peer")

        result = detector.detect_active("192.168.1.1", 502)

        indicator_names = [ind.name for ind in result.indicators]
        assert "modbus_connection_reset" in indicator_names

    def test_modbus_no_signature(self, detector, mock_socket):
        """Test no detection when Modbus response has no known signatures."""
        socket_instance = mock_socket.return_value

        # Valid Modbus response but with unknown vendor
        response = b"\x00\x01\x00\x00\x00\x20\x01\x2b\x0e\x01\x00\x00\x01\x00UnknownVendor\x00"
        socket_instance.recv.return_value = response

        result = detector.detect_active("192.168.1.1", 502)

        indicator_names = [ind.name for ind in result.indicators]
        assert "conpot_modbus_signature" not in indicator_names


class TestHTTPDetection:
    """Test HTTP detection for Conpot web interface signatures."""

    @pytest.fixture
    def detector(self):
        """Create Conpot detector instance."""
        return ConpotDetector()

    def test_http_siemens_reference(self, detector):
        """Test detection of Siemens reference in HTTP response."""
        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.text = "<html><body>Siemens Industrial Control</body></html>"
            mock_get.return_value = mock_response

            result = detector.detect_active("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "conpot_http_signature" in indicator_names
        assert any(ind.severity == Confidence.MEDIUM for ind in result.indicators)

    def test_http_s7_200_reference(self, detector):
        """Test detection of S7-200 reference in HTTP response."""
        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.text = "<html><body>Welcome to S7-200 Web Panel</body></html>"
            mock_get.return_value = mock_response

            result = detector.detect_active("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "conpot_http_signature" in indicator_names

    def test_http_no_signature(self, detector):
        """Test no detection when HTTP response has no Conpot signatures."""
        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.text = "<html><body>Normal website</body></html>"
            mock_get.return_value = mock_response

            result = detector.detect_active("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "conpot_http_signature" not in indicator_names

    def test_http_request_exception(self, detector):
        """Test handling of HTTP request exception."""
        with patch("requests.get") as mock_get:
            mock_get.side_effect = Exception("Connection refused")

            result = detector.detect_active("192.168.1.1", 80)

        assert not result.is_honeypot


class TestSNMPDetection:
    """Test SNMP detection for Conpot signatures."""

    @pytest.fixture
    def detector(self):
        """Create Conpot detector instance."""
        return ConpotDetector()

    @pytest.mark.parametrize(
        "snmp_value",
        [
            "S7-200",
            "Siemens",
        ],
    )
    def test_snmp_default_signatures(self, detector, mock_socket, snmp_value):
        """Test detection of Conpot default SNMP values."""
        socket_instance = mock_socket.return_value

        # SNMP response containing the signature
        response = b"\x30\x50\x02\x01\x00\x04\x06public\xa2\x43" + snmp_value.encode() + b"\x00" * 30

        socket_instance.recvfrom.return_value = (response, ("192.168.1.1", 161))

        result = detector.detect_active("192.168.1.1", 161)

        indicator_names = [ind.name for ind in result.indicators]
        assert "conpot_snmp_signature" in indicator_names

    def test_snmp_timeout(self, detector, mock_socket):
        """Test handling of SNMP timeout."""
        socket_instance = mock_socket.return_value
        socket_instance.recvfrom.side_effect = socket.timeout()

        result = detector.detect_active("192.168.1.1", 161)

        assert not result.is_honeypot

    def test_snmp_no_signature(self, detector, mock_socket):
        """Test no detection when SNMP response has no known signatures."""
        socket_instance = mock_socket.return_value

        response = b"\x30\x50\x02\x01\x00\x04\x06public\xa2\x43GenericDevice\x00" * 2
        socket_instance.recvfrom.return_value = (response, ("192.168.1.1", 161))

        result = detector.detect_active("192.168.1.1", 161)

        indicator_names = [ind.name for ind in result.indicators]
        assert "conpot_snmp_signature" not in indicator_names


class TestMultiPortDetection:
    """Test multi-ICS-port correlation detection."""

    @pytest.fixture
    def detector(self):
        """Create Conpot detector instance."""
        return ConpotDetector()

    def test_three_or_more_ics_ports_open(self, detector):
        """Test detection when 3+ ICS ports are open."""
        with patch("potsnitch.utils.network.is_port_open") as mock_is_open:
            # 4 ICS ports open
            mock_is_open.side_effect = lambda target, port, timeout: port in [102, 502, 47808, 80]

            result = DetectionResult(target="192.168.1.1", port=102)
            detector._check_port_combination("192.168.1.1", result)

        indicator_names = [ind.name for ind in result.indicators]
        assert "conpot_port_combination" in indicator_names
        assert any(ind.severity == Confidence.HIGH for ind in result.indicators)

    def test_two_ics_ports_open(self, detector):
        """Test detection when exactly 2 ICS ports are open."""
        with patch("potsnitch.utils.network.is_port_open") as mock_is_open:
            # 2 ICS ports open
            mock_is_open.side_effect = lambda target, port, timeout: port in [102, 502]

            result = DetectionResult(target="192.168.1.1", port=102)
            detector._check_port_combination("192.168.1.1", result)

        indicator_names = [ind.name for ind in result.indicators]
        assert "multi_ics_ports" in indicator_names
        assert any(ind.severity == Confidence.MEDIUM for ind in result.indicators)

    def test_single_ics_port_open(self, detector):
        """Test no detection when only 1 ICS port is open."""
        with patch("potsnitch.utils.network.is_port_open") as mock_is_open:
            mock_is_open.side_effect = lambda target, port, timeout: port == 102

            result = DetectionResult(target="192.168.1.1", port=102)
            detector._check_port_combination("192.168.1.1", result)

        assert len(result.indicators) == 0


class TestPassiveDetection:
    """Test passive detection mode."""

    @pytest.fixture
    def detector(self):
        """Create Conpot detector instance."""
        return ConpotDetector()

    @pytest.mark.parametrize(
        "port,expected_indicator",
        [
            (102, "s7comm_port"),
            (502, "modbus_port"),
            (47808, "bacnet_port"),
        ],
    )
    def test_passive_ics_port_detection(self, detector, port, expected_indicator):
        """Test passive detection of ICS ports."""
        with patch("potsnitch.utils.network.is_port_open") as mock_is_open:
            mock_is_open.return_value = False

            result = detector.detect_passive("192.168.1.1", port)

        indicator_names = [ind.name for ind in result.indicators]
        assert expected_indicator in indicator_names

    def test_passive_multi_port_check(self, detector):
        """Test passive mode includes multi-port correlation."""
        with patch("potsnitch.utils.network.is_port_open") as mock_is_open:
            mock_is_open.side_effect = lambda target, port, timeout: port in [102, 502, 80]

            result = detector.detect_passive("192.168.1.1", 102)

        indicator_names = [ind.name for ind in result.indicators]
        assert "conpot_port_combination" in indicator_names


class TestBACnetDetection:
    """Test BACnet protocol detection."""

    @pytest.fixture
    def detector(self):
        """Create Conpot detector instance."""
        return ConpotDetector()

    def test_bacnet_response_detection(self, detector, mock_socket):
        """Test detection of BACnet response."""
        socket_instance = mock_socket.return_value

        # BACnet I-Am response
        bacnet_response = b"\x81\x0b\x00\x12\x01\x00\x10\x00\xc4\x02\x00\x00\x01\x22\x01\xe0\x91\x00"
        socket_instance.recvfrom.return_value = (bacnet_response, ("192.168.1.1", 47808))

        result = detector.detect_active("192.168.1.1", 47808)

        indicator_names = [ind.name for ind in result.indicators]
        assert "bacnet_response" in indicator_names

    def test_bacnet_timeout(self, detector, mock_socket):
        """Test handling of BACnet timeout."""
        socket_instance = mock_socket.return_value
        socket_instance.recvfrom.side_effect = socket.timeout()

        result = detector.detect_active("192.168.1.1", 47808)

        assert not result.is_honeypot


class TestValidateMethod:
    """Test the validate method with multi-port checks."""

    @pytest.fixture
    def detector(self):
        """Create Conpot detector instance."""
        return ConpotDetector()

    def test_validate_multi_ics_ports(self, detector):
        """Test validate method checks for multiple ICS ports."""
        with patch("potsnitch.utils.network.scan_ports") as mock_scan, \
             patch("potsnitch.utils.network.is_port_open") as mock_is_open, \
             patch("socket.socket"):
            mock_scan.return_value = [102, 502, 161]
            mock_is_open.return_value = False

            result = detector.validate("192.168.1.1", 102)

        indicator_names = [ind.name for ind in result.indicators]
        assert "multi_ics_ports" in indicator_names


class TestRecommendations:
    """Test detector recommendations."""

    @pytest.fixture
    def detector(self):
        """Create Conpot detector instance."""
        return ConpotDetector()

    def test_s7_signature_recommendation(self, detector):
        """Test recommendations for S7 signature detection."""
        from potsnitch.core.result import Indicator

        result = DetectionResult(target="192.168.1.1", port=102)
        result.add_indicator(
            Indicator(
                name="conpot_s7_signature",
                description="Conpot default S7 system_names: Technodrome",
                severity=Confidence.DEFINITE,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any("template" in r.lower() for r in recommendations)

    def test_modbus_signature_recommendation(self, detector):
        """Test recommendations for Modbus signature detection."""
        from potsnitch.core.result import Indicator

        result = DetectionResult(target="192.168.1.1", port=502)
        result.add_indicator(
            Indicator(
                name="conpot_modbus_signature",
                description="Conpot default Modbus vendor",
                severity=Confidence.HIGH,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any("modbus" in r.lower() for r in recommendations)

    def test_multi_ics_recommendation(self, detector):
        """Test recommendations for multi-ICS port detection."""
        from potsnitch.core.result import Indicator

        result = DetectionResult(target="192.168.1.1", port=102)
        result.add_indicator(
            Indicator(
                name="multi_ics_ports",
                description="Multiple ICS ports open",
                severity=Confidence.HIGH,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any("protocol" in r.lower() for r in recommendations)


class TestDetectorProperties:
    """Test detector class properties."""

    def test_detector_name(self):
        """Test detector name property."""
        detector = ConpotDetector()
        assert detector.name == "conpot"

    def test_detector_description(self):
        """Test detector has description."""
        detector = ConpotDetector()
        assert detector.description is not None
        assert "conpot" in detector.description.lower() or "ics" in detector.description.lower()

    def test_detector_honeypot_types(self):
        """Test detector honeypot types."""
        detector = ConpotDetector()
        assert "conpot" in detector.honeypot_types

    def test_detector_default_ports(self):
        """Test detector default ports include ICS ports."""
        detector = ConpotDetector()
        assert 102 in detector.default_ports
        assert 502 in detector.default_ports
        assert 47808 in detector.default_ports

    def test_detector_modes(self):
        """Test detector can be initialized in different modes."""
        passive_detector = ConpotDetector(mode=DetectionMode.PASSIVE)
        assert passive_detector.mode == DetectionMode.PASSIVE

        active_detector = ConpotDetector(mode=DetectionMode.ACTIVE)
        assert active_detector.mode == DetectionMode.ACTIVE

        full_detector = ConpotDetector(mode=DetectionMode.FULL)
        assert full_detector.mode == DetectionMode.FULL
