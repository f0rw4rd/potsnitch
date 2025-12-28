"""
Unit tests for T-Pot multi-honeypot platform detector.

Tests T-Pot framework detection, Kibana port detection, honeypot combination
detection, individual honeypot signatures (Cowrie, Dionaea, Conpot), and
multi-service correlation.
"""

import socket
import pytest
from unittest.mock import MagicMock, patch, PropertyMock

from potsnitch.detectors.tpot import (
    TPotDetector,
    TPOT_STANDARD_PORTS,
    HERALDING_BANNERS,
    ELASTICPOT_DEFAULTS,
    TPOT_SIGNATURES,
)
from potsnitch.core.result import DetectionResult, Indicator, Confidence
from potsnitch.core.base import DetectionMode


class TestTPotDetectorProperties:
    """Tests for TPotDetector class properties."""

    @pytest.fixture
    def detector(self):
        """Create T-Pot detector instance."""
        return TPotDetector()

    def test_detector_name(self, detector):
        """Test detector name is set correctly."""
        assert detector.name == "tpot"

    def test_detector_description(self, detector):
        """Test detector has a description."""
        assert detector.description is not None
        assert len(detector.description) > 0

    def test_detector_honeypot_types(self, detector):
        """Test detector lists supported honeypot types."""
        assert "tpot" in detector.honeypot_types
        assert "heralding" in detector.honeypot_types
        assert "mailoney" in detector.honeypot_types
        assert "redishoneypot" in detector.honeypot_types
        assert "adbhoney" in detector.honeypot_types
        assert "ipphoney" in detector.honeypot_types
        assert "medpot" in detector.honeypot_types
        assert "dicompot" in detector.honeypot_types
        assert "sentrypeer" in detector.honeypot_types
        assert "ddospot" in detector.honeypot_types

    def test_detector_default_ports(self, detector):
        """Test detector has default ports configured."""
        assert 631 in detector.default_ports  # IPP
        assert 2575 in detector.default_ports  # HL7
        assert 5060 in detector.default_ports  # SIP
        assert 5555 in detector.default_ports  # ADB
        assert 6379 in detector.default_ports  # Redis
        assert 8443 in detector.default_ports  # Cisco ASA
        assert 9100 in detector.default_ports  # Printer
        assert 11112 in detector.default_ports  # DICOM

    def test_detector_info(self, detector):
        """Test get_info method."""
        info = detector.get_info()
        assert info["name"] == "tpot"
        assert len(info["honeypot_types"]) > 0
        assert len(info["default_ports"]) > 0


class TestTPotKibanaPortDetection:
    """Tests for T-Pot Kibana admin interface port detection."""

    @pytest.fixture
    def detector(self):
        """Create T-Pot detector instance."""
        return TPotDetector()

    def test_detect_kibana_port_64297(self, detector):
        """Test detection of T-Pot Kibana port 64297."""
        result = detector.detect_passive("192.168.1.100", 64297)

        assert result.is_honeypot
        assert result.honeypot_type == "tpot"
        assert any(i.name == "tpot_kibana_port" for i in result.indicators)
        assert any(i.severity == Confidence.HIGH for i in result.indicators)

    def test_no_detection_other_ports(self, detector):
        """Test that random ports don't trigger Kibana detection."""
        result = detector.detect_passive("192.168.1.100", 8080)

        assert not any(i.name == "tpot_kibana_port" for i in result.indicators)


class TestTPotADBPortDetection:
    """Tests for ADB honeypot port detection."""

    @pytest.fixture
    def detector(self):
        """Create T-Pot detector instance."""
        return TPotDetector()

    def test_detect_adb_port_5555(self, detector):
        """Test detection of ADB port 5555."""
        result = detector.detect_passive("192.168.1.100", 5555)

        assert any(i.name == "tpot_adb_port" for i in result.indicators)
        assert any(i.severity == Confidence.MEDIUM for i in result.indicators)

    def test_no_adb_detection_other_ports(self, detector):
        """Test that other ports don't trigger ADB detection."""
        result = detector.detect_passive("192.168.1.100", 8080)

        assert not any(i.name == "tpot_adb_port" for i in result.indicators)


class TestTPotMedicalPortDetection:
    """Tests for medical protocol honeypot port detection."""

    @pytest.fixture
    def detector(self):
        """Create T-Pot detector instance."""
        return TPotDetector()

    def test_detect_hl7_port_2575(self, detector):
        """Test detection of HL7 port 2575 (medpot)."""
        result = detector.detect_passive("192.168.1.100", 2575)

        assert result.is_honeypot
        assert any(i.name == "tpot_hl7_port" for i in result.indicators)
        assert any(i.severity == Confidence.HIGH for i in result.indicators)

    @pytest.mark.parametrize("port", [104, 11112])
    def test_detect_dicom_ports(self, detector, port):
        """Test detection of DICOM ports (dicompot)."""
        result = detector.detect_passive("192.168.1.100", port)

        assert result.is_honeypot
        assert any(i.name == "tpot_dicom_port" for i in result.indicators)
        assert any(i.severity == Confidence.HIGH for i in result.indicators)


class TestHeraldingMailBannerDetection:
    """Tests for Heralding mail protocol banner detection."""

    @pytest.fixture
    def detector(self):
        """Create T-Pot detector instance."""
        return TPotDetector()

    @pytest.mark.parametrize("port", [110, 995])
    def test_detect_heralding_pop3_banner(self, detector, port, mock_socket):
        """Test detection of Heralding POP3 banner."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"+OK POP3 server ready\r\n"

        result = detector.detect_passive("192.168.1.100", port)

        assert result.is_honeypot
        assert result.honeypot_type == "heralding"
        assert any(i.name == "heralding_pop3" for i in result.indicators)

    @pytest.mark.parametrize("port", [143, 993])
    def test_detect_heralding_imap_banner(self, detector, port, mock_socket):
        """Test detection of Heralding IMAP banner."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"* OK IMAP4rev1 Server Ready\r\n"

        result = detector.detect_passive("192.168.1.100", port)

        assert result.is_honeypot
        assert result.honeypot_type == "heralding"
        assert any(i.name == "heralding_imap" for i in result.indicators)

    def test_detect_heralding_smtp_banner(self, detector, mock_socket):
        """Test detection of Heralding SMTP banner."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"220 Microsoft ESMTP MAIL service ready\r\n"

        result = detector.detect_passive("192.168.1.100", 465)

        assert result.is_honeypot
        assert result.honeypot_type == "heralding"
        assert any(i.name == "heralding_smtp" for i in result.indicators)

    def test_socket_timeout_handling(self, detector, mock_socket):
        """Test graceful handling of socket timeout."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = socket.timeout()

        result = detector.detect_passive("192.168.1.100", 110)

        # Should not raise exception, just return result
        assert result.error is None

    def test_socket_error_handling(self, detector, mock_socket):
        """Test graceful handling of socket errors."""
        socket_instance = mock_socket.return_value
        socket_instance.connect.side_effect = socket.error("Connection refused")

        result = detector.detect_passive("192.168.1.100", 110)

        assert result.error is None


class TestTPotRedisHoneypotDetection:
    """Tests for Redis honeypot (redishoneypot) detection."""

    @pytest.fixture
    def detector(self):
        """Create T-Pot detector instance."""
        return TPotDetector()

    def test_detect_redis_honeypot_limited_commands(self, detector, mock_socket):
        """Test detection of Redis honeypot with limited command support."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = [
            b"+PONG\r\n",  # PING response
            b"-ERR unknown command 'CONFIG'\r\n",  # CONFIG GET rejected
        ]

        result = detector.detect_active("192.168.1.100", 6379)

        assert result.is_honeypot
        assert result.honeypot_type == "redishoneypot"
        assert any(i.name == "redis_honeypot" for i in result.indicators)

    def test_redis_honeypot_short_response(self, detector, mock_socket):
        """Test detection when CONFIG returns very short response."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = [
            b"+PONG\r\n",
            b"+OK\r\n",  # Very short response
        ]

        result = detector.detect_active("192.168.1.100", 6379)

        assert result.is_honeypot
        assert result.honeypot_type == "redishoneypot"

    def test_real_redis_not_detected(self, detector, mock_socket):
        """Test that real Redis with full CONFIG support is not flagged."""
        socket_instance = mock_socket.return_value
        # Real Redis returns extensive config data
        long_config = b"*200\r\n" + b"$20\r\n" * 100  # Long response
        socket_instance.recv.side_effect = [
            b"+PONG\r\n",
            long_config,
        ]

        result = detector.detect_active("192.168.1.100", 6379)

        assert not any(i.name == "redis_honeypot" for i in result.indicators)

    def test_redis_socket_timeout(self, detector, mock_socket):
        """Test Redis probe handles socket timeout gracefully."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = socket.timeout()

        result = detector.detect_active("192.168.1.100", 6379)

        assert result.error is None


class TestTPotADBHoneyDetection:
    """Tests for ADB honeypot (adbhoney) detection."""

    @pytest.fixture
    def detector(self):
        """Create T-Pot detector instance."""
        return TPotDetector()

    def test_detect_adb_honeypot_response(self, detector, mock_socket):
        """Test detection of ADB honeypot response."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"CNXN\x00\x01\x00\x00\x01\x00\x10\x00"

        result = detector.detect_active("192.168.1.100", 5555)

        assert result.is_honeypot
        assert result.honeypot_type == "adbhoney"
        assert any(i.name == "adb_honeypot" for i in result.indicators)

    def test_adb_no_response(self, detector, mock_socket):
        """Test ADB probe with no response."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b""

        result = detector.detect_active("192.168.1.100", 5555)

        assert not any(i.name == "adb_honeypot" for i in result.indicators)

    def test_adb_socket_error(self, detector, mock_socket):
        """Test ADB probe handles socket error gracefully."""
        socket_instance = mock_socket.return_value
        socket_instance.connect.side_effect = OSError("Connection refused")

        result = detector.detect_active("192.168.1.100", 5555)

        assert result.error is None


class TestTPotIPPHoneyDetection:
    """Tests for IPP honeypot (ipphoney) detection."""

    @pytest.fixture
    def detector(self):
        """Create T-Pot detector instance."""
        return TPotDetector()

    def test_detect_ipp_honeypot_200(self, detector):
        """Test detection of IPP honeypot with 200 response."""
        with patch.dict("sys.modules", {"requests": MagicMock()}):
            import sys
            mock_requests = sys.modules["requests"]
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.post.return_value = mock_response

            result = detector.detect_active("192.168.1.100", 631)

            assert result.is_honeypot
            assert result.honeypot_type == "ipphoney"
            assert any(i.name == "ipp_honeypot" for i in result.indicators)

    def test_detect_ipp_honeypot_400(self, detector):
        """Test detection of IPP honeypot with 400 response."""
        with patch.dict("sys.modules", {"requests": MagicMock()}):
            import sys
            mock_requests = sys.modules["requests"]
            mock_response = MagicMock()
            mock_response.status_code = 400
            mock_requests.post.return_value = mock_response

            result = detector.detect_active("192.168.1.100", 631)

            assert result.is_honeypot
            assert result.honeypot_type == "ipphoney"

    def test_ipp_request_exception(self, detector):
        """Test IPP probe handles request exception gracefully."""
        with patch.dict("sys.modules", {"requests": MagicMock()}):
            import sys
            mock_requests = sys.modules["requests"]
            mock_requests.post.side_effect = Exception("Connection failed")

            result = detector.detect_active("192.168.1.100", 631)

            assert result.error is None


class TestTPotPrinterHoneyDetection:
    """Tests for printer honeypot (miniprint) detection."""

    @pytest.fixture
    def detector(self):
        """Create T-Pot detector instance."""
        return TPotDetector()

    def test_detect_miniprint_pjl_response(self, detector, mock_socket):
        """Test detection of miniprint via PJL response."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"@PJL INFO ID\r\nHP LaserJet\r\n"

        result = detector.detect_active("192.168.1.100", 9100)

        assert result.is_honeypot
        assert result.honeypot_type == "miniprint"
        assert any(i.name == "printer_honeypot" for i in result.indicators)

    def test_printer_no_response(self, detector, mock_socket):
        """Test printer probe with no response."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b""

        result = detector.detect_active("192.168.1.100", 9100)

        assert not any(i.name == "printer_honeypot" for i in result.indicators)


class TestTPotMedpotDetection:
    """Tests for medical honeypot (medpot) detection."""

    @pytest.fixture
    def detector(self):
        """Create T-Pot detector instance."""
        return TPotDetector()

    def test_detect_medpot_hl7_response(self, detector, mock_socket):
        """Test detection of medpot via HL7 response."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"\x0bMSH|^~\\&|ACK\r\x1c\r"

        result = detector.detect_active("192.168.1.100", 2575)

        assert result.is_honeypot
        assert result.honeypot_type == "medpot"
        assert any(i.name == "hl7_honeypot" for i in result.indicators)
        assert any(i.severity == Confidence.HIGH for i in result.indicators)

    def test_medpot_socket_timeout(self, detector, mock_socket):
        """Test medpot probe handles timeout gracefully."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = socket.timeout()

        result = detector.detect_active("192.168.1.100", 2575)

        assert result.error is None


class TestTPotSIPDetection:
    """Tests for SIP honeypot (sentrypeer) detection."""

    @pytest.fixture
    def detector(self):
        """Create T-Pot detector instance."""
        return TPotDetector()

    def test_detect_sentrypeer_sip_response(self, detector, mock_socket):
        """Test detection of sentrypeer via SIP response."""
        socket_instance = mock_socket.return_value
        socket_instance.recvfrom.return_value = (
            b"SIP/2.0 200 OK\r\n",
            ("192.168.1.100", 5060),
        )

        result = detector.detect_active("192.168.1.100", 5060)

        assert result.is_honeypot
        assert result.honeypot_type == "sentrypeer"
        assert any(i.name == "sip_honeypot" for i in result.indicators)

    def test_sip_no_response(self, detector, mock_socket):
        """Test SIP probe with no response."""
        socket_instance = mock_socket.return_value
        socket_instance.recvfrom.side_effect = socket.timeout()

        result = detector.detect_active("192.168.1.100", 5060)

        assert result.error is None


class TestTPotDICOMDetection:
    """Tests for DICOM honeypot (dicompot) detection."""

    @pytest.fixture
    def detector(self):
        """Create T-Pot detector instance."""
        return TPotDetector()

    @pytest.mark.parametrize("port", [104, 11112])
    def test_detect_dicompot_response(self, detector, port, mock_socket):
        """Test detection of dicompot via DICOM response."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"\x02\x00DICOM\x00"

        result = detector.detect_active("192.168.1.100", port)

        assert result.is_honeypot
        assert result.honeypot_type == "dicompot"
        assert any(i.name == "dicom_honeypot" for i in result.indicators)

    def test_dicom_no_response(self, detector, mock_socket):
        """Test DICOM probe with no response."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b""

        result = detector.detect_active("192.168.1.100", 11112)

        assert not any(i.name == "dicom_honeypot" for i in result.indicators)


class TestTPotLog4PotDetection:
    """Tests for Log4j honeypot (log4pot) detection."""

    @pytest.fixture
    def detector(self):
        """Create T-Pot detector instance."""
        return TPotDetector()

    def test_detect_log4pot_sap_response(self, detector):
        """Test detection of log4pot with SAP NetWeaver response."""
        with patch.dict("sys.modules", {"requests": MagicMock()}):
            import sys
            mock_requests = sys.modules["requests"]
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "<html><title>SAP NetWeaver</title></html>"
            mock_requests.get.return_value = mock_response

            result = detector.detect_active("192.168.1.100", 8080)

            assert result.is_honeypot
            assert result.honeypot_type == "log4pot"
            assert any(i.name == "log4pot_sap" for i in result.indicators)

    def test_detect_log4pot_minimal_response(self, detector):
        """Test detection of log4pot with minimal HTTP response."""
        with patch.dict("sys.modules", {"requests": MagicMock()}):
            import sys
            mock_requests = sys.modules["requests"]
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "<html>OK</html>"  # Less than 1000 chars
            mock_requests.get.return_value = mock_response

            result = detector.detect_active("192.168.1.100", 8080)

            assert any(i.name == "log4pot_minimal" for i in result.indicators)

    def test_log4pot_request_exception(self, detector):
        """Test log4pot probe handles request exception gracefully."""
        with patch.dict("sys.modules", {"requests": MagicMock()}):
            import sys
            mock_requests = sys.modules["requests"]
            mock_requests.get.side_effect = Exception("Connection failed")

            result = detector.detect_active("192.168.1.100", 8080)

            assert result.error is None


class TestTPotDDoSPotDetection:
    """Tests for DDoS amplification honeypot (ddospot) detection."""

    @pytest.fixture
    def detector(self):
        """Create T-Pot detector instance."""
        return TPotDetector()

    def test_detect_ddospot_chargen(self, detector, mock_socket):
        """Test detection of ddospot chargen service."""
        socket_instance = mock_socket.return_value
        socket_instance.recvfrom.return_value = (
            b"!\"#$%&'()*+,-./0123456789",  # Chargen response
            ("192.168.1.100", 19),
        )

        result = detector.detect_active("192.168.1.100", 19)

        assert result.is_honeypot
        assert result.honeypot_type == "ddospot"
        assert any(i.name == "ddospot_chargen" for i in result.indicators)
        assert any(i.severity == Confidence.HIGH for i in result.indicators)

    def test_detect_ddospot_ssdp(self, detector, mock_socket):
        """Test detection of ddospot SSDP service."""
        socket_instance = mock_socket.return_value
        socket_instance.recvfrom.return_value = (
            b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n",
            ("192.168.1.100", 1900),
        )

        result = detector.detect_active("192.168.1.100", 1900)

        assert result.is_honeypot
        assert result.honeypot_type == "ddospot"
        assert any(i.name == "ddospot_ssdp" for i in result.indicators)

    def test_ddospot_chargen_timeout(self, detector, mock_socket):
        """Test chargen probe handles timeout gracefully."""
        socket_instance = mock_socket.return_value
        socket_instance.recvfrom.side_effect = socket.timeout()

        result = detector.detect_active("192.168.1.100", 19)

        assert result.error is None

    def test_ddospot_ssdp_timeout(self, detector, mock_socket):
        """Test SSDP probe handles timeout gracefully."""
        socket_instance = mock_socket.return_value
        socket_instance.recvfrom.side_effect = socket.timeout()

        result = detector.detect_active("192.168.1.100", 1900)

        assert result.error is None


class TestTPotValidation:
    """Tests for comprehensive T-Pot validation scanning."""

    @pytest.fixture
    def detector(self):
        """Create T-Pot detector instance."""
        return TPotDetector()

    @patch("potsnitch.detectors.tpot.scan_ports")
    def test_validate_tpot_port_signature(self, mock_scan_ports, detector, mock_socket):
        """Test validation detects T-Pot port signature."""
        # Simulate many T-Pot ports open
        mock_scan_ports.return_value = [
            22, 23, 80, 443, 631, 2575, 5555, 6379, 8080, 9100, 11112
        ]
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b""

        result = detector.validate("192.168.1.100", 22)

        assert result.is_honeypot
        assert result.honeypot_type == "tpot"
        assert any(i.name == "tpot_port_signature" for i in result.indicators)

    @patch("potsnitch.detectors.tpot.scan_ports")
    def test_validate_tpot_unique_services(self, mock_scan_ports, detector, mock_socket):
        """Test validation detects T-Pot unique service combination."""
        # Simulate T-Pot specific ports open
        mock_scan_ports.return_value = [5555, 631, 2575, 9100, 11112]
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b""

        result = detector.validate("192.168.1.100", 22)

        assert any(i.name == "tpot_unique_services" for i in result.indicators)

    @patch("potsnitch.detectors.tpot.scan_ports")
    def test_validate_few_ports_no_signature(self, mock_scan_ports, detector, mock_socket):
        """Test validation with few open ports doesn't trigger signature."""
        mock_scan_ports.return_value = [22, 80, 443]
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b""

        result = detector.validate("192.168.1.100", 22)

        assert not any(i.name == "tpot_port_signature" for i in result.indicators)


class TestTPotRecommendations:
    """Tests for T-Pot detection recommendations."""

    @pytest.fixture
    def detector(self):
        """Create T-Pot detector instance."""
        return TPotDetector()

    def test_recommendations_for_heralding(self, detector):
        """Test recommendations for Heralding detection."""
        result = DetectionResult(target="192.168.1.100", port=110)
        result.add_indicator(
            Indicator(
                name="heralding_pop3",
                description="Heralding POP3 banner detected",
                severity=Confidence.HIGH,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any("heralding" in r.lower() for r in recommendations)

    def test_recommendations_for_tpot_port(self, detector):
        """Test recommendations for T-Pot port detection."""
        result = DetectionResult(target="192.168.1.100", port=64297)
        result.add_indicator(
            Indicator(
                name="tpot_port_signature",
                description="T-Pot port configuration detected",
                severity=Confidence.HIGH,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any("honeypot" in r.lower() or "docker" in r.lower() for r in recommendations)

    def test_recommendations_for_redis(self, detector):
        """Test recommendations for Redis honeypot detection."""
        result = DetectionResult(target="192.168.1.100", port=6379)
        result.add_indicator(
            Indicator(
                name="redis_honeypot",
                description="Redis honeypot detected",
                severity=Confidence.HIGH,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any("redis" in r.lower() for r in recommendations)


class TestTPotDetectionModes:
    """Tests for T-Pot detector modes."""

    def test_passive_mode_only(self, mock_socket):
        """Test detector in passive-only mode."""
        detector = TPotDetector(mode=DetectionMode.PASSIVE)
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"+OK POP3 server ready\r\n"

        result = detector.detect("192.168.1.100", 110)

        # Should only run passive detection
        assert result.is_honeypot
        assert result.honeypot_type == "heralding"

    def test_active_mode_only(self, mock_socket):
        """Test detector in active-only mode."""
        detector = TPotDetector(mode=DetectionMode.ACTIVE)
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = [
            b"+PONG\r\n",
            b"-ERR unknown command\r\n",
        ]

        result = detector.detect("192.168.1.100", 6379)

        assert result.is_honeypot
        assert result.honeypot_type == "redishoneypot"

    def test_full_mode(self, mock_socket):
        """Test detector in full mode (default)."""
        detector = TPotDetector(mode=DetectionMode.FULL)

        assert detector.mode == DetectionMode.FULL


class TestTPotStandardPortsConfiguration:
    """Tests for T-Pot standard ports configuration."""

    def test_adbhoney_ports(self):
        """Test ADBHoney port configuration."""
        assert 5555 in TPOT_STANDARD_PORTS["adbhoney"]

    def test_cowrie_ports(self):
        """Test Cowrie port configuration."""
        assert 22 in TPOT_STANDARD_PORTS["cowrie"]
        assert 23 in TPOT_STANDARD_PORTS["cowrie"]

    def test_dionaea_ports(self):
        """Test Dionaea port configuration."""
        assert 21 in TPOT_STANDARD_PORTS["dionaea"]
        assert 445 in TPOT_STANDARD_PORTS["dionaea"]
        assert 3306 in TPOT_STANDARD_PORTS["dionaea"]

    def test_conpot_ports(self):
        """Test Conpot port configuration."""
        assert 161 in TPOT_STANDARD_PORTS["conpot"]
        assert 2404 in TPOT_STANDARD_PORTS["conpot"]

    def test_heralding_ports(self):
        """Test Heralding port configuration."""
        assert 110 in TPOT_STANDARD_PORTS["heralding"]
        assert 143 in TPOT_STANDARD_PORTS["heralding"]
        assert 5432 in TPOT_STANDARD_PORTS["heralding"]

    def test_elasticpot_ports(self):
        """Test Elasticpot port configuration."""
        assert 9200 in TPOT_STANDARD_PORTS["elasticpot"]


class TestHeraldingBannersConfiguration:
    """Tests for Heralding banner configuration."""

    def test_ftp_banners(self):
        """Test Heralding FTP banners."""
        assert b"Microsoft FTP Server" in HERALDING_BANNERS["ftp"]

    def test_pop3_banners(self):
        """Test Heralding POP3 banners."""
        assert b"+OK POP3 server ready" in HERALDING_BANNERS["pop3"]

    def test_imap_banners(self):
        """Test Heralding IMAP banners."""
        assert b"* OK IMAP4rev1 Server Ready" in HERALDING_BANNERS["imap"]

    def test_smtp_banners(self):
        """Test Heralding SMTP banners."""
        assert b"Microsoft ESMTP MAIL service ready" in HERALDING_BANNERS["smtp"]

    def test_ssh_banners(self):
        """Test Heralding SSH banners."""
        assert b"SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.8" in HERALDING_BANNERS["ssh"]


class TestElasticpotDefaults:
    """Tests for Elasticpot default configuration."""

    def test_instance_names(self):
        """Test Elasticpot instance names."""
        assert "Green Goblin" in ELASTICPOT_DEFAULTS["instance_names"]
        assert "USNYES01" in ELASTICPOT_DEFAULTS["instance_names"]

    def test_cluster_names(self):
        """Test Elasticpot cluster names."""
        assert "elasticsearch" in ELASTICPOT_DEFAULTS["cluster_names"]

    def test_versions(self):
        """Test Elasticpot versions."""
        assert "1.4.1" in ELASTICPOT_DEFAULTS["versions"]
        assert "2.4.6" in ELASTICPOT_DEFAULTS["versions"]


class TestTPotSignatures:
    """Tests for T-Pot honeypot signatures."""

    def test_redis_signatures(self):
        """Test Redis honeypot signatures."""
        assert b"-ERR unknown command" in TPOT_SIGNATURES["redis"]
        assert b"+PONG" in TPOT_SIGNATURES["redis"]

    def test_mailoney_signatures(self):
        """Test Mailoney signatures."""
        assert b"220 " in TPOT_SIGNATURES["mailoney"]
        assert b"schizo" in TPOT_SIGNATURES["mailoney"]

    def test_adbhoney_signatures(self):
        """Test ADBHoney signatures."""
        assert b"CNXN" in TPOT_SIGNATURES["adbhoney"]


class TestTPotMultiServiceCorrelation:
    """Tests for multi-service correlation detection."""

    @pytest.fixture
    def detector(self):
        """Create T-Pot detector instance."""
        return TPotDetector()

    @patch("potsnitch.detectors.tpot.scan_ports")
    def test_correlation_cowrie_dionaea_combo(self, mock_scan_ports, detector, mock_socket):
        """Test detection of Cowrie + Dionaea combination."""
        # Cowrie ports (22, 23) + Dionaea ports (21, 445, 1433)
        mock_scan_ports.return_value = [21, 22, 23, 445, 1433, 3306, 5555, 631, 2575, 9100]
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b""

        result = detector.validate("192.168.1.100", 22)

        assert result.is_honeypot
        assert any(i.name == "tpot_port_signature" for i in result.indicators)

    @patch("potsnitch.detectors.tpot.scan_ports")
    def test_correlation_conpot_ports(self, mock_scan_ports, detector, mock_socket):
        """Test detection of Conpot ICS ports."""
        # Conpot ports for ICS/SCADA
        mock_scan_ports.return_value = [161, 623, 1025, 2404, 10001, 50100, 5555, 631, 2575, 9100, 11112]
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b""

        result = detector.validate("192.168.1.100", 161)

        assert result.is_honeypot
        assert any(i.name == "tpot_port_signature" for i in result.indicators)
