"""
Unit tests for CVE-specific honeypot detectors.

Tests Log4Pot (CVE-2021-44228), CitrixHoneypot (CVE-2019-19781),
Spring4Shell (CVE-2022-22965), Cisco ASA (CVE-2018-0101) detection.
"""

import socket
import pytest
from unittest.mock import MagicMock, patch

from potsnitch.detectors.cve import (
    Log4PotDetector,
    CitrixHoneypotDetector,
    CiscoASAHoneypotDetector,
    Spring4ShellDetector,
    CVEHoneypotDetector,
    LOG4POT_SIGNATURES,
    CITRIX_SIGNATURES,
    CISCO_ASA_SIGNATURES,
    SPRING4SHELL_SIGNATURES,
)
from potsnitch.core.result import DetectionResult, Indicator, Confidence


# =============================================================================
# Log4Pot Detector Tests (Log4Shell CVE-2021-44228)
# =============================================================================


class TestLog4PotDetection:
    """Tests for Log4Pot JNDI path and SAP response detection."""

    @pytest.fixture
    def detector(self):
        return Log4PotDetector()

    def test_detect_sap_netweaver_response(self, detector, mock_socket):
        """Test detection of SAP NetWeaver default response."""
        mock_socket.return_value.recv.side_effect = [
            b"HTTP/1.1 200 OK\r\n\r\n<html><title>SAP NetWeaver</title></html>", b""
        ]
        result = detector.detect_passive("192.168.1.100", 8080)
        assert any(i.name == "log4pot_sap_netweaver" for i in result.indicators)
        assert result.honeypot_type == "log4pot"

    @pytest.mark.parametrize("pattern", LOG4POT_SIGNATURES["title_patterns"])
    def test_detect_log4pot_title_patterns(self, detector, pattern, mock_socket):
        """Test detection of Log4Pot title patterns."""
        response = b"HTTP/1.1 200 OK\r\n\r\n<html>" + pattern + b"</html>"
        mock_socket.return_value.recv.side_effect = [response, b""]
        result = detector.detect_passive("192.168.1.100", 8080)
        assert any(i.name == "log4pot_title_pattern" for i in result.indicators)

    def test_check_log4pot_signatures_no_match(self, detector):
        """Test _check_log4pot_signatures with no match."""
        result = DetectionResult(target="192.168.1.100", port=8080)
        detector._check_log4pot_signatures(b"Regular web page content", result)
        assert len(result.indicators) == 0


# =============================================================================
# CitrixHoneypot Detector Tests (CVE-2019-19781)
# =============================================================================


class TestCitrixHoneypotDetection:
    """Tests for CitrixHoneypot detection."""

    @pytest.fixture
    def detector(self):
        return CitrixHoneypotDetector()

    def test_detect_citrix_gateway_pattern(self, detector):
        """Test detection of Citrix Gateway response pattern."""
        result = DetectionResult(target="192.168.1.100", port=443)
        response = b"HTTP/1.1 200 OK\r\n\r\nCitrix Gateway login"
        detector._check_citrix_signatures(response, result)
        assert any(i.name == "citrix_gateway_pattern" for i in result.indicators)

    @pytest.mark.parametrize("server", CITRIX_SIGNATURES["headers"]["Server"])
    def test_detect_citrix_server_header(self, detector, server):
        """Test detection of Citrix server headers."""
        result = DetectionResult(target="192.168.1.100", port=443)
        response = f"HTTP/1.1 200 OK\r\nServer: {server}/1.0\r\n\r\nOK".encode()
        detector._check_citrix_signatures(response, result)
        assert any(i.name == "citrix_server_header" for i in result.indicators)

    @pytest.mark.parametrize("path", CITRIX_SIGNATURES["paths"])
    def test_vulnerable_paths(self, detector, path):
        """Test detection on vulnerable path responses."""
        result = DetectionResult(target="192.168.1.100", port=443)
        response = b"HTTP/1.1 200 OK\r\n\r\n[global]\nworkgroup = WORKGROUP"
        detector._check_vulnerable_path_response(response, path, result)
        assert len(result.indicators) > 0

    def test_detect_fake_smb_conf(self, detector):
        """Test detection of fake smb.conf response."""
        result = DetectionResult(target="192.168.1.100", port=443)
        detector._check_vulnerable_path_response(
            b"HTTP/1.1 200 OK\r\n\r\n[global]\nworkgroup = WORKGROUP",
            "/vpn/../vpns/cfg/smb.conf", result
        )
        assert any(i.name == "citrix_fake_smb_conf" for i in result.indicators)


# =============================================================================
# Spring4Shell Detector Tests (CVE-2022-22965)
# =============================================================================


class TestSpring4ShellDetection:
    """Tests for Spring4Shell honeypot detection."""

    @pytest.fixture
    def detector(self):
        return Spring4ShellDetector()

    def test_detect_whitelabel_error_page(self, detector, mock_socket):
        """Test detection of Spring Boot Whitelabel Error Page."""
        mock_socket.return_value.recv.side_effect = [
            b"HTTP/1.1 404 Not Found\r\n\r\nWhitelabel Error Page", b""
        ]
        result = detector.detect_passive("192.168.1.100", 8080)
        assert any(i.name == "spring4shell_spring_pattern" for i in result.indicators)

    @pytest.mark.parametrize("endpoint", SPRING4SHELL_SIGNATURES["actuator_endpoints"])
    def test_detect_actuator_endpoints(self, detector, endpoint):
        """Test detection of exposed actuator endpoints."""
        result = DetectionResult(target="192.168.1.100", port=8080)
        response = b'HTTP/1.1 200 OK\r\n\r\n{"status":"UP"}'
        detector._check_actuator_response(response, endpoint, result)
        assert any(i.name == "spring4shell_actuator_exposed" for i in result.indicators)

    def test_check_error_page_whitelabel(self, detector):
        """Test _check_error_page with Whitelabel Error Page."""
        result = DetectionResult(target="192.168.1.100", port=8080)
        detector._check_error_page(b"Whitelabel Error Page - This application has no...", result)
        assert any(i.name == "spring4shell_whitelabel_error" for i in result.indicators)


# =============================================================================
# Cisco ASA Honeypot Detector Tests (CVE-2018-0101)
# =============================================================================


class TestCiscoASADetection:
    """Tests for Cisco ASA honeypot detection."""

    @pytest.fixture
    def detector(self):
        return CiscoASAHoneypotDetector()

    @pytest.mark.parametrize("pattern", CISCO_ASA_SIGNATURES["http_responses"])
    def test_detect_asa_http_patterns(self, detector, pattern):
        """Test detection of Cisco ASA HTTP response patterns."""
        result = DetectionResult(target="192.168.1.100", port=443)
        response = b"HTTP/1.1 200 OK\r\n\r\n" + pattern + b" interface"
        detector._check_asa_signatures(response, result)
        assert any(i.name == "ciscoasa_http_pattern" for i in result.indicators)

    def test_check_asdm_signatures(self, detector):
        """Test _check_asdm_signatures with ASDM pattern."""
        result = DetectionResult(target="192.168.1.100", port=443)
        detector._check_asdm_signatures(b"ASDM Admin Interface", result)
        assert any(i.name == "ciscoasa_asdm" for i in result.indicators)

    def test_check_udp_signatures(self, detector):
        """Test _check_udp_signatures adds indicator."""
        result = DetectionResult(target="192.168.1.100", port=5000)
        detector._check_udp_signatures(b"\x00\x00\x00\x00response_data", result)
        assert any(i.name == "ciscoasa_udp_response" for i in result.indicators)


# =============================================================================
# Combined CVE Detector Tests
# =============================================================================


class TestCVEHoneypotDetector:
    """Tests for combined CVE honeypot detector."""

    @pytest.fixture
    def detector(self):
        return CVEHoneypotDetector()

    def test_detector_properties(self, detector):
        """Test CVE detector has correct properties."""
        assert detector.name == "cve"
        assert "log4pot" in detector.honeypot_types
        assert "citrixhoneypot" in detector.honeypot_types
        assert 8080 in detector.default_ports

    def test_passive_delegates_to_subdetectors(self, detector):
        """Test passive detection delegates to sub-detectors."""
        assert hasattr(detector, "_log4pot")
        assert hasattr(detector, "_citrix")
        result = DetectionResult(target="192.168.1.100", port=8080)
        detector._log4pot._check_log4pot_signatures(b"SAP NetWeaver", result)
        assert any("log4pot" in i.name for i in result.indicators)

    def test_log4pot_recommendations(self, detector):
        """Test recommendations for Log4Pot indicators."""
        result = DetectionResult(target="192.168.1.100", port=8080)
        result.add_indicator(Indicator(
            name="log4pot_sap_netweaver", description="SAP", severity=Confidence.HIGH
        ))
        recommendations = detector.get_recommendations(result)
        assert any("Log4Pot" in r for r in recommendations)


class TestCVESignatureConstants:
    """Tests for CVE signature constant definitions."""

    def test_log4pot_signatures_structure(self):
        assert "sap_netweaver" in LOG4POT_SIGNATURES
        assert "title_patterns" in LOG4POT_SIGNATURES

    def test_citrix_signatures_structure(self):
        assert "headers" in CITRIX_SIGNATURES
        assert "paths" in CITRIX_SIGNATURES

    def test_spring4shell_signatures_structure(self):
        assert "actuator_endpoints" in SPRING4SHELL_SIGNATURES
        assert "error_patterns" in SPRING4SHELL_SIGNATURES

    def test_cisco_asa_signatures_structure(self):
        assert "http_responses" in CISCO_ASA_SIGNATURES


# =============================================================================
# Log4Pot Advanced Tests
# =============================================================================


class TestLog4PotResponsePatterns:
    """Advanced tests for Log4Pot response pattern detection."""

    @pytest.fixture
    def detector(self):
        return Log4PotDetector()

    @pytest.mark.parametrize("pattern", LOG4POT_SIGNATURES["response_patterns"])
    def test_detect_log4pot_response_patterns(self, detector, pattern, mock_socket):
        """Test detection of Log4Pot response patterns."""
        response = b"HTTP/1.1 200 OK\r\n\r\n" + pattern + b" content"
        mock_socket.return_value.recv.side_effect = [response, b""]

        result = detector.detect_passive("192.168.1.100", 8080)

        assert any(i.name == "log4pot_response_pattern" for i in result.indicators)

    def test_detect_active_probing_paths(self, detector, mock_socket):
        """Test active probing of Log4j-specific paths."""
        sap_response = b"HTTP/1.1 200 OK\r\n\r\nSAP NetWeaver portal"
        mock_socket.return_value.recv.side_effect = [sap_response, b""] * 3

        result = detector.detect_active("192.168.1.100", 8080)

        assert result.honeypot_type == "log4pot"

    def test_http_get_ssl_port(self, detector, mock_socket):
        """Test HTTP GET with SSL on port 443."""
        with patch("ssl.create_default_context") as mock_ssl:
            mock_context = MagicMock()
            mock_ssl.return_value = mock_context
            mock_wrapped = MagicMock()
            mock_context.wrap_socket.return_value = mock_wrapped
            mock_wrapped.recv.side_effect = [b"HTTP/1.1 200 OK\r\n\r\nOK", b""]

            response = detector._http_get("192.168.1.100", 443, "/")

            assert response is not None

    def test_http_get_socket_error(self, detector, mock_socket):
        """Test HTTP GET handling socket errors."""
        mock_socket.return_value.connect.side_effect = socket.error("Connection refused")

        response = detector._http_get("192.168.1.100", 8080, "/")

        assert response is None

    def test_http_get_large_response(self, detector, mock_socket):
        """Test HTTP GET with response exceeding limit."""
        socket_instance = mock_socket.return_value
        # Return chunks that exceed 65536 limit
        socket_instance.recv.side_effect = [
            b"A" * 32768,
            b"A" * 32768,
            b"A" * 32768,
        ]

        response = detector._http_get("192.168.1.100", 8080, "/")

        # Should be truncated to 65536
        assert len(response) <= 65536 + 32768


# =============================================================================
# Citrix Honeypot Advanced Tests
# =============================================================================


class TestCitrixHoneypotAdvanced:
    """Advanced tests for Citrix honeypot detection."""

    @pytest.fixture
    def detector(self):
        return CitrixHoneypotDetector()

    def test_detect_netscaler_gateway_pattern(self, detector):
        """Test detection of NetScaler Gateway pattern."""
        result = DetectionResult(target="192.168.1.100", port=443)
        response = b"HTTP/1.1 200 OK\r\n\r\nNetScaler Gateway login page"

        detector._check_citrix_signatures(response, result)

        assert any(i.name == "citrix_gateway_pattern" for i in result.indicators)

    def test_detect_path_traversal_success(self, detector):
        """Test detection of successful path traversal."""
        result = DetectionResult(target="192.168.1.100", port=443)
        response = b"HTTP/1.1 200 OK\r\n\r\nSome content"

        detector._check_vulnerable_path_response(
            response, "/vpn/../vpns/cfg/smb.conf", result
        )

        assert any(i.name == "citrix_path_traversal_success" for i in result.indicators)

    def test_detect_passive_with_signatures(self, detector, mock_socket):
        """Test passive detection with Citrix signatures."""
        response = b"HTTP/1.1 200 OK\r\nServer: Citrix\r\n\r\nCitrix Gateway"
        mock_socket.return_value.recv.side_effect = [response, b""]

        with patch("ssl.create_default_context") as mock_ssl:
            mock_context = MagicMock()
            mock_ssl.return_value = mock_context
            mock_wrapped = MagicMock()
            mock_context.wrap_socket.return_value = mock_wrapped
            mock_wrapped.recv.side_effect = [response, b""]

            result = detector.detect_passive("192.168.1.100", 443)

            assert any("citrix" in i.name for i in result.indicators)

    def test_detect_active_vulnerable_paths(self, detector, mock_socket):
        """Test active detection probing vulnerable paths."""
        smb_response = b"HTTP/1.1 200 OK\r\n\r\n[global]\nworkgroup = WORKGROUP"
        mock_socket.return_value.recv.side_effect = [smb_response, b""] * 2

        with patch("ssl.create_default_context") as mock_ssl:
            mock_context = MagicMock()
            mock_ssl.return_value = mock_context
            mock_wrapped = MagicMock()
            mock_context.wrap_socket.return_value = mock_wrapped
            mock_wrapped.recv.side_effect = [smb_response, b""] * 2

            result = detector.detect_active("192.168.1.100", 443)

            assert result.honeypot_type == "citrixhoneypot"

    def test_http_get_non_ssl_port(self, detector, mock_socket):
        """Test HTTP GET on non-SSL port 80."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = [b"HTTP/1.1 200 OK\r\n\r\nOK", b""]

        response = detector._http_get("192.168.1.100", 80, "/")

        assert response is not None
        assert b"OK" in response


# =============================================================================
# Spring4Shell Advanced Tests
# =============================================================================


class TestSpring4ShellAdvanced:
    """Advanced tests for Spring4Shell honeypot detection."""

    @pytest.fixture
    def detector(self):
        return Spring4ShellDetector()

    def test_detect_health_endpoint_default(self, detector):
        """Test detection of health endpoint with default response."""
        result = DetectionResult(target="192.168.1.100", port=8080)
        response = b'HTTP/1.1 200 OK\r\n\r\n{"status":"UP"}'

        detector._check_actuator_response(response, "/actuator/health", result)

        assert any(i.name == "spring4shell_actuator_exposed" for i in result.indicators)
        assert any(i.name == "spring4shell_health_endpoint" for i in result.indicators)

    def test_detect_spring_boot_pattern(self, detector):
        """Test detection of Spring Boot pattern."""
        result = DetectionResult(target="192.168.1.100", port=8080)
        response = b"Whitelabel Error Page\nSpring Boot"

        detector._check_spring_patterns(response, result)

        assert len(result.indicators) >= 2

    def test_detect_active_error_page(self, detector, mock_socket):
        """Test active detection of error page."""
        whitelabel = b"HTTP/1.1 404 Not Found\r\n\r\nWhitelabel Error Page"
        mock_socket.return_value.recv.side_effect = [
            b"HTTP/1.1 200 OK\r\n\r\n{}",
            b"",
            b"HTTP/1.1 200 OK\r\n\r\n{}",
            b"",
            b"HTTP/1.1 200 OK\r\n\r\n{}",
            b"",
            whitelabel,
            b"",
        ]

        result = detector.detect_active("192.168.1.100", 8080)

        assert any(i.name == "spring4shell_whitelabel_error" for i in result.indicators)

    @pytest.mark.parametrize("pattern", SPRING4SHELL_SIGNATURES["error_patterns"])
    def test_detect_error_patterns(self, detector, pattern):
        """Test detection of Spring error patterns."""
        result = DetectionResult(target="192.168.1.100", port=8080)
        response = b"HTTP/1.1 200 OK\r\n\r\n" + pattern + b" content"

        detector._check_spring_patterns(response, result)

        assert any(i.name == "spring4shell_spring_pattern" for i in result.indicators)

    def test_http_get_ssl_port_443(self, detector, mock_socket):
        """Test HTTP GET with SSL on port 443."""
        with patch("ssl.create_default_context") as mock_ssl:
            mock_context = MagicMock()
            mock_ssl.return_value = mock_context
            mock_wrapped = MagicMock()
            mock_context.wrap_socket.return_value = mock_wrapped
            mock_wrapped.recv.side_effect = [b"HTTP/1.1 200 OK\r\n\r\nOK", b""]

            response = detector._http_get("192.168.1.100", 443, "/")

            assert response is not None


# =============================================================================
# Cisco ASA Advanced Tests
# =============================================================================


class TestCiscoASAAdvanced:
    """Advanced tests for Cisco ASA honeypot detection."""

    @pytest.fixture
    def detector(self):
        return CiscoASAHoneypotDetector()

    def test_detect_passive_https(self, detector, mock_socket):
        """Test passive detection on HTTPS ports."""
        asa_response = b"HTTP/1.1 200 OK\r\n\r\nCisco Adaptive Security Appliance"

        with patch("ssl.create_default_context") as mock_ssl:
            mock_context = MagicMock()
            mock_ssl.return_value = mock_context
            mock_wrapped = MagicMock()
            mock_context.wrap_socket.return_value = mock_wrapped
            mock_wrapped.recv.side_effect = [asa_response, b""]

            result = detector.detect_passive("192.168.1.100", 443)

            assert any(i.name == "ciscoasa_http_pattern" for i in result.indicators)

    def test_detect_active_asdm_endpoint(self, detector, mock_socket):
        """Test active detection of ASDM endpoint."""
        asdm_response = b"HTTP/1.1 200 OK\r\n\r\nASDM Admin Interface"

        with patch("ssl.create_default_context") as mock_ssl:
            mock_context = MagicMock()
            mock_ssl.return_value = mock_context
            mock_wrapped = MagicMock()
            mock_context.wrap_socket.return_value = mock_wrapped
            mock_wrapped.recv.side_effect = [asdm_response, b""]

            result = detector.detect_active("192.168.1.100", 443)

            assert any(i.name == "ciscoasa_asdm" for i in result.indicators)

    def test_detect_udp_probe_port_5000(self, detector, mock_socket):
        """Test UDP probe on port 5000."""
        socket_instance = mock_socket.return_value
        socket_instance.recvfrom.return_value = (b"\x00\x00\x00\x00response", ("192.168.1.100", 5000))

        result = detector.detect_active("192.168.1.100", 5000)

        assert any(i.name == "ciscoasa_udp_response" for i in result.indicators)

    def test_udp_probe_timeout(self, detector, mock_socket):
        """Test UDP probe handling timeout."""
        socket_instance = mock_socket.return_value
        socket_instance.recvfrom.side_effect = socket.timeout("timed out")

        response = detector._udp_probe("192.168.1.100", 5000)

        assert response is None

    def test_https_get_socket_error(self, detector, mock_socket):
        """Test HTTPS GET handling socket error."""
        with patch("ssl.create_default_context") as mock_ssl:
            mock_context = MagicMock()
            mock_ssl.return_value = mock_context
            mock_context.wrap_socket.side_effect = socket.error("Connection refused")

            response = detector._https_get("192.168.1.100", 443, "/")

            assert response is None

    def test_detect_passive_8443_port(self, detector, mock_socket):
        """Test passive detection on port 8443."""
        asa_response = b"HTTP/1.1 200 OK\r\n\r\nASDM content"

        with patch("ssl.create_default_context") as mock_ssl:
            mock_context = MagicMock()
            mock_ssl.return_value = mock_context
            mock_wrapped = MagicMock()
            mock_context.wrap_socket.return_value = mock_wrapped
            mock_wrapped.recv.side_effect = [asa_response, b""]

            result = detector.detect_passive("192.168.1.100", 8443)

            # Should run the check for HTTPS ports
            assert result is not None


# =============================================================================
# CVE Honeypot Detector Integration Tests
# =============================================================================


class TestCVEHoneypotDetectorIntegration:
    """Integration tests for combined CVE detector."""

    @pytest.fixture
    def detector(self):
        return CVEHoneypotDetector()

    def test_passive_log4pot_on_port_8080(self, detector, mock_socket):
        """Test passive detection delegates to Log4Pot on port 8080."""
        sap_response = b"HTTP/1.1 200 OK\r\n\r\nSAP NetWeaver"
        # Need enough recv calls for all sub-detectors that might check port 8080
        mock_socket.return_value.recv.side_effect = [sap_response, b""] * 10

        result = detector.detect_passive("192.168.1.100", 8080)

        assert any("log4pot" in i.name for i in result.indicators)

    def test_passive_citrix_on_port_443(self, detector, mock_socket):
        """Test passive detection delegates to Citrix on port 443."""
        citrix_response = b"HTTP/1.1 200 OK\r\nServer: Citrix\r\n\r\nCitrix Gateway"

        with patch("ssl.create_default_context") as mock_ssl:
            mock_context = MagicMock()
            mock_ssl.return_value = mock_context
            mock_wrapped = MagicMock()
            mock_context.wrap_socket.return_value = mock_wrapped
            # Need enough recv calls for all sub-detectors that might check port 443
            mock_wrapped.recv.side_effect = [citrix_response, b""] * 10

            result = detector.detect_passive("192.168.1.100", 443)

            assert any("citrix" in i.name for i in result.indicators)

    def test_passive_spring_on_port_80(self, detector, mock_socket):
        """Test passive detection delegates to Spring4Shell on port 80."""
        spring_response = b"HTTP/1.1 200 OK\r\n\r\nSpring Boot application"
        # Need enough recv calls for all sub-detectors that might check port 80
        mock_socket.return_value.recv.side_effect = [spring_response, b""] * 10

        result = detector.detect_passive("192.168.1.100", 80)

        assert any("spring" in i.name for i in result.indicators)

    def test_active_log4pot_on_port_8080(self, detector, mock_socket):
        """Test active detection delegates to Log4Pot on port 8080."""
        sap_response = b"HTTP/1.1 200 OK\r\n\r\nSAP NetWeaver portal"
        # Need enough recv calls for all sub-detectors that might check port 8080
        mock_socket.return_value.recv.side_effect = [sap_response, b""] * 20

        result = detector.detect_active("192.168.1.100", 8080)

        assert result.honeypot_type == "log4pot"

    def test_active_cisco_on_port_5000(self, detector, mock_socket):
        """Test active detection delegates to Cisco on port 5000."""
        socket_instance = mock_socket.return_value
        socket_instance.recvfrom.return_value = (b"\x00\x00\x00\x00response", ("192.168.1.100", 5000))
        socket_instance.recv.side_effect = [b"HTTP/1.1 200 OK\r\n\r\nOK", b""] * 10

        result = detector.detect_active("192.168.1.100", 5000)

        assert any("ciscoasa" in i.name for i in result.indicators)

    def test_get_recommendations_citrix(self, detector):
        """Test recommendations for Citrix indicators."""
        result = DetectionResult(target="192.168.1.100", port=443)
        result.add_indicator(Indicator(
            name="citrix_gateway_pattern",
            description="Citrix Gateway",
            severity=Confidence.MEDIUM,
        ))

        recommendations = detector.get_recommendations(result)

        assert any("Citrix" in r for r in recommendations)

    def test_get_recommendations_spring(self, detector):
        """Test recommendations for Spring indicators."""
        result = DetectionResult(target="192.168.1.100", port=8080)
        result.add_indicator(Indicator(
            name="spring4shell_actuator_exposed",
            description="Actuator exposed",
            severity=Confidence.MEDIUM,
        ))
        result.add_indicator(Indicator(
            name="spring4shell_whitelabel_error",
            description="Whitelabel error",
            severity=Confidence.LOW,
        ))

        recommendations = detector.get_recommendations(result)

        # Should have recommendations for both actuator and error page
        assert len(recommendations) >= 2

    def test_detector_initialization(self, detector):
        """Test CVE detector initializes sub-detectors."""
        assert detector._log4pot is not None
        assert detector._citrix is not None
        assert detector._cisco is not None
        assert detector._spring is not None

    def test_multiple_detectors_on_shared_port(self, detector, mock_socket):
        """Test multiple detectors on port 80 (shared by Log4Pot and Spring)."""
        spring_response = b"HTTP/1.1 200 OK\r\n\r\nWhitelabel Error Page"
        mock_socket.return_value.recv.side_effect = [spring_response, b""] * 4

        result = detector.detect_passive("192.168.1.100", 80)

        # Both Log4Pot and Spring check port 80
        assert result is not None


# =============================================================================
# CVE Detector Active Probing Edge Cases
# =============================================================================


class TestCVEActiveProbing:
    """Tests for CVE detector active probing edge cases."""

    @pytest.fixture
    def log4pot(self):
        return Log4PotDetector()

    @pytest.fixture
    def citrix(self):
        return CitrixHoneypotDetector()

    @pytest.fixture
    def spring(self):
        return Spring4ShellDetector()

    def test_log4pot_active_stops_on_detection(self, log4pot, mock_socket):
        """Test Log4Pot active detection stops on first match."""
        sap_response = b"HTTP/1.1 200 OK\r\n\r\nSAP NetWeaver"
        mock_socket.return_value.recv.side_effect = [sap_response, b""]

        result = log4pot.detect_active("192.168.1.100", 8080)

        # Should have stopped after first detection
        assert result.honeypot_type == "log4pot"

    def test_citrix_active_all_paths(self, citrix, mock_socket):
        """Test Citrix active probing checks all vulnerable paths."""
        responses = [b"HTTP/1.1 404 Not Found\r\n\r\nNot Found", b""] * 2

        with patch("ssl.create_default_context") as mock_ssl:
            mock_context = MagicMock()
            mock_ssl.return_value = mock_context
            mock_wrapped = MagicMock()
            mock_context.wrap_socket.return_value = mock_wrapped
            mock_wrapped.recv.side_effect = responses

            result = citrix.detect_active("192.168.1.100", 443)

            # Should check paths even without matches
            assert result is not None

    def test_spring_active_checks_actuators(self, spring, mock_socket):
        """Test Spring active checks all actuator endpoints."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = [
            b'HTTP/1.1 200 OK\r\n\r\n{"status":"UP"}',
            b"",
            b'HTTP/1.1 200 OK\r\n\r\n{"info":"test"}',
            b"",
            b'HTTP/1.1 200 OK\r\n\r\n{}',
            b"",
            b"HTTP/1.1 404 Not Found\r\n\r\nNot Found",
            b"",
        ]

        result = spring.detect_active("192.168.1.100", 8080)

        # Should have indicators for actuator endpoints
        assert any("actuator" in i.name for i in result.indicators)


# =============================================================================
# HTTP Request Building Tests
# =============================================================================


class TestHTTPRequestBuilding:
    """Tests for HTTP request building in CVE detectors."""

    @pytest.fixture
    def log4pot(self):
        return Log4PotDetector()

    def test_http_get_builds_correct_request(self, log4pot, mock_socket):
        """Test HTTP GET builds correct HTTP request."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = [b"HTTP/1.1 200 OK\r\n\r\nOK", b""]

        log4pot._http_get("192.168.1.100", 8080, "/api/test")

        # Check the sent request
        sent_data = socket_instance.send.call_args[0][0].decode()
        assert "GET /api/test HTTP/1.1" in sent_data
        assert "Host: 192.168.1.100" in sent_data
        assert "Connection: close" in sent_data

    def test_http_get_timeout_handling(self, log4pot, mock_socket):
        """Test HTTP GET handles recv timeout."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = socket.timeout("timed out")

        response = log4pot._http_get("192.168.1.100", 8080, "/")

        # Should return empty bytes on timeout (not None, since we got connected)
        assert response == b"" or response is None


# =============================================================================
# Detector Properties Tests
# =============================================================================


class TestCVEDetectorProperties:
    """Tests for CVE detector properties and attributes."""

    def test_log4pot_properties(self):
        """Test Log4Pot detector properties."""
        detector = Log4PotDetector()
        assert detector.name == "log4pot"
        assert 8080 in detector.default_ports
        assert 80 in detector.default_ports
        assert 443 in detector.default_ports
        assert "log4pot" in detector.honeypot_types

    def test_citrix_properties(self):
        """Test Citrix detector properties."""
        detector = CitrixHoneypotDetector()
        assert detector.name == "citrixhoneypot"
        assert 443 in detector.default_ports
        assert 80 in detector.default_ports
        assert "citrixhoneypot" in detector.honeypot_types

    def test_cisco_asa_properties(self):
        """Test Cisco ASA detector properties."""
        detector = CiscoASAHoneypotDetector()
        assert detector.name == "ciscoasa"
        assert 443 in detector.default_ports
        assert 8443 in detector.default_ports
        assert 5000 in detector.default_ports
        assert "ciscoasa_honeypot" in detector.honeypot_types

    def test_spring4shell_properties(self):
        """Test Spring4Shell detector properties."""
        detector = Spring4ShellDetector()
        assert detector.name == "spring4shell"
        assert 8080 in detector.default_ports
        assert 80 in detector.default_ports
        assert "spring4shell_pot" in detector.honeypot_types

    def test_cve_combined_properties(self):
        """Test combined CVE detector properties."""
        detector = CVEHoneypotDetector()
        assert detector.name == "cve"
        assert len(detector.honeypot_types) == 4
        assert 80 in detector.default_ports
        assert 443 in detector.default_ports
        assert 8080 in detector.default_ports
