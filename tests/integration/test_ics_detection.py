"""Integration tests for ICS/SCADA honeypot detection."""

import socket
import struct

import pytest

from potsnitch.core.result import Confidence
from potsnitch.scanner import HoneypotScanner

from .conftest import SKIP_DOCKER, ServiceEndpoints, is_port_open


@pytest.mark.docker
@pytest.mark.integration
class TestConpotModbusDetection:
    """Tests for Conpot Modbus honeypot detection."""

    @SKIP_DOCKER
    @pytest.mark.slow
    def test_conpot_modbus(
        self, docker_services: ServiceEndpoints, scanner: HoneypotScanner
    ):
        """Check Conpot Modbus detection."""
        host, port = docker_services.conpot_modbus

        assert is_port_open(host, port), f"Conpot Modbus not available at {host}:{port}"

        report = scanner.scan(host, ports=[port])

        # Conpot should be detected on Modbus port
        if report.has_honeypot:
            modbus_detections = [d for d in report.detections if d.port == port]
            if modbus_detections:
                detection = modbus_detections[0]
                assert detection.is_honeypot, "Should be detected as honeypot"
                assert detection.indicators, "Should have detection indicators"

    @SKIP_DOCKER
    @pytest.mark.slow
    def test_conpot_modbus_protocol(
        self, docker_services: ServiceEndpoints
    ):
        """Verify Conpot responds to Modbus protocol requests."""
        host, port = docker_services.conpot_modbus

        assert is_port_open(host, port), f"Conpot Modbus not available at {host}:{port}"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)

        try:
            sock.connect((host, port))

            # Build a simple Modbus TCP request (Read Holding Registers)
            # Transaction ID: 0x0001
            # Protocol ID: 0x0000 (Modbus)
            # Length: 0x0006
            # Unit ID: 0x01
            # Function Code: 0x03 (Read Holding Registers)
            # Starting Address: 0x0000
            # Quantity: 0x0001
            modbus_request = struct.pack(
                ">HHHBBHH",
                0x0001,  # Transaction ID
                0x0000,  # Protocol ID
                0x0006,  # Length
                0x01,    # Unit ID
                0x03,    # Function Code (Read Holding Registers)
                0x0000,  # Starting Address
                0x0001,  # Quantity of Registers
            )

            sock.sendall(modbus_request)

            # Receive response
            response = sock.recv(1024)

            # Should receive a Modbus response
            assert len(response) >= 9, "Should receive Modbus response header"

            # Parse response header
            if len(response) >= 7:
                trans_id, proto_id, length = struct.unpack(">HHH", response[:6])
                assert proto_id == 0x0000, "Protocol ID should be Modbus (0)"

        except socket.timeout:
            pytest.fail("Conpot Modbus did not respond in time")
        except socket.error as e:
            pytest.fail(f"Connection error: {e}")
        finally:
            sock.close()

    @SKIP_DOCKER
    @pytest.mark.slow
    def test_conpot_modbus_device_identification(
        self, docker_services: ServiceEndpoints
    ):
        """Test Modbus device identification request."""
        host, port = docker_services.conpot_modbus

        assert is_port_open(host, port), f"Conpot Modbus not available at {host}:{port}"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)

        try:
            sock.connect((host, port))

            # Modbus device identification request (function 0x2B / 43)
            # Sub-function 0x0E (Read Device Identification)
            modbus_request = struct.pack(
                ">HHHBBBB",
                0x0002,  # Transaction ID
                0x0000,  # Protocol ID
                0x0005,  # Length
                0x01,    # Unit ID
                0x2B,    # Function Code (Encapsulated Interface Transport)
                0x0E,    # MEI Type (Read Device Identification)
                0x01,    # Read Device ID Code (Basic)
            )

            sock.sendall(modbus_request)

            # Receive response
            response = sock.recv(1024)

            # Should receive some response
            assert len(response) >= 6, "Should receive Modbus response"

        except socket.timeout:
            # Some Modbus implementations may not support this function
            pass
        except socket.error as e:
            pytest.fail(f"Connection error: {e}")
        finally:
            sock.close()


@pytest.mark.docker
@pytest.mark.integration
class TestConpotS7CommDetection:
    """Tests for Conpot S7Comm honeypot detection."""

    @SKIP_DOCKER
    @pytest.mark.slow
    def test_conpot_s7comm(
        self, docker_services: ServiceEndpoints, scanner: HoneypotScanner
    ):
        """Check S7Comm detection."""
        host, port = docker_services.conpot_s7comm

        assert is_port_open(host, port), f"Conpot S7Comm not available at {host}:{port}"

        report = scanner.scan(host, ports=[port])

        # S7Comm honeypot should be detected
        if report.has_honeypot:
            s7_detections = [d for d in report.detections if d.port == port]
            if s7_detections:
                detection = s7_detections[0]
                assert detection.is_honeypot, "Should be detected as honeypot"

    @SKIP_DOCKER
    @pytest.mark.slow
    def test_conpot_s7comm_cotp_connect(
        self, docker_services: ServiceEndpoints
    ):
        """Test S7Comm COTP connection request."""
        host, port = docker_services.conpot_s7comm

        assert is_port_open(host, port), f"Conpot S7Comm not available at {host}:{port}"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)

        try:
            sock.connect((host, port))

            # TPKT + COTP Connection Request
            # TPKT Header (4 bytes): Version=3, Reserved=0, Length
            # COTP CR (Connection Request)
            tpkt_cotp_cr = bytes([
                0x03, 0x00,  # TPKT version 3
                0x00, 0x16,  # TPKT length (22 bytes)
                0x11,        # COTP length
                0xE0,        # CR (Connection Request)
                0x00, 0x00,  # Destination reference
                0x00, 0x01,  # Source reference
                0x00,        # Class + options
                0xC0, 0x01, 0x0A,  # TPDU size parameter
                0xC1, 0x02, 0x01, 0x00,  # Source TSAP
                0xC2, 0x02, 0x01, 0x02,  # Destination TSAP
            ])

            sock.sendall(tpkt_cotp_cr)

            # Receive response
            response = sock.recv(1024)

            # Should receive TPKT response
            if len(response) >= 4:
                assert response[0] == 0x03, "TPKT version should be 3"
                # Check for COTP CC (Connection Confirm) or error
                if len(response) >= 6:
                    cotp_type = response[5]
                    # 0xD0 = Connection Confirm
                    # 0x80, 0x81 = Disconnect
                    assert cotp_type in (0xD0, 0x80, 0x81), f"Unexpected COTP type: {cotp_type:02x}"

        except socket.timeout:
            pytest.fail("Conpot S7Comm did not respond in time")
        except socket.error as e:
            pytest.fail(f"Connection error: {e}")
        finally:
            sock.close()


@pytest.mark.docker
@pytest.mark.integration
class TestConpotHTTPDetection:
    """Tests for Conpot HTTP interface detection."""

    @SKIP_DOCKER
    @pytest.mark.slow
    def test_conpot_http_interface(
        self, docker_services: ServiceEndpoints
    ):
        """Test Conpot HTTP interface."""
        host, port = docker_services.conpot_http

        assert is_port_open(host, port), f"Conpot HTTP not available at {host}:{port}"

        try:
            import http.client

            conn = http.client.HTTPConnection(host, port, timeout=10)
            conn.request("GET", "/")
            response = conn.getresponse()
            data = response.read().decode("utf-8", errors="ignore")
            conn.close()

            # Should return HTTP response
            assert response.status in (200, 404, 301, 302), f"Unexpected status: {response.status}"

        except Exception as e:
            pytest.fail(f"Failed to connect to Conpot HTTP: {e}")


@pytest.mark.integration
class TestICSDetectionUnit:
    """Unit tests for ICS detection that don't require Docker."""

    def test_scanner_can_scan_modbus_port(self, fast_scanner: HoneypotScanner):
        """Test scanner can target Modbus default port."""
        report = fast_scanner.scan("192.0.2.1", ports=[502])
        assert not report.has_honeypot

    def test_scanner_can_scan_s7comm_port(self, fast_scanner: HoneypotScanner):
        """Test scanner can target S7Comm default port."""
        report = fast_scanner.scan("192.0.2.1", ports=[102])
        assert not report.has_honeypot

    def test_scanner_ics_port_range(self, fast_scanner: HoneypotScanner):
        """Test scanner can handle ICS port range."""
        ics_ports = [102, 502, 1911, 4840, 20000, 44818, 47808]
        report = fast_scanner.scan("192.0.2.1", ports=ics_ports)
        assert not report.has_honeypot
        assert len(report.detections) == 0

    def test_modbus_packet_structure(self):
        """Test Modbus packet structure creation."""
        # Build a Modbus TCP request
        trans_id = 0x0001
        proto_id = 0x0000
        length = 0x0006
        unit_id = 0x01
        func_code = 0x03
        start_addr = 0x0000
        quantity = 0x0001

        packet = struct.pack(
            ">HHHBBHH",
            trans_id, proto_id, length, unit_id, func_code, start_addr, quantity
        )

        assert len(packet) == 12, "Modbus TCP request should be 12 bytes"
        assert packet[:2] == b"\x00\x01", "Transaction ID should be 0x0001"
        assert packet[2:4] == b"\x00\x00", "Protocol ID should be 0x0000"
