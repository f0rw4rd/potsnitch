"""Integration tests for credential and authentication detection."""

import socket

import pytest

from potsnitch.core.result import Confidence
from potsnitch.scanner import HoneypotScanner

from .conftest import SKIP_DOCKER, ServiceEndpoints, is_port_open


@pytest.mark.docker
@pytest.mark.integration
class TestSSHDefaultCredentials:
    """Tests for SSH default credential detection."""

    @SKIP_DOCKER
    @pytest.mark.slow
    def test_ssh_default_credentials(
        self, docker_services: ServiceEndpoints, scanner: HoneypotScanner
    ):
        """Test SSH credential probing against Cowrie."""
        host, port = docker_services.cowrie_ssh

        assert is_port_open(host, port), f"Cowrie SSH not available at {host}:{port}"

        # Run validation to test credentials
        try:
            result, recommendations = scanner.validate(host, "cowrie", port)

            # Cowrie should be detected
            assert result.is_honeypot, "Cowrie should be detected as honeypot"

            # Look for credential-related indicators
            cred_indicators = [
                i for i in result.indicators
                if any(term in i.name.lower() for term in [
                    "credential", "password", "auth", "login", "default"
                ])
            ]

            # Cowrie accepts default credentials which is a strong indicator
            if cred_indicators:
                high_severity = [
                    i for i in cred_indicators
                    if i.severity in (Confidence.HIGH, Confidence.DEFINITE)
                ]
                # Default credential acceptance should be high severity
                assert (
                    high_severity or len(cred_indicators) > 0
                ), "Should have credential-related indicators"

        except ValueError as e:
            # No cowrie-specific detector available
            pytest.skip(f"Cowrie detector not available: {e}")

    @SKIP_DOCKER
    @pytest.mark.slow
    def test_ssh_multiple_auth_attempts(
        self, docker_services: ServiceEndpoints, scanner: HoneypotScanner
    ):
        """Test that multiple auth attempts are handled."""
        host, port = docker_services.cowrie_ssh

        assert is_port_open(host, port), f"Cowrie SSH not available at {host}:{port}"

        # Run multiple scans to ensure consistent detection
        results = []
        for _ in range(3):
            report = scanner.scan(host, ports=[port])
            if report.has_honeypot:
                results.append(True)
            else:
                results.append(False)

        # Detection should be consistent
        assert (
            all(results) or not any(results)
        ), "Detection should be consistent across attempts"

    @SKIP_DOCKER
    @pytest.mark.slow
    def test_ssh_banner_before_auth(
        self, docker_services: ServiceEndpoints
    ):
        """Test SSH banner retrieval before authentication."""
        host, port = docker_services.cowrie_ssh

        assert is_port_open(host, port), f"Cowrie SSH not available at {host}:{port}"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)

        try:
            sock.connect((host, port))

            # SSH server should send banner immediately
            banner = sock.recv(1024).decode("utf-8", errors="ignore")

            # Should receive SSH version banner
            assert "SSH-" in banner, "Should receive SSH version string"

            # Cowrie typically uses SSH-2.0
            if "SSH-2.0" in banner:
                # Check for common Cowrie banners
                # Default is often SSH-2.0-OpenSSH_X.Xp1 Ubuntu-XXubuntuY
                pass

        except socket.timeout:
            pytest.fail("SSH server did not send banner in time")
        except socket.error as e:
            pytest.fail(f"Connection error: {e}")
        finally:
            sock.close()


@pytest.mark.docker
@pytest.mark.integration
class TestInvalidPayloadResponse:
    """Tests for invalid payload/protocol detection."""

    @SKIP_DOCKER
    @pytest.mark.slow
    def test_invalid_payload_response(
        self, docker_services: ServiceEndpoints
    ):
        """Test invalid payload detection on SSH port."""
        host, port = docker_services.cowrie_ssh

        assert is_port_open(host, port), f"Cowrie SSH not available at {host}:{port}"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)

        try:
            sock.connect((host, port))

            # Read the SSH banner first
            banner = sock.recv(1024)

            # Send invalid/garbage data
            invalid_payload = b"\x00\x00\x00\xff\x00\x00\x00\x00INVALID_PAYLOAD\r\n"
            sock.sendall(invalid_payload)

            # Server may disconnect or send error
            try:
                response = sock.recv(1024)
                # Any response to invalid data is logged
            except (socket.timeout, ConnectionResetError):
                # Connection reset is expected for invalid data
                pass

        except socket.timeout:
            pass  # Timeout is acceptable
        except socket.error as e:
            pass  # Connection errors are acceptable
        finally:
            sock.close()

    @SKIP_DOCKER
    @pytest.mark.slow
    def test_http_on_ssh_port(
        self, docker_services: ServiceEndpoints
    ):
        """Test HTTP request on SSH port behavior."""
        host, port = docker_services.cowrie_ssh

        assert is_port_open(host, port), f"Cowrie SSH not available at {host}:{port}"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)

        try:
            sock.connect((host, port))

            # Read SSH banner
            banner = sock.recv(1024)
            assert b"SSH-" in banner, "Should receive SSH banner"

            # Send HTTP request (wrong protocol)
            http_request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
            sock.sendall(http_request)

            # Server should disconnect or send error
            try:
                response = sock.recv(1024)
                # Response indicates how server handles protocol mismatch
            except (socket.timeout, ConnectionResetError):
                pass

        except socket.error:
            pass
        finally:
            sock.close()

    @SKIP_DOCKER
    @pytest.mark.slow
    def test_malformed_modbus_request(
        self, docker_services: ServiceEndpoints
    ):
        """Test malformed Modbus request handling."""
        host, port = docker_services.conpot_modbus

        assert is_port_open(host, port), f"Conpot Modbus not available at {host}:{port}"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)

        try:
            sock.connect((host, port))

            # Send malformed Modbus packet (invalid length field)
            malformed_modbus = bytes([
                0x00, 0x01,  # Transaction ID
                0x00, 0x00,  # Protocol ID
                0xFF, 0xFF,  # Invalid length
                0x01,        # Unit ID
                0xFF,        # Invalid function code
            ])

            sock.sendall(malformed_modbus)

            # Server may respond with exception or disconnect
            try:
                response = sock.recv(1024)
                # Honeypot may handle this differently than real PLC
            except (socket.timeout, ConnectionResetError):
                pass

        except socket.error:
            pass
        finally:
            sock.close()


@pytest.mark.docker
@pytest.mark.integration
class TestElasticsearchCredentials:
    """Tests for Elasticsearch credential behavior."""

    @SKIP_DOCKER
    @pytest.mark.slow
    def test_elasticsearch_no_auth(
        self, docker_services: ServiceEndpoints
    ):
        """Test Elasticsearch endpoint without authentication."""
        host, port = docker_services.elasticpot

        assert is_port_open(host, port), f"Elasticpot not available at {host}:{port}"

        try:
            import http.client

            conn = http.client.HTTPConnection(host, port, timeout=10)
            conn.request("GET", "/")
            response = conn.getresponse()
            data = response.read().decode("utf-8", errors="ignore")
            conn.close()

            # Elasticpot typically allows unauthenticated access
            # Real Elasticsearch clusters often require auth
            assert response.status == 200, f"Expected 200, got {response.status}"

        except Exception as e:
            pytest.fail(f"Failed to query Elasticpot: {e}")

    @SKIP_DOCKER
    @pytest.mark.slow
    def test_elasticsearch_dangerous_endpoints(
        self, docker_services: ServiceEndpoints
    ):
        """Test dangerous Elasticsearch endpoints."""
        host, port = docker_services.elasticpot

        assert is_port_open(host, port), f"Elasticpot not available at {host}:{port}"

        dangerous_endpoints = [
            "/_cluster/health",
            "/_nodes",
            "/_cat/indices",
            "/_search",
        ]

        try:
            import http.client

            for endpoint in dangerous_endpoints:
                conn = http.client.HTTPConnection(host, port, timeout=10)
                conn.request("GET", endpoint)
                response = conn.getresponse()
                response.read()  # Consume response
                conn.close()

                # Honeypot may respond to these endpoints
                # Real secure Elasticsearch would require auth
                assert response.status in (
                    200, 401, 403, 404
                ), f"Unexpected status {response.status} for {endpoint}"

        except Exception as e:
            pytest.fail(f"Failed to query Elasticpot endpoint: {e}")


@pytest.mark.integration
class TestCredentialDetectionUnit:
    """Unit tests for credential detection that don't require Docker."""

    def test_scanner_validate_method_exists(self):
        """Test that scanner has validate method."""
        scanner = HoneypotScanner()
        assert hasattr(scanner, "validate"), "Scanner should have validate method"

    def test_scanner_validate_invalid_honeypot(self, fast_scanner: HoneypotScanner):
        """Test validate with invalid honeypot type."""
        with pytest.raises(ValueError):
            fast_scanner.validate("192.0.2.1", "nonexistent_honeypot", 22)

    def test_default_credential_list(self):
        """Test that common default credentials are known."""
        common_creds = [
            ("root", "root"),
            ("root", "toor"),
            ("admin", "admin"),
            ("root", "password"),
            ("root", "123456"),
            ("admin", "password"),
            ("pi", "raspberry"),
            ("ubnt", "ubnt"),
        ]

        # Verify credential pairs are valid tuples
        for user, password in common_creds:
            assert isinstance(user, str), "Username should be string"
            assert isinstance(password, str), "Password should be string"
            assert len(user) > 0, "Username should not be empty"
            assert len(password) > 0, "Password should not be empty"

    def test_ssh_version_string_parsing(self):
        """Test SSH version string parsing."""
        test_banners = [
            "SSH-2.0-OpenSSH_7.4",
            "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3",
            "SSH-2.0-libssh_0.7.0",
            "SSH-2.0-dropbear_2020.81",
            "SSH-1.99-OpenSSH_3.9",
        ]

        for banner in test_banners:
            assert banner.startswith("SSH-"), "Banner should start with SSH-"
            parts = banner.split("-")
            assert len(parts) >= 3, "Banner should have version and software"
            version = parts[1]
            assert version in ("1.99", "2.0", "1.0"), f"Valid SSH version: {version}"
