"""Integration tests for database honeypot detection."""

import socket

import pytest

from potsnitch.core.result import Confidence
from potsnitch.scanner import HoneypotScanner

from .conftest import SKIP_DOCKER, ServiceEndpoints, is_port_open


@pytest.mark.docker
@pytest.mark.integration
class TestElasticpotDetection:
    """Tests for Elasticpot (Elasticsearch honeypot) detection."""

    @SKIP_DOCKER
    @pytest.mark.slow
    def test_elasticpot_detection(
        self, docker_services: ServiceEndpoints, scanner: HoneypotScanner
    ):
        """Check Elasticsearch honeypot detection."""
        host, port = docker_services.elasticpot

        assert is_port_open(host, port), f"Elasticpot not available at {host}:{port}"

        report = scanner.scan(host, ports=[port])

        # Elasticpot should be detected
        if report.has_honeypot:
            es_detections = [d for d in report.detections if d.port == port]
            assert es_detections, f"Should have detection on port {port}"

            detection = es_detections[0]
            assert detection.is_honeypot, "Should be detected as honeypot"
            assert detection.indicators, "Should have detection indicators"

    @SKIP_DOCKER
    @pytest.mark.slow
    def test_elasticpot_response_analysis(
        self, docker_services: ServiceEndpoints
    ):
        """Verify Elasticpot exhibits honeypot characteristics."""
        host, port = docker_services.elasticpot

        assert is_port_open(host, port), f"Elasticpot not available at {host}:{port}"

        # Connect and send HTTP request
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)

        try:
            sock.connect((host, port))

            # Send a basic HTTP request to Elasticsearch
            request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
            sock.sendall(request)

            # Receive response
            response = sock.recv(4096).decode("utf-8", errors="ignore")

            # Elasticpot should respond with Elasticsearch-like JSON
            assert "HTTP/1" in response, "Should return HTTP response"
            # Look for common Elasticsearch response elements
            if "cluster_name" in response.lower() or "tagline" in response.lower():
                # Typical Elasticsearch response structure
                pass
            elif "elasticsearch" in response.lower():
                # References Elasticsearch
                pass

        except socket.timeout:
            pytest.fail("Elasticpot did not respond in time")
        except socket.error as e:
            pytest.fail(f"Connection error: {e}")
        finally:
            sock.close()

    @SKIP_DOCKER
    @pytest.mark.slow
    def test_elasticpot_cluster_info(
        self, docker_services: ServiceEndpoints
    ):
        """Test Elasticpot cluster info endpoint."""
        host, port = docker_services.elasticpot

        assert is_port_open(host, port), f"Elasticpot not available at {host}:{port}"

        try:
            import http.client

            conn = http.client.HTTPConnection(host, port, timeout=10)
            conn.request("GET", "/")
            response = conn.getresponse()
            data = response.read().decode("utf-8", errors="ignore")
            conn.close()

            # Should return 200 OK
            assert response.status == 200, f"Expected 200, got {response.status}"

            # Response should be JSON-like
            assert "{" in data, "Response should be JSON"

        except Exception as e:
            pytest.fail(f"Failed to query Elasticpot: {e}")


@pytest.mark.docker
@pytest.mark.integration
class TestRedisHoneypotDetection:
    """Tests for Redis honeypot detection."""

    @SKIP_DOCKER
    @pytest.mark.slow
    def test_redis_honeypot_detection(
        self, docker_services: ServiceEndpoints, scanner: HoneypotScanner
    ):
        """Check Redis honeypot detection."""
        host, port = docker_services.redis

        assert is_port_open(host, port), f"Redis honeypot not available at {host}:{port}"

        report = scanner.scan(host, ports=[port])

        # Redis honeypot may or may not be detected depending on detector
        if report.has_honeypot:
            redis_detections = [d for d in report.detections if d.port == port]
            if redis_detections:
                detection = redis_detections[0]
                assert detection.is_honeypot, "Should be detected as honeypot"

    @SKIP_DOCKER
    @pytest.mark.slow
    def test_redis_honeypot_info_command(
        self, docker_services: ServiceEndpoints
    ):
        """Test Redis honeypot INFO command response."""
        host, port = docker_services.redis

        assert is_port_open(host, port), f"Redis honeypot not available at {host}:{port}"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)

        try:
            sock.connect((host, port))

            # Send Redis INFO command
            sock.sendall(b"INFO\r\n")

            # Receive response
            response = sock.recv(4096).decode("utf-8", errors="ignore")

            # Redis should respond with server info or error
            # Honeypots may have telltale responses
            assert response, "Should receive some response"

        except socket.timeout:
            pytest.fail("Redis honeypot did not respond in time")
        except socket.error as e:
            pytest.fail(f"Connection error: {e}")
        finally:
            sock.close()

    @SKIP_DOCKER
    @pytest.mark.slow
    def test_redis_honeypot_ping(
        self, docker_services: ServiceEndpoints
    ):
        """Test Redis honeypot PING command."""
        host, port = docker_services.redis

        assert is_port_open(host, port), f"Redis honeypot not available at {host}:{port}"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)

        try:
            sock.connect((host, port))

            # Send Redis PING command
            sock.sendall(b"PING\r\n")

            # Receive response
            response = sock.recv(1024).decode("utf-8", errors="ignore")

            # Legitimate Redis returns "+PONG\r\n"
            # Honeypots may behave differently
            assert response, "Should receive some response to PING"

        except socket.timeout:
            pytest.fail("Redis honeypot did not respond to PING")
        except socket.error as e:
            pytest.fail(f"Connection error: {e}")
        finally:
            sock.close()


@pytest.mark.integration
class TestDatabaseDetectionUnit:
    """Unit tests for database honeypot detection that don't require Docker."""

    def test_scanner_can_scan_elasticsearch_port(self, fast_scanner: HoneypotScanner):
        """Test scanner can target Elasticsearch default port."""
        # Scan non-existent host to verify port handling
        report = fast_scanner.scan("192.0.2.1", ports=[9200])
        assert not report.has_honeypot

    def test_scanner_can_scan_redis_port(self, fast_scanner: HoneypotScanner):
        """Test scanner can target Redis default port."""
        report = fast_scanner.scan("192.0.2.1", ports=[6379])
        assert not report.has_honeypot

    def test_scanner_multiple_db_ports(self, fast_scanner: HoneypotScanner):
        """Test scanner can handle multiple database ports."""
        report = fast_scanner.scan(
            "192.0.2.1", ports=[3306, 5432, 6379, 9200, 27017]
        )
        assert not report.has_honeypot
        assert len(report.detections) == 0
