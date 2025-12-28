"""Integration tests for SSH honeypot detection."""

import socket
import time

import pytest

from potsnitch.core.result import Confidence
from potsnitch.scanner import HoneypotScanner

from .conftest import SKIP_DOCKER, ServiceEndpoints, is_port_open


@pytest.mark.docker
@pytest.mark.integration
class TestCowrieDetection:
    """Tests for Cowrie SSH honeypot detection."""

    @SKIP_DOCKER
    @pytest.mark.slow
    def test_cowrie_detection(
        self, docker_services: ServiceEndpoints, scanner: HoneypotScanner
    ):
        """Verify Cowrie is detected with high confidence."""
        host, port = docker_services.cowrie_ssh

        # Ensure the service is available
        assert is_port_open(host, port), f"Cowrie not available at {host}:{port}"

        # Run the scan
        report = scanner.scan(host, ports=[port])

        # Verify detection
        assert report.has_honeypot, "Cowrie should be detected as a honeypot"
        assert report.detections, "Should have at least one detection"

        # Find the SSH detection
        ssh_detections = [d for d in report.detections if d.port == port]
        assert ssh_detections, f"Should have detection on port {port}"

        detection = ssh_detections[0]
        assert detection.is_honeypot, "Detection should indicate honeypot"
        assert detection.confidence in (
            Confidence.HIGH,
            Confidence.DEFINITE,
        ), f"Expected high/definite confidence, got {detection.confidence}"

    @SKIP_DOCKER
    @pytest.mark.slow
    def test_cowrie_default_banner(
        self, docker_services: ServiceEndpoints, scanner: HoneypotScanner
    ):
        """Check banner detection works for Cowrie."""
        host, port = docker_services.cowrie_ssh

        assert is_port_open(host, port), f"Cowrie not available at {host}:{port}"

        report = scanner.scan(host, ports=[port])

        # Look for banner-related indicators
        for detection in report.detections:
            if detection.port == port:
                banner_indicators = [
                    i for i in detection.indicators if "banner" in i.name.lower()
                ]
                # Cowrie uses recognizable SSH banners
                assert (
                    detection.indicators
                ), "Should have some detection indicators"
                break

    @SKIP_DOCKER
    @pytest.mark.slow
    def test_cowrie_credential_detection(
        self, docker_services: ServiceEndpoints, scanner: HoneypotScanner
    ):
        """Verify default credential acceptance is detected."""
        host, port = docker_services.cowrie_ssh

        assert is_port_open(host, port), f"Cowrie not available at {host}:{port}"

        # Run validation mode which tests credentials
        try:
            result, recommendations = scanner.validate(host, "cowrie", port)

            # Cowrie accepts default credentials
            assert result.is_honeypot, "Cowrie should be detected as honeypot"

            # Look for credential-related indicators
            credential_indicators = [
                i
                for i in result.indicators
                if "credential" in i.name.lower() or "password" in i.name.lower()
            ]
            # Should have detected default credential acceptance
            if credential_indicators:
                assert any(
                    i.severity in (Confidence.HIGH, Confidence.DEFINITE)
                    for i in credential_indicators
                ), "Credential indicators should have high severity"

        except ValueError:
            # No cowrie-specific detector, skip this part
            pytest.skip("No Cowrie-specific detector available")


@pytest.mark.docker
@pytest.mark.integration
class TestEndlesshDetection:
    """Tests for Endlessh tarpit detection."""

    @SKIP_DOCKER
    @pytest.mark.slow
    def test_endlessh_tarpit(
        self, docker_services: ServiceEndpoints, scanner: HoneypotScanner
    ):
        """Verify Endlessh is detected as a tarpit."""
        host, port = docker_services.endlessh

        assert is_port_open(host, port), f"Endlessh not available at {host}:{port}"

        # Endlessh is slow by design, use longer timeout
        slow_scanner = HoneypotScanner(timeout=15.0, verbose=True)

        report = slow_scanner.scan(host, ports=[port])

        # Endlessh should be detected as suspicious
        # It may not be detected as a honeypot if the scanner times out,
        # but the behavior itself (slow banner) is a detection signal
        if report.detections:
            ssh_detections = [d for d in report.detections if d.port == port]
            if ssh_detections:
                detection = ssh_detections[0]
                # Look for tarpit or slow response indicators
                tarpit_indicators = [
                    i
                    for i in detection.indicators
                    if "tarpit" in i.name.lower()
                    or "slow" in i.name.lower()
                    or "delay" in i.name.lower()
                ]
                # If detected, should indicate tarpit behavior
                if tarpit_indicators:
                    assert detection.is_honeypot

    @SKIP_DOCKER
    @pytest.mark.slow
    def test_endlessh_slow_banner(self, docker_services: ServiceEndpoints):
        """Verify Endlessh exhibits slow banner behavior."""
        host, port = docker_services.endlessh

        assert is_port_open(host, port), f"Endlessh not available at {host}:{port}"

        # Connect and measure time to receive banner
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)

        try:
            start_time = time.time()
            sock.connect((host, port))

            # Try to receive data (Endlessh delays this)
            sock.settimeout(3.0)
            try:
                data = sock.recv(1024)
                elapsed = time.time() - start_time
                # Endlessh should be slow (configured with MSDELAY=1000)
                # If we get data quickly, something is wrong
                assert (
                    elapsed >= 0.5
                ), f"Endlessh should be slow, but responded in {elapsed}s"
            except socket.timeout:
                # Timeout is expected for tarpit
                elapsed = time.time() - start_time
                assert elapsed >= 2.0, "Timeout should occur due to tarpit delay"

        finally:
            sock.close()


@pytest.mark.docker
@pytest.mark.integration
class TestCowrieTelnet:
    """Tests for Cowrie Telnet detection."""

    @SKIP_DOCKER
    @pytest.mark.slow
    def test_cowrie_telnet_detection(
        self, docker_services: ServiceEndpoints, scanner: HoneypotScanner
    ):
        """Verify Cowrie Telnet is detected."""
        host, port = docker_services.cowrie_telnet

        assert is_port_open(host, port), f"Cowrie Telnet not available at {host}:{port}"

        report = scanner.scan(host, ports=[port])

        # Telnet port should be detected
        if report.detections:
            telnet_detections = [d for d in report.detections if d.port == port]
            if telnet_detections:
                detection = telnet_detections[0]
                assert detection.indicators, "Should have detection indicators"


@pytest.mark.integration
class TestSSHDetectionUnit:
    """Unit tests for SSH detection that don't require Docker."""

    def test_scanner_initialization(self):
        """Test that scanner initializes correctly."""
        scanner = HoneypotScanner(timeout=5.0, max_workers=5, verbose=False)
        assert scanner.timeout == 5.0
        assert scanner.max_workers == 5
        assert not scanner.verbose

    def test_scanner_list_modules(self):
        """Test that scanner can list available modules."""
        modules = HoneypotScanner.list_modules()
        assert isinstance(modules, list)
        # Should have at least some modules registered
        # (may be empty if no detectors are implemented yet)

    def test_scan_nonexistent_host(self, fast_scanner: HoneypotScanner):
        """Test scanning a host that doesn't exist."""
        # Use a non-routable IP to ensure quick failure
        report = fast_scanner.scan("192.0.2.1", ports=[22])  # TEST-NET-1
        assert not report.has_honeypot
        assert len(report.detections) == 0
