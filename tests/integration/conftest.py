"""Pytest fixtures for Docker-based integration testing."""

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Generator, Optional

import pytest

from potsnitch.scanner import HoneypotScanner


@dataclass
class ServiceEndpoints:
    """Container for all honeypot service endpoints."""

    # SSH Honeypots
    cowrie_ssh: tuple[str, int] = ("localhost", 2222)
    cowrie_telnet: tuple[str, int] = ("localhost", 2223)
    endlessh: tuple[str, int] = ("localhost", 2224)

    # Database Honeypots
    elasticpot: tuple[str, int] = ("localhost", 9201)
    redis: tuple[str, int] = ("localhost", 6380)

    # ICS/SCADA Honeypots
    conpot_http: tuple[str, int] = ("localhost", 10080)
    conpot_s7comm: tuple[str, int] = ("localhost", 10102)
    conpot_modbus: tuple[str, int] = ("localhost", 10502)
    conpot_snmp: tuple[str, int] = ("localhost", 10161)

    # Web Honeypots
    hellpot: tuple[str, int] = ("localhost", 8081)

    # Multi-Service Honeypots (Dionaea)
    dionaea_ftp: tuple[str, int] = ("localhost", 2121)
    dionaea_http: tuple[str, int] = ("localhost", 4080)
    dionaea_https: tuple[str, int] = ("localhost", 4443)
    dionaea_smb: tuple[str, int] = ("localhost", 4445)
    dionaea_mssql: tuple[str, int] = ("localhost", 11433)
    dionaea_mysql: tuple[str, int] = ("localhost", 13306)
    dionaea_sip: tuple[str, int] = ("localhost", 15060)

    # Email Honeypots
    mailoney: tuple[str, int] = ("localhost", 2525)


def _docker_compose_path() -> Path:
    """Get the path to docker-compose.yml."""
    return Path(__file__).parent.parent / "docker" / "docker-compose.yml"


def _is_docker_available() -> bool:
    """Check if Docker is available."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def _is_docker_compose_available() -> bool:
    """Check if docker-compose is available."""
    try:
        # Try docker compose (v2)
        result = subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True,
            timeout=10,
        )
        if result.returncode == 0:
            return True

        # Try docker-compose (v1)
        result = subprocess.run(
            ["docker-compose", "version"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def _get_compose_command() -> list[str]:
    """Get the appropriate docker compose command."""
    try:
        result = subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True,
            timeout=10,
        )
        if result.returncode == 0:
            return ["docker", "compose"]
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    return ["docker-compose"]


def _are_services_running() -> bool:
    """Check if the Docker services are already running."""
    compose_file = _docker_compose_path()
    if not compose_file.exists():
        return False

    compose_cmd = _get_compose_command()
    try:
        result = subprocess.run(
            compose_cmd + ["-f", str(compose_file), "ps", "--format", "json"],
            capture_output=True,
            timeout=30,
            text=True,
        )
        # If we get output and no error, services are defined
        # Check if any containers are actually running
        if result.returncode == 0 and result.stdout.strip():
            return True
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    return False


def _wait_for_services(endpoints: ServiceEndpoints, timeout: int = 120) -> bool:
    """Wait for key services to become available."""
    import socket

    key_services = [
        endpoints.cowrie_ssh,
        endpoints.elasticpot,
        endpoints.conpot_modbus,
    ]

    start_time = time.time()
    while time.time() - start_time < timeout:
        all_ready = True
        for host, port in key_services:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, port))
                sock.close()
                if result != 0:
                    all_ready = False
                    break
            except socket.error:
                all_ready = False
                break

        if all_ready:
            # Give services a bit more time to fully initialize
            time.sleep(5)
            return True

        time.sleep(2)

    return False


# Pytest markers
def pytest_configure(config):
    """Configure custom pytest markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "docker: marks tests as requiring Docker"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )


# Skip condition for Docker-dependent tests
DOCKER_AVAILABLE = _is_docker_available() and _is_docker_compose_available()
SKIP_DOCKER = pytest.mark.skipif(
    not DOCKER_AVAILABLE,
    reason="Docker or docker-compose not available",
)


@pytest.fixture(scope="session")
def docker_services() -> Generator[ServiceEndpoints, None, None]:
    """
    Session-scoped fixture that starts Docker services and yields endpoints.

    Starts the honeypot Docker containers before the first test and
    stops them after all tests complete.
    """
    if not DOCKER_AVAILABLE:
        pytest.skip("Docker not available")

    compose_file = _docker_compose_path()
    if not compose_file.exists():
        pytest.skip(f"docker-compose.yml not found at {compose_file}")

    compose_cmd = _get_compose_command()
    endpoints = ServiceEndpoints()

    # Check if services are already running (for development)
    already_running = _are_services_running()

    if not already_running:
        # Start services
        try:
            subprocess.run(
                compose_cmd + ["-f", str(compose_file), "up", "-d"],
                check=True,
                capture_output=True,
                timeout=300,
            )
        except subprocess.CalledProcessError as e:
            pytest.fail(f"Failed to start Docker services: {e.stderr.decode()}")
        except subprocess.TimeoutExpired:
            pytest.fail("Timeout starting Docker services")

        # Wait for services to be ready
        if not _wait_for_services(endpoints):
            # Try to get logs for debugging
            try:
                logs = subprocess.run(
                    compose_cmd + ["-f", str(compose_file), "logs", "--tail=50"],
                    capture_output=True,
                    timeout=30,
                    text=True,
                )
                print(f"Docker logs:\n{logs.stdout}")
            except Exception:
                pass

            # Clean up
            subprocess.run(
                compose_cmd + ["-f", str(compose_file), "down", "-v"],
                capture_output=True,
                timeout=60,
            )
            pytest.fail("Services did not become ready in time")

    yield endpoints

    # Only stop services if we started them
    if not already_running:
        try:
            subprocess.run(
                compose_cmd + ["-f", str(compose_file), "down", "-v"],
                capture_output=True,
                timeout=120,
            )
        except Exception:
            pass  # Best effort cleanup


@pytest.fixture
def scanner() -> HoneypotScanner:
    """Create a HoneypotScanner instance for testing."""
    return HoneypotScanner(
        timeout=10.0,
        max_workers=5,
        verbose=True,
    )


@pytest.fixture
def fast_scanner() -> HoneypotScanner:
    """Create a fast HoneypotScanner instance for quick tests."""
    return HoneypotScanner(
        timeout=5.0,
        max_workers=10,
        verbose=False,
    )


@pytest.fixture
def endpoints() -> ServiceEndpoints:
    """Get service endpoints without starting Docker (for unit tests)."""
    return ServiceEndpoints()


def is_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """Helper function to check if a port is open."""
    import socket

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except socket.error:
        return False
