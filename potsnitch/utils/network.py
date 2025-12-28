"""Network utility functions."""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional


def is_port_open(target: str, port: int, timeout: float = 2.0) -> bool:
    """Check if a port is open on target.

    Args:
        target: IP address or hostname
        port: Port number
        timeout: Connection timeout in seconds

    Returns:
        True if port is open
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except (socket.error, socket.timeout, OSError):
        return False


def scan_ports(
    target: str, ports: list[int], timeout: float = 2.0, max_workers: int = 20
) -> list[int]:
    """Scan multiple ports on target.

    Args:
        target: IP address or hostname
        ports: List of port numbers to scan
        timeout: Connection timeout per port
        max_workers: Maximum concurrent scanners

    Returns:
        List of open port numbers
    """
    open_ports = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(is_port_open, target, port, timeout): port for port in ports
        }

        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                pass

    return sorted(open_ports)


def resolve_hostname(hostname: str) -> Optional[str]:
    """Resolve hostname to IP address.

    Args:
        hostname: Hostname to resolve

    Returns:
        IP address string or None if resolution fails
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def get_banner(target: str, port: int, timeout: float = 5.0) -> Optional[str]:
    """Get service banner from port.

    Args:
        target: IP address or hostname
        port: Port number
        timeout: Connection timeout in seconds

    Returns:
        Banner string or None
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))

        # Some services send banner on connect, others need a nudge
        sock.settimeout(2.0)
        try:
            banner = sock.recv(1024)
        except socket.timeout:
            # Try sending a newline to trigger response
            sock.send(b"\r\n")
            try:
                banner = sock.recv(1024)
            except socket.timeout:
                banner = None

        sock.close()
        return banner.decode("utf-8", errors="ignore").strip() if banner else None
    except (socket.error, socket.timeout, OSError):
        return None
