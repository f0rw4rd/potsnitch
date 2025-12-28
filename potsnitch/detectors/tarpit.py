"""Tarpit honeypot detectors for Endlessh and HellPot."""

import socket
import time
from typing import Optional, Tuple

from potsnitch.core.base import BaseDetector, DetectionMode, register_detector
from potsnitch.core.result import DetectionResult, Indicator, Confidence


# Endlessh default configuration
ENDLESSH_DEFAULT_DELAY_MS = 10000  # 10 seconds between bytes
ENDLESSH_DETECTION_THRESHOLD_S = 5  # If first byte takes > 5s, likely tarpit

# HellPot known paths that trigger tarpitting
HELLPOT_TARPIT_PATHS = [
    "/wp-login.php",
    "/wp-admin/",
    "/wp-content/",
    "/.git/",
    "/.env",
    "/admin/",
    "/phpmyadmin/",
    "/phpMyAdmin/",
    "/pma/",
    "/login.php",
    "/shell.php",
    "/c99.php",
    "/r57.php",
]

# HellPot server header
HELLPOT_SERVER_HEADER = "nginx"


@register_detector
class EndlesshDetector(BaseDetector):
    """Detector for Endlessh SSH tarpit.

    Endlessh is an SSH tarpit that slowly sends an endless SSH banner
    to keep malicious SSH clients locked up for hours.

    Static (Passive) Detection:
    - Partial SSH banner without newline
    - Banner that starts with SSH-2.0- but never completes
    - Default Endlessh port patterns (22, 2222, 22222)

    Dynamic (Active) Detection:
    - Timing analysis (delayed first byte)
    - Slow data rate detection (tarpit behavior)
    - Incomplete banner after extended wait
    """

    name = "endlessh"
    description = "Detects Endlessh SSH tarpit"
    honeypot_types = ["endlessh"]
    default_ports = [22, 2222, 22222]

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive/static Endlessh detection.

        Checks for static signatures like partial banners without
        extensive timing analysis.

        Args:
            target: IP address or hostname
            port: SSH port

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        # Check for default Endlessh port patterns
        if port == 22222:
            result.add_indicator(
                Indicator(
                    name="endlessh_default_port",
                    description="Endlessh default alternative port 22222",
                    severity=Confidence.MEDIUM,
                    details="Port 22222 commonly used for Endlessh tarpit",
                )
            )

        # Quick banner check with short timeout
        banner = self._get_partial_banner(target, port, timeout=3.0)
        if banner:
            self._check_banner(banner, result)

        if result.is_honeypot:
            result.honeypot_type = "endlessh"

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active/dynamic Endlessh probing.

        Performs timing analysis to detect tarpit behavior by measuring
        first byte delay and data rate.

        Args:
            target: IP address or hostname
            port: SSH port

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        # Measure time to receive first data (active timing probe)
        timing = self._measure_banner_timing(target, port)
        if timing:
            first_byte_time, total_bytes, duration = timing
            self._analyze_timing(first_byte_time, total_bytes, duration, result)

        if result.is_honeypot:
            result.honeypot_type = "endlessh"

        return result

    def _measure_banner_timing(
        self, target: str, port: int, max_wait: float = 15.0
    ) -> Optional[Tuple[float, int, float]]:
        """Measure timing of SSH banner delivery.

        Returns:
            Tuple of (time_to_first_byte, total_bytes_received, total_duration)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(max_wait)
            sock.setblocking(False)

            start_time = time.time()
            try:
                sock.connect((target, port))
            except BlockingIOError:
                pass

            # Wait for connection or data
            import select
            first_byte_time = None
            total_bytes = 0
            data_chunks = []

            while time.time() - start_time < max_wait:
                readable, _, _ = select.select([sock], [], [], 0.5)
                if readable:
                    try:
                        chunk = sock.recv(1024)
                        if chunk:
                            if first_byte_time is None:
                                first_byte_time = time.time() - start_time
                            total_bytes += len(chunk)
                            data_chunks.append(chunk)

                            # Check if we got a complete SSH banner (ends with \n or \r\n)
                            full_data = b"".join(data_chunks)
                            if b"\n" in full_data and full_data.startswith(b"SSH-"):
                                break
                        else:
                            break
                    except (socket.error, OSError):
                        break

            sock.close()
            duration = time.time() - start_time

            if first_byte_time is not None:
                return (first_byte_time, total_bytes, duration)
            return None

        except (socket.error, socket.timeout, OSError):
            return None

    def _analyze_timing(
        self,
        first_byte_time: float,
        total_bytes: int,
        duration: float,
        result: DetectionResult,
    ) -> None:
        """Analyze timing for tarpit behavior."""
        # Endlessh delays sending the banner
        if first_byte_time > ENDLESSH_DETECTION_THRESHOLD_S:
            result.add_indicator(
                Indicator(
                    name="endlessh_delayed_banner",
                    description="Significant delay before SSH banner",
                    severity=Confidence.HIGH,
                    details=f"First byte received after {first_byte_time:.1f} seconds",
                )
            )

        # Very slow data rate indicates tarpit
        if duration > 5 and total_bytes > 0:
            bytes_per_second = total_bytes / duration
            if bytes_per_second < 2:  # Less than 2 bytes/second
                result.add_indicator(
                    Indicator(
                        name="endlessh_slow_rate",
                        description="Extremely slow data rate (tarpit behavior)",
                        severity=Confidence.DEFINITE,
                        details=f"Rate: {bytes_per_second:.2f} bytes/second",
                    )
                )

        # Incomplete banner after long wait
        if duration > 10 and total_bytes > 0 and total_bytes < 50:
            result.add_indicator(
                Indicator(
                    name="endlessh_incomplete_banner",
                    description="SSH banner incomplete after extended wait",
                    severity=Confidence.HIGH,
                    details=f"Only {total_bytes} bytes in {duration:.1f} seconds",
                )
            )

    def _get_partial_banner(
        self, target: str, port: int, timeout: float = 3.0
    ) -> Optional[bytes]:
        """Get partial SSH banner with short timeout."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))

            data = b""
            try:
                data = sock.recv(256)
            except socket.timeout:
                pass

            sock.close()
            return data if data else None
        except (socket.error, socket.timeout, OSError):
            return None

    def _check_banner(self, banner: bytes, result: DetectionResult) -> None:
        """Check banner for Endlessh patterns."""
        # Endlessh sends random SSH-2.0- strings slowly
        if banner.startswith(b"SSH-2.0-"):
            # Check if banner is incomplete (no newline)
            if b"\n" not in banner:
                result.add_indicator(
                    Indicator(
                        name="endlessh_partial_banner",
                        description="Partial SSH banner without newline",
                        severity=Confidence.HIGH,
                        details=f"Banner: {banner[:50]}...",
                    )
                )

    def get_recommendations(self, result: DetectionResult) -> list[str]:
        """Get recommendations for Endlessh."""
        return [
            "Endlessh is designed to be detectable - it's a tarpit, not a deceptive honeypot",
            "Consider using Endlessh on a non-standard port with iptables redirect",
        ]


@register_detector
class HellPotDetector(BaseDetector):
    """Detector for HellPot HTTP tarpit.

    HellPot is an HTTP tarpit that sends infinite data streams
    to bad bots requesting vulnerable paths.

    Static (Passive) Detection:
    - Server header patterns (nginx default)
    - Response headers on normal paths
    - Port patterns

    Dynamic (Active) Detection:
    - Tarpit path probing (wp-login, admin, etc.)
    - Infinite data stream detection
    - Response timing analysis
    """

    name = "hellpot"
    description = "Detects HellPot HTTP tarpit"
    honeypot_types = ["hellpot"]
    default_ports = [80, 8080]

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive/static HellPot detection.

        Checks normal response headers and static signatures without
        triggering tarpit paths.

        Args:
            target: IP address or hostname
            port: HTTP port

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        # Check normal path for Server header signatures
        normal_response = self._http_request(target, port, "/")
        if normal_response:
            self._check_normal_response(normal_response, result)

        if result.is_honeypot:
            result.honeypot_type = "hellpot"

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active/dynamic HellPot probing.

        Probes known tarpit paths to detect infinite data streams.

        Args:
            target: IP address or hostname
            port: HTTP port

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        # Check tarpit paths (active probing)
        for path in HELLPOT_TARPIT_PATHS[:3]:  # Test first 3 paths
            tarpit_result = self._check_tarpit_path(target, port, path)
            if tarpit_result:
                result.add_indicator(tarpit_result)
                result.honeypot_type = "hellpot"
                break  # One tarpit path is enough to confirm

        return result

    def _http_request(
        self, target: str, port: int, path: str, max_bytes: int = 4096
    ) -> Optional[bytes]:
        """Make HTTP request and return response."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            request = f"GET {path} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())

            response = b""
            while len(response) < max_bytes:
                try:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break

            sock.close()
            return response
        except (socket.error, socket.timeout, OSError):
            return None

    def _check_tarpit_path(
        self, target: str, port: int, path: str
    ) -> Optional[Indicator]:
        """Check if path triggers tarpit behavior."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)  # Longer timeout for tarpit detection
            sock.connect((target, port))

            request = f"GET {path} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())

            # Measure data reception
            start_time = time.time()
            total_bytes = 0
            chunks_received = 0

            sock.settimeout(2.0)  # Short timeout per recv
            while time.time() - start_time < 8.0:  # Max 8 seconds
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    chunks_received += 1

                    # Tarpit indicator: receiving data continuously
                    if chunks_received > 5 and total_bytes > 10000:
                        sock.close()
                        return Indicator(
                            name="hellpot_infinite_response",
                            description=f"Infinite data stream on {path}",
                            severity=Confidence.DEFINITE,
                            details=f"Received {total_bytes} bytes in {time.time() - start_time:.1f}s",
                        )
                except socket.timeout:
                    continue

            sock.close()

            # Check for unusually large response
            duration = time.time() - start_time
            if total_bytes > 50000 and duration > 5:
                return Indicator(
                    name="hellpot_large_response",
                    description=f"Unusually large response on {path}",
                    severity=Confidence.HIGH,
                    details=f"Received {total_bytes} bytes",
                )

            return None

        except (socket.error, socket.timeout, OSError):
            return None

    def _check_normal_response(self, response: bytes, result: DetectionResult) -> None:
        """Check normal response for HellPot signatures."""
        try:
            response_str = response.decode("utf-8", errors="ignore")
            headers, _, body = response_str.partition("\r\n\r\n")

            # Check Server header
            for line in headers.split("\r\n"):
                if line.lower().startswith("server:"):
                    server = line.split(":", 1)[1].strip()
                    if server.lower() == HELLPOT_SERVER_HEADER:
                        result.add_indicator(
                            Indicator(
                                name="hellpot_nginx_header",
                                description="HellPot default nginx Server header",
                                severity=Confidence.LOW,
                                details=f"Server: {server}",
                            )
                        )
        except UnicodeDecodeError:
            pass

    def get_recommendations(self, result: DetectionResult) -> list[str]:
        """Get recommendations for HellPot."""
        return [
            "HellPot is designed as a tarpit - detection is expected behavior",
            "Customize the server header in HellPot config",
            "Adjust tarpit paths to match your environment",
        ]


@register_detector
class TarpitDetector(BaseDetector):
    """Generic tarpit detector combining SSH and HTTP tarpit detection.

    Static (Passive) Detection:
    - Banner patterns (partial SSH banners)
    - Server headers
    - Port patterns

    Dynamic (Active) Detection:
    - Timing analysis for SSH tarpits
    - Tarpit path probing for HTTP tarpits
    - Infinite stream detection
    """

    name = "tarpit"
    description = "Detects various tarpit honeypots (Endlessh, HellPot)"
    honeypot_types = ["endlessh", "hellpot", "tarpit"]
    default_ports = [22, 80, 2222, 8080]

    def __init__(
        self,
        timeout: float = 5.0,
        verbose: bool = False,
        mode: DetectionMode = DetectionMode.FULL,
    ):
        super().__init__(timeout, verbose, mode)
        self._endlessh = EndlesshDetector(timeout, verbose, mode)
        self._hellpot = HellPotDetector(timeout, verbose, mode)

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive/static tarpit detection.

        Delegates to appropriate sub-detector based on port.

        Args:
            target: IP address or hostname
            port: Port to check

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        if port in [22, 2222, 22222]:
            sub_result = self._endlessh.detect_passive(target, port)
            for indicator in sub_result.indicators:
                result.add_indicator(indicator)
            if sub_result.honeypot_type:
                result.honeypot_type = sub_result.honeypot_type

        elif port in [80, 443, 8080, 8443]:
            sub_result = self._hellpot.detect_passive(target, port)
            for indicator in sub_result.indicators:
                result.add_indicator(indicator)
            if sub_result.honeypot_type:
                result.honeypot_type = sub_result.honeypot_type

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active/dynamic tarpit probing.

        Delegates to appropriate sub-detector based on port.

        Args:
            target: IP address or hostname
            port: Port to check

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        if port in [22, 2222, 22222]:
            sub_result = self._endlessh.detect_active(target, port)
            for indicator in sub_result.indicators:
                result.add_indicator(indicator)
            if sub_result.honeypot_type:
                result.honeypot_type = sub_result.honeypot_type

        elif port in [80, 443, 8080, 8443]:
            sub_result = self._hellpot.detect_active(target, port)
            for indicator in sub_result.indicators:
                result.add_indicator(indicator)
            if sub_result.honeypot_type:
                result.honeypot_type = sub_result.honeypot_type

        return result
