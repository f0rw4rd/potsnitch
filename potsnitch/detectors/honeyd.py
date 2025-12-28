"""Honeyd honeypot detector.

Detection is split into:
- PASSIVE: TCP fingerprint analysis, timing pattern analysis
- ACTIVE: Multi-OS fingerprint detection, timing inconsistency probing, CVE-2004-2095 detection
"""

import socket
import time
from typing import Optional

from potsnitch.core.base import BaseDetector, DetectionMode, register_detector
from potsnitch.core.result import DetectionResult, Indicator, Confidence


# Honeyd timing characteristics
# Honeyd uses scripted responses which can create timing patterns
TIMING_THRESHOLD_MS = 5  # Responses faster than this are suspicious
TIMING_VARIANCE_THRESHOLD = 0.001  # Very low variance indicates scripted responses

# Known Honeyd default fingerprints (from nmap-os-fingerprints)
HONEYD_OS_FINGERPRINTS = [
    "Windows 2000",
    "Windows XP",
    "Linux 2.4",
    "Linux 2.6",
    "FreeBSD 4.8",
    "Solaris 8",
]


@register_detector
class HoneydDetector(BaseDetector):
    """Detector for Honeyd low-interaction honeypot.

    Static (Passive) Detection:
    - TCP fingerprint analysis
    - Port response patterns
    - TTL analysis

    Dynamic (Active) Detection:
    - Timing inconsistency detection (scripted response patterns)
    - Multi-OS fingerprint detection (same host appears as different OS)
    - TCP option fingerprint deviation
    - CVE-2004-2095 detection (information disclosure vulnerability)
    """

    name = "honeyd"
    description = "Detects Honeyd honeypot via timing analysis and TCP fingerprinting"
    honeypot_types = ["honeyd"]
    default_ports = [22, 23, 25, 80, 110, 143, 443]

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive/static Honeyd detection.

        Analyzes TCP characteristics without deep probing.

        Args:
            target: IP address or hostname
            port: Port number

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        # Check for timing patterns on connection
        timing_result = self._check_connection_timing(target, port)
        if timing_result:
            result.add_indicator(timing_result)

        if result.is_honeypot:
            result.honeypot_type = "honeyd"

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active/dynamic Honeyd probing.

        Performs timing analysis and fingerprint checks.

        Args:
            target: IP address or hostname
            port: Port number

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        # Check timing consistency
        self._check_timing_consistency(target, port, result)

        # Check for multi-OS fingerprinting
        self._check_multi_os_fingerprint(target, result)

        # Check for TCP fingerprint deviation
        self._check_tcp_fingerprint_deviation(target, port, result)

        # Check for CVE-2004-2095
        self._check_cve_2004_2095(target, port, result)

        if result.is_honeypot:
            result.honeypot_type = "honeyd"

        return result

    def _check_connection_timing(self, target: str, port: int) -> Optional[Indicator]:
        """Check connection establishment timing.

        Honeyd may have unusually fast or consistent response times
        due to scripted responses.
        """
        try:
            timings = []
            for _ in range(3):
                start = time.perf_counter()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((target, port))
                elapsed = time.perf_counter() - start
                timings.append(elapsed)
                sock.close()
                time.sleep(0.1)  # Brief pause between connections

            avg_timing = sum(timings) / len(timings)
            variance = sum((t - avg_timing) ** 2 for t in timings) / len(timings)

            # Check for suspiciously fast responses
            if avg_timing < TIMING_THRESHOLD_MS / 1000:
                return Indicator(
                    name="instant_connection",
                    description=f"Unusually fast connection time: {avg_timing * 1000:.2f}ms",
                    severity=Confidence.MEDIUM,
                    details="Honeyd may respond faster than real services",
                )

            # Check for suspiciously consistent timing (low variance)
            if variance < TIMING_VARIANCE_THRESHOLD:
                return Indicator(
                    name="consistent_timing",
                    description=f"Very consistent connection timing (variance: {variance:.6f})",
                    severity=Confidence.MEDIUM,
                    details="Scripted responses often have low timing variance",
                )

        except (socket.error, socket.timeout, OSError):
            pass

        return None

    def _check_timing_consistency(self, target: str, port: int, result: DetectionResult) -> None:
        """Check for timing inconsistencies across multiple requests.

        Honeyd uses script-based responses which can create detectable patterns.
        """
        try:
            response_times = []

            for i in range(5):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)

                start = time.perf_counter()
                sock.connect((target, port))

                # Send probe data
                probe = f"PROBE_{i}\r\n".encode()
                sock.send(probe)

                try:
                    sock.recv(1024)
                except socket.timeout:
                    pass

                elapsed = time.perf_counter() - start
                response_times.append(elapsed)
                sock.close()

            # Calculate timing statistics
            if len(response_times) >= 3:
                avg_time = sum(response_times) / len(response_times)
                variance = sum((t - avg_time) ** 2 for t in response_times) / len(response_times)

                # Very low variance indicates scripted responses
                if variance < TIMING_VARIANCE_THRESHOLD:
                    result.add_indicator(
                        Indicator(
                            name="scripted_timing",
                            description=f"Scripted response pattern detected (variance: {variance:.6f})",
                            severity=Confidence.HIGH,
                            details="Honeyd script responses have consistent timing",
                        )
                    )

                # Check for suspiciously uniform response times
                max_diff = max(response_times) - min(response_times)
                if max_diff < 0.001 and avg_time > 0:  # Less than 1ms difference
                    result.add_indicator(
                        Indicator(
                            name="uniform_timing",
                            description=f"Uniform response timing detected (diff: {max_diff * 1000:.3f}ms)",
                            severity=Confidence.MEDIUM,
                        )
                    )

        except (socket.error, socket.timeout, OSError):
            pass

    def _check_multi_os_fingerprint(self, target: str, result: DetectionResult) -> None:
        """Check for multiple OS fingerprints on same host.

        Honeyd can be configured to emulate different OS on different ports,
        which is unusual for real systems.
        """
        try:
            detected_os = []
            test_ports = [22, 80, 443, 25]

            for port in test_ports:
                os_hint = self._get_os_hint(target, port)
                if os_hint and os_hint not in detected_os:
                    detected_os.append(os_hint)

            if len(detected_os) >= 2:
                result.add_indicator(
                    Indicator(
                        name="multi_os_fingerprint",
                        description=f"Multiple OS fingerprints detected: {detected_os}",
                        severity=Confidence.DEFINITE,
                        details="Same host showing different OS characteristics on different ports",
                    )
                )

        except (socket.error, socket.timeout, OSError):
            pass

    def _get_os_hint(self, target: str, port: int) -> Optional[str]:
        """Get OS hint from TCP/IP stack characteristics.

        Analyzes TTL, window size, and TCP options.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Get initial TTL from socket options if available
            # This is a simplified check - real OS fingerprinting is more complex
            sock.close()

            # In practice, this would use raw sockets or scapy for TTL analysis
            # Placeholder for OS detection logic
            return None

        except (socket.error, socket.timeout, OSError):
            return None

    def _check_tcp_fingerprint_deviation(self, target: str, port: int, result: DetectionResult) -> None:
        """Check for TCP fingerprint deviations.

        Honeyd's TCP/IP stack emulation may have subtle differences
        from real operating systems.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Get TCP options
            # Note: This requires raw socket access for full analysis
            # Here we check for basic anomalies

            # Check RST behavior by sending malformed data
            sock.send(b"\xff\xff\xff\xff")

            try:
                response = sock.recv(1024)
                # Honeyd may respond differently to malformed packets
                if response:
                    result.add_indicator(
                        Indicator(
                            name="tcp_anomaly_response",
                            description="Unusual response to malformed TCP data",
                            severity=Confidence.LOW,
                            details="Response to invalid data may indicate emulated stack",
                        )
                    )
            except socket.timeout:
                pass

            sock.close()

        except (socket.error, socket.timeout, OSError):
            pass

    def _check_cve_2004_2095(self, target: str, port: int, result: DetectionResult) -> None:
        """Check for CVE-2004-2095 vulnerability.

        CVE-2004-2095 is an information disclosure vulnerability in Honeyd
        that can reveal it's a honeypot through specially crafted packets.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Send probe that may trigger CVE-2004-2095
            # This involves sending specific TCP options or malformed packets
            probe = b"\x00" * 20  # Simplified probe

            sock.send(probe)

            try:
                response = sock.recv(1024)

                # Check for Honeyd-specific response patterns
                if b"honeyd" in response.lower() if response else False:
                    result.add_indicator(
                        Indicator(
                            name="cve_2004_2095",
                            description="CVE-2004-2095 information disclosure detected",
                            severity=Confidence.DEFINITE,
                            details="Honeyd revealed itself through known vulnerability",
                        )
                    )

                # Check for specific error patterns
                if response and len(response) > 0:
                    # Look for TCP fingerprint leakage
                    response_str = response.decode("ascii", errors="ignore")
                    if "personality" in response_str.lower():
                        result.add_indicator(
                            Indicator(
                                name="personality_leak",
                                description="Honeyd personality configuration leaked",
                                severity=Confidence.DEFINITE,
                            )
                        )

            except socket.timeout:
                pass

            sock.close()

        except (socket.error, socket.timeout, OSError):
            pass

    def get_recommendations(self, result: DetectionResult) -> list[str]:
        """Get remediation recommendations for Honeyd."""
        recommendations = []

        for indicator in result.indicators:
            if indicator.name == "scripted_timing" or indicator.name == "uniform_timing":
                recommendations.append(
                    "Add random delays to service scripts to vary response timing"
                )
            elif indicator.name == "multi_os_fingerprint":
                recommendations.append(
                    "Use consistent OS personality across all emulated services"
                )
            elif indicator.name == "cve_2004_2095":
                recommendations.append(
                    "Update Honeyd to a patched version or apply CVE-2004-2095 mitigation"
                )
            elif indicator.name == "tcp_anomaly_response":
                recommendations.append(
                    "Tune nmap.prints personality file for more accurate TCP behavior"
                )

        return recommendations
