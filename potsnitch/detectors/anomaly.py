"""Anomaly-based honeypot detector (service combinations, port patterns).

Detection is split into:
- PASSIVE: Port combination analysis, multi-service patterns, known signatures
- ACTIVE: Behavioral consistency checks, timing analysis, service verification
"""

import socket
import time
from typing import Optional

from potsnitch.core.base import BaseDetector, DetectionMode, register_detector
from potsnitch.core.result import DetectionResult, Indicator, Confidence
from potsnitch.utils.network import scan_ports


# Default port configurations for known honeypots (from checkpot)
HONEYPOT_PORT_SIGNATURES = {
    "amun": [21, 23, 25, 42, 80, 105, 110, 135, 139, 143, 443, 445, 554, 587, 617,
             1023, 1025, 1080, 1111, 1581, 1900, 2101, 2103, 2105, 2107, 2380, 2555,
             2745, 2954, 2967, 2968, 3127, 3128, 3268, 3372, 3389, 3628, 5000, 5168,
             5554, 6070, 6101, 6129, 7144, 7547, 8080, 9999, 10203, 27347, 38292, 41523],
    "artillery": [21, 22, 25, 53, 110, 1433, 1723, 5800, 5900, 8080, 10000, 16993, 44443],
    "dionaea": [21, 42, 80, 135, 443, 445, 1433, 1723, 3306, 5060, 5061],
    "honeypy": [7, 8, 23, 24, 2048, 4096, 10007, 10008, 10009, 10010],
}

# Windows-exclusive services
WINDOWS_EXCLUSIVE_SERVICES = ["ms-sql", "iis", "windows", "microsoft", "mssql", "smb"]

# Threshold for port signature matching (percentage)
PORT_MATCH_THRESHOLD = 70


@register_detector
class AnomalyDetector(BaseDetector):
    """Detector for honeypots via service/port anomaly analysis.

    Static (Passive) Detection:
    - Port combination analysis against known honeypot signatures
    - Multi-service pattern detection
    - OS/service mismatch detection

    Dynamic (Active) Detection:
    - Behavioral consistency checks across services
    - Response timing analysis
    - Service verification probes
    """

    name = "anomaly"
    description = "Detects honeypots via service combinations, port patterns, and OS mismatches"
    honeypot_types = ["amun", "artillery", "honeypy", "generic"]
    default_ports = []  # This detector scans many ports

    def __init__(
        self,
        timeout: float = 5.0,
        verbose: bool = False,
        mode: DetectionMode = DetectionMode.FULL,
    ):
        super().__init__(timeout, verbose, mode)
        self._all_ports = self._get_all_signature_ports()

    def _get_all_signature_ports(self) -> list[int]:
        """Get all ports from honeypot signatures."""
        ports = set()
        for port_list in HONEYPOT_PORT_SIGNATURES.values():
            ports.update(port_list)
        return sorted(ports)

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive/static anomaly detection.

        Analyzes port combinations and patterns without sending
        any probing traffic beyond port scanning.

        Args:
            target: IP address or hostname
            port: Port (reference port, scans all signature ports)

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        # Scan for open ports
        open_ports = scan_ports(target, self._all_ports, timeout=self.timeout)

        if not open_ports:
            return result

        # Check for port signature matches
        self._check_port_signatures(open_ports, result)

        # Check for duplicate services
        self._check_duplicate_services(target, open_ports, result)

        # Check for OS/service mismatches
        self._check_os_service_mismatch(target, open_ports, result)

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active/dynamic anomaly probing.

        Sends probes to verify service behavior and analyze
        timing patterns that may indicate honeypot behavior.

        Args:
            target: IP address or hostname
            port: Port (reference port)

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        # Scan for open ports first
        open_ports = scan_ports(target, self._all_ports, timeout=self.timeout)

        if not open_ports:
            return result

        # Check response timing consistency
        self._check_timing_consistency(target, open_ports, result)

        # Check for behavioral anomalies
        self._check_behavioral_consistency(target, open_ports, result)

        return result

    def _check_port_signatures(self, open_ports: list[int], result: DetectionResult) -> None:
        """Check if open ports match known honeypot configurations."""
        for honeypot_name, signature_ports in HONEYPOT_PORT_SIGNATURES.items():
            matched = len(set(open_ports) & set(signature_ports))
            match_percent = (matched / len(signature_ports)) * 100

            if match_percent >= PORT_MATCH_THRESHOLD:
                result.add_indicator(
                    Indicator(
                        name="port_signature_match",
                        description=f"Port configuration {match_percent:.0f}% similar to {honeypot_name}",
                        severity=Confidence.HIGH if match_percent >= 90 else Confidence.MEDIUM,
                        details=f"Matched {matched}/{len(signature_ports)} ports",
                    )
                )
                result.honeypot_type = honeypot_name

    def _check_duplicate_services(
        self, target: str, open_ports: list[int], result: DetectionResult
    ) -> None:
        """Check for duplicate services on multiple ports."""
        # Common services that shouldn't be duplicated
        ssh_ports = [p for p in open_ports if p in [22, 2222, 22222]]
        http_ports = [p for p in open_ports if p in [80, 8080, 8000, 8888]]
        ftp_ports = [p for p in open_ports if p in [21, 2121]]

        if len(ssh_ports) > 1:
            result.add_indicator(
                Indicator(
                    name="duplicate_ssh",
                    description=f"Multiple SSH ports open: {ssh_ports}",
                    severity=Confidence.MEDIUM,
                    details="Honeypots often expose SSH on multiple ports",
                )
            )

        if len(http_ports) > 2:
            result.add_indicator(
                Indicator(
                    name="many_http_ports",
                    description=f"Many HTTP ports open: {http_ports}",
                    severity=Confidence.LOW,
                )
            )

    def _check_os_service_mismatch(
        self, target: str, open_ports: list[int], result: DetectionResult
    ) -> None:
        """Check for OS/service mismatches (Linux host running Windows services)."""
        # Check if Windows-specific ports are open alongside Linux services
        windows_ports = {445, 135, 139, 1433, 3389}  # SMB, RPC, MSSQL, RDP
        linux_ports = {22}  # SSH

        has_windows = bool(set(open_ports) & windows_ports)
        has_linux = bool(set(open_ports) & linux_ports)

        if has_windows and has_linux:
            # This could be a honeypot running both
            result.add_indicator(
                Indicator(
                    name="mixed_os_services",
                    description="Both Windows and Linux services detected",
                    severity=Confidence.MEDIUM,
                    details="Same host running Windows (SMB/RDP) and Linux (SSH) services",
                )
            )

        # Check for too many services (honeypots often expose many)
        if len(open_ports) > 15:
            result.add_indicator(
                Indicator(
                    name="many_open_ports",
                    description=f"Unusually many ports open ({len(open_ports)})",
                    severity=Confidence.MEDIUM,
                    details="Honeypots often expose many services to attract attackers",
                )
            )

    def _check_timing_consistency(
        self, target: str, open_ports: list[int], result: DetectionResult
    ) -> None:
        """Check response timing consistency across services.

        Honeypots often have very consistent/fast response times since
        they're running from the same process, while real services have
        more variable timing.
        """
        if len(open_ports) < 3:
            return

        response_times = []

        # Sample a few ports
        sample_ports = open_ports[:min(5, len(open_ports))]

        for port in sample_ports:
            try:
                start = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((target, port))
                sock.recv(256)  # Try to get banner
                sock.close()
                elapsed = time.time() - start
                response_times.append(elapsed)
            except (socket.error, socket.timeout, OSError):
                pass

        if len(response_times) >= 3:
            # Calculate variance in response times
            avg_time = sum(response_times) / len(response_times)
            variance = sum((t - avg_time) ** 2 for t in response_times) / len(response_times)

            # Very low variance across different services is suspicious
            # Real services have different response characteristics
            if variance < 0.001 and avg_time < 0.1:
                result.add_indicator(
                    Indicator(
                        name="uniform_timing",
                        description="Suspiciously uniform response timing across services",
                        severity=Confidence.MEDIUM,
                        details=f"Variance: {variance:.6f}, avg response: {avg_time:.3f}s",
                    )
                )

    def _check_behavioral_consistency(
        self, target: str, open_ports: list[int], result: DetectionResult
    ) -> None:
        """Check for behavioral consistency anomalies.

        Probes services to detect if they share common honeypot
        characteristics like identical error messages.
        """
        error_responses = []

        # Sample ports and send invalid data to trigger errors
        sample_ports = open_ports[:min(5, len(open_ports))]

        for port in sample_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((target, port))

                # Send garbage data to trigger error
                sock.send(b"\xff\xfe\x00\x00INVALID_PROBE\r\n")
                sock.settimeout(2.0)

                try:
                    response = sock.recv(1024)
                    if response:
                        error_responses.append(response[:100])  # First 100 bytes
                except socket.timeout:
                    pass

                sock.close()
            except (socket.error, socket.timeout, OSError):
                pass

        # Check if multiple services return identical error responses
        if len(error_responses) >= 3:
            unique_responses = set(error_responses)
            if len(unique_responses) == 1:
                result.add_indicator(
                    Indicator(
                        name="identical_error_responses",
                        description="Multiple services return identical error responses",
                        severity=Confidence.HIGH,
                        details=f"All {len(error_responses)} tested ports returned identical responses",
                    )
                )
            elif len(unique_responses) <= len(error_responses) / 2:
                result.add_indicator(
                    Indicator(
                        name="similar_error_responses",
                        description="Multiple services return similar error responses",
                        severity=Confidence.MEDIUM,
                        details=f"{len(unique_responses)} unique responses from {len(error_responses)} ports",
                    )
                )

    def get_recommendations(self, result: DetectionResult) -> list[str]:
        """Get remediation recommendations."""
        recommendations = []

        for indicator in result.indicators:
            if "port_signature" in indicator.name:
                recommendations.append(
                    "Customize port configuration - avoid using default honeypot ports"
                )
            elif "duplicate" in indicator.name:
                recommendations.append(
                    "Avoid exposing services on multiple well-known ports"
                )
            elif "mixed_os" in indicator.name:
                recommendations.append(
                    "Consider if exposing both Windows and Linux services is realistic"
                )
            elif "many_open" in indicator.name:
                recommendations.append(
                    "Reduce the number of exposed services to match a realistic server"
                )
            elif "timing" in indicator.name:
                recommendations.append(
                    "Introduce realistic timing variations between different services"
                )
            elif "error_response" in indicator.name:
                recommendations.append(
                    "Ensure different services return distinct, protocol-appropriate error messages"
                )

        return recommendations
