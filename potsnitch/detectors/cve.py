"""CVE-specific honeypot detectors (Log4Pot, CitrixHoneypot, CiscoASA, Spring4Shell)."""

import socket
import ssl
from typing import Optional

from potsnitch.core.base import BaseDetector, DetectionMode, register_detector
from potsnitch.core.result import DetectionResult, Indicator, Confidence


# Log4Pot signatures (Log4Shell CVE-2021-44228)
LOG4POT_SIGNATURES = {
    "sap_netweaver": b"SAP NetWeaver",
    "title_patterns": [
        b"<title>SAP NetWeaver",
        b"<title>Log4j",
    ],
    "response_patterns": [
        b"webdynpro",
        b"sap/bc/",
    ],
}

# CitrixHoneypot signatures (CVE-2019-19781)
CITRIX_SIGNATURES = {
    "headers": {
        "Server": ["Citrix", "NetScaler"],
    },
    "paths": [
        "/vpn/../vpns/cfg/smb.conf",
        "/vpn/../vpns/portal/scripts/",
    ],
    "responses": [
        b"Citrix Gateway",
        b"NetScaler Gateway",
    ],
}

# Cisco ASA Honeypot signatures (CVE-2018-0101)
CISCO_ASA_SIGNATURES = {
    "http_responses": [
        b"Cisco Adaptive Security Appliance",
        b"ASDM",
    ],
    "snmp_patterns": [],
}

# Spring4Shell signatures (CVE-2022-22965)
SPRING4SHELL_SIGNATURES = {
    "actuator_endpoints": [
        "/actuator/health",
        "/actuator/info",
        "/actuator/env",
    ],
    "error_patterns": [
        b"Whitelabel Error Page",
        b"Spring Boot",
    ],
}


@register_detector
class Log4PotDetector(BaseDetector):
    """Detector for Log4Pot (Log4Shell CVE-2021-44228 honeypot).

    Static (Passive) Detection:
    - SAP NetWeaver default response page
    - Known port patterns (8080)
    - Response body signatures

    Dynamic (Active) Detection:
    - JNDI header probing
    - CVE-specific path testing
    """

    name = "log4pot"
    description = "Detects Log4Pot Log4Shell honeypot"
    honeypot_types = ["log4pot"]
    default_ports = [8080, 80, 443]

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive/static Log4Pot detection.

        Checks main page for SAP NetWeaver and known signatures.

        Args:
            target: IP address or hostname
            port: HTTP port

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        # Check main page for SAP NetWeaver signature (static response)
        response = self._http_get(target, port, "/")
        if response:
            self._check_log4pot_signatures(response, result)

        if result.is_honeypot:
            result.honeypot_type = "log4pot"

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active/dynamic Log4Pot probing.

        Probes Log4j-specific endpoints to elicit honeypot responses.

        Args:
            target: IP address or hostname
            port: HTTP port

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        # Probe Log4j-specific endpoints (active probing)
        for path in ["/api", "/login", "/admin"]:
            response = self._http_get(target, port, path)
            if response:
                self._check_log4pot_signatures(response, result)
                if result.is_honeypot:
                    break

        if result.is_honeypot:
            result.honeypot_type = "log4pot"

        return result

    def _http_get(
        self, target: str, port: int, path: str, use_ssl: bool = False
    ) -> Optional[bytes]:
        """Make HTTP GET request."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            if use_ssl or port == 443:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=target)

            sock.connect((target, port))

            request = f"GET {path} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())

            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 65536:  # Limit response size
                        break
                except socket.timeout:
                    break

            sock.close()
            return response
        except (socket.error, socket.timeout, ssl.SSLError, OSError):
            return None

    def _check_log4pot_signatures(
        self, response: bytes, result: DetectionResult
    ) -> None:
        """Check response for Log4Pot signatures."""
        # Check for SAP NetWeaver signature
        if LOG4POT_SIGNATURES["sap_netweaver"] in response:
            result.add_indicator(
                Indicator(
                    name="log4pot_sap_netweaver",
                    description="SAP NetWeaver response (Log4Pot default)",
                    severity=Confidence.HIGH,
                    details="T-Pot Log4Pot uses SAP NetWeaver as default page",
                )
            )

        # Check title patterns
        for pattern in LOG4POT_SIGNATURES["title_patterns"]:
            if pattern in response:
                result.add_indicator(
                    Indicator(
                        name="log4pot_title_pattern",
                        description="Log4Pot title pattern detected",
                        severity=Confidence.MEDIUM,
                    )
                )
                break

        # Check response patterns
        for pattern in LOG4POT_SIGNATURES["response_patterns"]:
            if pattern in response:
                result.add_indicator(
                    Indicator(
                        name="log4pot_response_pattern",
                        description=f"Log4Pot pattern detected: {pattern.decode()}",
                        severity=Confidence.MEDIUM,
                    )
                )


@register_detector
class CitrixHoneypotDetector(BaseDetector):
    """Detector for CitrixHoneypot (CVE-2019-19781).

    Static (Passive) Detection:
    - Citrix Gateway response patterns
    - Server header analysis
    - Certificate patterns

    Dynamic (Active) Detection:
    - Path traversal response testing
    - Vulnerable path probing
    - Fake smb.conf detection
    """

    name = "citrixhoneypot"
    description = "Detects CitrixHoneypot (CVE-2019-19781)"
    honeypot_types = ["citrixhoneypot"]
    default_ports = [443, 80]

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive/static Citrix honeypot detection.

        Checks main page for Citrix Gateway signatures.

        Args:
            target: IP address or hostname
            port: HTTPS/HTTP port

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        # Check main page for Citrix signatures
        response = self._http_get(target, port, "/")
        if response:
            self._check_citrix_signatures(response, result)

        if result.is_honeypot:
            result.honeypot_type = "citrixhoneypot"

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active/dynamic Citrix honeypot probing.

        Probes vulnerable paths to detect honeypot responses.

        Args:
            target: IP address or hostname
            port: HTTPS/HTTP port

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        # Probe vulnerable paths (active probing)
        for path in CITRIX_SIGNATURES["paths"]:
            response = self._http_get(target, port, path)
            if response:
                self._check_vulnerable_path_response(response, path, result)

        if result.is_honeypot:
            result.honeypot_type = "citrixhoneypot"

        return result

    def _http_get(
        self, target: str, port: int, path: str
    ) -> Optional[bytes]:
        """Make HTTP GET request."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            if port == 443:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=target)

            sock.connect((target, port))

            request = f"GET {path} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())

            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 65536:
                        break
                except socket.timeout:
                    break

            sock.close()
            return response
        except (socket.error, socket.timeout, ssl.SSLError, OSError):
            return None

    def _check_citrix_signatures(
        self, response: bytes, result: DetectionResult
    ) -> None:
        """Check response for Citrix honeypot signatures."""
        # Check for Citrix Gateway patterns
        for pattern in CITRIX_SIGNATURES["responses"]:
            if pattern in response:
                result.add_indicator(
                    Indicator(
                        name="citrix_gateway_pattern",
                        description="Citrix Gateway response pattern",
                        severity=Confidence.MEDIUM,
                        details=f"Pattern: {pattern.decode()}",
                    )
                )

        # Check headers
        try:
            response_str = response.decode("utf-8", errors="ignore")
            headers = response_str.split("\r\n\r\n")[0]
            for line in headers.split("\r\n"):
                if line.lower().startswith("server:"):
                    server = line.split(":", 1)[1].strip()
                    for citrix_server in CITRIX_SIGNATURES["headers"]["Server"]:
                        if citrix_server.lower() in server.lower():
                            result.add_indicator(
                                Indicator(
                                    name="citrix_server_header",
                                    description=f"Citrix Server header: {server}",
                                    severity=Confidence.MEDIUM,
                                )
                            )
        except UnicodeDecodeError:
            pass

    def _check_vulnerable_path_response(
        self, response: bytes, path: str, result: DetectionResult
    ) -> None:
        """Check response to vulnerable path request."""
        # Honeypots often respond to path traversal with fake config
        if b"smb.conf" in path.encode() and (
            b"[global]" in response or b"workgroup" in response.lower()
        ):
            result.add_indicator(
                Indicator(
                    name="citrix_fake_smb_conf",
                    description="Fake smb.conf returned (honeypot indicator)",
                    severity=Confidence.HIGH,
                    details=f"Path: {path}",
                )
            )

        # Check for 200 OK on path traversal (real Citrix would block)
        if b"HTTP/1.1 200" in response or b"HTTP/1.0 200" in response:
            if ".." in path:
                result.add_indicator(
                    Indicator(
                        name="citrix_path_traversal_success",
                        description="Path traversal returns 200 OK",
                        severity=Confidence.HIGH,
                        details="Real Citrix ADC blocks path traversal",
                    )
                )


@register_detector
class CiscoASAHoneypotDetector(BaseDetector):
    """Detector for Cisco ASA honeypots (CVE-2018-0101).

    Static (Passive) Detection:
    - Cisco ASA HTTP response patterns
    - ASDM interface signatures
    - Port patterns (443, 8443, 5000)

    Dynamic (Active) Detection:
    - UDP probe responses on port 5000
    - Admin interface probing
    """

    name = "ciscoasa"
    description = "Detects Cisco ASA honeypots"
    honeypot_types = ["ciscoasa_honeypot"]
    default_ports = [443, 8443, 5000]

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive/static Cisco ASA honeypot detection.

        Checks main page for ASA signatures.

        Args:
            target: IP address or hostname
            port: Port to check

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        # Check HTTPS admin interface for static signatures
        if port in [443, 8443]:
            response = self._https_get(target, port, "/")
            if response:
                self._check_asa_signatures(response, result)

        if result.is_honeypot:
            result.honeypot_type = "ciscoasa_honeypot"

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active/dynamic Cisco ASA honeypot probing.

        Probes ASDM endpoints and UDP port 5000.

        Args:
            target: IP address or hostname
            port: Port to check

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        # Active probing: check ASDM endpoint
        if port in [443, 8443]:
            asdm_response = self._https_get(target, port, "/admin/")
            if asdm_response:
                self._check_asdm_signatures(asdm_response, result)

        # Active UDP probe on port 5000
        if port == 5000:
            udp_response = self._udp_probe(target, port)
            if udp_response:
                self._check_udp_signatures(udp_response, result)

        if result.is_honeypot:
            result.honeypot_type = "ciscoasa_honeypot"

        return result

    def _https_get(self, target: str, port: int, path: str) -> Optional[bytes]:
        """Make HTTPS GET request."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=target)

            sock.connect((target, port))

            request = f"GET {path} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())

            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 65536:
                        break
                except socket.timeout:
                    break

            sock.close()
            return response
        except (socket.error, socket.timeout, ssl.SSLError, OSError):
            return None

    def _udp_probe(self, target: str, port: int) -> Optional[bytes]:
        """Send UDP probe."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(b"\x00" * 8, (target, port))
            response, _ = sock.recvfrom(1024)
            sock.close()
            return response
        except (socket.error, socket.timeout, OSError):
            return None

    def _check_asa_signatures(
        self, response: bytes, result: DetectionResult
    ) -> None:
        """Check response for Cisco ASA signatures."""
        for pattern in CISCO_ASA_SIGNATURES["http_responses"]:
            if pattern in response:
                result.add_indicator(
                    Indicator(
                        name="ciscoasa_http_pattern",
                        description="Cisco ASA HTTP pattern detected",
                        severity=Confidence.MEDIUM,
                        details=f"Pattern: {pattern.decode()}",
                    )
                )

    def _check_asdm_signatures(
        self, response: bytes, result: DetectionResult
    ) -> None:
        """Check ASDM response signatures."""
        if b"ASDM" in response:
            result.add_indicator(
                Indicator(
                    name="ciscoasa_asdm",
                    description="ASDM interface detected",
                    severity=Confidence.MEDIUM,
                )
            )

        # Check for default/fake certificate
        # Would require certificate inspection

    def _check_udp_signatures(
        self, response: bytes, result: DetectionResult
    ) -> None:
        """Check UDP response signatures."""
        # Honeypot may respond to malformed packets
        result.add_indicator(
            Indicator(
                name="ciscoasa_udp_response",
                description="UDP port 5000 responds to probe",
                severity=Confidence.LOW,
            )
        )


@register_detector
class Spring4ShellDetector(BaseDetector):
    """Detector for Spring4Shell honeypots (CVE-2022-22965).

    Static (Passive) Detection:
    - Spring Boot Whitelabel Error Page
    - Main page Spring patterns
    - Port patterns (8080)

    Dynamic (Active) Detection:
    - Actuator endpoint probing
    - Error page analysis
    - CVE-specific path testing
    """

    name = "spring4shell"
    description = "Detects Spring4Shell honeypots"
    honeypot_types = ["spring4shell_pot"]
    default_ports = [8080, 80, 443]

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive/static Spring4Shell honeypot detection.

        Checks main page for Spring Boot patterns.

        Args:
            target: IP address or hostname
            port: HTTP port

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        # Check main page for Spring Boot patterns
        main_response = self._http_get(target, port, "/")
        if main_response:
            self._check_spring_patterns(main_response, result)

        if result.is_honeypot:
            result.honeypot_type = "spring4shell_pot"

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active/dynamic Spring4Shell honeypot probing.

        Probes actuator endpoints and error pages.

        Args:
            target: IP address or hostname
            port: HTTP port

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        # Check actuator endpoints (active probing)
        for endpoint in SPRING4SHELL_SIGNATURES["actuator_endpoints"]:
            response = self._http_get(target, port, endpoint)
            if response:
                self._check_actuator_response(response, endpoint, result)

        # Check error page (active probing with nonexistent path)
        error_response = self._http_get(target, port, "/nonexistent-path-12345")
        if error_response:
            self._check_error_page(error_response, result)

        if result.is_honeypot:
            result.honeypot_type = "spring4shell_pot"

        return result

    def _http_get(self, target: str, port: int, path: str) -> Optional[bytes]:
        """Make HTTP GET request."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            if port == 443:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=target)

            sock.connect((target, port))

            request = f"GET {path} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())

            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 65536:
                        break
                except socket.timeout:
                    break

            sock.close()
            return response
        except (socket.error, socket.timeout, ssl.SSLError, OSError):
            return None

    def _check_actuator_response(
        self, response: bytes, endpoint: str, result: DetectionResult
    ) -> None:
        """Check actuator endpoint response."""
        # Actuator endpoints returning 200 OK
        if b"HTTP/1.1 200" in response or b"HTTP/1.0 200" in response:
            result.add_indicator(
                Indicator(
                    name="spring4shell_actuator_exposed",
                    description=f"Spring Actuator endpoint exposed: {endpoint}",
                    severity=Confidence.MEDIUM,
                    details="Exposed actuators common in honeypots",
                )
            )

            # Check for sensitive data exposure
            if b'"status":"UP"' in response:
                result.add_indicator(
                    Indicator(
                        name="spring4shell_health_endpoint",
                        description="Health endpoint with default response",
                        severity=Confidence.LOW,
                    )
                )

    def _check_spring_patterns(
        self, response: bytes, result: DetectionResult
    ) -> None:
        """Check for Spring Boot patterns."""
        for pattern in SPRING4SHELL_SIGNATURES["error_patterns"]:
            if pattern in response:
                result.add_indicator(
                    Indicator(
                        name="spring4shell_spring_pattern",
                        description=f"Spring Boot pattern: {pattern.decode()}",
                        severity=Confidence.LOW,
                    )
                )

    def _check_error_page(
        self, response: bytes, result: DetectionResult
    ) -> None:
        """Check error page for honeypot indicators."""
        if b"Whitelabel Error Page" in response:
            result.add_indicator(
                Indicator(
                    name="spring4shell_whitelabel_error",
                    description="Default Spring Boot Whitelabel Error Page",
                    severity=Confidence.LOW,
                    details="Default error page often left enabled in honeypots",
                )
            )


@register_detector
class CVEHoneypotDetector(BaseDetector):
    """Combined detector for CVE-specific honeypots.

    Static (Passive) Detection:
    - Delegates to individual CVE detectors for static signatures
    - Response body patterns
    - Server headers

    Dynamic (Active) Detection:
    - CVE-specific path probing
    - Vulnerability emulation testing
    - Actuator/admin endpoint probing
    """

    name = "cve"
    description = "Detects CVE-specific honeypots (Log4j, Citrix, Cisco ASA, Spring4Shell)"
    honeypot_types = ["log4pot", "citrixhoneypot", "ciscoasa_honeypot", "spring4shell_pot"]
    default_ports = [80, 443, 8080, 8443]

    def __init__(
        self,
        timeout: float = 5.0,
        verbose: bool = False,
        mode: DetectionMode = DetectionMode.FULL,
    ):
        super().__init__(timeout, verbose, mode)
        self._log4pot = Log4PotDetector(timeout, verbose, mode)
        self._citrix = CitrixHoneypotDetector(timeout, verbose, mode)
        self._cisco = CiscoASAHoneypotDetector(timeout, verbose, mode)
        self._spring = Spring4ShellDetector(timeout, verbose, mode)

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive/static CVE honeypot detection.

        Delegates to individual CVE detectors for passive checks.

        Args:
            target: IP address or hostname
            port: Port to check

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        # Run each detector's passive detection and combine results
        detectors = [
            (self._log4pot, [8080, 80]),
            (self._citrix, [443, 80]),
            (self._cisco, [443, 8443, 5000]),
            (self._spring, [8080, 80]),
        ]

        for detector, ports in detectors:
            if port in ports:
                sub_result = detector.detect_passive(target, port)
                for indicator in sub_result.indicators:
                    result.add_indicator(indicator)
                if sub_result.honeypot_type and not result.honeypot_type:
                    result.honeypot_type = sub_result.honeypot_type

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active/dynamic CVE honeypot probing.

        Delegates to individual CVE detectors for active probes.

        Args:
            target: IP address or hostname
            port: Port to check

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        # Run each detector's active detection and combine results
        detectors = [
            (self._log4pot, [8080, 80]),
            (self._citrix, [443, 80]),
            (self._cisco, [443, 8443, 5000]),
            (self._spring, [8080, 80]),
        ]

        for detector, ports in detectors:
            if port in ports:
                sub_result = detector.detect_active(target, port)
                for indicator in sub_result.indicators:
                    result.add_indicator(indicator)
                if sub_result.honeypot_type and not result.honeypot_type:
                    result.honeypot_type = sub_result.honeypot_type

        return result

    def get_recommendations(self, result: DetectionResult) -> list[str]:
        """Get recommendations for CVE honeypots."""
        recommendations = []

        for indicator in result.indicators:
            if "log4pot" in indicator.name:
                recommendations.append(
                    "Customize Log4Pot's default SAP NetWeaver page"
                )
            elif "citrix" in indicator.name:
                recommendations.append(
                    "Ensure CitrixHoneypot blocks actual path traversal attempts"
                )
            elif "spring" in indicator.name:
                recommendations.append(
                    "Disable or customize Spring Actuator endpoints"
                )
                recommendations.append(
                    "Use custom error page instead of Whitelabel Error Page"
                )

        return list(set(recommendations))  # Deduplicate
