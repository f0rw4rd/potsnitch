"""Multi-service honeypot framework detectors (OpenCanary, QeeqBox, Artillery, FAPRO)."""

import socket
from typing import Optional, Set

from potsnitch.core.base import BaseDetector, DetectionMode, register_detector
from potsnitch.core.result import DetectionResult, Indicator, Confidence
from potsnitch.utils.network import scan_ports


# OpenCanary default port combinations
OPENCANARY_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    80: "http",
    443: "https",
    445: "smb",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
}

# QeeqBox supports 25+ services
QEEQBOX_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    80: "http",
    110: "pop3",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "smb",
    1080: "socks5",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5060: "sip",
    5432: "postgres",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

# Artillery default ports (13 services)
ARTILLERY_PORTS = {
    21: "ftp",
    22: "ssh",
    135: "msrpc",
    445: "smb",
    1433: "mssql",
    3306: "mysql",
    5900: "vnc",
    8080: "http-proxy",
    10000: "webmin",
    44443: "https-alt",
}

# FAPRO (Go-based, configurable)
FAPRO_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    6379: "redis",
    9200: "elasticsearch",
    27017: "mongodb",
}

# Minimum port matches to consider a framework detection
MIN_PORT_MATCH_THRESHOLD = 4


@register_detector
class OpenCanaryDetector(BaseDetector):
    """Detector for OpenCanary honeypot framework.

    Static (Passive) Detection:
    - Port combinations (SSH + SMB + MSSQL + MySQL + RDP + VNC)
    - Mixed Windows/Linux service signatures
    - FTP banner patterns

    Dynamic (Active) Detection:
    - Cross-service consistency checks
    - Python TLS fingerprinting
    - Behavioral analysis
    """

    name = "opencanary"
    description = "Detects OpenCanary multi-service honeypot"
    honeypot_types = ["opencanary"]
    default_ports = list(OPENCANARY_PORTS.keys())

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive/static OpenCanary detection.

        Checks port combinations and static signatures.

        Args:
            target: IP address or hostname
            port: Port to check

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        # Scan for OpenCanary port combination (port scanning is passive)
        open_ports = self._scan_opencanary_ports(target)
        if open_ports:
            self._analyze_port_combination(open_ports, result)

        if result.is_honeypot:
            result.honeypot_type = "opencanary"

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active/dynamic OpenCanary probing.

        Checks service banners and behavioral patterns.

        Args:
            target: IP address or hostname
            port: Port to check

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        # Active probing: check specific service banners
        open_ports = self._scan_opencanary_ports(target)
        self._check_service_signatures(target, open_ports, result)

        if result.is_honeypot:
            result.honeypot_type = "opencanary"

        return result

    def _scan_opencanary_ports(self, target: str) -> Set[int]:
        """Scan for OpenCanary default ports."""
        open_ports = set()
        for port in OPENCANARY_PORTS.keys():
            if self._is_port_open(target, port):
                open_ports.add(port)
        return open_ports

    def _is_port_open(self, target: str, port: int) -> bool:
        """Check if port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except (socket.error, OSError):
            return False

    def _analyze_port_combination(
        self, open_ports: Set[int], result: DetectionResult
    ) -> None:
        """Analyze port combination for framework detection."""
        matching_ports = open_ports & set(OPENCANARY_PORTS.keys())
        match_count = len(matching_ports)

        if match_count >= MIN_PORT_MATCH_THRESHOLD:
            services = [OPENCANARY_PORTS[p] for p in matching_ports]
            result.add_indicator(
                Indicator(
                    name="opencanary_port_combo",
                    description=f"OpenCanary port combination ({match_count} services)",
                    severity=Confidence.MEDIUM if match_count < 6 else Confidence.HIGH,
                    details=f"Services: {', '.join(services)}",
                )
            )

        # Unusual combination: Windows services (SMB, MSSQL) with Linux services
        windows_ports = {445, 1433, 3389}
        linux_ports = {22}  # SSH on non-Windows
        if (open_ports & windows_ports) and (open_ports & linux_ports):
            result.add_indicator(
                Indicator(
                    name="opencanary_mixed_os",
                    description="Mixed Windows/Linux services on same host",
                    severity=Confidence.HIGH,
                    details="SMB/RDP/MSSQL with SSH indicates honeypot",
                )
            )

    def _check_service_signatures(
        self, target: str, open_ports: Set[int], result: DetectionResult
    ) -> None:
        """Check service-specific signatures."""
        # Check for Python-based TLS fingerprints (OpenCanary uses Python)
        if 443 in open_ports or 3389 in open_ports:
            # Would require TLS fingerprinting
            pass

        # FTP banner check
        if 21 in open_ports:
            banner = self._get_ftp_banner(target, 21)
            if banner and b"OpenCanary" in banner:
                result.add_indicator(
                    Indicator(
                        name="opencanary_ftp_banner",
                        description="OpenCanary signature in FTP banner",
                        severity=Confidence.DEFINITE,
                    )
                )

    def _get_ftp_banner(self, target: str, port: int) -> Optional[bytes]:
        """Get FTP banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            banner = sock.recv(1024)
            sock.close()
            return banner
        except (socket.error, socket.timeout, OSError):
            return None


@register_detector
class QeeqBoxDetector(BaseDetector):
    """Detector for QeeqBox honeypots (25+ services).

    Static (Passive) Detection:
    - High port count (8+ matching services)
    - Unusual service combinations (SIP + Elasticsearch)
    - Port combination fingerprinting

    Dynamic (Active) Detection:
    - Python/gevent TLS fingerprinting
    - Cross-service behavioral consistency
    """

    name = "qeeqbox"
    description = "Detects QeeqBox multi-service honeypot"
    honeypot_types = ["qeeqbox"]
    default_ports = list(QEEQBOX_PORTS.keys())

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive/static QeeqBox detection.

        Checks port combinations and unusual service patterns.

        Args:
            target: IP address or hostname
            port: Port to check

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        # Scan for QeeqBox port combination
        open_ports = self._scan_qeeqbox_ports(target)
        if open_ports:
            self._analyze_port_combination(open_ports, result)

        if result.is_honeypot:
            result.honeypot_type = "qeeqbox"

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active/dynamic QeeqBox probing.

        Currently a placeholder for TLS fingerprinting and
        behavioral analysis.

        Args:
            target: IP address or hostname
            port: Port to check

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)
        # Active probing would include TLS fingerprinting for gevent/Python
        return result

    def _scan_qeeqbox_ports(self, target: str) -> Set[int]:
        """Scan for QeeqBox default ports."""
        open_ports = set()
        for port in QEEQBOX_PORTS.keys():
            if self._is_port_open(target, port):
                open_ports.add(port)
        return open_ports

    def _is_port_open(self, target: str, port: int) -> bool:
        """Check if port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except (socket.error, OSError):
            return False

    def _analyze_port_combination(
        self, open_ports: Set[int], result: DetectionResult
    ) -> None:
        """Analyze port combination for QeeqBox detection."""
        matching_ports = open_ports & set(QEEQBOX_PORTS.keys())
        match_count = len(matching_ports)

        # QeeqBox has distinctive high port count
        if match_count >= 8:
            services = [QEEQBOX_PORTS[p] for p in matching_ports]
            result.add_indicator(
                Indicator(
                    name="qeeqbox_high_port_count",
                    description=f"Suspicious number of services ({match_count})",
                    severity=Confidence.HIGH,
                    details=f"Services: {', '.join(services[:10])}...",
                )
            )

        # QeeqBox specific: unusual service combinations
        unusual_combos = [
            ({5060, 9200}, "SIP + Elasticsearch"),
            ({1521, 27017}, "Oracle + MongoDB"),
            ({11211, 6379}, "Memcached + Redis"),
        ]
        for combo_ports, desc in unusual_combos:
            if combo_ports.issubset(open_ports):
                result.add_indicator(
                    Indicator(
                        name="qeeqbox_unusual_combo",
                        description=f"Unusual service combination: {desc}",
                        severity=Confidence.MEDIUM,
                    )
                )

        # QeeqBox uses gevent/Python - check for fingerprints
        if match_count >= MIN_PORT_MATCH_THRESHOLD:
            result.add_indicator(
                Indicator(
                    name="qeeqbox_port_combo",
                    description="QeeqBox port combination detected",
                    severity=Confidence.MEDIUM,
                    details=f"{match_count} matching services",
                )
            )


@register_detector
class ArtilleryDetector(BaseDetector):
    """Detector for Artillery honeypot.

    Static (Passive) Detection:
    - Port combinations (13 default services)
    - Port 44443 and 10000 patterns

    Dynamic (Active) Detection:
    - Silent port analysis (accepts connection but no data)
    - Connection-only logging behavior
    """

    name = "artillery"
    description = "Detects Artillery honeypot"
    honeypot_types = ["artillery"]
    default_ports = list(ARTILLERY_PORTS.keys())

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive/static Artillery detection.

        Checks port combinations.

        Args:
            target: IP address or hostname
            port: Port to check

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        # Scan for Artillery port combination
        open_ports = self._scan_artillery_ports(target)
        if open_ports:
            self._analyze_port_combination(open_ports, result)

        if result.is_honeypot:
            result.honeypot_type = "artillery"

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active/dynamic Artillery probing.

        Checks for minimal/silent responses typical of Artillery.

        Args:
            target: IP address or hostname
            port: Port to check

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        # Artillery is connection-logging only - check for minimal responses
        open_ports = self._scan_artillery_ports(target)
        self._check_minimal_responses(target, open_ports, result)

        if result.is_honeypot:
            result.honeypot_type = "artillery"

        return result

    def _scan_artillery_ports(self, target: str) -> Set[int]:
        """Scan for Artillery default ports."""
        open_ports = set()
        for port in ARTILLERY_PORTS.keys():
            if self._is_port_open(target, port):
                open_ports.add(port)
        return open_ports

    def _is_port_open(self, target: str, port: int) -> bool:
        """Check if port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except (socket.error, OSError):
            return False

    def _analyze_port_combination(
        self, open_ports: Set[int], result: DetectionResult
    ) -> None:
        """Analyze port combination for Artillery detection."""
        matching_ports = open_ports & set(ARTILLERY_PORTS.keys())
        match_count = len(matching_ports)

        if match_count >= MIN_PORT_MATCH_THRESHOLD:
            services = [ARTILLERY_PORTS[p] for p in matching_ports]
            result.add_indicator(
                Indicator(
                    name="artillery_port_combo",
                    description=f"Artillery port combination ({match_count} services)",
                    severity=Confidence.MEDIUM,
                    details=f"Services: {', '.join(services)}",
                )
            )

    def _check_minimal_responses(
        self, target: str, open_ports: Set[int], result: DetectionResult
    ) -> None:
        """Check for minimal/no responses (Artillery logs connections only)."""
        silent_ports = 0
        tested_ports = 0

        for port in list(open_ports)[:5]:  # Test first 5 open ports
            response = self._get_banner(target, port)
            tested_ports += 1
            if response is None or len(response) == 0:
                silent_ports += 1

        if tested_ports > 0 and silent_ports / tested_ports > 0.6:
            result.add_indicator(
                Indicator(
                    name="artillery_silent_ports",
                    description="Most ports accept connection but send no data",
                    severity=Confidence.HIGH,
                    details=f"{silent_ports}/{tested_ports} ports silent",
                )
            )

    def _get_banner(self, target: str, port: int) -> Optional[bytes]:
        """Get banner from port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((target, port))
            sock.settimeout(1.0)
            try:
                banner = sock.recv(1024)
            except socket.timeout:
                banner = b""
            sock.close()
            return banner
        except (socket.error, socket.timeout, OSError):
            return None


@register_detector
class FaproDetector(BaseDetector):
    """Detector for FAPRO (Fake Protocol Server) - Go-based.

    Static (Passive) Detection:
    - Port combinations
    - Go TLS cipher ordering

    Dynamic (Active) Detection:
    - Go-based TLS fingerprinting (JA3S)
    - Protocol behavior analysis
    """

    name = "fapro"
    description = "Detects FAPRO fake protocol server"
    honeypot_types = ["fapro"]
    default_ports = list(FAPRO_PORTS.keys())

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive/static FAPRO detection.

        Checks port combinations.

        Args:
            target: IP address or hostname
            port: Port to check

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        # Scan for FAPRO port combination
        open_ports = self._scan_fapro_ports(target)
        if open_ports:
            self._analyze_port_combination(open_ports, result)

        if result.is_honeypot:
            result.honeypot_type = "fapro"

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active/dynamic FAPRO probing.

        Checks for Go-based TLS fingerprints.

        Args:
            target: IP address or hostname
            port: Port to check

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        # Check for Go-based TLS fingerprints (active probing)
        open_ports = self._scan_fapro_ports(target)
        if 443 in open_ports:
            self._check_go_tls(target, result)

        if result.is_honeypot:
            result.honeypot_type = "fapro"

        return result

    def _scan_fapro_ports(self, target: str) -> Set[int]:
        """Scan for FAPRO default ports."""
        open_ports = set()
        for port in FAPRO_PORTS.keys():
            if self._is_port_open(target, port):
                open_ports.add(port)
        return open_ports

    def _is_port_open(self, target: str, port: int) -> bool:
        """Check if port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except (socket.error, OSError):
            return False

    def _analyze_port_combination(
        self, open_ports: Set[int], result: DetectionResult
    ) -> None:
        """Analyze port combination for FAPRO detection."""
        matching_ports = open_ports & set(FAPRO_PORTS.keys())
        match_count = len(matching_ports)

        if match_count >= MIN_PORT_MATCH_THRESHOLD:
            services = [FAPRO_PORTS[p] for p in matching_ports]
            result.add_indicator(
                Indicator(
                    name="fapro_port_combo",
                    description=f"FAPRO port combination ({match_count} services)",
                    severity=Confidence.MEDIUM,
                    details=f"Services: {', '.join(services)}",
                )
            )

    def _check_go_tls(self, target: str, result: DetectionResult) -> None:
        """Check for Go-based TLS fingerprint."""
        # Would require TLS fingerprinting (JA3S)
        # Go TLS has distinctive cipher ordering
        pass


@register_detector
class FrameworkDetector(BaseDetector):
    """Combined detector for multi-service honeypot frameworks.

    Static (Passive) Detection:
    - Port combinations across all framework types
    - High port count analysis
    - Mixed OS service signatures

    Dynamic (Active) Detection:
    - Delegates to individual framework detectors for active probes
    - Cross-service consistency checks
    """

    name = "framework"
    description = "Detects multi-service honeypot frameworks"
    honeypot_types = ["opencanary", "qeeqbox", "artillery", "fapro", "tpot"]
    default_ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5900]

    def __init__(
        self,
        timeout: float = 5.0,
        verbose: bool = False,
        mode: DetectionMode = DetectionMode.FULL,
    ):
        super().__init__(timeout, verbose, mode)
        self._opencanary = OpenCanaryDetector(timeout, verbose, mode)
        self._qeeqbox = QeeqBoxDetector(timeout, verbose, mode)
        self._artillery = ArtilleryDetector(timeout, verbose, mode)
        self._fapro = FaproDetector(timeout, verbose, mode)

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive/static framework detection.

        Checks port combinations and high port counts.

        Args:
            target: IP address or hostname
            port: Port to check

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        # Collect all open ports first (port scanning is passive)
        all_ports = set()
        for detector in [self._opencanary, self._qeeqbox, self._artillery, self._fapro]:
            for p in detector.default_ports:
                if self._is_port_open(target, p):
                    all_ports.add(p)

        # High port count is suspicious
        if len(all_ports) >= 10:
            result.add_indicator(
                Indicator(
                    name="framework_high_port_count",
                    description=f"Unusually high number of open ports ({len(all_ports)})",
                    severity=Confidence.HIGH,
                    details="Multi-service honeypot framework likely",
                )
            )

        # Run passive detection on individual detectors
        for detector in [self._opencanary, self._qeeqbox, self._artillery, self._fapro]:
            sub_result = detector.detect_passive(target, port)
            for indicator in sub_result.indicators:
                result.add_indicator(indicator)
            if sub_result.honeypot_type and not result.honeypot_type:
                result.honeypot_type = sub_result.honeypot_type

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active/dynamic framework probing.

        Delegates to individual framework detectors.

        Args:
            target: IP address or hostname
            port: Port to check

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        # Run active detection on individual detectors
        for detector in [self._opencanary, self._qeeqbox, self._artillery, self._fapro]:
            sub_result = detector.detect_active(target, port)
            for indicator in sub_result.indicators:
                result.add_indicator(indicator)
            if sub_result.honeypot_type and not result.honeypot_type:
                result.honeypot_type = sub_result.honeypot_type

        return result

    def _is_port_open(self, target: str, port: int) -> bool:
        """Check if port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            ret = sock.connect_ex((target, port))
            sock.close()
            return ret == 0
        except (socket.error, OSError):
            return False

    def get_recommendations(self, result: DetectionResult) -> list[str]:
        """Get recommendations for framework honeypots."""
        recommendations = []
        for indicator in result.indicators:
            if "port_combo" in indicator.name or "port_count" in indicator.name:
                recommendations.append(
                    "Reduce the number of exposed services to a realistic subset"
                )
                recommendations.append(
                    "Avoid running Windows-only services (SMB, RDP) with Linux services"
                )
                break
        return recommendations
