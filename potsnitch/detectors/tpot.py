"""T-Pot multi-honeypot platform detector.

Detects T-Pot installations and individual honeypots from the T-Pot suite.
Based on analysis of https://github.com/telekom-security/tpotce
"""

import socket
from typing import Optional

from potsnitch.core.base import BaseDetector, DetectionMode, register_detector
from potsnitch.core.result import DetectionResult, Indicator, Confidence
from potsnitch.utils.network import scan_ports, get_banner


# T-Pot Standard edition default port configuration
TPOT_STANDARD_PORTS = {
    # Honeypot: [ports]
    "adbhoney": [5555],
    "beelzebub": [22, 80, 8080],
    "ciscoasa": [5000, 8443],
    "citrixhoneypot": [443],
    "conpot": [161, 623, 1025, 2404, 10001, 50100],
    "cowrie": [22, 23],
    "ddospot": [19, 53, 123, 1900],
    "dicompot": [104, 11112],
    "dionaea": [20, 21, 42, 69, 81, 135, 445, 1433, 1723, 1883, 3306, 27017],
    "elasticpot": [9200],
    "endlessh": [22],
    "galah": [80, 443, 8080],
    "glutton": [21, 22, 23, 25, 80],
    "go-pot": [8080],
    "h0neytr4p": [443],
    "hellpot": [80],
    "heralding": [110, 143, 465, 993, 995, 1080, 5432, 5900],
    "honeyaml": [3000],
    "honeypots": [21, 22, 23, 25, 80, 110, 143],
    "honeytrap": [21, 22, 23, 25, 80, 443],
    "ipphoney": [631],
    "log4pot": [8080],
    "mailoney": [25, 587],
    "medpot": [2575],
    "miniprint": [9100],
    "redishoneypot": [6379],
    "sentrypeer": [5060],
    "snare": [80],
    "wordpot": [8080],
}

# Heralding default banners across versions (from heralding.yml + source)
HERALDING_BANNERS = {
    "ftp": [
        b"Microsoft FTP Server",
        b"220 Microsoft FTP Server",
    ],
    "pop3": [
        b"+OK POP3 server ready",
    ],
    "pop3s": [
        b"+OK POP3 server ready",
    ],
    "imap": [
        b"* OK IMAP4rev1 Server Ready",
    ],
    "imaps": [
        b"* OK IMAP4rev1 Server Ready",
    ],
    "smtp": [
        b"Microsoft ESMTP MAIL service ready",
    ],
    "smtps": [
        b"Microsoft ESMTP MAIL service ready",
    ],
    "ssh": [
        b"SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.8",
    ],
    "http": [
        b"Microsoft-IIS/5.0",  # Default HTTP server header
    ],
}

# Elasticpot default values across versions
ELASTICPOT_DEFAULTS = {
    "instance_names": [
        "Green Goblin",   # Default in elasticpot.py
        "USNYES01",       # T-Pot default
    ],
    "cluster_names": [
        "elasticsearch",  # Default
    ],
    "versions": [
        "1.4.1",          # Default spoofed version
        "1.4.2",
        "2.4.6",
    ],
    "host_names": [
        "elk",            # Default
        "usnyes01",       # T-Pot default
    ],
}

# Other T-Pot honeypot signatures
TPOT_SIGNATURES = {
    # Redis honeypot default responses
    "redis": [b"-ERR unknown command", b"+PONG"],
    # Mailoney responses
    "mailoney": [b"220 ", b"schizo"],
    # ADBHoney
    "adbhoney": [b"CNXN"],
}


@register_detector
class TPotDetector(BaseDetector):
    """Detector for T-Pot honeypot platform and its components.

    Static (Passive) Detection:
    - T-Pot port combinations (24+ services)
    - Port 64297 (Kibana admin interface)
    - Heralding default banners
    - Docker container patterns

    Dynamic (Active) Detection:
    - Redis command probing
    - ADB connection testing
    - Protocol-specific handshakes (HL7, DICOM, SIP)
    - Log4Pot JNDI header probing
    """

    name = "tpot"
    description = "Detects T-Pot multi-honeypot platform installations"
    honeypot_types = [
        "tpot", "heralding", "mailoney", "redishoneypot", "adbhoney",
        "ipphoney", "miniprint", "medpot", "dicompot", "sentrypeer",
        "wordpot", "snare", "h0neytr4p", "honeyaml", "ciscoasa",
        "log4pot", "endlessh", "ddospot", "hellpot", "galah",
        "beelzebub", "citrixhoneypot", "glutton", "honeytrap"
    ]
    default_ports = [
        # High-value T-Pot specific ports
        631,    # IPP (ipphoney)
        2575,   # HL7 (medpot)
        5060,   # SIP (sentrypeer)
        5555,   # ADB (adbhoney)
        6379,   # Redis (redishoneypot)
        8443,   # Cisco ASA (ciscoasa)
        9100,   # Printer (miniprint)
        11112,  # DICOM (dicompot)
        19,     # Chargen (ddospot)
        1900,   # SSDP (ddospot)
    ]

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive/static T-Pot detection.

        Checks port patterns, banners, and static signatures without
        sending protocol-specific probe commands.

        Args:
            target: IP address or hostname
            port: Port to check

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        # Check for T-Pot Kibana admin interface port
        if port == 64297:
            result.add_indicator(
                Indicator(
                    name="tpot_kibana_port",
                    description="T-Pot Kibana admin interface port 64297",
                    severity=Confidence.HIGH,
                    details="Default T-Pot management interface",
                )
            )
            result.honeypot_type = "tpot"

        # Check for T-Pot-specific port combinations (static signature)
        if port in TPOT_STANDARD_PORTS.get("adbhoney", []):
            result.add_indicator(
                Indicator(
                    name="tpot_adb_port",
                    description="ADB port 5555 (T-Pot adbhoney target)",
                    severity=Confidence.MEDIUM,
                    details="Port commonly targeted by mirai variants",
                )
            )

        if port in TPOT_STANDARD_PORTS.get("medpot", []):
            result.add_indicator(
                Indicator(
                    name="tpot_hl7_port",
                    description="HL7 port 2575 (T-Pot medpot)",
                    severity=Confidence.HIGH,
                    details="Medical protocol on internet is very suspicious",
                )
            )

        if port in TPOT_STANDARD_PORTS.get("dicompot", []):
            result.add_indicator(
                Indicator(
                    name="tpot_dicom_port",
                    description="DICOM port (T-Pot dicompot)",
                    severity=Confidence.HIGH,
                    details="Medical imaging protocol on internet is very suspicious",
                )
            )

        # Check Heralding mail protocol banners (passive - just read banner)
        if port in (110, 143, 993, 995, 465):
            self._check_heralding_mail_passive(target, port, result)

        if result.is_honeypot and not result.honeypot_type:
            result.honeypot_type = "tpot"

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active/dynamic T-Pot probing.

        Sends protocol-specific commands and probes to elicit
        honeypot-specific responses.

        Args:
            target: IP address or hostname
            port: Port to check

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        # Active protocol probes based on port
        if port == 6379:
            self._check_redis(target, port, result)
        elif port == 5555:
            self._check_adb(target, port, result)
        elif port == 631:
            self._check_ipp(target, port, result)
        elif port == 9100:
            self._check_printer(target, port, result)
        elif port == 2575:
            self._check_medpot(target, port, result)
        elif port == 5060:
            self._check_sip(target, port, result)
        elif port == 11112 or port == 104:
            self._check_dicom(target, port, result)
        elif port == 8080:
            self._check_log4pot(target, port, result)
        elif port == 19:
            self._check_ddospot_chargen(target, port, result)
        elif port == 1900:
            self._check_ddospot_ssdp(target, port, result)

        return result

    def _check_heralding_mail_passive(self, target: str, port: int, result: DetectionResult) -> None:
        """Check for Heralding mail protocol banners (passive - just read banner)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            banner = sock.recv(1024)
            sock.close()

            banner_str = banner.decode('utf-8', errors='ignore').strip()

            # Check for Heralding default POP3 banners
            if any(b in banner for b in HERALDING_BANNERS["pop3"]):
                result.add_indicator(
                    Indicator(
                        name="heralding_pop3",
                        description="Heralding POP3 default banner detected",
                        severity=Confidence.HIGH,
                        details=f"Banner: {banner_str}",
                    )
                )
                result.honeypot_type = "heralding"
            # Check for Heralding default IMAP banners
            elif any(b in banner for b in HERALDING_BANNERS["imap"]):
                result.add_indicator(
                    Indicator(
                        name="heralding_imap",
                        description="Heralding IMAP default banner detected",
                        severity=Confidence.HIGH,
                        details=f"Banner: {banner_str}",
                    )
                )
                result.honeypot_type = "heralding"
            # Check for Heralding default SMTP banners
            elif any(b in banner for b in HERALDING_BANNERS["smtp"]):
                result.add_indicator(
                    Indicator(
                        name="heralding_smtp",
                        description="Heralding SMTP default banner detected",
                        severity=Confidence.HIGH,
                        details=f"Banner: {banner_str}",
                    )
                )
                result.honeypot_type = "heralding"

        except (socket.error, socket.timeout, OSError):
            pass

    def _check_redis(self, target: str, port: int, result: DetectionResult) -> None:
        """Check for Redis honeypot (redishoneypot)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Send PING command
            sock.send(b"PING\r\n")
            response = sock.recv(1024)
            sock.close()

            if b"+PONG" in response:
                # Try an invalid command to check behavior
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((target, port))
                sock.send(b"CONFIG GET *\r\n")
                response2 = sock.recv(1024)
                sock.close()

                # Real Redis returns config, honeypot may not
                if b"-ERR" in response2 or len(response2) < 50:
                    result.add_indicator(
                        Indicator(
                            name="redis_honeypot",
                            description="Redis honeypot detected (limited command support)",
                            severity=Confidence.HIGH,
                        )
                    )
                    result.honeypot_type = "redishoneypot"

        except (socket.error, socket.timeout, OSError):
            pass

    def _check_adb(self, target: str, port: int, result: DetectionResult) -> None:
        """Check for ADB honeypot (adbhoney)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # ADB connect message
            # Real ADB requires proper handshake
            sock.send(b"CNXN\x00\x00\x00\x01\x00\x10\x00\x00")
            response = sock.recv(1024)
            sock.close()

            if response:
                result.add_indicator(
                    Indicator(
                        name="adb_honeypot",
                        description="ADB service on port 5555 (possible adbhoney)",
                        severity=Confidence.MEDIUM,
                        details="Port 5555 ADB exposure is common honeypot target",
                    )
                )
                result.honeypot_type = "adbhoney"

        except (socket.error, socket.timeout, OSError):
            pass

    def _check_ipp(self, target: str, port: int, result: DetectionResult) -> None:
        """Check for IPP honeypot (ipphoney)."""
        try:
            import requests

            # IPP uses HTTP-like protocol
            response = requests.post(
                f"http://{target}:{port}/",
                headers={"Content-Type": "application/ipp"},
                data=b"\x01\x01\x00\x0b",  # IPP Get-Printer-Attributes
                timeout=self.timeout,
            )

            if response.status_code in (200, 400):
                result.add_indicator(
                    Indicator(
                        name="ipp_honeypot",
                        description="IPP/Printer service on port 631 (possible ipphoney)",
                        severity=Confidence.MEDIUM,
                    )
                )
                result.honeypot_type = "ipphoney"

        except Exception:
            pass

    def _check_printer(self, target: str, port: int, result: DetectionResult) -> None:
        """Check for printer honeypot (miniprint)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Send PJL command
            sock.send(b"\x1b%-12345X@PJL INFO ID\r\n")
            response = sock.recv(1024)
            sock.close()

            if response:
                result.add_indicator(
                    Indicator(
                        name="printer_honeypot",
                        description="Printer/JetDirect service on port 9100 (possible miniprint)",
                        severity=Confidence.MEDIUM,
                    )
                )
                result.honeypot_type = "miniprint"

        except (socket.error, socket.timeout, OSError):
            pass

    def _check_medpot(self, target: str, port: int, result: DetectionResult) -> None:
        """Check for medical honeypot (medpot - HL7)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # HL7 message starts with 0x0b
            sock.send(b"\x0bMSH|^~\\&|TEST\r\x1c\r")
            response = sock.recv(1024)
            sock.close()

            if response:
                result.add_indicator(
                    Indicator(
                        name="hl7_honeypot",
                        description="HL7 medical protocol on port 2575 (possible medpot)",
                        severity=Confidence.HIGH,
                        details="HL7 on internet is very suspicious - likely honeypot",
                    )
                )
                result.honeypot_type = "medpot"

        except (socket.error, socket.timeout, OSError):
            pass

    def _check_sip(self, target: str, port: int, result: DetectionResult) -> None:
        """Check for SIP honeypot (sentrypeer)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            # SIP OPTIONS request
            sip_options = (
                b"OPTIONS sip:test@" + target.encode() + b" SIP/2.0\r\n"
                b"Via: SIP/2.0/UDP scanner:5060\r\n"
                b"From: <sip:scanner@scanner>\r\n"
                b"To: <sip:test@" + target.encode() + b">\r\n"
                b"Call-ID: test123@scanner\r\n"
                b"CSeq: 1 OPTIONS\r\n"
                b"Max-Forwards: 70\r\n"
                b"\r\n"
            )

            sock.sendto(sip_options, (target, port))
            response, _ = sock.recvfrom(2048)
            sock.close()

            if b"SIP/2.0" in response:
                result.add_indicator(
                    Indicator(
                        name="sip_honeypot",
                        description="SIP service responding (possible sentrypeer)",
                        severity=Confidence.MEDIUM,
                    )
                )
                result.honeypot_type = "sentrypeer"

        except (socket.error, socket.timeout, OSError):
            pass

    def _check_dicom(self, target: str, port: int, result: DetectionResult) -> None:
        """Check for DICOM honeypot (dicompot)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # DICOM A-ASSOCIATE-RQ
            # This is a simplified probe
            sock.send(b"\x01\x00")  # PDU type
            response = sock.recv(1024)
            sock.close()

            if response:
                result.add_indicator(
                    Indicator(
                        name="dicom_honeypot",
                        description="DICOM service on internet (possible dicompot)",
                        severity=Confidence.HIGH,
                        details="DICOM/PACS on internet is very unusual - likely honeypot",
                    )
                )
                result.honeypot_type = "dicompot"

        except (socket.error, socket.timeout, OSError):
            pass

    def _check_log4pot(self, target: str, port: int, result: DetectionResult) -> None:
        """Check for Log4j/Log4Pot honeypot."""
        try:
            import requests

            # Log4Pot responds to HTTP requests on 8080
            # Send request with JNDI lookup pattern in headers
            headers = {
                "User-Agent": "${jndi:ldap://test/a}",
                "X-Api-Version": "${jndi:ldap://test/a}",
            }
            response = requests.get(
                f"http://{target}:{port}/",
                headers=headers,
                timeout=self.timeout,
            )

            # Log4Pot serves static HTML (SAP NetWeaver by default in T-Pot)
            if response.status_code == 200:
                content = response.text.lower()
                # T-Pot log4pot uses SAP NetWeaver response by default
                if "sap" in content or "netweaver" in content:
                    result.add_indicator(
                        Indicator(
                            name="log4pot_sap",
                            description="Log4Pot honeypot with SAP NetWeaver response",
                            severity=Confidence.HIGH,
                            details="T-Pot default log4pot response page",
                        )
                    )
                    result.honeypot_type = "log4pot"
                # Check for minimal HTTP response (common for log4j honeypots)
                elif len(content) < 1000:
                    result.add_indicator(
                        Indicator(
                            name="log4pot_minimal",
                            description="Minimal HTTP response on port 8080 (possible log4pot)",
                            severity=Confidence.MEDIUM,
                        )
                    )

        except Exception:
            pass

    def _check_ddospot_chargen(self, target: str, port: int, result: DetectionResult) -> None:
        """Check for DDOSPot chargen amplification honeypot."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            # Send UDP packet to chargen service
            sock.sendto(b"\x00", (target, port))
            response, _ = sock.recvfrom(2048)
            sock.close()

            if response:
                # Chargen should return character stream
                result.add_indicator(
                    Indicator(
                        name="ddospot_chargen",
                        description="Chargen service on port 19 (possible ddospot)",
                        severity=Confidence.HIGH,
                        details="Chargen exposed to internet is unusual - likely honeypot",
                    )
                )
                result.honeypot_type = "ddospot"

        except (socket.error, socket.timeout, OSError):
            pass

    def _check_ddospot_ssdp(self, target: str, port: int, result: DetectionResult) -> None:
        """Check for DDOSPot SSDP amplification honeypot."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            # SSDP M-SEARCH request
            ssdp_request = (
                b"M-SEARCH * HTTP/1.1\r\n"
                b"HOST: 239.255.255.250:1900\r\n"
                b"MAN: \"ssdp:discover\"\r\n"
                b"MX: 1\r\n"
                b"ST: upnp:rootdevice\r\n"
                b"\r\n"
            )
            sock.sendto(ssdp_request, (target, port))
            response, _ = sock.recvfrom(2048)
            sock.close()

            if b"HTTP/1.1 200 OK" in response:
                result.add_indicator(
                    Indicator(
                        name="ddospot_ssdp",
                        description="SSDP service responding on port 1900 (possible ddospot)",
                        severity=Confidence.HIGH,
                        details="SSDP exposed to internet is common DDoS amplification target",
                    )
                )
                result.honeypot_type = "ddospot"

        except (socket.error, socket.timeout, OSError):
            pass

    def validate(self, target: str, port: int) -> DetectionResult:
        """Comprehensive T-Pot validation scan."""
        result = self.detect(target, port)

        # Scan for T-Pot port signature
        all_tpot_ports = []
        for ports in TPOT_STANDARD_PORTS.values():
            all_tpot_ports.extend(ports)
        all_tpot_ports = list(set(all_tpot_ports))

        open_ports = scan_ports(target, all_tpot_ports, timeout=self.timeout)

        if len(open_ports) >= 10:
            result.add_indicator(
                Indicator(
                    name="tpot_port_signature",
                    description=f"T-Pot-like port configuration ({len(open_ports)} matching ports)",
                    severity=Confidence.HIGH,
                    details=f"Open ports: {open_ports[:10]}...",
                )
            )
            result.honeypot_type = "tpot"

        # Check for specific T-Pot port combinations
        tpot_specific = {5555, 631, 2575, 9100, 11112}
        matches = tpot_specific & set(open_ports)
        if len(matches) >= 2:
            result.add_indicator(
                Indicator(
                    name="tpot_unique_services",
                    description=f"Multiple T-Pot-specific services: {matches}",
                    severity=Confidence.HIGH,
                    details="ADB, IPP, HL7, Printer, DICOM are T-Pot specialties",
                )
            )

        return result

    def get_recommendations(self, result: DetectionResult) -> list[str]:
        """Get remediation recommendations for T-Pot."""
        recommendations = []

        for indicator in result.indicators:
            if "heralding" in indicator.name:
                recommendations.append(
                    "Customize Heralding banners in /etc/heralding/heralding.yml"
                )
            elif "tpot_port" in indicator.name:
                recommendations.append(
                    "Disable unused honeypots in docker-compose.yml to reduce fingerprint"
                )
            elif "redis" in indicator.name:
                recommendations.append(
                    "Implement more Redis commands in redishoneypot"
                )

        return recommendations
