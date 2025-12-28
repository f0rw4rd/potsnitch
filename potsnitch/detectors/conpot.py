"""Conpot ICS/SCADA honeypot detector.

Detection is split into:
- PASSIVE: Multi-port fingerprinting, known port combinations (102, 502, 47808, 80, 161, 623)
- ACTIVE: S7Comm probing, Modbus device ID queries, SNMP queries, BACnet Who-Is, HTTP requests
"""

import socket
import struct
from typing import Optional

from potsnitch.core.base import BaseDetector, DetectionMode, register_detector
from potsnitch.core.result import DetectionResult, Indicator, Confidence


# Conpot default S7Comm values across versions (from template.xml)
CONPOT_S7_SIGNATURES = {
    # SystemName defaults
    "system_names": [
        b"Technodrome",      # Default template
        b"S7-200",
        b"SIMATIC",
    ],
    # FacilityName/PlantName defaults
    "facility_names": [
        b"Mouser",           # Short form
        b"Mouser Factory",   # Full form from template.xml
    ],
    # Serial numbers (s7_id)
    "serials": [
        b"88111222",         # Default from template.xml
    ],
    # sysLocation defaults
    "locations": [
        b"Venus",            # Default from template.xml
    ],
    # Module types
    "module_types": [
        b"IM151-8 PN/DP CPU",
        b"CPU 315-2 PN/DP",
    ],
    # sysContact
    "contacts": [
        b"Siemens AG",
    ],
}

# Default Conpot Modbus device ID across versions
CONPOT_MODBUS_SIGNATURES = {
    "vendor_names": [
        "Siemens",
    ],
    "product_codes": [
        "SIMATIC",
    ],
    "revisions": [
        "S7-200",
        "S7-300",
        "S7-400",
    ],
    "descriptions": [
        "Siemens, SIMATIC, S7-200",
    ],
}

# Conpot SNMP defaults
CONPOT_SNMP_SIGNATURES = {
    "sysName": [
        "CP 443-1 EX40",
    ],
    "sysLocation": [
        "Venus",
    ],
    "sysContact": [
        "Siemens AG",
    ],
}


# Known Conpot default port combinations - ICS honeypots expose multiple protocols
CONPOT_DEFAULT_PORTS = [102, 502, 47808, 80, 161, 623]


@register_detector
class ConpotDetector(BaseDetector):
    """Detector for Conpot ICS/SCADA honeypot.

    Static (Passive) Detection:
    - Default port combinations (102, 502, 47808, 80, 161, 623)
    - Port 102 (S7Comm), 502 (Modbus) presence check
    - Known default template values in responses

    Dynamic (Active) Detection:
    - S7Comm protocol probing with SZL requests
    - Modbus device identification queries
    - SNMP sysDescr queries
    - BACnet Who-Is broadcasts
    - HTTP requests to web interface
    """

    name = "conpot"
    description = "Detects Conpot ICS/SCADA honeypot via Modbus, S7, and multi-protocol analysis"
    honeypot_types = ["conpot"]
    default_ports = [80, 102, 161, 502, 623, 47808]

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive/static Conpot detection.

        Checks for known port combinations and static signatures
        without deep protocol probing.

        Args:
            target: IP address or hostname
            port: Port number

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        # Check for typical Conpot port combinations (static indicator)
        self._check_port_combination(target, result)

        # Check for default ICS ports
        if port == 102:
            result.add_indicator(
                Indicator(
                    name="s7comm_port",
                    description="S7Comm port 102 open (common Conpot protocol)",
                    severity=Confidence.LOW,
                )
            )
        elif port == 502:
            result.add_indicator(
                Indicator(
                    name="modbus_port",
                    description="Modbus port 502 open (common Conpot protocol)",
                    severity=Confidence.LOW,
                )
            )
        elif port == 47808:
            result.add_indicator(
                Indicator(
                    name="bacnet_port",
                    description="BACnet port 47808 open (common Conpot protocol)",
                    severity=Confidence.LOW,
                )
            )

        if result.is_honeypot:
            result.honeypot_type = "conpot"

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active/dynamic Conpot probing.

        Performs protocol-specific queries to identify honeypot
        signatures in responses.

        Args:
            target: IP address or hostname
            port: Port number

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        if port == 102:
            self._check_s7comm(target, port, result)
        elif port == 502:
            self._check_modbus(target, port, result)
        elif port == 161:
            self._check_snmp(target, port, result)
        elif port == 80:
            self._check_http(target, port, result)
        elif port == 47808:
            self._check_bacnet(target, port, result)

        if result.is_honeypot:
            result.honeypot_type = "conpot"

        return result

    def _check_port_combination(self, target: str, result: DetectionResult) -> None:
        """Check for typical Conpot multi-port exposure.

        Real ICS devices rarely expose multiple protocols to the same IP.
        Conpot commonly exposes S7, Modbus, BACnet, HTTP, and SNMP together.
        """
        from potsnitch.utils.network import is_port_open

        open_ports = []
        for port in CONPOT_DEFAULT_PORTS:
            if is_port_open(target, port, self.timeout):
                open_ports.append(port)

        if len(open_ports) >= 3:
            result.add_indicator(
                Indicator(
                    name="conpot_port_combination",
                    description=f"Multiple ICS ports open: {open_ports}",
                    severity=Confidence.HIGH,
                    details="Real ICS devices rarely expose multiple protocols to same IP",
                )
            )
        elif len(open_ports) >= 2:
            result.add_indicator(
                Indicator(
                    name="multi_ics_ports",
                    description=f"Two ICS ports open: {open_ports}",
                    severity=Confidence.MEDIUM,
                    details="Multiple ICS protocols may indicate honeypot",
                )
            )

    def _check_s7comm(self, target: str, port: int, result: DetectionResult) -> None:
        """Check S7Comm protocol for Conpot signatures."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # COTP Connection Request
            cotp_cr = bytes([
                0x03, 0x00,  # TPKT Version, Reserved
                0x00, 0x16,  # Length
                0x11,        # COTP length
                0xe0,        # COTP PDU Type: CR
                0x00, 0x00,  # Destination reference
                0x00, 0x01,  # Source reference
                0x00,        # Class
                0xc0, 0x01, 0x0a,  # Parameter: tpdu-size
                0xc1, 0x02, 0x01, 0x00,  # Parameter: src-tsap
                0xc2, 0x02, 0x01, 0x02,  # Parameter: dst-tsap
            ])

            sock.send(cotp_cr)
            response = sock.recv(1024)

            if len(response) < 7:
                sock.close()
                return

            # Send S7Comm setup communication request
            s7_setup = bytes([
                0x03, 0x00, 0x00, 0x19,  # TPKT
                0x02, 0xf0, 0x80,         # COTP DT
                0x32,                     # S7Comm protocol ID
                0x01,                     # ROSCTR: Job
                0x00, 0x00,               # Redundancy identification
                0x00, 0x00,               # Protocol data unit reference
                0x00, 0x08,               # Parameter length
                0x00, 0x00,               # Data length
                0xf0,                     # Function: Setup communication
                0x00,                     # Reserved
                0x00, 0x01,               # Max AmQ calling
                0x00, 0x01,               # Max AmQ called
                0x01, 0xe0,               # PDU length
            ])

            sock.send(s7_setup)
            response = sock.recv(1024)

            # Now request CPU info (SZL)
            szl_request = bytes([
                0x03, 0x00, 0x00, 0x21,  # TPKT
                0x02, 0xf0, 0x80,         # COTP DT
                0x32,                     # S7Comm protocol ID
                0x07,                     # ROSCTR: Userdata
                0x00, 0x00,               # Redundancy identification
                0x00, 0x01,               # Protocol data unit reference
                0x00, 0x08,               # Parameter length
                0x00, 0x08,               # Data length
                0x00, 0x01, 0x12,         # Parameter head
                0x04,                     # Parameter length
                0x11,                     # Type request
                0x44,                     # Function group: CPU
                0x01,                     # Subfunction: Read SZL
                0x00,                     # Sequence number
                0xff,                     # Return code
                0x09,                     # Transport size
                0x00, 0x04,               # Data length
                0x00, 0x1c,               # SZL-ID: Component identification
                0x00, 0x00,               # SZL-Index
            ])

            sock.send(szl_request)
            response = sock.recv(2048)
            sock.close()

            # Check for Conpot default values in response
            for category, signatures in CONPOT_S7_SIGNATURES.items():
                for sig in signatures:
                    if sig in response:
                        result.add_indicator(
                            Indicator(
                                name="conpot_s7_signature",
                                description=f"Conpot default S7 {category}: {sig.decode()}",
                                severity=Confidence.DEFINITE,
                            )
                        )

        except (socket.error, socket.timeout, OSError):
            pass

    def _check_modbus(self, target: str, port: int, result: DetectionResult) -> None:
        """Check Modbus TCP for Conpot signatures."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Modbus Read Device Identification (function code 43, MEI type 14)
            # Transaction ID (2) + Protocol ID (2) + Length (2) + Unit ID (1) + FC (1) + MEI (1) + Read Device ID (1) + Object ID (1)
            modbus_request = bytes([
                0x00, 0x01,  # Transaction ID
                0x00, 0x00,  # Protocol ID (Modbus)
                0x00, 0x05,  # Length
                0x01,        # Unit ID
                0x2b,        # Function code 43 (Read Device Identification)
                0x0e,        # MEI Type: Read Device Identification
                0x01,        # Read Device ID code: Basic
                0x00,        # Object ID: Vendor Name
            ])

            sock.send(modbus_request)
            response = sock.recv(1024)
            sock.close()

            if len(response) < 9:
                # Conpot may disconnect on malformed/unsupported requests
                result.add_indicator(
                    Indicator(
                        name="modbus_disconnect",
                        description="Server disconnected on Modbus device ID request",
                        severity=Confidence.MEDIUM,
                        details="Conpot disconnects instead of responding to some requests",
                    )
                )
                return

            # Parse response for device identification
            response_str = response.decode("ascii", errors="ignore")
            for category, signatures in CONPOT_MODBUS_SIGNATURES.items():
                for sig in signatures:
                    if sig in response_str:
                        result.add_indicator(
                            Indicator(
                                name="conpot_modbus_signature",
                                description=f"Conpot default Modbus {category}: {sig}",
                                severity=Confidence.HIGH,
                            )
                        )

        except (socket.error, socket.timeout, OSError) as e:
            if "Connection reset" in str(e) or "Connection refused" not in str(e):
                result.add_indicator(
                    Indicator(
                        name="modbus_connection_reset",
                        description="Modbus connection reset (possible Conpot)",
                        severity=Confidence.LOW,
                    )
                )

    def _check_snmp(self, target: str, port: int, result: DetectionResult) -> None:
        """Check SNMP for Conpot signatures."""
        try:
            # SNMP Get Request for sysDescr.0 (1.3.6.1.2.1.1.1.0)
            snmp_get = bytes([
                0x30, 0x29,  # Sequence, length
                0x02, 0x01, 0x00,  # Version: SNMPv1
                0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,  # Community: public
                0xa0, 0x1c,  # GetRequest-PDU
                0x02, 0x04, 0x00, 0x00, 0x00, 0x01,  # Request ID
                0x02, 0x01, 0x00,  # Error status
                0x02, 0x01, 0x00,  # Error index
                0x30, 0x0e,  # Varbind list
                0x30, 0x0c,  # Varbind
                0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,  # OID: sysDescr.0
                0x05, 0x00,  # Null value
            ])

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(snmp_get, (target, port))
            response, _ = sock.recvfrom(1024)
            sock.close()

            # Check for Siemens S7-200 in SNMP response
            response_str = response.decode("ascii", errors="ignore")
            if "S7-200" in response_str or "Siemens" in response_str:
                result.add_indicator(
                    Indicator(
                        name="conpot_snmp_signature",
                        description="Siemens S7-200 SNMP sysDescr (default Conpot)",
                        severity=Confidence.HIGH,
                    )
                )

        except (socket.error, socket.timeout, OSError):
            pass

    def _check_http(self, target: str, port: int, result: DetectionResult) -> None:
        """Check HTTP for Conpot web interface signatures."""
        try:
            import requests

            url = f"http://{target}:{port}/"
            response = requests.get(url, timeout=self.timeout)

            # Conpot default web interface markers
            if "Siemens" in response.text or "S7-200" in response.text:
                result.add_indicator(
                    Indicator(
                        name="conpot_http_signature",
                        description="Conpot web interface detected (Siemens reference)",
                        severity=Confidence.MEDIUM,
                    )
                )

        except Exception:
            pass

    def _check_bacnet(self, target: str, port: int, result: DetectionResult) -> None:
        """Check BACnet for Conpot signatures."""
        try:
            # BACnet Who-Is request
            bacnet_whois = bytes([
                0x81,  # Type: BACnet/IP
                0x0b,  # Function: Original-Broadcast-NPDU
                0x00, 0x0c,  # Length
                0x01,  # Version
                0x20,  # Control (expecting reply)
                0xff, 0xff,  # DNET: broadcast
                0x00,  # DLEN
                0xff,  # Hop count
                0x10, 0x08,  # APDU: Unconfirmed Who-Is
            ])

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(bacnet_whois, (target, port))

            response, _ = sock.recvfrom(1024)
            sock.close()

            if response:
                # Any response on this port indicates BACnet is running
                # Conpot commonly runs BACnet alongside other ICS protocols
                result.add_indicator(
                    Indicator(
                        name="bacnet_response",
                        description="BACnet service responding",
                        severity=Confidence.LOW,
                        details="Multiple ICS protocols on same host may indicate honeypot",
                    )
                )

        except (socket.error, socket.timeout, OSError):
            pass

    def validate(self, target: str, port: int) -> DetectionResult:
        """Run comprehensive validation including multi-port check."""
        result = self.detect(target, port)

        # Check for multiple ICS ports open (strong honeypot indicator)
        from potsnitch.utils.network import scan_ports

        ics_ports = [102, 502, 161, 47808, 623]
        open_ports = scan_ports(target, ics_ports, timeout=self.timeout)

        if len(open_ports) >= 3:
            result.add_indicator(
                Indicator(
                    name="multi_ics_ports",
                    description=f"Multiple ICS ports open: {open_ports}",
                    severity=Confidence.HIGH,
                    details="Real ICS devices rarely expose multiple protocols to same IP",
                )
            )

        return result

    def get_recommendations(self, result: DetectionResult) -> list[str]:
        """Get remediation recommendations for Conpot."""
        recommendations = []

        for indicator in result.indicators:
            if "s7_signature" in indicator.name:
                recommendations.append(
                    "Modify templates/default.xml to change PLC Name, Plant ID, and Serial Number"
                )
            elif "modbus" in indicator.name:
                recommendations.append(
                    "Customize Modbus device identification in conpot.cfg"
                )
            elif "multi_ics" in indicator.name:
                recommendations.append(
                    "Consider exposing only protocols relevant to your threat model"
                )

        return recommendations
