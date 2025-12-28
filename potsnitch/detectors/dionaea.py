"""Dionaea honeypot detector (SMB, FTP, HTTP).

Detection is split into:
- PASSIVE: FTP/SMTP banners received on connect, static SMB signatures in negotiate
- ACTIVE: HTTP requests, MS-SQL probing, deep SMB session probing
"""

import socket
import struct
from typing import Optional

from potsnitch.core.base import BaseDetector, DetectionMode, register_detector
from potsnitch.core.result import DetectionResult, Indicator, Confidence


# Dionaea default SMB values across versions
DIONAEA_SMB_SIGNATURES = {
    # OemDomainName defaults
    "domains": ["WORKGROUP", "MSHOME"],
    # ServerName defaults
    "servers": [
        "HOMEUSER-3AF6FE",  # Default in smbfields.py
        "VENUS",
        "COMPUTER",
    ],
    # NativeOS defaults (indicates emulated Windows version)
    "native_os": [
        "Windows 5.1",      # Windows XP (default)
        "Windows 6.1",      # Windows 7
        "Windows Server 2003",
        "Windows",
    ],
    # NativeLanManager defaults
    "lan_manager": [
        "Windows 2000 LAN Manager",
        "Windows Server 2003 5.2",
    ],
}

# Dionaea default values (for backward compatibility)
DIONAEA_DEFAULT_WORKGROUP = "WORKGROUP"
DIONAEA_DEFAULT_SERVER = "HOMEUSER-3AF6FE"

# Known FTP honeypot banners across versions (from checkpot + honeyscanner + source)
KNOWN_FTP_BANNERS = {
    # Dionaea banners (various versions)
    b'220 DiskStation FTP server ready.\r\n': "dionaea",
    b'220 DiskStation FTP server ready': "dionaea",
    b'220 Welcome to the ftp service\r\n': "dionaea",
    b'220 Welcome to the ftp service': "dionaea",
    b'220 Service ready\r\n': "dionaea",
    # Amun banners
    b'220 Welcome to my FTP Server\r\n': "amun",
    b'220 Welcome to my FTP Server': "amun",
    # BearTrap banners
    b'220 BearTrap-ftpd Service ready\r\n': "beartrap",
    # Nepenthes banners
    b'220 Nepenthes FTP server ready': "nepenthes",
    # Generic suspicious
    b'220 FTP Server ready\r\n': "generic-honeypot",
}

# Known SMTP honeypot banners across versions (from checkpot + source)
KNOWN_SMTP_BANNERS = {
    b'220 mail.example.com SMTP Mailserver\r\n': "amun",
    b'220 localhost SMTP Mailserver\r\n': "dionaea",
    b'220 Microsoft ESMTP MAIL service ready': "heralding",
}


@register_detector
class DionaeaDetector(BaseDetector):
    """Detector for Dionaea honeypot.

    Static (Passive) Detection:
    - FTP banners received on connect
    - SMTP banners received on connect
    - SMB negotiate response signatures (OemDomainName, ServerName)

    Dynamic (Active) Detection:
    - HTTP requests and header analysis
    - MS-SQL TDS protocol probing
    - Deep SMB session establishment
    """

    name = "dionaea"
    description = "Detects Dionaea honeypot via SMB, FTP, and HTTP fingerprinting"
    honeypot_types = ["dionaea"]
    default_ports = [21, 80, 443, 445, 1433, 3306, 5060, 5061]

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive/static Dionaea detection.

        Analyzes banners and responses received immediately on connect
        without sending probing commands.

        Args:
            target: IP address or hostname
            port: Port number

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        if port == 445:
            self._check_smb_passive(target, port, result)
        elif port == 21:
            self._check_ftp(target, port, result)
        elif port == 25:
            self._check_smtp(target, port, result)

        if result.is_honeypot:
            result.honeypot_type = "dionaea"

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active/dynamic Dionaea probing.

        Sends specific requests and analyzes responses to identify
        honeypot behavior patterns.

        Args:
            target: IP address or hostname
            port: Port number

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        if port == 445:
            self._check_smb_active(target, port, result)
        elif port in (80, 443):
            self._check_http(target, port, result)
        elif port == 1433:
            self._check_mssql(target, port, result)

        if result.is_honeypot:
            result.honeypot_type = "dionaea"

        return result

    def _check_smb_passive(self, target: str, port: int, result: DetectionResult) -> None:
        """Check SMB negotiate response for Dionaea signatures (passive).

        This sends a minimal SMB negotiate request and analyzes the
        response for static signatures. The negotiate is necessary
        to receive any SMB data.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Send SMB negotiate request (minimal required to get response)
            negotiate = self._build_smb_negotiate()
            sock.send(negotiate)

            # Read response
            response = sock.recv(2048)
            sock.close()

            if len(response) < 36:
                return

            # Parse SMB response for static signatures
            self._parse_smb_response(response, result)

        except (socket.error, socket.timeout, OSError):
            pass

    def _check_smb_active(self, target: str, port: int, result: DetectionResult) -> None:
        """Check SMB service with active probing (session setup).

        Performs deeper SMB protocol probing beyond negotiate
        to identify honeypot behavior.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Send SMB negotiate request
            negotiate = self._build_smb_negotiate()
            sock.send(negotiate)

            # Read negotiate response
            response = sock.recv(2048)

            if len(response) < 36:
                sock.close()
                return

            # Check if SMB2/3 is offered (Dionaea typically only does SMB1)
            # Real Windows systems prefer SMB2/3
            if response[4:8] != b"\xffSMB":
                # Not SMB1 response, skip
                sock.close()
                return

            # Try SMB session setup - Dionaea's implementation is limited
            session_setup = self._build_smb_session_setup()
            sock.send(session_setup)

            session_response = sock.recv(2048)
            sock.close()

            # Dionaea may have limited session handling
            if len(session_response) < 36:
                result.add_indicator(
                    Indicator(
                        name="smb_limited_session",
                        description="Limited SMB session response (possible Dionaea)",
                        severity=Confidence.MEDIUM,
                    )
                )

        except (socket.error, socket.timeout, OSError):
            pass

    def _build_smb_session_setup(self) -> bytes:
        """Build SMB1 session setup request."""
        # NetBIOS session header
        netbios = b"\x00"

        # SMB header
        smb_header = b"\xffSMB"  # Protocol
        smb_header += b"\x73"  # Command: Session Setup AndX
        smb_header += b"\x00\x00\x00\x00"  # NT Status
        smb_header += b"\x18"  # Flags
        smb_header += b"\x53\xc0"  # Flags2
        smb_header += b"\x00" * 12  # Various fields
        smb_header += b"\x00\x00"  # TID
        smb_header += b"\x00\x00"  # PID
        smb_header += b"\x00\x00"  # UID
        smb_header += b"\x01\x00"  # MID

        # Session setup request (minimal)
        word_count = b"\x0d"  # 13 words
        andx_command = b"\xff"  # No further commands
        reserved = b"\x00"
        andx_offset = b"\x00\x00"
        max_buffer = b"\x04\x11"  # Max buffer size
        max_mpx = b"\x32\x00"  # Max multiplexed pending requests
        vc_number = b"\x00\x00"  # VC number
        session_key = b"\x00\x00\x00\x00"  # Session key
        oem_password_len = b"\x01\x00"  # OEM password length
        unicode_password_len = b"\x00\x00"  # Unicode password length
        reserved2 = b"\x00\x00\x00\x00"
        capabilities = b"\xd4\x00\x00\x00"

        words = (andx_command + reserved + andx_offset + max_buffer +
                 max_mpx + vc_number + session_key + oem_password_len +
                 unicode_password_len + reserved2 + capabilities)

        # Byte data (minimal)
        byte_count = b"\x01\x00"
        byte_data = b"\x00"  # Null password

        smb_data = word_count + words + byte_count + byte_data
        smb_message = smb_header + smb_data

        # Add NetBIOS length
        length = struct.pack(">I", len(smb_message))[1:]  # 3 bytes
        return netbios + length + smb_message

    def _check_smtp(self, target: str, port: int, result: DetectionResult) -> None:
        """Check SMTP service for honeypot signatures (passive)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # SMTP sends banner on connect
            banner_raw = sock.recv(1024)
            sock.close()

            # Check for exact known honeypot banners
            for known_banner, honeypot_name in KNOWN_SMTP_BANNERS.items():
                if banner_raw.startswith(known_banner) or known_banner in banner_raw:
                    result.add_indicator(
                        Indicator(
                            name="known_smtp_banner",
                            description=f"Known {honeypot_name} SMTP banner detected",
                            severity=Confidence.DEFINITE,
                            details=f"Banner: {banner_raw.decode('utf-8', errors='ignore').strip()}",
                        )
                    )
                    result.honeypot_type = honeypot_name
                    return

        except (socket.error, socket.timeout, OSError):
            pass

    def _build_smb_negotiate(self) -> bytes:
        """Build SMB1 negotiate protocol request."""
        # NetBIOS session header
        netbios = b"\x00"  # Message type
        # Length will be added later

        # SMB header
        smb_header = b"\xffSMB"  # Protocol
        smb_header += b"\x72"  # Command: Negotiate
        smb_header += b"\x00\x00\x00\x00"  # NT Status
        smb_header += b"\x18"  # Flags
        smb_header += b"\x53\xc0"  # Flags2
        smb_header += b"\x00" * 12  # Various fields
        smb_header += b"\x00\x00"  # TID
        smb_header += b"\x00\x00"  # PID
        smb_header += b"\x00\x00"  # UID
        smb_header += b"\x00\x00"  # MID

        # Negotiate request
        dialects = b"\x02NT LM 0.12\x00"
        word_count = b"\x00"
        byte_count = struct.pack("<H", len(dialects))

        smb_data = word_count + byte_count + dialects
        smb_message = smb_header + smb_data

        # Add NetBIOS length
        length = struct.pack(">I", len(smb_message))[1:]  # 3 bytes
        return netbios + length + smb_message

    def _parse_smb_response(self, response: bytes, result: DetectionResult) -> None:
        """Parse SMB negotiate response for Dionaea signatures."""
        # Look for domain/workgroup name in response
        try:
            # Search for typical Dionaea defaults in response
            response_str = response.decode("utf-16-le", errors="ignore")

            if DIONAEA_DEFAULT_SERVER in response_str:
                result.add_indicator(
                    Indicator(
                        name="dionaea_servername",
                        description=f"Default Dionaea server name: {DIONAEA_DEFAULT_SERVER}",
                        severity=Confidence.DEFINITE,
                    )
                )

            if DIONAEA_DEFAULT_WORKGROUP in response_str:
                result.add_indicator(
                    Indicator(
                        name="dionaea_workgroup",
                        description="Default Dionaea workgroup 'WORKGROUP'",
                        severity=Confidence.LOW,  # WORKGROUP is also a Windows default
                    )
                )

        except Exception:
            pass

        # Check for ASCII version
        response_ascii = response.decode("ascii", errors="ignore")
        if DIONAEA_DEFAULT_SERVER in response_ascii:
            result.add_indicator(
                Indicator(
                    name="dionaea_servername",
                    description=f"Default Dionaea server name: {DIONAEA_DEFAULT_SERVER}",
                    severity=Confidence.DEFINITE,
                )
            )

    def _check_ftp(self, target: str, port: int, result: DetectionResult) -> None:
        """Check FTP service for honeypot signatures."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # FTP sends banner on connect
            banner_raw = sock.recv(1024)
            sock.close()

            # Check for exact known honeypot banners (from checkpot)
            for known_banner, honeypot_name in KNOWN_FTP_BANNERS.items():
                if banner_raw.startswith(known_banner) or known_banner in banner_raw:
                    result.add_indicator(
                        Indicator(
                            name="known_ftp_banner",
                            description=f"Known {honeypot_name} FTP banner detected",
                            severity=Confidence.DEFINITE,
                            details=f"Banner: {banner_raw.decode('utf-8', errors='ignore').strip()}",
                        )
                    )
                    result.honeypot_type = honeypot_name
                    return

            banner = banner_raw.decode("utf-8", errors="ignore")

            # Check for non-standard FTP banners that might indicate honeypot
            if not banner.startswith("220 "):
                result.add_indicator(
                    Indicator(
                        name="unusual_ftp_banner",
                        description="Non-standard FTP banner format",
                        severity=Confidence.LOW,
                        details=f"Banner: {banner.strip()[:100]}",
                    )
                )

        except (socket.error, socket.timeout, OSError):
            pass

    def _check_http(self, target: str, port: int, result: DetectionResult) -> None:
        """Check HTTP service for Dionaea signatures."""
        try:
            import requests

            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{target}:{port}/"

            response = requests.get(url, timeout=self.timeout, verify=False)

            # Check server header
            server = response.headers.get("Server", "")

            # Dionaea's HTTP is minimal
            if not server and response.status_code == 200:
                result.add_indicator(
                    Indicator(
                        name="missing_server_header",
                        description="Missing Server header (possible honeypot)",
                        severity=Confidence.LOW,
                    )
                )

        except Exception:
            pass

    def _check_mssql(self, target: str, port: int, result: DetectionResult) -> None:
        """Check MS-SQL service for Dionaea signatures."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Send TDS prelogin packet
            prelogin = bytes([
                0x12, 0x01,  # Type: Prelogin
                0x00, 0x2f,  # Length
                0x00, 0x00,  # SPID
                0x00,        # Packet ID
                0x00,        # Window
            ])

            sock.send(prelogin + b"\x00" * 39)
            response = sock.recv(1024)
            sock.close()

            # Dionaea's MSSQL emulation is limited
            if len(response) < 10:
                result.add_indicator(
                    Indicator(
                        name="limited_mssql_response",
                        description="Limited MS-SQL TDS response (possible Dionaea)",
                        severity=Confidence.MEDIUM,
                    )
                )

        except (socket.error, socket.timeout, OSError):
            pass

    def get_recommendations(self, result: DetectionResult) -> list[str]:
        """Get remediation recommendations for Dionaea."""
        recommendations = []

        for indicator in result.indicators:
            if indicator.name == "dionaea_servername":
                recommendations.append(
                    "Change ServerName in /usr/lib/dionaea/python/dionaea/smb/include/smbfields.py"
                )
            elif indicator.name == "dionaea_workgroup":
                recommendations.append(
                    "Change OemDomainName in smb/include/smbfields.py to something unique"
                )
            elif indicator.name == "dionaea_ftp_banner":
                recommendations.append(
                    "Modify FTP banner in dionaea.conf or the FTP module to mimic real server"
                )

        return recommendations
