"""Telnet honeypot detector (Cowrie telnet, custom honeypots).

Detection is split into:
- PASSIVE: Known banner signatures, IAC sequences, login prompts, BusyBox patterns
- ACTIVE: Command responses, shell emulation limits, interactive probing
"""

import socket
import re
from typing import Optional, Tuple, List

from potsnitch.core.base import BaseDetector, DetectionMode, register_detector
from potsnitch.core.result import DetectionResult, Indicator, Confidence
from potsnitch.probes.credentials import TELNET_HONEYPOT_CREDENTIALS, COWRIE_SYSTEM_SIGNATURES


# Known telnet honeypot banners (from checkpot)
KNOWN_TELNET_BANNERS = {
    b'\xff\xfb\x03\xff\xfb\x01\xff\xfd\x1f\xff\xfd\x18\r\nlogin: ': "telnetlogger",
    b'\xff\xfd\x1flogin: ': "cowrie",
    b'\xff\xfb\x01\xff\xfb\x03\xff\xfc\'\xff\xfe\x01\xff\xfd\x03\xff\xfe"\xff\xfd\'\xff\xfd\x18\xff\xfe\x1f': "mtpot",
    b'\xff\xfb\x01\xff\xfb\x03': "mtpot",
    b'\xff\xfb\x01': "mtpot",
    b'Debian GNU/Linux 7\r\nLogin: ': "honeypy",
}

COWRIE_DEFAULT_HOSTNAMES = [
    "srv04",
    "svr04",
    "nas3",
    "localhost",
]

COWRIE_DEFAULT_UNAME = "3.2.0-4-amd64"


@register_detector
class TelnetDetector(BaseDetector):
    """Detector for Telnet-based honeypots.

    Static (Passive) Detection:
    - Known telnet honeypot banner signatures (IAC sequences)
    - Login prompt patterns and hostnames
    - Telnet option negotiation fingerprinting

    Dynamic (Active) Detection:
    - Command response analysis (uname, id, cat, etc.)
    - Shell emulation limits detection
    - BusyBox command set probing
    """

    name = "telnet"
    description = "Detects Telnet honeypots via banner and response analysis"
    honeypot_types = ["cowrie-telnet", "telnet-honeypot"]
    default_ports = [23, 2323]

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive/static Telnet detection.

        Checks banners, IAC sequences, and telnet option patterns without
        sending commands or interacting beyond initial connection.

        Args:
            target: IP address or hostname
            port: Telnet port

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        # Check for default Cowrie telnet port
        if port == 2323:
            result.add_indicator(
                Indicator(
                    name="default_port",
                    description="Running on Cowrie default telnet port 2323",
                    severity=Confidence.MEDIUM,
                )
            )

        # Get telnet banner and negotiate
        banner_info = self._get_telnet_banner(target, port)
        if banner_info:
            self._analyze_banner(banner_info, result)

        if result.is_honeypot and not result.honeypot_type:
            result.honeypot_type = "cowrie-telnet"

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active/dynamic Telnet probing.

        Sends commands and analyzes responses to detect shell emulation
        limits and honeypot-specific behaviors.

        Args:
            target: IP address or hostname
            port: Telnet port

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        # Probe with default credentials and check for honeypot patterns
        cred_indicators = self._probe_telnet_credentials(target, port)
        for indicator in cred_indicators:
            result.add_indicator(indicator)

        # Probe shell emulation completeness
        shell_emulation_indicators = self._probe_shell_emulation(target, port)
        for indicator in shell_emulation_indicators:
            result.add_indicator(indicator)

        # Probe shell commands and check responses
        shell_info = self._probe_shell_commands(target, port)
        if shell_info:
            self._analyze_shell_responses(shell_info, result)

        # Check for BusyBox emulation limits
        busybox_detected = self._probe_busybox_limits(target, port)
        if busybox_detected:
            result.add_indicator(
                Indicator(
                    name="busybox_emulation",
                    description="BusyBox emulation limits detected",
                    severity=Confidence.HIGH,
                    details="Shell responds with limited BusyBox-style command set",
                )
            )

        if result.is_honeypot and not result.honeypot_type:
            result.honeypot_type = "cowrie-telnet"

        return result

    def _get_telnet_banner(self, target: str, port: int) -> Optional[dict]:
        """Connect to telnet and get initial banner/prompts."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Collect initial data (banner, telnet negotiations)
            data = b""
            try:
                while True:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                    # Stop if we see a login prompt
                    if b"login:" in data.lower() or b"username:" in data.lower():
                        break
                    if len(data) > 4096:
                        break
            except socket.timeout:
                pass

            sock.close()

            return {
                "raw": data,
                "text": data.decode("utf-8", errors="ignore"),
            }

        except (socket.error, socket.timeout, OSError):
            return None

    def _analyze_banner(self, banner_info: dict, result: DetectionResult) -> None:
        """Analyze telnet banner for honeypot indicators."""
        text = banner_info["text"]
        raw = banner_info["raw"]

        # Check for exact known honeypot banners (from checkpot)
        for known_banner, honeypot_name in KNOWN_TELNET_BANNERS.items():
            if raw.startswith(known_banner) or known_banner in raw:
                result.add_indicator(
                    Indicator(
                        name="known_telnet_banner",
                        description=f"Known {honeypot_name} telnet banner detected",
                        severity=Confidence.DEFINITE,
                        details=f"Matched signature for {honeypot_name}",
                    )
                )
                result.honeypot_type = honeypot_name
                return

        # Check for default hostnames in login prompt
        for hostname in COWRIE_DEFAULT_HOSTNAMES:
            if hostname in text:
                result.add_indicator(
                    Indicator(
                        name="default_hostname",
                        description=f"Default Cowrie hostname detected: {hostname}",
                        severity=Confidence.HIGH,
                    )
                )
                break

        # Check for kernel version in banner
        if COWRIE_DEFAULT_UNAME in text:
            result.add_indicator(
                Indicator(
                    name="default_kernel",
                    description="Default Cowrie kernel version in banner",
                    severity=Confidence.HIGH,
                    details=f"Kernel: {COWRIE_DEFAULT_UNAME}",
                )
            )

        # Check for Debian 7 references
        if "debian" in text.lower() and ("wheezy" in text.lower() or "3.2.0" in text):
            result.add_indicator(
                Indicator(
                    name="debian7_banner",
                    description="Debian 7 (wheezy) reference in banner",
                    severity=Confidence.MEDIUM,
                )
            )

        # Check telnet negotiation options (Cowrie/Twisted specific)
        self._check_telnet_options(raw, result)

    def _check_telnet_options(self, raw: bytes, result: DetectionResult) -> None:
        """Check telnet option negotiation for honeypot patterns."""
        # Telnet command bytes
        IAC = 0xff
        WILL = 0xfb
        WONT = 0xfc
        DO = 0xfd
        DONT = 0xfe

        # Parse telnet commands
        commands = []
        i = 0
        while i < len(raw) - 2:
            if raw[i] == IAC:
                if raw[i + 1] in (WILL, WONT, DO, DONT):
                    commands.append((raw[i + 1], raw[i + 2]))
                    i += 3
                    continue
            i += 1

        # Cowrie has specific telnet option patterns
        # It typically offers/requests specific options in a predictable order
        if len(commands) > 0:
            # Check for unusual option combinations
            options = [cmd[1] for cmd in commands]

            # Cowrie commonly negotiates these options
            cowrie_options = {1, 3, 24, 31, 32, 33, 34, 35, 36, 37, 38, 39}
            matched = set(options) & cowrie_options

            if len(matched) >= 5:
                result.add_indicator(
                    Indicator(
                        name="telnet_options",
                        description="Telnet option negotiation matches Cowrie pattern",
                        severity=Confidence.MEDIUM,
                    )
                )

    def _probe_shell_commands(self, target: str, port: int) -> Optional[dict]:
        """Send shell commands and collect responses (active probing).

        Attempts to login with common default credentials and send
        commands to probe shell behavior.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Collect initial banner
            data = b""
            try:
                while True:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                    if b"login:" in data.lower() or b"username:" in data.lower():
                        break
                    if len(data) > 4096:
                        break
            except socket.timeout:
                pass

            # Try to send a login (common honeypot credentials)
            sock.send(b"root\r\n")
            sock.settimeout(2.0)

            # Wait for password prompt
            try:
                response = sock.recv(1024)
                if b"password" in response.lower():
                    # Try common passwords
                    sock.send(b"123456\r\n")
                    sock.settimeout(3.0)

                    # Collect post-login data
                    post_login = b""
                    try:
                        while True:
                            chunk = sock.recv(1024)
                            if not chunk:
                                break
                            post_login += chunk
                            # Check for shell prompt
                            if b"$" in post_login or b"#" in post_login:
                                # Send test commands
                                commands_output = {}

                                # Test uname
                                sock.send(b"uname -a\r\n")
                                sock.settimeout(2.0)
                                try:
                                    uname_resp = sock.recv(1024)
                                    commands_output["uname"] = uname_resp.decode("utf-8", errors="ignore")
                                except socket.timeout:
                                    pass

                                # Test id
                                sock.send(b"id\r\n")
                                sock.settimeout(2.0)
                                try:
                                    id_resp = sock.recv(1024)
                                    commands_output["id"] = id_resp.decode("utf-8", errors="ignore")
                                except socket.timeout:
                                    pass

                                sock.close()
                                return commands_output

                            if len(post_login) > 4096:
                                break
                    except socket.timeout:
                        pass
            except socket.timeout:
                pass

            sock.close()
            return None

        except (socket.error, socket.timeout, OSError):
            return None

    def _analyze_shell_responses(self, shell_info: dict, result: DetectionResult) -> None:
        """Analyze shell command responses for honeypot indicators."""
        # Check for default Cowrie uname output
        uname = shell_info.get("uname", "")
        if COWRIE_DEFAULT_UNAME in uname:
            result.add_indicator(
                Indicator(
                    name="default_uname",
                    description="Default Cowrie uname output detected",
                    severity=Confidence.HIGH,
                    details=f"uname -a returned default Cowrie kernel: {COWRIE_DEFAULT_UNAME}",
                )
            )

        # Check for default uid/gid patterns
        id_output = shell_info.get("id", "")
        if "uid=0(root)" in id_output and "phil" in id_output:
            result.add_indicator(
                Indicator(
                    name="cowrie_user",
                    description="Cowrie default user 'phil' detected in groups",
                    severity=Confidence.HIGH,
                )
            )

    def _probe_busybox_limits(self, target: str, port: int) -> bool:
        """Probe for BusyBox emulation limits.

        Cowrie emulates a limited BusyBox environment. Test commands
        that should work on real systems but fail on Cowrie.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Skip through login (this is a simplified check)
            sock.settimeout(3.0)
            try:
                # Collect until login prompt
                data = b""
                while len(data) < 4096:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                    if b"login:" in data.lower():
                        break
            except socket.timeout:
                pass

            # Send login
            sock.send(b"root\r\n")
            sock.settimeout(2.0)
            try:
                sock.recv(1024)  # password prompt
            except socket.timeout:
                sock.close()
                return False

            sock.send(b"123456\r\n")
            sock.settimeout(3.0)

            try:
                sock.recv(2048)  # post-login banner
            except socket.timeout:
                sock.close()
                return False

            # Test a command that Cowrie BusyBox doesn't support well
            # Real BusyBox: "busybox" shows applet list
            sock.send(b"busybox\r\n")
            sock.settimeout(2.0)

            try:
                busybox_output = sock.recv(2048).decode("utf-8", errors="ignore")
                sock.close()

                # Cowrie's BusyBox output is limited/different from real BusyBox
                # Real BusyBox lists many applets, Cowrie may have truncated list
                if "BusyBox" in busybox_output:
                    # Count number of applets listed
                    applets = busybox_output.count(",")
                    if applets < 10:  # Real BusyBox has 100+ applets
                        return True

            except socket.timeout:
                sock.close()
                return False

            return False

        except (socket.error, socket.timeout, OSError):
            return False

    def _probe_telnet_credentials(self, target: str, port: int) -> List[Indicator]:
        """Probe telnet with default IoT credentials and check for honeypot patterns.

        Attempts authentication with known default credentials and, if successful,
        executes commands to detect Cowrie/BusyBox honeypot signatures.

        Args:
            target: IP address or hostname
            port: Telnet port

        Returns:
            List of Indicator objects for any honeypot patterns detected
        """
        indicators = []
        telnet_timeout = 8  # 5-10 seconds for telnet operations

        for username, password in TELNET_HONEYPOT_CREDENTIALS[:10]:  # Try first 10 creds
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(telnet_timeout)
                sock.connect((target, port))

                # Wait for login prompt
                data = b""
                try:
                    while len(data) < 4096:
                        chunk = sock.recv(1024)
                        if not chunk:
                            break
                        data += chunk
                        if b"login:" in data.lower() or b"username:" in data.lower():
                            break
                except socket.timeout:
                    sock.close()
                    continue

                if b"login:" not in data.lower() and b"username:" not in data.lower():
                    sock.close()
                    continue

                # Send username
                sock.send(username.encode() + b"\r\n")
                sock.settimeout(5)

                try:
                    response = sock.recv(1024)
                except socket.timeout:
                    sock.close()
                    continue

                # Check if password prompt or direct shell
                if b"password" in response.lower():
                    sock.send(password.encode() + b"\r\n")
                    sock.settimeout(5)
                    try:
                        post_login = sock.recv(2048)
                    except socket.timeout:
                        sock.close()
                        continue
                else:
                    post_login = response

                # Check if we got a shell prompt (authentication succeeded)
                if b"$" in post_login or b"#" in post_login or b">" in post_login:
                    # Default credentials accepted - this is suspicious
                    indicators.append(
                        Indicator(
                            name="default_credentials_accepted",
                            description=f"Default credentials accepted: {username}:{password}",
                            severity=Confidence.HIGH,
                            details=f"Telnet accepted default IoT credentials ({username}:{password})",
                        )
                    )

                    # Now probe for honeypot signatures
                    command_outputs = {}

                    # Test uname -a for Cowrie default kernel
                    sock.send(b"uname -a\r\n")
                    sock.settimeout(5)
                    try:
                        uname_resp = sock.recv(2048).decode("utf-8", errors="ignore")
                        command_outputs["uname"] = uname_resp
                    except socket.timeout:
                        pass

                    # Test cat /proc/version for Cowrie signatures
                    sock.send(b"cat /proc/version\r\n")
                    sock.settimeout(5)
                    try:
                        version_resp = sock.recv(2048).decode("utf-8", errors="ignore")
                        command_outputs["proc_version"] = version_resp
                    except socket.timeout:
                        pass

                    # Test id for restricted user environment
                    sock.send(b"id\r\n")
                    sock.settimeout(5)
                    try:
                        id_resp = sock.recv(2048).decode("utf-8", errors="ignore")
                        command_outputs["id"] = id_resp
                    except socket.timeout:
                        pass

                    sock.close()

                    # Analyze command outputs for honeypot signatures
                    uname_output = command_outputs.get("uname", "")
                    proc_version = command_outputs.get("proc_version", "")
                    id_output = command_outputs.get("id", "")

                    # Check for Cowrie default kernel version
                    cowrie_kernel = COWRIE_SYSTEM_SIGNATURES.get("kernel_version", "")
                    cowrie_kernel_full = COWRIE_SYSTEM_SIGNATURES.get("kernel_full", "")

                    if cowrie_kernel and cowrie_kernel in uname_output:
                        indicators.append(
                            Indicator(
                                name="cowrie_default_kernel",
                                description="Cowrie default kernel version detected",
                                severity=Confidence.DEFINITE,
                                details=f"uname -a returned Cowrie default: {cowrie_kernel}",
                            )
                        )

                    if cowrie_kernel_full and cowrie_kernel_full in proc_version:
                        indicators.append(
                            Indicator(
                                name="cowrie_proc_version",
                                description="Cowrie /proc/version signature detected",
                                severity=Confidence.DEFINITE,
                                details="cat /proc/version matches Cowrie default",
                            )
                        )

                    # Check for Cowrie default hostname in uname output
                    cowrie_hostname = COWRIE_SYSTEM_SIGNATURES.get("hostname", "")
                    if cowrie_hostname and cowrie_hostname in uname_output:
                        indicators.append(
                            Indicator(
                                name="cowrie_default_hostname_in_uname",
                                description=f"Cowrie default hostname '{cowrie_hostname}' in uname",
                                severity=Confidence.HIGH,
                                details=f"System hostname matches Cowrie default: {cowrie_hostname}",
                            )
                        )

                    # Check for Cowrie default user in id output
                    cowrie_user = COWRIE_SYSTEM_SIGNATURES.get("default_user", "")
                    if cowrie_user and cowrie_user in id_output:
                        indicators.append(
                            Indicator(
                                name="cowrie_default_user",
                                description=f"Cowrie default user '{cowrie_user}' detected",
                                severity=Confidence.HIGH,
                                details=f"id command shows Cowrie default user: {cowrie_user}",
                            )
                        )

                    # Check for BusyBox shell pattern
                    if "busybox" in uname_output.lower() or "busybox" in post_login.decode("utf-8", errors="ignore").lower():
                        indicators.append(
                            Indicator(
                                name="busybox_shell_pattern",
                                description="BusyBox shell pattern detected",
                                severity=Confidence.MEDIUM,
                                details="Shell indicates BusyBox environment (common in IoT honeypots)",
                            )
                        )

                    # Run comprehensive BusyBox post-auth detection
                    # Need to reconnect since we used the socket for basic probing
                    try:
                        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock2.settimeout(telnet_timeout)
                        sock2.connect((target, port))

                        # Re-authenticate
                        data2 = b""
                        try:
                            while len(data2) < 4096:
                                chunk = sock2.recv(1024)
                                if not chunk:
                                    break
                                data2 += chunk
                                if b"login:" in data2.lower():
                                    break
                        except socket.timeout:
                            pass

                        if b"login:" in data2.lower():
                            sock2.send(username.encode() + b"\r\n")
                            sock2.settimeout(5)
                            try:
                                resp2 = sock2.recv(1024)
                                if b"password" in resp2.lower():
                                    sock2.send(password.encode() + b"\r\n")
                                    sock2.settimeout(5)
                                    sock2.recv(2048)  # consume post-login

                                    # Run BusyBox-specific post-auth detection
                                    busybox_indicators = self._probe_busybox_post_auth(sock2)
                                    indicators.extend(busybox_indicators)
                            except socket.timeout:
                                pass

                        sock2.close()
                    except (socket.error, socket.timeout, OSError):
                        pass

                    # Successfully authenticated and probed, no need to try more creds
                    return indicators

                sock.close()

            except (socket.error, socket.timeout, OSError):
                continue

        return indicators

    def _probe_busybox_post_auth(self, sock: socket.socket) -> List[Indicator]:
        """Run comprehensive BusyBox honeypot detection after successful auth.

        Tests BusyBox applet count, missing commands, /proc filesystem,
        and other indicators that distinguish honeypot BusyBox from real IoT devices.

        Args:
            sock: Connected and authenticated socket

        Returns:
            List of Indicator objects for detected honeypot signs
        """
        import time

        indicators: List[Indicator] = []

        def send_cmd(cmd: str) -> str:
            """Send command and return output."""
            try:
                sock.send(cmd.encode() + b"\r\n")
                sock.settimeout(3)
                response = sock.recv(4096).decode("utf-8", errors="ignore")
                return response
            except (socket.timeout, OSError):
                return ""

        # Test BusyBox applet count - DEFINITE (real has 100+, honeypot has <10)
        busybox_output = send_cmd("busybox --list 2>/dev/null | wc -l")
        try:
            # Extract the number from output
            lines = busybox_output.strip().split("\n")
            for line in lines:
                line = line.strip()
                if line.isdigit():
                    applet_count = int(line)
                    if applet_count < 15:
                        indicators.append(
                            Indicator(
                                name="busybox_limited_applets",
                                description=f"BusyBox has only {applet_count} applets (expected 100+)",
                                severity=Confidence.DEFINITE,
                                details="Real IoT devices have 100+ BusyBox applets",
                            )
                        )
                    break
        except (ValueError, IndexError):
            pass

        # Test /proc/self/exe - DEFINITE (honeypots fail this)
        proc_self_output = send_cmd("cat /proc/self/exe 2>&1")
        if "No such file" in proc_self_output or proc_self_output.strip() == "":
            indicators.append(
                Indicator(
                    name="proc_self_exe_missing",
                    description="/proc/self/exe not accessible (honeypot signature)",
                    severity=Confidence.DEFINITE,
                )
            )

        # Test /proc/self/fd - HIGH
        proc_fd_output = send_cmd("ls /proc/self/fd 2>&1")
        if "No such file" in proc_fd_output or "not found" in proc_fd_output.lower():
            indicators.append(
                Indicator(
                    name="proc_self_fd_missing",
                    description="/proc/self/fd not accessible",
                    severity=Confidence.HIGH,
                )
            )

        # Test for missing IoT commands - HIGH (real IoT devices have these)
        missing_cmds = []
        for cmd in ["wget", "curl", "tftp", "nc"]:
            which_output = send_cmd(f"which {cmd} 2>&1")
            if not which_output.strip() or "not found" in which_output.lower():
                missing_cmds.append(cmd)

        if len(missing_cmds) >= 3:
            indicators.append(
                Indicator(
                    name="missing_iot_commands",
                    description=f"Missing IoT-typical commands: {', '.join(missing_cmds)}",
                    severity=Confidence.HIGH,
                    details="Real IoT devices typically have wget, curl, tftp, nc",
                )
            )

        # Test invalid BusyBox applet - HIGH
        # Real BusyBox returns "applet not found", honeypots may differ
        invalid_applet_output = send_cmd("/bin/busybox ECCHI 2>&1")
        if "applet not found" not in invalid_applet_output.lower():
            if invalid_applet_output.strip() == "" or "not found" not in invalid_applet_output.lower():
                indicators.append(
                    Indicator(
                        name="busybox_invalid_applet_response",
                        description="BusyBox responds incorrectly to invalid applet",
                        severity=Confidence.HIGH,
                        details="Real BusyBox says 'applet not found'",
                    )
                )

        # Test for static uname output - HIGH
        uname_output = send_cmd("uname -a")
        if "3.2.0-4-amd64" in uname_output and "Debian" in uname_output:
            indicators.append(
                Indicator(
                    name="cowrie_default_kernel_telnet",
                    description="Cowrie default kernel in uname -a",
                    severity=Confidence.HIGH,
                    details=uname_output.strip()[:100],
                )
            )

        # Test for static uptime - HIGH
        uptime_output = send_cmd("uptime")
        if "0.00, 0.00, 0.00" in uptime_output:
            indicators.append(
                Indicator(
                    name="static_zero_load_telnet",
                    description="Load average always 0.00 (static honeypot)",
                    severity=Confidence.HIGH,
                )
            )

        # Test for default users in /etc/passwd - HIGH
        passwd_output = send_cmd("cat /etc/passwd 2>&1")
        for user in ["phil", "richard"]:
            if f"{user}:" in passwd_output:
                indicators.append(
                    Indicator(
                        name=f"default_user_{user}_telnet",
                        description=f"Default Cowrie user '{user}' in /etc/passwd",
                        severity=Confidence.HIGH,
                    )
                )

        return indicators

    def _probe_shell_emulation(self, target: str, port: int) -> List[Indicator]:
        """Test shell completeness to detect honeypot emulation limits.

        Honeypots often don't have real utilities like wget, curl, nc,
        and have restricted filesystem access. This method tests for these
        limitations.

        Args:
            target: IP address or hostname
            port: Telnet port

        Returns:
            List of Indicator objects for emulation limit patterns detected
        """
        indicators = []
        telnet_timeout = 8

        # Commands that real systems typically have but honeypots don't
        test_commands = [
            ("wget --version", "wget"),
            ("curl --version", "curl"),
            ("nc -h", "nc"),
            ("netcat -h", "netcat"),
            ("python --version", "python"),
            ("perl -v", "perl"),
        ]

        # Patterns indicating command not found (honeypot signatures)
        not_found_patterns = [
            b"not found",
            b"command not found",
            b"applet not found",
            b"unknown command",
            b"-sh:",
            b"ash:",
        ]

        # Try to login with first successful credential
        for username, password in TELNET_HONEYPOT_CREDENTIALS[:5]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(telnet_timeout)
                sock.connect((target, port))

                # Wait for login prompt
                data = b""
                try:
                    while len(data) < 4096:
                        chunk = sock.recv(1024)
                        if not chunk:
                            break
                        data += chunk
                        if b"login:" in data.lower():
                            break
                except socket.timeout:
                    sock.close()
                    continue

                if b"login:" not in data.lower():
                    sock.close()
                    continue

                # Send credentials
                sock.send(username.encode() + b"\r\n")
                sock.settimeout(5)
                try:
                    response = sock.recv(1024)
                except socket.timeout:
                    sock.close()
                    continue

                if b"password" in response.lower():
                    sock.send(password.encode() + b"\r\n")
                    sock.settimeout(5)
                    try:
                        post_login = sock.recv(2048)
                    except socket.timeout:
                        sock.close()
                        continue
                else:
                    post_login = response

                # Check if we got a shell
                if b"$" not in post_login and b"#" not in post_login and b">" not in post_login:
                    sock.close()
                    continue

                # We have a shell - test commands
                missing_commands = []
                command_not_found_count = 0

                for cmd, cmd_name in test_commands:
                    sock.send(cmd.encode() + b"\r\n")
                    sock.settimeout(3)
                    try:
                        cmd_response = sock.recv(2048)
                        # Check for not found patterns
                        for pattern in not_found_patterns:
                            if pattern in cmd_response.lower():
                                missing_commands.append(cmd_name)
                                command_not_found_count += 1
                                break
                    except socket.timeout:
                        pass

                # Test filesystem access - try to read a file that should exist
                sock.send(b"cat /etc/passwd 2>&1\r\n")
                sock.settimeout(3)
                passwd_restricted = False
                try:
                    passwd_response = sock.recv(2048)
                    if b"permission denied" in passwd_response.lower() or b"no such file" in passwd_response.lower():
                        passwd_restricted = True
                except socket.timeout:
                    pass

                # Try to create a file (honeypots often block this)
                sock.send(b"touch /tmp/test_$$ 2>&1 && echo SUCCESS || echo FAILED\r\n")
                sock.settimeout(3)
                file_create_blocked = False
                try:
                    touch_response = sock.recv(2048)
                    if b"FAILED" in touch_response or b"permission denied" in touch_response.lower() or b"read-only" in touch_response.lower():
                        file_create_blocked = True
                except socket.timeout:
                    pass

                sock.close()

                # Analyze results
                if command_not_found_count >= 3:
                    indicators.append(
                        Indicator(
                            name="missing_common_commands",
                            description="Multiple common commands not found",
                            severity=Confidence.MEDIUM,
                            details=f"Missing commands: {', '.join(missing_commands)}. Real systems typically have these.",
                        )
                    )

                if passwd_restricted:
                    indicators.append(
                        Indicator(
                            name="restricted_filesystem",
                            description="Filesystem access restricted",
                            severity=Confidence.MEDIUM,
                            details="/etc/passwd not accessible - may indicate sandboxed honeypot",
                        )
                    )

                if file_create_blocked:
                    indicators.append(
                        Indicator(
                            name="file_creation_blocked",
                            description="File creation blocked in /tmp",
                            severity=Confidence.MEDIUM,
                            details="Cannot create files in /tmp - may indicate read-only honeypot filesystem",
                        )
                    )

                # Check for consistent command not found message format
                # Honeypots often have uniform error messages
                if command_not_found_count >= 2:
                    # All commands gave the same style of error - suspicious
                    indicators.append(
                        Indicator(
                            name="uniform_error_messages",
                            description="Uniform 'command not found' error pattern",
                            severity=Confidence.LOW,
                            details="Error messages are uniformly formatted, suggesting emulated shell",
                        )
                    )

                return indicators

            except (socket.error, socket.timeout, OSError):
                continue

        return indicators

    def get_recommendations(self, result: DetectionResult) -> list[str]:
        """Get remediation recommendations for Telnet honeypots."""
        recommendations = []

        for indicator in result.indicators:
            if indicator.name == "default_hostname":
                recommendations.append(
                    "Change hostname in cowrie.cfg to something realistic"
                )
            elif indicator.name == "default_kernel":
                recommendations.append(
                    "Customize kernel version in cowrie.cfg or txtcmds/bin/uname"
                )
            elif indicator.name == "default_port":
                recommendations.append(
                    "Use iptables to redirect port 23 to 2323"
                )

        return recommendations
