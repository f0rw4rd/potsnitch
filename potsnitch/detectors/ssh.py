"""SSH honeypot detector for Cowrie and Kippo.

Detection is split into:
- PASSIVE: Banner analysis, HASSH fingerprinting, KEX algorithm checking
- ACTIVE: CR probe, bad version probe, spacer packet probe, double banner probe,
          credential probing, invalid payload testing
"""

import socket
import struct
from typing import Optional, List

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

from potsnitch.core.base import BaseDetector, DetectionMode, register_detector
from potsnitch.core.result import DetectionResult, Indicator, Confidence


# Known Cowrie/Kippo default banners across all versions
# Sources: detect-kippo-cowrie, honeyscanner, T-Pot, cowrie.cfg.dist, kippo source
COWRIE_DEFAULT_BANNERS = [
    # Cowrie current default (v2.5+)
    "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
    # Cowrie classic default (v1.0-2.4)
    "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",
    # T-Pot specific Cowrie banners
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
    # Heralding SSH banner (from T-Pot heralding.yml)
    "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.8",
    # Kippo original default
    "SSH-2.0-OpenSSH_5.1p1 Debian-5",
    # Other documented Cowrie/Kippo defaults from cowrie.cfg.dist
    "SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.4",
    "SSH-1.99-OpenSSH_4.3",
    "SSH-1.99-OpenSSH_4.7",
    "SSH-1.99-Sun_SSH_1.1",
    "SSH-2.0-OpenSSH_4.2p1 Debian-7ubuntu3.1",
    "SSH-2.0-OpenSSH_4.3",
    "SSH-2.0-OpenSSH_4.6",
    "SSH-2.0-OpenSSH_5.1p1 FreeBSD-20080901",
    "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu5",
    "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu6",
    "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu7",
    "SSH-2.0-OpenSSH_5.5p1 Debian-6",
    "SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze1",
    "SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze2",
    "SSH-2.0-OpenSSH_5.8p2_hpn13v11 FreeBSD-20110503",
    "SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1",
    "SSH-2.0-OpenSSH_5.9",
]

# Cowrie/Kippo default hostnames across versions
COWRIE_DEFAULT_HOSTNAMES = [
    "svr04",   # Cowrie default
    "svr03",   # Kippo default
    "ubuntu",  # T-Pot Cowrie default
    "nas3",    # Alternate Cowrie config
    "server",  # Common custom
]

# Cowrie default usernames for authentication
COWRIE_DEFAULT_USERS = [
    "phil",    # Cowrie default in auth.py
    "root",
    "richard",
]

# Cowrie default /proc/version (for authenticated checks)
COWRIE_DEFAULT_PROC_VERSION = "Linux version 3.2.0-4-amd64 (debian-kernel@lists.debian.org) (gcc version 4.6.3 (Debian 4.6.3-14) ) #1 SMP Debian 3.2.68-1+deb7u1"

# Cowrie default memory info
COWRIE_DEFAULT_MEMFREE = "MemFree:          997740 kB"

# Cowrie default CPU
COWRIE_DEFAULT_CPU = "Intel(R) Core(TM)2 Duo CPU     E8200  @ 2.66GHz"

# Cowrie default user/group
COWRIE_DEFAULT_USER = "phil"

# Cowrie default hostname
COWRIE_DEFAULT_HOSTNAME = "svr04"

# Cowrie uses Twisted's Conch library which has specific KEX algorithms
COWRIE_KEX_ALGORITHMS = [
    b"diffie-hellman-group-exchange-sha256",
    b"diffie-hellman-group-exchange-sha1",
    b"diffie-hellman-group14-sha1",
    b"diffie-hellman-group1-sha1",
]

# Cowrie default ciphers (from TwistedConch)
COWRIE_CIPHERS = [
    b"aes128-ctr",
    b"aes192-ctr",
    b"aes256-ctr",
    b"aes128-cbc",
    b"3des-cbc",
    b"blowfish-cbc",
    b"cast128-cbc",
    b"aes192-cbc",
    b"aes256-cbc",
]

# Default uname output in Cowrie
COWRIE_DEFAULT_UNAME = "Linux srv04 3.2.0-4-amd64 #1 SMP Debian 3.2.68-1+deb7u1 x86_64 GNU/Linux"


@register_detector
class SSHDetector(BaseDetector):
    """Detector for SSH-based honeypots (Cowrie, Kippo).

    Static (Passive) Detection:
    - SSH banner matching against known honeypot defaults
    - KEX algorithm fingerprinting (HASSH-style)
    - Default port detection (2222)

    Dynamic (Active) Detection:
    - Kippo carriage return probe
    - Bad version string probe
    - Spacer/corrupt packet probe
    - Double banner probe
    """

    name = "ssh"
    description = "Detects Cowrie and Kippo SSH honeypots"
    honeypot_types = ["cowrie", "kippo"]
    default_ports = [22, 2222]

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive/static SSH detection.

        Checks banners, KEX algorithms, and port patterns without
        sending any malformed or probe packets.

        Args:
            target: IP address or hostname
            port: SSH port

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        # Check for default Cowrie port (static indicator)
        if port == 2222:
            result.add_indicator(
                Indicator(
                    name="default_port_2222",
                    description="Running on Cowrie default port 2222",
                    severity=Confidence.LOW,
                )
            )

        # Get SSH banner (received passively on connect)
        banner = self._get_ssh_banner(target, port)
        if banner:
            self._check_banner(banner, result)

        # Check KEX algorithms (HASSH fingerprinting)
        kex_info = self._get_kex_init(target, port)
        if kex_info:
            self._check_kex(kex_info, result)

        # Set honeypot type if detected
        if result.is_honeypot and not result.honeypot_type:
            result.honeypot_type = "cowrie"

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active/dynamic SSH probing.

        Sends malformed packets and probes to elicit honeypot-specific
        responses. More accurate but detectable by honeypot operators.

        Args:
            target: IP address or hostname
            port: SSH port

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        # Kippo carriage return probe
        kippo_detected = self._kippo_cr_probe(target, port)
        if kippo_detected:
            result.add_indicator(
                Indicator(
                    name="kippo_cr_probe",
                    description="Kippo detected via carriage return probe",
                    severity=Confidence.DEFINITE,
                    details="Server responded with 'bad packet length' to CR probe",
                )
            )
            result.honeypot_type = "kippo"

        # Bad version probe (from detect-kippo-cowrie)
        if self._probe_bad_version(target, port):
            result.add_indicator(
                Indicator(
                    name="bad_version_probe",
                    description="Honeypot detected via bad version probe",
                    severity=Confidence.HIGH,
                    details="Server responded with 'bad version' to SSH-1337 probe",
                )
            )

        # Spacer/packet corrupt probe (from detect-kippo-cowrie)
        if self._probe_spacer_packet(target, port):
            result.add_indicator(
                Indicator(
                    name="spacer_packet_probe",
                    description="Honeypot detected via spacer packet probe",
                    severity=Confidence.HIGH,
                    details="Server responded with 'corrupt' or 'mismatch' to newline probe",
                )
            )

        # Double banner probe (from detect-kippo-cowrie)
        if self._probe_double_banner(target, port):
            result.add_indicator(
                Indicator(
                    name="double_banner_probe",
                    description="Honeypot detected via double banner probe",
                    severity=Confidence.HIGH,
                    details="Server responded abnormally to double banner",
                )
            )

        # Credential-based detection using paramiko
        credential_indicators = self._probe_auth_credentials(target, port)
        for indicator in credential_indicators:
            result.add_indicator(indicator)

        # Invalid payload uniformity detection
        invalid_payload_indicators = self._probe_invalid_payloads(target, port)
        for indicator in invalid_payload_indicators:
            result.add_indicator(indicator)

        # Set honeypot type if detected via active probes
        if result.is_honeypot and not result.honeypot_type:
            result.honeypot_type = "cowrie"

        return result

    def _get_ssh_banner(self, target: str, port: int) -> Optional[str]:
        """Get SSH version banner from server."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # SSH sends banner on connect
            banner = sock.recv(256)
            sock.close()

            return banner.decode("utf-8", errors="ignore").strip()
        except (socket.error, socket.timeout, OSError):
            return None

    def _check_banner(self, banner: str, result: DetectionResult) -> None:
        """Check SSH banner for honeypot indicators."""
        # Check for exact default banners
        for default in COWRIE_DEFAULT_BANNERS:
            if banner == default:
                result.add_indicator(
                    Indicator(
                        name="default_banner",
                        description="Default Cowrie SSH banner detected",
                        severity=Confidence.HIGH,
                        details=f"Banner: {banner}",
                    )
                )
                return

        # Check for outdated OpenSSH versions commonly used by honeypots
        if "OpenSSH_6.0" in banner or "OpenSSH_5." in banner:
            result.add_indicator(
                Indicator(
                    name="outdated_version",
                    description="Outdated OpenSSH version (common in honeypots)",
                    severity=Confidence.LOW,
                    details=f"Banner: {banner}",
                )
            )

        # Check for Debian 7 (wheezy) which Cowrie defaults to
        if "deb7" in banner or "Debian-4" in banner:
            result.add_indicator(
                Indicator(
                    name="debian7_banner",
                    description="Debian 7 (wheezy) signature in banner",
                    severity=Confidence.MEDIUM,
                    details="Cowrie defaults to Debian 7 environment",
                )
            )

    def _get_kex_init(self, target: str, port: int) -> Optional[dict]:
        """Get SSH key exchange initialization data."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Read and send banner
            banner = sock.recv(256)
            sock.send(b"SSH-2.0-PotSnitch_Scanner\r\n")

            # Read SSH packet (KEX_INIT should come next)
            # SSH packet format: length (4) + padding_len (1) + type (1) + payload
            header = sock.recv(5)
            if len(header) < 5:
                sock.close()
                return None

            packet_len = struct.unpack(">I", header[:4])[0]
            padding_len = header[4]

            # Read rest of packet
            data = header[4:] + sock.recv(packet_len - 1)
            sock.close()

            if len(data) < 2:
                return None

            msg_type = data[1] if len(data) > 1 else data[0]

            # SSH_MSG_KEXINIT = 20
            if msg_type == 20:
                return self._parse_kex_init(data[2:] if len(data) > 2 else data[1:])

            return None
        except (socket.error, socket.timeout, OSError, struct.error):
            return None

    def _parse_kex_init(self, data: bytes) -> Optional[dict]:
        """Parse KEX_INIT packet to extract algorithm lists."""
        try:
            # Skip 16 bytes of cookie
            pos = 16
            if len(data) < pos:
                return None

            result = {}
            fields = [
                "kex_algorithms",
                "server_host_key_algorithms",
                "encryption_client_to_server",
                "encryption_server_to_client",
                "mac_client_to_server",
                "mac_server_to_client",
                "compression_client_to_server",
                "compression_server_to_client",
            ]

            for field in fields:
                if pos + 4 > len(data):
                    break
                length = struct.unpack(">I", data[pos : pos + 4])[0]
                pos += 4
                if pos + length > len(data):
                    break
                result[field] = data[pos : pos + length]
                pos += length

            return result
        except (struct.error, IndexError):
            return None

    def _check_kex(self, kex_info: dict, result: DetectionResult) -> None:
        """Check KEX algorithms for Cowrie/Twisted signatures."""
        if "encryption_client_to_server" not in kex_info:
            return

        ciphers = kex_info["encryption_client_to_server"]

        # Check if cipher list matches Cowrie defaults exactly
        cowrie_cipher_list = b",".join(COWRIE_CIPHERS)
        if ciphers == cowrie_cipher_list:
            result.add_indicator(
                Indicator(
                    name="cowrie_ciphers",
                    description="Cipher list matches Cowrie/Twisted defaults exactly",
                    severity=Confidence.HIGH,
                    details="TwistedConch library signature detected",
                )
            )

        # Check for specific Cowrie cipher ordering
        cipher_list = ciphers.split(b",")
        if cipher_list == COWRIE_CIPHERS:
            result.add_indicator(
                Indicator(
                    name="twisted_cipher_order",
                    description="Cipher ordering matches TwistedConch library",
                    severity=Confidence.MEDIUM,
                )
            )

    def _kippo_cr_probe(self, target: str, port: int) -> bool:
        """Probe for Kippo using carriage return trick.

        Kippo returns "bad packet length 168430090" when sent 8 CR characters
        as the SSH client version, while real OpenSSH returns "Protocol mismatch".
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Read server banner
            sock.recv(256)

            # Send 8 carriage returns as version
            sock.send(b"\r\r\r\r\r\r\r\r")

            # Read response
            response = sock.recv(256)
            sock.close()

            response_str = response.decode("utf-8", errors="ignore")

            # Kippo-specific error message
            if "bad packet length" in response_str:
                return True
            # Could also check for the specific number: 168430090

            return False
        except (socket.error, socket.timeout, OSError):
            return False

    def _probe_bad_version(self, target: str, port: int) -> bool:
        """Probe with invalid SSH version string.

        From detect-kippo-cowrie: Cowrie/Kippo responds with 'bad version'
        while real OpenSSH handles it differently.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Read server banner
            sock.recv(256)

            # Send invalid version
            sock.send(b"SSH-1337\n")

            response = sock.recv(1024)
            sock.close()

            response_str = response.decode("utf-8", errors="ignore").lower()
            return "bad version" in response_str

        except (socket.error, socket.timeout, OSError):
            return False

    def _probe_spacer_packet(self, target: str, port: int) -> bool:
        """Probe with version string followed by newlines.

        From detect-kippo-cowrie: Cowrie responds with 'packet corrupt' or
        'protocol mismatch' in certain cases.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Read server banner
            sock.recv(256)

            # Send version with extra newlines
            sock.send(b"SSH-2.0-OpenSSH\n\n\n\n\n\n\n\n\n\n")

            response = sock.recv(1024)
            sock.close()

            response_str = response.decode("utf-8", errors="ignore").lower()
            return "corrupt" in response_str or "mismatch" in response_str

        except (socket.error, socket.timeout, OSError):
            return False

    def _probe_double_banner(self, target: str, port: int) -> bool:
        """Probe with double SSH banner.

        From detect-kippo-cowrie: Send the same banner twice and check response.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Read server banner
            sock.recv(256)

            # Send double banner
            sock.send(b"SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2\nSSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2\n")

            response = sock.recv(1024)
            sock.close()

            response_str = response.decode("utf-8", errors="ignore").lower()
            return "corrupt" in response_str or "mismatch" in response_str

        except (socket.error, socket.timeout, OSError):
            return False

    def _probe_auth_credentials(self, target: str, port: int) -> List[Indicator]:
        """Probe SSH server with default honeypot credentials.

        Attempts authentication with known default credentials used by
        Cowrie and other SSH honeypots. If authentication succeeds,
        probes system info to check for honeypot signatures.

        Args:
            target: IP address or hostname
            port: SSH port

        Returns:
            List of Indicator objects for detected honeypot signs
        """
        indicators: List[Indicator] = []

        if not HAS_PARAMIKO:
            return indicators

        from potsnitch.probes.credentials import (
            SSH_HONEYPOT_CREDENTIALS,
            COWRIE_SYSTEM_SIGNATURES,
        )

        # Limit credential attempts to avoid lockouts (3-5 attempts)
        max_attempts = 5
        credentials_to_try = SSH_HONEYPOT_CREDENTIALS[:max_attempts]

        for username, password in credentials_to_try:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                try:
                    client.connect(
                        target,
                        port=port,
                        username=username,
                        password=password,
                        timeout=self.timeout,
                        allow_agent=False,
                        look_for_keys=False,
                        banner_timeout=self.timeout,
                        auth_timeout=self.timeout,
                    )
                except paramiko.AuthenticationException:
                    # Auth failed, try next credential
                    continue
                except (paramiko.SSHException, socket.error, OSError):
                    # Connection error, stop trying
                    break

                # Authentication succeeded with default credentials
                indicators.append(
                    Indicator(
                        name="default_credentials_accepted",
                        description="SSH server accepted default honeypot credentials",
                        severity=Confidence.HIGH,
                        details=f"Accepted credentials: {username}:{password}",
                    )
                )

                # Probe system info to check for Cowrie signatures
                system_info = self._get_system_info(client)
                signature_matches = self._check_cowrie_signatures(
                    system_info, COWRIE_SYSTEM_SIGNATURES
                )

                for match_name, match_details in signature_matches:
                    indicators.append(
                        Indicator(
                            name=f"cowrie_signature_{match_name}",
                            description=f"Cowrie system signature detected: {match_name}",
                            severity=Confidence.HIGH,
                            details=match_details,
                        )
                    )

                # Run comprehensive post-auth command detection
                post_auth_indicators = self._probe_post_auth_commands(client)
                indicators.extend(post_auth_indicators)

                try:
                    client.close()
                except Exception:
                    pass

                # Stop after first successful auth
                break

            except Exception:
                # Catch any unexpected paramiko errors
                continue

        return indicators

    def _get_system_info(self, client: "paramiko.SSHClient") -> dict:
        """Execute commands to gather system info after successful auth.

        Args:
            client: Connected paramiko SSHClient

        Returns:
            Dictionary with system info (proc_version, uname, hostname)
        """
        system_info = {}
        commands = {
            "proc_version": "cat /proc/version",
            "uname": "uname -a",
            "hostname": "hostname",
        }

        for key, cmd in commands.items():
            try:
                stdin, stdout, stderr = client.exec_command(cmd, timeout=self.timeout)
                output = stdout.read().decode("utf-8", errors="ignore").strip()
                system_info[key] = output
            except Exception:
                system_info[key] = ""

        return system_info

    def _check_cowrie_signatures(
        self, system_info: dict, signatures: dict
    ) -> List[tuple]:
        """Check system info against known Cowrie signatures.

        Args:
            system_info: Dictionary with proc_version, uname, hostname
            signatures: COWRIE_SYSTEM_SIGNATURES dictionary

        Returns:
            List of (signature_name, details) tuples for matches
        """
        matches = []

        # Check kernel version in proc_version or uname
        kernel_sig = signatures.get("kernel_version", "")
        if kernel_sig:
            if kernel_sig in system_info.get("proc_version", ""):
                matches.append(
                    ("kernel_version", f"Cowrie default kernel: {kernel_sig}")
                )
            elif kernel_sig in system_info.get("uname", ""):
                matches.append(
                    ("kernel_version", f"Cowrie default kernel in uname: {kernel_sig}")
                )

        # Check full kernel string
        kernel_full = signatures.get("kernel_full", "")
        if kernel_full and kernel_full in system_info.get("proc_version", ""):
            matches.append(
                ("kernel_full", "Exact Cowrie /proc/version match")
            )

        # Check hostname
        hostname_sig = signatures.get("hostname", "")
        if hostname_sig and system_info.get("hostname", "") == hostname_sig:
            matches.append(
                ("hostname", f"Cowrie default hostname: {hostname_sig}")
            )

        # Check for default user in system info
        default_user = signatures.get("default_user", "")
        if default_user:
            for info in system_info.values():
                if default_user in info:
                    matches.append(
                        ("default_user", f"Cowrie default user found: {default_user}")
                    )
                    break

        # Check CPU model
        cpu_model = signatures.get("cpu_model", "")
        if cpu_model:
            for info in system_info.values():
                if cpu_model in info:
                    matches.append(
                        ("cpu_model", f"Cowrie default CPU: {cpu_model}")
                    )
                    break

        return matches

    def _probe_post_auth_commands(self, client: "paramiko.SSHClient") -> List[Indicator]:
        """Run comprehensive detection commands after successful SSH auth.

        Tests filesystem anomalies, command behavior, and static output patterns
        that are characteristic of Cowrie/Kippo honeypots.

        Args:
            client: Connected and authenticated paramiko SSHClient

        Returns:
            List of Indicator objects for detected honeypot signs
        """
        import time

        indicators: List[Indicator] = []

        def exec_cmd(cmd: str) -> str:
            """Execute command and return output."""
            try:
                stdin, stdout, stderr = client.exec_command(cmd, timeout=self.timeout)
                return stdout.read().decode("utf-8", errors="ignore").strip()
            except Exception:
                return ""

        # Test /proc/self/exe - DEFINITE detection (Cowrie returns "No such file")
        proc_self_output = exec_cmd("cat /proc/self/exe 2>&1")
        if "No such file" in proc_self_output or proc_self_output == "":
            indicators.append(
                Indicator(
                    name="proc_self_exe_missing",
                    description="/proc/self/exe not accessible (Cowrie signature)",
                    severity=Confidence.DEFINITE,
                    details="Real systems return binary data, honeypots fail",
                )
            )

        # Test file /proc/self/exe - DEFINITE detection
        file_proc_output = exec_cmd("file /proc/self/exe 2>&1")
        if "cannot open" in file_proc_output or "No such file" in file_proc_output:
            indicators.append(
                Indicator(
                    name="file_proc_self_exe_fails",
                    description="'file /proc/self/exe' fails (Cowrie signature)",
                    severity=Confidence.DEFINITE,
                )
            )

        # Test 'which' command - MEDIUM (returns empty in Cowrie)
        which_ls = exec_cmd("which ls")
        if which_ls == "":
            indicators.append(
                Indicator(
                    name="which_returns_empty",
                    description="'which ls' returns nothing (honeypot shell limitation)",
                    severity=Confidence.MEDIUM,
                )
            )

        # Test for default Cowrie users in /etc/passwd - HIGH
        passwd_output = exec_cmd("cat /etc/passwd")
        for user in ["phil", "richard"]:
            if f"{user}:" in passwd_output:
                indicators.append(
                    Indicator(
                        name=f"default_user_{user}",
                        description=f"Default Cowrie user '{user}' found in /etc/passwd",
                        severity=Confidence.HIGH,
                    )
                )

        # Test uname for known Cowrie signatures - HIGH
        uname_output = exec_cmd("uname -a")
        if "3.2.0-4-amd64" in uname_output and "Debian 3.2.68" in uname_output:
            indicators.append(
                Indicator(
                    name="cowrie_default_kernel",
                    description="Default Cowrie kernel version in uname -a",
                    severity=Confidence.HIGH,
                    details=uname_output[:100],
                )
            )

        # Test for static zero load average - DEFINITE
        uptime_output = exec_cmd("uptime")
        if "0.00, 0.00, 0.00" in uptime_output:
            indicators.append(
                Indicator(
                    name="static_zero_load",
                    description="Load average always 0.00 (static honeypot environment)",
                    severity=Confidence.DEFINITE,
                )
            )

        # Test for static output (run 'free -m' twice and compare) - MEDIUM
        free_output1 = exec_cmd("free -m")
        time.sleep(0.5)
        free_output2 = exec_cmd("free -m")
        if free_output1 == free_output2 and "Mem:" in free_output1 and free_output1 != "":
            indicators.append(
                Indicator(
                    name="static_free_output",
                    description="'free -m' output identical across calls (static environment)",
                    severity=Confidence.MEDIUM,
                )
            )

        # Test for missing commands - MEDIUM
        missing_commands = []
        for cmd in ["openssl version", "strace -V", "lsof -v"]:
            output = exec_cmd(cmd + " 2>&1")
            if "command not found" in output.lower() or "not found" in output.lower():
                missing_commands.append(cmd.split()[0])

        if len(missing_commands) >= 2:
            indicators.append(
                Indicator(
                    name="missing_common_commands",
                    description=f"Common commands missing: {', '.join(missing_commands)}",
                    severity=Confidence.MEDIUM,
                    details="Honeypots often have limited command sets",
                )
            )

        # Test /home directory for default users - HIGH
        home_output = exec_cmd("ls /home/")
        if "richard" in home_output or "phil" in home_output:
            indicators.append(
                Indicator(
                    name="default_home_dirs",
                    description="Default Cowrie user home directories found",
                    severity=Confidence.HIGH,
                    details=home_output,
                )
            )

        # Test /proc/net/arp for empty ARP table - MEDIUM
        arp_output = exec_cmd("cat /proc/net/arp")
        if arp_output.strip() == "" or (arp_output and arp_output.count("\n") == 0):
            indicators.append(
                Indicator(
                    name="empty_arp_table",
                    description="Empty or minimal ARP table (isolated honeypot environment)",
                    severity=Confidence.MEDIUM,
                )
            )

        return indicators

    def _probe_invalid_payloads(self, target: str, port: int) -> List[Indicator]:
        """Send invalid SSH payloads and check for uniform responses.

        Honeypots often return the same error message for different
        invalid inputs, while real SSH servers may vary their responses.

        Args:
            target: IP address or hostname
            port: SSH port

        Returns:
            List of Indicator objects if uniform response detected
        """
        indicators: List[Indicator] = []

        from potsnitch.probes.credentials import SSH_INVALID_PAYLOADS

        responses = []

        for payload in SSH_INVALID_PAYLOADS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((target, port))

                # Read server banner first
                sock.recv(256)

                # Send invalid payload
                sock.send(payload)

                # Collect response
                try:
                    response = sock.recv(1024)
                    response_str = response.decode("utf-8", errors="ignore").strip()
                    responses.append(response_str)
                except (socket.timeout, OSError):
                    responses.append("")

                sock.close()

            except (socket.error, socket.timeout, OSError):
                responses.append("")
                continue

        # Check if all non-empty responses are identical (uniform response)
        non_empty = [r for r in responses if r]
        if len(non_empty) >= 2:
            unique_responses = set(non_empty)
            if len(unique_responses) == 1:
                indicators.append(
                    Indicator(
                        name="uniform_error_response",
                        description="SSH server returns uniform errors for different invalid payloads",
                        severity=Confidence.MEDIUM,
                        details=f"All {len(non_empty)} payloads got same response: {non_empty[0][:100]}",
                    )
                )

        return indicators

    def validate(self, target: str, port: int) -> DetectionResult:
        """Run comprehensive validation for defensive testing."""
        result = self.detect(target, port)

        # Additional validation checks
        # Check if both 22 and 2222 are running SSH
        from potsnitch.utils.network import is_port_open

        if port == 22 and is_port_open(target, 2222, self.timeout):
            result.add_indicator(
                Indicator(
                    name="dual_ssh_ports",
                    description="Both port 22 and 2222 running SSH",
                    severity=Confidence.MEDIUM,
                    details="Cowrie commonly uses port redirection from 22 to 2222",
                )
            )
        elif port == 2222 and is_port_open(target, 22, self.timeout):
            result.add_indicator(
                Indicator(
                    name="dual_ssh_ports",
                    description="Both port 22 and 2222 running SSH",
                    severity=Confidence.MEDIUM,
                    details="Cowrie commonly uses port redirection from 22 to 2222",
                )
            )

        return result

    def get_recommendations(self, result: DetectionResult) -> list[str]:
        """Get remediation recommendations for Cowrie/Kippo."""
        recommendations = []

        for indicator in result.indicators:
            if indicator.name == "default_banner":
                recommendations.append(
                    "Customize SSH banner in cowrie.cfg [ssh] section: 'version = SSH-2.0-OpenSSH_8.9p1'"
                )
            elif indicator.name == "default_port":
                recommendations.append(
                    "Use iptables to redirect port 22 to 2222 instead of exposing 2222 directly"
                )
            elif indicator.name == "cowrie_ciphers" or indicator.name == "twisted_cipher_order":
                recommendations.append(
                    "Consider using OpenSSH as frontend (docs.cowrie.org) to mask TwistedConch signatures"
                )
            elif indicator.name == "kippo_cr_probe":
                recommendations.append(
                    "Upgrade from Kippo to Cowrie - Kippo is unmaintained and easily fingerprinted"
                )
            elif indicator.name == "dual_ssh_ports":
                recommendations.append(
                    "Ensure port 2222 is not directly exposed - use iptables NAT redirection"
                )

        return recommendations
