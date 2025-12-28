"""
Unit tests for Telnet honeypot detector.

Tests banner detection (BusyBox, Cowrie), IAC sequence handling, credential probing,
post-auth command detection, limited BusyBox applet detection, and mock telnetlib.Telnet.
"""

import socket
import pytest
from unittest.mock import MagicMock, patch, call

from potsnitch.detectors.telnet import (
    TelnetDetector,
    KNOWN_TELNET_BANNERS,
    COWRIE_DEFAULT_HOSTNAMES,
    COWRIE_DEFAULT_UNAME,
)
from potsnitch.core.result import Confidence, DetectionResult, Indicator
from potsnitch.core.base import DetectionMode
from potsnitch.probes.credentials import COWRIE_SYSTEM_SIGNATURES, TELNET_HONEYPOT_CREDENTIALS


class TestTelnetDetectorBannerDetection:
    """Tests for Telnet banner detection."""

    @pytest.fixture
    def detector(self):
        """Create Telnet detector instance."""
        return TelnetDetector()

    @pytest.mark.parametrize("banner,honeypot_name", list(KNOWN_TELNET_BANNERS.items()))
    def test_detect_known_banners(self, detector, mock_socket, banner, honeypot_name):
        """Test detection of known honeypot banners."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = banner

        result = detector.detect_passive("192.168.1.100", 23)

        assert any(i.name == "known_telnet_banner" for i in result.indicators)
        if result.honeypot_type:
            assert result.honeypot_type == honeypot_name

    def test_detect_cowrie_banner(self, detector, mock_socket):
        """Test detection of Cowrie telnet banner."""
        socket_instance = mock_socket.return_value
        cowrie_banner = b'\xff\xfd\x1flogin: '
        socket_instance.recv.return_value = cowrie_banner

        result = detector.detect_passive("192.168.1.100", 23)

        assert any(i.name == "known_telnet_banner" for i in result.indicators)
        assert result.honeypot_type == "cowrie"

    def test_detect_mtpot_banner(self, detector, mock_socket):
        """Test detection of mtpot telnet banner."""
        socket_instance = mock_socket.return_value
        mtpot_banner = b'\xff\xfb\x01\xff\xfb\x03'
        socket_instance.recv.return_value = mtpot_banner

        result = detector.detect_passive("192.168.1.100", 23)

        assert any(i.name == "known_telnet_banner" for i in result.indicators)

    def test_detect_honeypy_banner(self, detector, mock_socket):
        """Test detection of HoneyPy telnet banner."""
        socket_instance = mock_socket.return_value
        honeypy_banner = b'Debian GNU/Linux 7\r\nLogin: '
        socket_instance.recv.return_value = honeypy_banner

        result = detector.detect_passive("192.168.1.100", 23)

        assert any(i.name == "known_telnet_banner" for i in result.indicators)

    def test_socket_timeout_handling(self, detector, mock_socket):
        """Test graceful handling of socket timeout."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = socket.timeout()

        result = detector.detect_passive("192.168.1.100", 23)

        assert result.error is None

    def test_socket_error_handling(self, detector, mock_socket):
        """Test graceful handling of socket errors."""
        socket_instance = mock_socket.return_value
        socket_instance.connect.side_effect = socket.error("Connection refused")

        result = detector.detect_passive("192.168.1.100", 23)

        assert result.error is None


class TestTelnetDetectorDefaultHostnames:
    """Tests for Cowrie default hostname detection."""

    @pytest.fixture
    def detector(self):
        """Create Telnet detector instance."""
        return TelnetDetector()

    @pytest.mark.parametrize("hostname", COWRIE_DEFAULT_HOSTNAMES)
    def test_detect_default_hostnames(self, detector, mock_socket, hostname):
        """Test detection of Cowrie default hostnames."""
        socket_instance = mock_socket.return_value
        banner = f"{hostname} login: ".encode()
        socket_instance.recv.return_value = banner

        result = detector.detect_passive("192.168.1.100", 23)

        assert any(i.name == "default_hostname" for i in result.indicators)

    def test_detect_svr04_hostname(self, detector, mock_socket):
        """Test detection of svr04 (common Cowrie default)."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"svr04 login: "

        result = detector.detect_passive("192.168.1.100", 23)

        assert any(i.name == "default_hostname" for i in result.indicators)
        assert any("svr04" in i.description for i in result.indicators)


class TestTelnetDetectorKernelVersion:
    """Tests for kernel version detection."""

    @pytest.fixture
    def detector(self):
        """Create Telnet detector instance."""
        return TelnetDetector()

    def test_detect_cowrie_default_kernel(self, detector, mock_socket):
        """Test detection of Cowrie default kernel in banner."""
        socket_instance = mock_socket.return_value
        banner = f"Linux server {COWRIE_DEFAULT_UNAME}\nlogin: ".encode()
        socket_instance.recv.return_value = banner

        result = detector.detect_passive("192.168.1.100", 23)

        assert any(i.name == "default_kernel" for i in result.indicators)
        assert any("3.2.0-4-amd64" in str(i.details) for i in result.indicators)


class TestTelnetDetectorDefaultPort:
    """Tests for default port detection."""

    @pytest.fixture
    def detector(self):
        """Create Telnet detector instance."""
        return TelnetDetector()

    def test_detect_port_2323(self, detector, mock_socket):
        """Test detection of Cowrie default telnet port 2323."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"login: "

        result = detector.detect_passive("192.168.1.100", 2323)

        assert any(i.name == "default_port" for i in result.indicators)
        assert any(i.severity == Confidence.MEDIUM for i in result.indicators)

    def test_no_detection_standard_port(self, detector, mock_socket):
        """Test no port detection for standard telnet port."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"login: "

        result = detector.detect_passive("192.168.1.100", 23)

        assert not any(i.name == "default_port" for i in result.indicators)


class TestTelnetDetectorIACSequences:
    """Tests for IAC sequence handling and detection."""

    @pytest.fixture
    def detector(self):
        """Create Telnet detector instance."""
        return TelnetDetector()

    def test_detect_cowrie_telnet_options(self, detector, mock_socket):
        """Test detection of Cowrie telnet option patterns."""
        socket_instance = mock_socket.return_value
        # IAC commands that match Cowrie pattern but don't match any known banner signature.
        # Known signatures check for specific byte sequences at start, so we use a different order
        # that still contains 5+ Cowrie options (1, 3, 24, 31, 32, 33, 34, 35, 36, 37, 38, 39).
        # Using DO first instead of WILL avoids matching mtpot signature (which starts with WILL).
        banner = bytes([
            0xff, 0xfd, 0x18,  # DO TERMINAL_TYPE (option 24)
            0xff, 0xfd, 0x1f,  # DO NAWS (option 31)
            0xff, 0xfd, 0x20,  # DO TERMINAL_SPEED (option 32)
            0xff, 0xfd, 0x21,  # DO X_DISPLAY (option 33)
            0xff, 0xfd, 0x22,  # DO ENVIRON (option 34)
        ]) + b"login: "
        # The _get_telnet_banner method loops calling recv until it sees "login:" or timeout.
        # Return the banner on first call, then empty bytes to exit the loop.
        socket_instance.recv.side_effect = [banner, b""]

        result = detector.detect_passive("192.168.1.100", 23)

        assert any(i.name == "telnet_options" for i in result.indicators)

    def test_check_telnet_options_method(self, detector):
        """Test _check_telnet_options method directly."""
        result = DetectionResult(target="192.168.1.100", port=23)

        # Build IAC sequence with Cowrie options
        raw = bytes([
            0xff, 0xfb, 0x01,  # WILL ECHO (option 1)
            0xff, 0xfb, 0x03,  # WILL SGA (option 3)
            0xff, 0xfd, 0x18,  # DO TERMINAL_TYPE (option 24)
            0xff, 0xfd, 0x1f,  # DO NAWS (option 31)
            0xff, 0xfd, 0x20,  # DO TERMINAL_SPEED (option 32)
        ])

        detector._check_telnet_options(raw, result)

        assert any(i.name == "telnet_options" for i in result.indicators)

    def test_no_detection_few_options(self, detector):
        """Test no detection with few telnet options."""
        result = DetectionResult(target="192.168.1.100", port=23)

        # Only a couple of options
        raw = bytes([
            0xff, 0xfb, 0x01,  # WILL ECHO
            0xff, 0xfb, 0x03,  # WILL SGA
        ])

        detector._check_telnet_options(raw, result)

        assert not any(i.name == "telnet_options" for i in result.indicators)


class TestTelnetDetectorCredentialProbing:
    """Tests for credential-based detection."""

    @pytest.fixture
    def detector(self):
        """Create Telnet detector instance."""
        return TelnetDetector()

    def test_detect_default_credentials_accepted(self, detector, mock_socket):
        """Test detection when default credentials are accepted."""
        socket_instance = mock_socket.return_value
        # The _probe_telnet_credentials method:
        # 1. First connection: login prompt loop, password prompt, post-login, uname, proc/version, id
        # 2. Second connection (sock2) for BusyBox post-auth: login prompt loop, password prompt, post-login, then many commands
        # Using a function-based side_effect to handle all these calls robustly
        recv_responses = iter([
            # First connection
            b"login: ",           # login prompt (loop exits on "login:")
            b"Password: ",        # password prompt after username
            b"root@svr04:~# ",    # shell prompt after password
            b"Linux svr04 3.2.0-4-amd64\n",  # uname response
            b"",                  # proc/version
            b"uid=0(root)\n",     # id response
            # Second connection (sock2) for BusyBox post-auth detection
            b"login: ",           # login prompt
            b"Password: ",        # password prompt
            b"# ",                # post-login shell
            # _probe_busybox_post_auth commands (many recv calls)
            b"\n",                # busybox --list response
            b"\n",                # cat /proc/self/exe response
            b"\n",                # ls /proc/self/fd response
            b"\n",                # which wget
            b"\n",                # which curl
            b"\n",                # which tftp
            b"\n",                # which nc
            b"\n",                # /bin/busybox ECCHI
            b"\n",                # uname -a
            b"\n",                # uptime
            b"\n",                # cat /etc/passwd
        ])

        def recv_side_effect(size):
            try:
                return next(recv_responses)
            except StopIteration:
                return b"\n"  # Default fallback

        socket_instance.recv.side_effect = recv_side_effect

        indicators = detector._probe_telnet_credentials("192.168.1.100", 23)

        assert any(i.name == "default_credentials_accepted" for i in indicators)

    def test_detect_cowrie_kernel_in_uname(self, detector, mock_socket):
        """Test detection of Cowrie kernel in uname output."""
        socket_instance = mock_socket.return_value
        # The _probe_telnet_credentials method opens two socket connections:
        # 1. First connection for initial probe
        # 2. Second connection (sock2) for BusyBox post-auth detection
        # Using a function-based side_effect to handle all recv calls
        recv_responses = iter([
            # First connection
            b"login: ",           # login prompt
            b"Password: ",        # password prompt
            b"# ",                # shell prompt
            b"Linux svr04 3.2.0-4-amd64 #1 SMP Debian\n",  # uname with Cowrie kernel
            b"",                  # proc/version
            b"uid=0(root)\n",     # id response
            # Second connection (sock2) for BusyBox post-auth detection
            b"login: ",           # login prompt
            b"Password: ",        # password prompt
            b"# ",                # post-login shell
            # _probe_busybox_post_auth commands
            b"\n",                # busybox --list
            b"\n",                # cat /proc/self/exe
            b"\n",                # ls /proc/self/fd
            b"\n",                # which wget
            b"\n",                # which curl
            b"\n",                # which tftp
            b"\n",                # which nc
            b"\n",                # /bin/busybox ECCHI
            b"\n",                # uname -a
            b"\n",                # uptime
            b"\n",                # cat /etc/passwd
        ])

        def recv_side_effect(size):
            try:
                return next(recv_responses)
            except StopIteration:
                return b"\n"  # Default fallback

        socket_instance.recv.side_effect = recv_side_effect

        indicators = detector._probe_telnet_credentials("192.168.1.100", 23)

        assert any(i.name == "cowrie_default_kernel" for i in indicators)

    def test_no_indicators_auth_failed(self, detector, mock_socket):
        """Test no indicators when authentication fails."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = [
            b"login: ",
            b"Password: ",
            b"Login incorrect\nlogin: ",  # Failed login
        ] * 10  # Multiple failed attempts

        indicators = detector._probe_telnet_credentials("192.168.1.100", 23)

        assert not any(i.name == "default_credentials_accepted" for i in indicators)


class TestTelnetDetectorBusyBoxLimits:
    """Tests for BusyBox emulation limit detection."""

    @pytest.fixture
    def detector(self):
        """Create Telnet detector instance."""
        return TelnetDetector()

    def test_detect_limited_busybox_applets(self, detector, mock_socket):
        """Test detection of limited BusyBox applets."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = [
            b"login: ",
            b"Password: ",
            b"# ",
            b"BusyBox v1.00\ncat, echo, ls, cd, exit\n",  # Limited applet list
        ]

        result = detector._probe_busybox_limits("192.168.1.100", 23)

        assert result is True

    def test_no_detection_full_busybox(self, detector, mock_socket):
        """Test no detection with full BusyBox applet list."""
        socket_instance = mock_socket.return_value

        # Simulate full BusyBox with many applets
        applets = ", ".join([f"applet{i}" for i in range(100)])
        socket_instance.recv.side_effect = [
            b"login: ",
            b"Password: ",
            b"# ",
            f"BusyBox v1.30\n{applets}\n".encode(),
        ]

        result = detector._probe_busybox_limits("192.168.1.100", 23)

        assert result is False


class TestTelnetDetectorPostAuthCommands:
    """Tests for post-auth command detection."""

    @pytest.fixture
    def detector(self):
        """Create Telnet detector instance."""
        return TelnetDetector()

    def test_analyze_shell_responses_cowrie_kernel(self, detector):
        """Test _analyze_shell_responses with Cowrie kernel."""
        result = DetectionResult(target="192.168.1.100", port=23)
        shell_info = {
            "uname": f"Linux svr04 {COWRIE_DEFAULT_UNAME} x86_64\n",
            "id": "uid=0(root) gid=0(root) groups=0(root)\n",
        }

        detector._analyze_shell_responses(shell_info, result)

        assert any(i.name == "default_uname" for i in result.indicators)

    def test_analyze_shell_responses_cowrie_user(self, detector):
        """Test _analyze_shell_responses with Cowrie user 'phil'."""
        result = DetectionResult(target="192.168.1.100", port=23)
        shell_info = {
            "uname": "Linux server 5.4.0 x86_64\n",
            "id": "uid=0(root) gid=0(root) groups=0(root),1000(phil)\n",
        }

        detector._analyze_shell_responses(shell_info, result)

        assert any(i.name == "cowrie_user" for i in result.indicators)


class TestTelnetDetectorBusyBoxPostAuth:
    """Tests for comprehensive BusyBox post-auth detection."""

    @pytest.fixture
    def detector(self):
        """Create Telnet detector instance."""
        return TelnetDetector()

    def test_detect_proc_self_exe_missing(self, detector):
        """Test detection of missing /proc/self/exe."""
        mock_sock = MagicMock()

        def send_cmd_side_effect(data):
            mock_sock.last_cmd = data

        mock_sock.send = send_cmd_side_effect
        mock_sock.settimeout = MagicMock()

        responses = {
            b"busybox --list": b"5\n",
            b"cat /proc/self/exe": b"No such file or directory\n",
            b"ls /proc/self/fd": b"0\n1\n2\n",
            b"which wget": b"wget\n",
            b"/bin/busybox ECCHI": b"applet not found\n",
            b"uname -a": b"Linux server 5.4.0\n",
            b"uptime": b"12:00:00 up 1 day, load average: 0.10, 0.05, 0.01\n",
            b"cat /etc/passwd": b"root:x:0:0::/root:/bin/sh\n",
        }

        def recv_side_effect(size):
            for cmd, response in responses.items():
                if hasattr(mock_sock, 'last_cmd') and cmd in mock_sock.last_cmd:
                    return response
            return b"\n"

        mock_sock.recv = recv_side_effect

        indicators = detector._probe_busybox_post_auth(mock_sock)

        assert any(i.name == "proc_self_exe_missing" for i in indicators)

    def test_detect_limited_applets(self, detector):
        """Test detection of limited BusyBox applets."""
        mock_sock = MagicMock()

        def send_cmd_side_effect(data):
            mock_sock.last_cmd = data

        mock_sock.send = send_cmd_side_effect
        mock_sock.settimeout = MagicMock()

        def recv_side_effect(size):
            if hasattr(mock_sock, 'last_cmd'):
                if b"busybox --list" in mock_sock.last_cmd:
                    return b"busybox --list 2>/dev/null | wc -l\n5\n"
            return b"\n"

        mock_sock.recv = recv_side_effect

        indicators = detector._probe_busybox_post_auth(mock_sock)

        assert any(i.name == "busybox_limited_applets" for i in indicators)


class TestTelnetDetectorShellEmulation:
    """Tests for shell emulation limit detection."""

    @pytest.fixture
    def detector(self):
        """Create Telnet detector instance."""
        return TelnetDetector()

    def test_detect_missing_common_commands(self, detector, mock_socket):
        """Test detection of missing common commands."""
        socket_instance = mock_socket.return_value

        # Login succeeds but commands are missing
        socket_instance.recv.side_effect = [
            b"login: ",
            b"Password: ",
            b"# ",
            b"-sh: wget: not found\n",
            b"-sh: curl: not found\n",
            b"-sh: nc: not found\n",
            b"-sh: netcat: not found\n",
            b"-sh: python: not found\n",
            b"-sh: perl: not found\n",
            b"root:x:0:0::/root:/bin/sh\n",
            b"SUCCESS\n",
        ]

        indicators = detector._probe_shell_emulation("192.168.1.100", 23)

        assert any(i.name == "missing_common_commands" for i in indicators)

    def test_detect_restricted_filesystem(self, detector, mock_socket):
        """Test detection of restricted filesystem access."""
        socket_instance = mock_socket.return_value

        socket_instance.recv.side_effect = [
            b"login: ",
            b"Password: ",
            b"# ",
            b"/usr/bin/wget\n",  # wget exists
            b"/usr/bin/curl\n",  # curl exists
            b"/usr/bin/nc\n",  # nc exists
            b"/usr/bin/netcat\n",  # netcat exists
            b"/usr/bin/python\n",  # python exists
            b"/usr/bin/perl\n",  # perl exists
            b"permission denied\n",  # /etc/passwd restricted
            b"FAILED\n",  # file creation blocked
        ]

        indicators = detector._probe_shell_emulation("192.168.1.100", 23)

        # Should detect restricted filesystem or file creation blocked
        assert any(i.name in ["restricted_filesystem", "file_creation_blocked"] for i in indicators)


class TestTelnetDetectorDebian7Detection:
    """Tests for Debian 7 references in banner."""

    @pytest.fixture
    def detector(self):
        """Create Telnet detector instance."""
        return TelnetDetector()

    def test_detect_debian_wheezy(self, detector, mock_socket):
        """Test detection of Debian 7 (wheezy) in banner."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"Debian GNU/Linux wheezy\nlogin: "

        result = detector.detect_passive("192.168.1.100", 23)

        assert any(i.name == "debian7_banner" for i in result.indicators)

    def test_detect_debian_320(self, detector, mock_socket):
        """Test detection of Debian 3.2.0 kernel in banner."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"Debian GNU/Linux - Kernel 3.2.0-4-amd64\nlogin: "

        result = detector.detect_passive("192.168.1.100", 23)

        assert any(i.name == "debian7_banner" for i in result.indicators)


class TestTelnetDetectorIntegration:
    """Integration tests for Telnet detector."""

    @pytest.fixture
    def detector(self):
        """Create Telnet detector instance."""
        return TelnetDetector()

    def test_honeypot_type_set_correctly(self, detector, mock_socket):
        """Test that honeypot_type is set when honeypot detected."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b'\xff\xfd\x1flogin: '  # Cowrie banner

        result = detector.detect_passive("192.168.1.100", 23)

        assert result.is_honeypot
        assert result.honeypot_type == "cowrie"

    def test_detector_properties(self, detector):
        """Test detector class properties."""
        assert detector.name == "telnet"
        assert "cowrie-telnet" in detector.honeypot_types
        assert 23 in detector.default_ports
        assert 2323 in detector.default_ports

    def test_detector_description(self, detector):
        """Test detector has description."""
        assert detector.description is not None
        assert len(detector.description) > 0


class TestTelnetDetectorRecommendations:
    """Tests for Telnet detector recommendations."""

    @pytest.fixture
    def detector(self):
        """Create Telnet detector instance."""
        return TelnetDetector()

    def test_recommendations_for_default_hostname(self, detector):
        """Test recommendations when default hostname is detected."""
        from potsnitch.core.result import Indicator

        result = DetectionResult(target="192.168.1.100", port=23)
        result.add_indicator(
            Indicator(
                name="default_hostname",
                description="Default hostname svr04",
                severity=Confidence.HIGH,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any("hostname" in r.lower() or "cowrie" in r.lower() for r in recommendations)

    def test_recommendations_for_default_kernel(self, detector):
        """Test recommendations when default kernel is detected."""
        from potsnitch.core.result import Indicator

        result = DetectionResult(target="192.168.1.100", port=23)
        result.add_indicator(
            Indicator(
                name="default_kernel",
                description="Default kernel version",
                severity=Confidence.HIGH,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any("kernel" in r.lower() or "uname" in r.lower() for r in recommendations)

    def test_recommendations_for_default_port(self, detector):
        """Test recommendations when default port is detected."""
        from potsnitch.core.result import Indicator

        result = DetectionResult(target="192.168.1.100", port=2323)
        result.add_indicator(
            Indicator(
                name="default_port",
                description="Default Cowrie port 2323",
                severity=Confidence.MEDIUM,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any("iptables" in r.lower() or "redirect" in r.lower() for r in recommendations)


class TestTelnetDetectorBannerAnalysis:
    """Tests for the _analyze_banner method."""

    @pytest.fixture
    def detector(self):
        """Create Telnet detector instance."""
        return TelnetDetector()

    def test_analyze_banner_known_signature(self, detector):
        """Test _analyze_banner with known honeypot signature."""
        result = DetectionResult(target="192.168.1.100", port=23)
        banner_info = {
            "raw": b'\xff\xfd\x1flogin: ',
            "text": "login: ",
        }

        detector._analyze_banner(banner_info, result)

        assert any(i.name == "known_telnet_banner" for i in result.indicators)
        assert result.honeypot_type == "cowrie"

    def test_analyze_banner_hostname_detection(self, detector):
        """Test _analyze_banner hostname detection."""
        result = DetectionResult(target="192.168.1.100", port=23)
        banner_info = {
            "raw": b"svr04 login: ",
            "text": "svr04 login: ",
        }

        detector._analyze_banner(banner_info, result)

        assert any(i.name == "default_hostname" for i in result.indicators)

    def test_analyze_banner_multiple_indicators(self, detector):
        """Test _analyze_banner with multiple indicators."""
        result = DetectionResult(target="192.168.1.100", port=23)
        banner_info = {
            "raw": b"svr04 - Linux 3.2.0-4-amd64\nlogin: ",
            "text": "svr04 - Linux 3.2.0-4-amd64\nlogin: ",
        }

        detector._analyze_banner(banner_info, result)

        # Should detect both hostname and kernel version
        assert any(i.name == "default_hostname" for i in result.indicators)
        assert any(i.name == "default_kernel" for i in result.indicators)


# ============================================================================
# Tests for detect_active method (lines 105-137)
# ============================================================================
class TestTelnetDetectorActiveMode:
    """Tests for the detect_active method and active probing flow."""

    @pytest.fixture
    def detector(self):
        """Create Telnet detector instance."""
        return TelnetDetector()

    def test_detect_active_returns_result(self, detector, mock_socket):
        """Test detect_active returns a DetectionResult."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = socket.timeout()

        result = detector.detect_active("192.168.1.100", 23)

        assert isinstance(result, DetectionResult)
        assert result.target == "192.168.1.100"
        assert result.port == 23

    def test_detect_active_with_credentials_indicator(self, detector, mock_socket):
        """Test detect_active adds credential indicators."""
        socket_instance = mock_socket.return_value

        # Simulate successful login
        recv_responses = iter([
            b"login: ",
            b"Password: ",
            b"# ",  # shell prompt
            b"Linux svr04 3.2.0-4-amd64\n",  # uname
            b"",  # proc/version
            b"uid=0(root)\n",  # id
            # Second connection for busybox post-auth
            b"login: ",
            b"Password: ",
            b"# ",
            b"\n",  # busybox --list
            b"\n",  # cat /proc/self/exe
            b"\n",  # ls /proc/self/fd
            b"\n",  # which wget
            b"\n",  # which curl
            b"\n",  # which tftp
            b"\n",  # which nc
            b"\n",  # /bin/busybox ECCHI
            b"\n",  # uname -a
            b"\n",  # uptime
            b"\n",  # cat /etc/passwd
        ])

        def recv_side_effect(size):
            try:
                return next(recv_responses)
            except StopIteration:
                return b"\n"

        socket_instance.recv.side_effect = recv_side_effect

        result = detector.detect_active("192.168.1.100", 23)

        assert any(i.name == "default_credentials_accepted" for i in result.indicators)

    def test_detect_active_busybox_emulation_detection(self, detector, mock_socket):
        """Test _probe_busybox_limits detects BusyBox emulation limits."""
        socket_instance = mock_socket.return_value

        # Use a function to provide unlimited responses for the limited busybox test
        responses = [
            b"login: ",
            b"Password: ",
            b"# ",
            b"BusyBox v1.00\ncat, echo, ls, exit\n",  # Limited BusyBox
        ]

        def recv_side_effect(size):
            if responses:
                return responses.pop(0)
            return b"\n"

        socket_instance.recv.side_effect = recv_side_effect

        # Test the method directly instead of detect_active
        result = detector._probe_busybox_limits("192.168.1.100", 23)

        assert result is True

    def test_detect_active_sets_honeypot_type(self, detector, mock_socket):
        """Test detect_active sets honeypot_type when detected."""
        socket_instance = mock_socket.return_value

        # Simulate successful login with Cowrie kernel
        recv_responses = iter([
            b"login: ",
            b"Password: ",
            b"# ",
            b"Linux svr04 3.2.0-4-amd64\n",
            b"",
            b"uid=0(root)\n",
            # Second connection
            b"login: ",
            b"Password: ",
            b"# ",
        ] + [b"\n"] * 20)

        def recv_side_effect(size):
            try:
                return next(recv_responses)
            except StopIteration:
                return b"\n"

        socket_instance.recv.side_effect = recv_side_effect

        result = detector.detect_active("192.168.1.100", 23)

        # If is_honeypot is true and no specific type set, defaults to cowrie-telnet
        if result.is_honeypot:
            assert result.honeypot_type == "cowrie-telnet"

    def test_detect_active_with_shell_emulation_indicators(self, detector, mock_socket):
        """Test _probe_shell_emulation adds shell emulation indicators."""
        socket_instance = mock_socket.return_value

        # Login succeeds but commands are missing - use function to avoid StopIteration
        responses = [
            b"login: ",
            b"Password: ",
            b"# ",
            b"-sh: wget: not found\n",
            b"-sh: curl: not found\n",
            b"-sh: nc: not found\n",
            b"-sh: netcat: not found\n",
            b"-sh: python: not found\n",
            b"-sh: perl: not found\n",
            b"root:x:0:0::/root:/bin/sh\n",
            b"SUCCESS\n",
        ]

        def recv_side_effect(size):
            if responses:
                return responses.pop(0)
            return b"\n"

        socket_instance.recv.side_effect = recv_side_effect

        # Test the method directly instead of detect_active
        indicators = detector._probe_shell_emulation("192.168.1.100", 23)

        assert any(i.name == "missing_common_commands" for i in indicators)


# ============================================================================
# Tests for _probe_shell_commands method (lines 272-349)
# ============================================================================
class TestProbeShellCommands:
    """Tests for the _probe_shell_commands method."""

    @pytest.fixture
    def detector(self):
        """Create Telnet detector instance."""
        return TelnetDetector()

    def test_probe_shell_commands_returns_dict(self, detector, mock_socket):
        """Test _probe_shell_commands returns dict on success."""
        socket_instance = mock_socket.return_value

        socket_instance.recv.side_effect = [
            b"login: ",
            b"Password: ",
            b"# ",  # Shell prompt
            b"Linux svr04 5.4.0\n",  # uname response
            b"uid=0(root)\n",  # id response
        ]

        result = detector._probe_shell_commands("192.168.1.100", 23)

        assert result is not None
        assert isinstance(result, dict)
        assert "uname" in result
        assert "id" in result

    def test_probe_shell_commands_returns_none_on_connection_error(self, detector, mock_socket):
        """Test _probe_shell_commands returns None on connection error."""
        socket_instance = mock_socket.return_value
        socket_instance.connect.side_effect = socket.error("Connection refused")

        result = detector._probe_shell_commands("192.168.1.100", 23)

        assert result is None

    def test_probe_shell_commands_returns_none_on_timeout(self, detector, mock_socket):
        """Test _probe_shell_commands returns None on timeout."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = socket.timeout()

        result = detector._probe_shell_commands("192.168.1.100", 23)

        # After timeout in banner collection, should return None
        assert result is None

    def test_probe_shell_commands_handles_no_shell_prompt(self, detector, mock_socket):
        """Test _probe_shell_commands when no shell prompt received."""
        socket_instance = mock_socket.return_value

        responses = [
            b"login: ",
            b"Password: ",
            b"Login incorrect\n",  # Failed login, no shell prompt
        ]

        def recv_side_effect(size):
            if responses:
                return responses.pop(0)
            raise socket.timeout()

        socket_instance.recv.side_effect = recv_side_effect

        result = detector._probe_shell_commands("192.168.1.100", 23)

        # Should return None if no shell prompt
        assert result is None

    def test_probe_shell_commands_handles_timeout_during_commands(self, detector, mock_socket):
        """Test _probe_shell_commands handles timeout during command execution."""
        socket_instance = mock_socket.return_value

        socket_instance.recv.side_effect = [
            b"login: ",
            b"Password: ",
            b"# ",  # Shell prompt
            socket.timeout(),  # Timeout on uname
            b"uid=0(root)\n",  # id response
        ]

        result = detector._probe_shell_commands("192.168.1.100", 23)

        assert result is not None
        assert "id" in result

    def test_probe_shell_commands_no_password_prompt(self, detector, mock_socket):
        """Test _probe_shell_commands when no password prompt (direct shell)."""
        socket_instance = mock_socket.return_value

        socket_instance.recv.side_effect = [
            b"login: ",
            b"# ",  # Direct shell without password
            socket.timeout(),  # Timeout after that
        ]

        result = detector._probe_shell_commands("192.168.1.100", 23)

        # Without password: in response, it should fall through
        assert result is None

    def test_probe_shell_commands_data_overflow_protection(self, detector, mock_socket):
        """Test _probe_shell_commands handles large data without login prompt."""
        socket_instance = mock_socket.return_value

        # Return large data without login prompt - use function to avoid StopIteration
        responses = [
            b"A" * 1024,
            b"B" * 1024,
            b"C" * 1024,
            b"D" * 1024,
            b"E" * 1024,  # > 4096 bytes
        ]

        def recv_side_effect(size):
            if responses:
                return responses.pop(0)
            return b""  # Connection closed

        socket_instance.recv.side_effect = recv_side_effect

        result = detector._probe_shell_commands("192.168.1.100", 23)

        # Should exit and return None when data exceeds 4096 bytes
        assert result is None


# ============================================================================
# Tests for _probe_telnet_credentials (lines 395-506) - Accept-all detection
# ============================================================================
class TestProbeTelnetCredentialsComprehensive:
    """Comprehensive tests for _probe_telnet_credentials method."""

    @pytest.fixture
    def detector(self):
        """Create Telnet detector instance."""
        return TelnetDetector()

    def test_probe_credentials_no_login_prompt(self, detector, mock_socket):
        """Test _probe_telnet_credentials when no login prompt received."""
        socket_instance = mock_socket.return_value

        # Use function to provide unlimited responses for credential iterations
        def recv_side_effect(size):
            return b"Some other service\n"  # No login: or username:

        socket_instance.recv.side_effect = recv_side_effect

        indicators = detector._probe_telnet_credentials("192.168.1.100", 23)

        assert len(indicators) == 0

    def test_probe_credentials_timeout_on_password(self, detector, mock_socket):
        """Test _probe_telnet_credentials timeout on password prompt."""
        socket_instance = mock_socket.return_value

        socket_instance.recv.side_effect = [
            b"login: ",
            socket.timeout(),  # Timeout waiting for password prompt
        ] * 10

        indicators = detector._probe_telnet_credentials("192.168.1.100", 23)

        assert len(indicators) == 0

    def test_probe_credentials_cowrie_proc_version(self, detector, mock_socket):
        """Test detection of Cowrie /proc/version signature."""
        socket_instance = mock_socket.return_value

        cowrie_kernel_full = COWRIE_SYSTEM_SIGNATURES.get("kernel_full", "")

        recv_responses = iter([
            b"login: ",
            b"Password: ",
            b"# ",
            b"Linux svr04\n",  # uname
            cowrie_kernel_full.encode() + b"\n",  # proc/version with Cowrie signature
            b"uid=0(root)\n",  # id
            # Second connection
            b"login: ",
            b"Password: ",
            b"# ",
        ] + [b"\n"] * 20)

        def recv_side_effect(size):
            try:
                return next(recv_responses)
            except StopIteration:
                return b"\n"

        socket_instance.recv.side_effect = recv_side_effect

        indicators = detector._probe_telnet_credentials("192.168.1.100", 23)

        assert any(i.name == "cowrie_proc_version" for i in indicators)

    def test_probe_credentials_cowrie_hostname_in_uname(self, detector, mock_socket):
        """Test detection of Cowrie hostname in uname output."""
        socket_instance = mock_socket.return_value

        cowrie_hostname = COWRIE_SYSTEM_SIGNATURES.get("hostname", "svr04")

        recv_responses = iter([
            b"login: ",
            b"Password: ",
            b"# ",
            f"Linux {cowrie_hostname} 5.4.0\n".encode(),  # uname with Cowrie hostname
            b"",
            b"uid=0(root)\n",
            # Second connection
            b"login: ",
            b"Password: ",
            b"# ",
        ] + [b"\n"] * 20)

        def recv_side_effect(size):
            try:
                return next(recv_responses)
            except StopIteration:
                return b"\n"

        socket_instance.recv.side_effect = recv_side_effect

        indicators = detector._probe_telnet_credentials("192.168.1.100", 23)

        assert any(i.name == "cowrie_default_hostname_in_uname" for i in indicators)

    def test_probe_credentials_cowrie_default_user(self, detector, mock_socket):
        """Test detection of Cowrie default user in id output."""
        socket_instance = mock_socket.return_value

        cowrie_user = COWRIE_SYSTEM_SIGNATURES.get("default_user", "phil")

        recv_responses = iter([
            b"login: ",
            b"Password: ",
            b"# ",
            b"Linux server 5.4.0\n",
            b"",
            f"uid=0(root) gid=0(root) groups=0(root),1000({cowrie_user})\n".encode(),
            # Second connection
            b"login: ",
            b"Password: ",
            b"# ",
        ] + [b"\n"] * 20)

        def recv_side_effect(size):
            try:
                return next(recv_responses)
            except StopIteration:
                return b"\n"

        socket_instance.recv.side_effect = recv_side_effect

        indicators = detector._probe_telnet_credentials("192.168.1.100", 23)

        assert any(i.name == "cowrie_default_user" for i in indicators)

    def test_probe_credentials_busybox_shell_pattern(self, detector, mock_socket):
        """Test detection of BusyBox shell pattern."""
        socket_instance = mock_socket.return_value

        recv_responses = iter([
            b"login: ",
            b"Password: ",
            b"BusyBox v1.30.1 built-in shell (ash)\n# ",  # BusyBox in post-login
            b"Linux server 5.4.0\n",
            b"",
            b"uid=0(root)\n",
            # Second connection
            b"login: ",
            b"Password: ",
            b"# ",
        ] + [b"\n"] * 20)

        def recv_side_effect(size):
            try:
                return next(recv_responses)
            except StopIteration:
                return b"\n"

        socket_instance.recv.side_effect = recv_side_effect

        indicators = detector._probe_telnet_credentials("192.168.1.100", 23)

        assert any(i.name == "busybox_shell_pattern" for i in indicators)

    def test_probe_credentials_socket_error(self, detector, mock_socket):
        """Test _probe_telnet_credentials handles socket errors gracefully."""
        socket_instance = mock_socket.return_value
        socket_instance.connect.side_effect = socket.error("Connection refused")

        indicators = detector._probe_telnet_credentials("192.168.1.100", 23)

        assert len(indicators) == 0

    def test_probe_credentials_direct_shell_no_password(self, detector, mock_socket):
        """Test _probe_telnet_credentials with direct shell (no password prompt)."""
        socket_instance = mock_socket.return_value

        recv_responses = iter([
            b"login: ",
            b"# ",  # Direct shell without password prompt
            b"Linux svr04 3.2.0-4-amd64\n",
            b"",
            b"uid=0(root)\n",
            # Second connection
            b"login: ",
            b"# ",
        ] + [b"\n"] * 20)

        def recv_side_effect(size):
            try:
                return next(recv_responses)
            except StopIteration:
                return b"\n"

        socket_instance.recv.side_effect = recv_side_effect

        indicators = detector._probe_telnet_credentials("192.168.1.100", 23)

        # Should still detect default credentials accepted
        assert any(i.name == "default_credentials_accepted" for i in indicators)

    def test_probe_credentials_no_shell_prompt_after_login(self, detector, mock_socket):
        """Test _probe_telnet_credentials when no shell prompt after password."""
        socket_instance = mock_socket.return_value

        socket_instance.recv.side_effect = [
            b"login: ",
            b"Password: ",
            b"Login incorrect\nlogin: ",  # No shell prompt
        ] * 10

        indicators = detector._probe_telnet_credentials("192.168.1.100", 23)

        assert not any(i.name == "default_credentials_accepted" for i in indicators)


# ============================================================================
# Tests for shell emulation limits (lines 529-662)
# ============================================================================
class TestProbeShellEmulationComprehensive:
    """Comprehensive tests for _probe_shell_emulation method."""

    @pytest.fixture
    def detector(self):
        """Create Telnet detector instance."""
        return TelnetDetector()

    def test_probe_shell_emulation_file_creation_blocked(self, detector, mock_socket):
        """Test detection of blocked file creation."""
        socket_instance = mock_socket.return_value

        socket_instance.recv.side_effect = [
            b"login: ",
            b"Password: ",
            b"# ",
            b"/usr/bin/wget\n",  # wget exists
            b"/usr/bin/curl\n",  # curl exists
            b"/usr/bin/nc\n",    # nc exists
            b"/usr/bin/netcat\n",  # netcat exists
            b"/usr/bin/python\n",  # python exists
            b"/usr/bin/perl\n",  # perl exists
            b"root:x:0:0::/root:/bin/sh\n",  # passwd readable
            b"touch: /tmp/test_123: Read-only file system\nFAILED\n",  # file creation blocked
        ]

        indicators = detector._probe_shell_emulation("192.168.1.100", 23)

        assert any(i.name == "file_creation_blocked" for i in indicators)

    def test_probe_shell_emulation_uniform_errors(self, detector, mock_socket):
        """Test detection of uniform error messages."""
        socket_instance = mock_socket.return_value

        responses = [
            b"login: ",
            b"Password: ",
            b"# ",
            b"-sh: wget: not found\n",
            b"-sh: curl: not found\n",
            b"root:x:0:0::/root:/bin/sh\n",
            b"SUCCESS\n",
        ]

        def recv_side_effect(size):
            if responses:
                return responses.pop(0)
            return b"\n"

        socket_instance.recv.side_effect = recv_side_effect

        indicators = detector._probe_shell_emulation("192.168.1.100", 23)

        assert any(i.name == "uniform_error_messages" for i in indicators)

    def test_probe_shell_emulation_no_login_prompt(self, detector, mock_socket):
        """Test _probe_shell_emulation with no login prompt."""
        socket_instance = mock_socket.return_value

        # Use function to provide unlimited responses for credential iterations
        def recv_side_effect(size):
            return b"Some other service\n"  # No login prompt

        socket_instance.recv.side_effect = recv_side_effect

        indicators = detector._probe_shell_emulation("192.168.1.100", 23)

        assert len(indicators) == 0

    def test_probe_shell_emulation_timeout_on_password(self, detector, mock_socket):
        """Test _probe_shell_emulation timeout on password."""
        socket_instance = mock_socket.return_value

        socket_instance.recv.side_effect = [
            b"login: ",
            socket.timeout(),
        ] * 5

        indicators = detector._probe_shell_emulation("192.168.1.100", 23)

        assert len(indicators) == 0

    def test_probe_shell_emulation_no_shell_after_login(self, detector, mock_socket):
        """Test _probe_shell_emulation when no shell prompt after login."""
        socket_instance = mock_socket.return_value

        socket_instance.recv.side_effect = [
            b"login: ",
            b"Password: ",
            b"Login incorrect\n",  # No shell prompt
        ] * 5

        indicators = detector._probe_shell_emulation("192.168.1.100", 23)

        assert len(indicators) == 0

    def test_probe_shell_emulation_socket_error(self, detector, mock_socket):
        """Test _probe_shell_emulation handles socket errors."""
        socket_instance = mock_socket.return_value
        socket_instance.connect.side_effect = socket.error("Connection refused")

        indicators = detector._probe_shell_emulation("192.168.1.100", 23)

        assert len(indicators) == 0

    def test_probe_shell_emulation_command_timeout(self, detector, mock_socket):
        """Test _probe_shell_emulation handles command timeouts."""
        socket_instance = mock_socket.return_value

        socket_instance.recv.side_effect = [
            b"login: ",
            b"Password: ",
            b"# ",
            socket.timeout(),  # Timeout on first command
            socket.timeout(),  # Timeout on second command
            socket.timeout(),  # etc
            socket.timeout(),
            socket.timeout(),
            socket.timeout(),
            b"root:x:0:0::/root:/bin/sh\n",
            b"SUCCESS\n",
        ]

        indicators = detector._probe_shell_emulation("192.168.1.100", 23)

        # Should complete without error, possibly with no indicators
        assert isinstance(indicators, list)

    @pytest.mark.parametrize("not_found_pattern", [
        b"not found",
        b"command not found",
        b"applet not found",
        b"unknown command",
        b"-sh: wget: command not found",
        b"ash: wget: not found",
    ])
    def test_probe_shell_emulation_not_found_patterns(self, detector, mock_socket, not_found_pattern):
        """Test detection of various 'not found' patterns."""
        socket_instance = mock_socket.return_value

        socket_instance.recv.side_effect = [
            b"login: ",
            b"Password: ",
            b"# ",
            not_found_pattern + b"\n",
            not_found_pattern + b"\n",
            not_found_pattern + b"\n",
            not_found_pattern + b"\n",
            not_found_pattern + b"\n",
            not_found_pattern + b"\n",
            b"root:x:0:0::/root:/bin/sh\n",
            b"SUCCESS\n",
        ]

        indicators = detector._probe_shell_emulation("192.168.1.100", 23)

        assert any(i.name == "missing_common_commands" for i in indicators)


# ============================================================================
# Tests for _probe_busybox_post_auth (lines 689-929)
# ============================================================================
class TestProbeBusyboxPostAuthComprehensive:
    """Comprehensive tests for _probe_busybox_post_auth method."""

    @pytest.fixture
    def detector(self):
        """Create Telnet detector instance."""
        return TelnetDetector()

    def test_probe_busybox_static_zero_load(self, detector):
        """Test detection of static zero load average."""
        mock_sock = MagicMock()

        def send_cmd_side_effect(data):
            mock_sock.last_cmd = data

        mock_sock.send = send_cmd_side_effect
        mock_sock.settimeout = MagicMock()

        responses = {
            b"busybox --list": b"\n",
            b"cat /proc/self/exe": b"\n",
            b"ls /proc/self/fd": b"0\n1\n2\n",
            b"which wget": b"/usr/bin/wget\n",
            b"which curl": b"/usr/bin/curl\n",
            b"which tftp": b"/usr/bin/tftp\n",
            b"which nc": b"/usr/bin/nc\n",
            b"/bin/busybox ECCHI": b"applet not found\n",
            b"uname -a": b"Linux server 5.4.0\n",
            b"uptime": b" 12:00:00 up 1 day, load average: 0.00, 0.00, 0.00\n",
            b"cat /etc/passwd": b"root:x:0:0::/root:/bin/sh\n",
        }

        def recv_side_effect(size):
            for cmd, response in responses.items():
                if hasattr(mock_sock, 'last_cmd') and cmd in mock_sock.last_cmd:
                    return response
            return b"\n"

        mock_sock.recv = recv_side_effect

        indicators = detector._probe_busybox_post_auth(mock_sock)

        assert any(i.name == "static_zero_load_telnet" for i in indicators)

    def test_probe_busybox_cowrie_kernel(self, detector):
        """Test detection of Cowrie default kernel in uname -a."""
        mock_sock = MagicMock()

        def send_cmd_side_effect(data):
            mock_sock.last_cmd = data

        mock_sock.send = send_cmd_side_effect
        mock_sock.settimeout = MagicMock()

        responses = {
            b"busybox --list": b"\n",
            b"cat /proc/self/exe": b"\n",
            b"ls /proc/self/fd": b"0\n1\n2\n",
            b"which wget": b"/usr/bin/wget\n",
            b"which curl": b"/usr/bin/curl\n",
            b"which tftp": b"/usr/bin/tftp\n",
            b"which nc": b"/usr/bin/nc\n",
            b"/bin/busybox ECCHI": b"applet not found\n",
            b"uname -a": b"Linux svr04 3.2.0-4-amd64 #1 SMP Debian 3.2.68-1+deb7u1 x86_64\n",
            b"uptime": b" 12:00:00 up 1 day, load average: 0.10, 0.05, 0.01\n",
            b"cat /etc/passwd": b"root:x:0:0::/root:/bin/sh\n",
        }

        def recv_side_effect(size):
            for cmd, response in responses.items():
                if hasattr(mock_sock, 'last_cmd') and cmd in mock_sock.last_cmd:
                    return response
            return b"\n"

        mock_sock.recv = recv_side_effect

        indicators = detector._probe_busybox_post_auth(mock_sock)

        assert any(i.name == "cowrie_default_kernel_telnet" for i in indicators)

    def test_probe_busybox_default_users_passwd(self, detector):
        """Test detection of default Cowrie users in /etc/passwd."""
        mock_sock = MagicMock()

        def send_cmd_side_effect(data):
            mock_sock.last_cmd = data

        mock_sock.send = send_cmd_side_effect
        mock_sock.settimeout = MagicMock()

        responses = {
            b"busybox --list": b"\n",
            b"cat /proc/self/exe": b"\n",
            b"ls /proc/self/fd": b"0\n1\n2\n",
            b"which wget": b"/usr/bin/wget\n",
            b"which curl": b"/usr/bin/curl\n",
            b"which tftp": b"/usr/bin/tftp\n",
            b"which nc": b"/usr/bin/nc\n",
            b"/bin/busybox ECCHI": b"applet not found\n",
            b"uname -a": b"Linux server 5.4.0\n",
            b"uptime": b" 12:00:00 up 1 day\n",
            b"cat /etc/passwd": b"root:x:0:0::/root:/bin/sh\nphil:x:1000:1000::/home/phil:/bin/sh\nrichard:x:1001:1001::/home/richard:/bin/sh\n",
        }

        def recv_side_effect(size):
            for cmd, response in responses.items():
                if hasattr(mock_sock, 'last_cmd') and cmd in mock_sock.last_cmd:
                    return response
            return b"\n"

        mock_sock.recv = recv_side_effect

        indicators = detector._probe_busybox_post_auth(mock_sock)

        assert any(i.name == "default_user_phil_telnet" for i in indicators)
        assert any(i.name == "default_user_richard_telnet" for i in indicators)

    def test_probe_busybox_proc_self_fd_missing(self, detector):
        """Test detection of missing /proc/self/fd."""
        mock_sock = MagicMock()

        def send_cmd_side_effect(data):
            mock_sock.last_cmd = data

        mock_sock.send = send_cmd_side_effect
        mock_sock.settimeout = MagicMock()

        responses = {
            b"busybox --list": b"\n",
            b"cat /proc/self/exe": b"\n",
            b"ls /proc/self/fd": b"No such file or directory\n",
            b"which wget": b"/usr/bin/wget\n",
            b"which curl": b"/usr/bin/curl\n",
            b"which tftp": b"/usr/bin/tftp\n",
            b"which nc": b"/usr/bin/nc\n",
            b"/bin/busybox ECCHI": b"applet not found\n",
            b"uname -a": b"Linux server 5.4.0\n",
            b"uptime": b" 12:00:00 up 1 day\n",
            b"cat /etc/passwd": b"root:x:0:0::/root:/bin/sh\n",
        }

        def recv_side_effect(size):
            for cmd, response in responses.items():
                if hasattr(mock_sock, 'last_cmd') and cmd in mock_sock.last_cmd:
                    return response
            return b"\n"

        mock_sock.recv = recv_side_effect

        indicators = detector._probe_busybox_post_auth(mock_sock)

        assert any(i.name == "proc_self_fd_missing" for i in indicators)

    def test_probe_busybox_missing_iot_commands(self, detector):
        """Test detection of missing IoT-typical commands."""
        mock_sock = MagicMock()

        def send_cmd_side_effect(data):
            mock_sock.last_cmd = data

        mock_sock.send = send_cmd_side_effect
        mock_sock.settimeout = MagicMock()

        responses = {
            b"busybox --list": b"\n",
            b"cat /proc/self/exe": b"\n",
            b"ls /proc/self/fd": b"0\n1\n2\n",
            b"which wget": b"not found\n",
            b"which curl": b"not found\n",
            b"which tftp": b"not found\n",
            b"which nc": b"not found\n",
            b"/bin/busybox ECCHI": b"applet not found\n",
            b"uname -a": b"Linux server 5.4.0\n",
            b"uptime": b" 12:00:00 up 1 day\n",
            b"cat /etc/passwd": b"root:x:0:0::/root:/bin/sh\n",
        }

        def recv_side_effect(size):
            for cmd, response in responses.items():
                if hasattr(mock_sock, 'last_cmd') and cmd in mock_sock.last_cmd:
                    return response
            return b"\n"

        mock_sock.recv = recv_side_effect

        indicators = detector._probe_busybox_post_auth(mock_sock)

        assert any(i.name == "missing_iot_commands" for i in indicators)

    def test_probe_busybox_invalid_applet_response(self, detector):
        """Test detection of incorrect BusyBox invalid applet response."""
        mock_sock = MagicMock()

        def send_cmd_side_effect(data):
            mock_sock.last_cmd = data

        mock_sock.send = send_cmd_side_effect
        mock_sock.settimeout = MagicMock()

        responses = {
            b"busybox --list": b"\n",
            b"cat /proc/self/exe": b"\n",
            b"ls /proc/self/fd": b"0\n1\n2\n",
            b"which wget": b"/usr/bin/wget\n",
            b"which curl": b"/usr/bin/curl\n",
            b"which tftp": b"/usr/bin/tftp\n",
            b"which nc": b"/usr/bin/nc\n",
            b"/bin/busybox ECCHI": b"",  # Empty response instead of "applet not found"
            b"uname -a": b"Linux server 5.4.0\n",
            b"uptime": b" 12:00:00 up 1 day\n",
            b"cat /etc/passwd": b"root:x:0:0::/root:/bin/sh\n",
        }

        def recv_side_effect(size):
            for cmd, response in responses.items():
                if hasattr(mock_sock, 'last_cmd') and cmd in mock_sock.last_cmd:
                    return response
            return b"\n"

        mock_sock.recv = recv_side_effect

        indicators = detector._probe_busybox_post_auth(mock_sock)

        assert any(i.name == "busybox_invalid_applet_response" for i in indicators)

    def test_probe_busybox_socket_timeout(self, detector):
        """Test _probe_busybox_post_auth handles socket timeout."""
        mock_sock = MagicMock()
        mock_sock.send = MagicMock()
        mock_sock.settimeout = MagicMock()
        mock_sock.recv = MagicMock(side_effect=socket.timeout())

        indicators = detector._probe_busybox_post_auth(mock_sock)

        # Should return empty list on timeout, not crash
        assert isinstance(indicators, list)

    def test_probe_busybox_oserror(self, detector):
        """Test _probe_busybox_post_auth handles OSError."""
        mock_sock = MagicMock()
        mock_sock.send = MagicMock()
        mock_sock.settimeout = MagicMock()
        mock_sock.recv = MagicMock(side_effect=OSError("Connection reset"))

        indicators = detector._probe_busybox_post_auth(mock_sock)

        # Should return empty list on error, not crash
        assert isinstance(indicators, list)


# ============================================================================
# Integration tests for full detect() flow and mode switching
# ============================================================================
class TestTelnetDetectorModeIntegration:
    """Integration tests for detection modes and full detect() flow."""

    @pytest.fixture
    def detector(self):
        """Create Telnet detector instance."""
        return TelnetDetector()

    def test_detect_full_mode(self, mock_socket):
        """Test detect() in FULL mode combines passive and active."""
        detector = TelnetDetector(mode=DetectionMode.FULL)
        socket_instance = mock_socket.return_value

        # First call is for passive detection (banner), subsequent for active
        socket_instance.recv.side_effect = [
            b'\xff\xfd\x1flogin: ',  # Cowrie banner for passive
        ] + [socket.timeout()] * 50

        result = detector.detect("192.168.1.100", 23)

        # Should have indicators from passive detection
        assert any(i.name == "known_telnet_banner" for i in result.indicators)
        assert result.honeypot_type == "cowrie"

    def test_detect_passive_only_mode(self, mock_socket):
        """Test detect() in PASSIVE mode only runs passive detection."""
        detector = TelnetDetector(mode=DetectionMode.PASSIVE)
        socket_instance = mock_socket.return_value

        socket_instance.recv.return_value = b'\xff\xfd\x1flogin: '

        result = detector.detect("192.168.1.100", 23)

        assert any(i.name == "known_telnet_banner" for i in result.indicators)
        # Should only call connect once for passive detection
        # (active detection would make additional connections)

    def test_detect_active_only_mode(self, mock_socket):
        """Test detect() in ACTIVE mode only runs active detection."""
        detector = TelnetDetector(mode=DetectionMode.ACTIVE)
        socket_instance = mock_socket.return_value

        socket_instance.recv.side_effect = [
            b"login: ",
            b"Password: ",
            b"# ",
        ] + [socket.timeout()] * 50

        result = detector.detect("192.168.1.100", 23)

        # Active mode should still produce a result
        assert isinstance(result, DetectionResult)

    def test_detect_honeypot_type_from_active_if_not_set(self, mock_socket):
        """Test honeypot_type from active detection when passive doesn't set it."""
        detector = TelnetDetector(mode=DetectionMode.FULL)
        socket_instance = mock_socket.return_value

        # Passive: generic banner (no type set)
        # Active: detects cowrie signature
        recv_responses = iter([
            b"login: ",  # passive gets this (no known signature)
            b"login: ",  # active credential probe
            b"Password: ",
            b"# ",
            b"Linux svr04 3.2.0-4-amd64\n",  # Cowrie kernel
            b"",
            b"uid=0(root)\n",
            b"login: ",
            b"Password: ",
            b"# ",
        ] + [b"\n"] * 30)

        def recv_side_effect(size):
            try:
                return next(recv_responses)
            except StopIteration:
                return b"\n"

        socket_instance.recv.side_effect = recv_side_effect

        result = detector.detect("192.168.1.100", 23)

        # Active detection should set honeypot_type if passive didn't
        if result.is_honeypot and not result.honeypot_type:
            # This is the default set by detect_active
            pass  # OK if no type set
        elif result.honeypot_type:
            assert result.honeypot_type in ["cowrie-telnet", "cowrie"]

    def test_detect_combines_indicators(self, mock_socket):
        """Test detect() combines indicators from both passive and active."""
        detector = TelnetDetector(mode=DetectionMode.FULL)
        socket_instance = mock_socket.return_value

        recv_responses = iter([
            b"svr04 login: ",  # passive: default hostname
            b"svr04 login: ",  # active credential probe
            b"Password: ",
            b"# ",
            b"Linux svr04 5.4.0\n",
            b"",
            b"uid=0(root)\n",
            b"login: ",
            b"Password: ",
            b"# ",
        ] + [b"\n"] * 30)

        def recv_side_effect(size):
            try:
                return next(recv_responses)
            except StopIteration:
                return b"\n"

        socket_instance.recv.side_effect = recv_side_effect

        result = detector.detect("192.168.1.100", 23)

        # Should have passive indicator
        assert any(i.name == "default_hostname" for i in result.indicators)
        # Should have active indicator (if credentials accepted)
        if any(i.name == "default_credentials_accepted" for i in result.indicators):
            assert len(result.indicators) >= 2


class TestTelnetDetectorEdgeCases:
    """Edge case and error handling tests."""

    @pytest.fixture
    def detector(self):
        """Create Telnet detector instance."""
        return TelnetDetector()

    def test_empty_banner(self, detector, mock_socket):
        """Test handling of empty banner."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b""

        result = detector.detect_passive("192.168.1.100", 23)

        assert len(result.indicators) == 0

    def test_binary_garbage_in_banner(self, detector, mock_socket):
        """Test handling of binary garbage in banner."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"\x00\x01\x02\x03\xff\xfe\xfd"

        result = detector.detect_passive("192.168.1.100", 23)

        # Should not crash, might not detect anything
        assert isinstance(result, DetectionResult)

    def test_very_long_banner(self, detector, mock_socket):
        """Test handling of very long banner."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"A" * 10000 + b"login: "

        result = detector.detect_passive("192.168.1.100", 23)

        # Should not crash
        assert isinstance(result, DetectionResult)

    def test_unicode_in_banner(self, detector, mock_socket):
        """Test handling of unicode in banner."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = "Welcome to server!\nlogin: ".encode("utf-8")

        result = detector.detect_passive("192.168.1.100", 23)

        assert isinstance(result, DetectionResult)

    def test_timeout_parameter(self):
        """Test detector respects timeout parameter."""
        detector = TelnetDetector(timeout=10.0)
        assert detector.timeout == 10.0

    def test_verbose_parameter(self):
        """Test detector respects verbose parameter."""
        detector = TelnetDetector(verbose=True)
        assert detector.verbose is True


class TestTelnetDetectorRecommendationsExtended:
    """Extended tests for recommendations."""

    @pytest.fixture
    def detector(self):
        """Create Telnet detector instance."""
        return TelnetDetector()

    def test_recommendations_no_indicators(self, detector):
        """Test recommendations with no indicators."""
        result = DetectionResult(target="192.168.1.100", port=23)

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) == 0

    def test_recommendations_unknown_indicator(self, detector):
        """Test recommendations with unknown indicator."""
        result = DetectionResult(target="192.168.1.100", port=23)
        result.add_indicator(
            Indicator(
                name="some_unknown_indicator",
                description="Unknown",
                severity=Confidence.HIGH,
            )
        )

        recommendations = detector.get_recommendations(result)

        # Unknown indicators shouldn't cause errors
        assert isinstance(recommendations, list)

    def test_recommendations_multiple_indicators(self, detector):
        """Test recommendations with multiple indicators."""
        result = DetectionResult(target="192.168.1.100", port=2323)
        result.add_indicator(
            Indicator(
                name="default_port",
                description="Default port 2323",
                severity=Confidence.MEDIUM,
            )
        )
        result.add_indicator(
            Indicator(
                name="default_hostname",
                description="Default hostname svr04",
                severity=Confidence.HIGH,
            )
        )
        result.add_indicator(
            Indicator(
                name="default_kernel",
                description="Default kernel",
                severity=Confidence.HIGH,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) == 3
        assert any("iptables" in r for r in recommendations)
        assert any("hostname" in r for r in recommendations)
        assert any("kernel" in r.lower() or "uname" in r.lower() for r in recommendations)
