"""
Unit tests for SSH honeypot detector.

Tests banner detection, HASSH fingerprinting, KEX algorithm detection,
active probes (CR, bad version, spacer, double banner), credential probing,
post-auth command detection, and invalid payload detection.
"""

import socket
import struct
import pytest
from unittest.mock import MagicMock, patch, call

from potsnitch.detectors.ssh import (
    SSHDetector,
    COWRIE_DEFAULT_BANNERS,
    COWRIE_CIPHERS,
    COWRIE_KEX_ALGORITHMS,
)
from potsnitch.core.result import Confidence


class TestSSHDetectorBannerDetection:
    """Tests for SSH banner detection."""

    @pytest.fixture
    def detector(self):
        """Create SSH detector instance."""
        return SSHDetector()

    @pytest.mark.parametrize("banner", COWRIE_DEFAULT_BANNERS[:10])
    def test_detect_cowrie_default_banners(self, detector, banner, mock_socket):
        """Test detection of known Cowrie default banners."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = banner.encode() + b"\r\n"

        result = detector.detect_passive("192.168.1.100", 22)

        assert any(i.name == "default_banner" for i in result.indicators)
        assert result.is_honeypot

    def test_detect_openssh_5x_banner(self, detector, mock_socket):
        """Test detection of outdated OpenSSH 5.x versions."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"SSH-2.0-OpenSSH_5.4p1 Ubuntu-2\r\n"

        result = detector.detect_passive("192.168.1.100", 22)

        assert any(i.name == "outdated_version" for i in result.indicators)

    def test_detect_openssh_60_banner(self, detector, mock_socket):
        """Test detection of outdated OpenSSH 6.0 versions."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"SSH-2.0-OpenSSH_6.0p1 Debian-1\r\n"

        result = detector.detect_passive("192.168.1.100", 22)

        assert any(i.name == "outdated_version" for i in result.indicators)

    def test_detect_debian7_banner(self, detector, mock_socket):
        """Test detection of Debian 7 signature in banner."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"SSH-2.0-OpenSSH_7.0p1 deb7-custom\r\n"

        result = detector.detect_passive("192.168.1.100", 22)

        assert any(i.name == "debian7_banner" for i in result.indicators)

    def test_detect_debian4_banner(self, detector, mock_socket):
        """Test detection of Debian-4 signature in banner."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2\r\n"

        result = detector.detect_passive("192.168.1.100", 22)

        # Should match as default banner
        assert any(i.name == "default_banner" for i in result.indicators)

    def test_no_detection_modern_openssh(self, detector, mock_socket):
        """Test that modern OpenSSH versions are not flagged."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"SSH-2.0-OpenSSH_9.0p1 Ubuntu-1\r\n"

        result = detector.detect_passive("192.168.1.100", 22)

        assert not any(i.name == "default_banner" for i in result.indicators)
        assert not any(i.name == "outdated_version" for i in result.indicators)

    def test_default_port_2222_indicator(self, detector, mock_socket):
        """Test that port 2222 is flagged as default Cowrie port."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"SSH-2.0-OpenSSH_9.0p1\r\n"

        result = detector.detect_passive("192.168.1.100", 2222)

        assert any(i.name == "default_port_2222" for i in result.indicators)

    def test_socket_timeout_handling(self, detector, mock_socket):
        """Test graceful handling of socket timeout."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = socket.timeout()

        result = detector.detect_passive("192.168.1.100", 22)

        # Should return result without error, no indicators
        assert result.error is None
        assert len(result.indicators) == 0

    def test_socket_error_handling(self, detector, mock_socket):
        """Test graceful handling of socket errors."""
        socket_instance = mock_socket.return_value
        socket_instance.connect.side_effect = socket.error("Connection refused")

        result = detector.detect_passive("192.168.1.100", 22)

        assert result.error is None  # Errors are silently handled


class TestSSHDetectorKEXDetection:
    """Tests for SSH KEX algorithm detection (HASSH-style fingerprinting)."""

    @pytest.fixture
    def detector(self):
        """Create SSH detector instance."""
        return SSHDetector()

    def test_check_kex_cowrie_ciphers(self, detector):
        """Test _check_kex detection of Cowrie cipher list."""
        from potsnitch.core.result import DetectionResult

        result = DetectionResult(target="192.168.1.100", port=22)

        # Build kex_info with Cowrie default ciphers
        cowrie_ciphers = b",".join(COWRIE_CIPHERS)
        kex_info = {
            "encryption_client_to_server": cowrie_ciphers,
        }

        detector._check_kex(kex_info, result)

        assert any(i.name == "cowrie_ciphers" for i in result.indicators)
        assert any(i.name == "twisted_cipher_order" for i in result.indicators)

    def test_check_kex_non_cowrie_ciphers(self, detector):
        """Test _check_kex with non-Cowrie ciphers."""
        from potsnitch.core.result import DetectionResult

        result = DetectionResult(target="192.168.1.100", port=22)

        # Modern cipher list
        modern_ciphers = b"chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com"
        kex_info = {
            "encryption_client_to_server": modern_ciphers,
        }

        detector._check_kex(kex_info, result)

        assert not any(i.name == "cowrie_ciphers" for i in result.indicators)

    def test_parse_kex_init_valid(self, detector):
        """Test parsing valid KEX_INIT packet."""
        # Build a valid KEX_INIT payload (after message type byte)
        cookie = b"\x00" * 16
        kex_algs = b"diffie-hellman-group14-sha1"
        host_key_algs = b"ssh-rsa"
        ciphers = b"aes128-ctr,aes256-ctr"

        def pack_namelist(data: bytes) -> bytes:
            return struct.pack(">I", len(data)) + data

        payload = cookie
        payload += pack_namelist(kex_algs)
        payload += pack_namelist(host_key_algs)
        payload += pack_namelist(ciphers)  # c2s
        payload += pack_namelist(ciphers)  # s2c
        payload += pack_namelist(b"hmac-sha1")  # mac c2s
        payload += pack_namelist(b"hmac-sha1")  # mac s2c
        payload += pack_namelist(b"none")  # comp c2s
        payload += pack_namelist(b"none")  # comp s2c

        result = detector._parse_kex_init(payload)

        assert result is not None
        assert "kex_algorithms" in result
        assert "encryption_client_to_server" in result


class TestSSHDetectorCRProbe:
    """Tests for Kippo carriage return probe."""

    @pytest.fixture
    def detector(self):
        """Create SSH detector instance."""
        return SSHDetector()

    def test_kippo_cr_probe_method(self, detector, mock_socket):
        """Test _kippo_cr_probe method directly."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = [
            b"SSH-2.0-OpenSSH_5.1p1\r\n",  # Banner
            b"bad packet length 168430090",  # Kippo response
        ]

        result = detector._kippo_cr_probe("192.168.1.100", 22)

        assert result is True

    def test_kippo_cr_probe_protocol_mismatch(self, detector, mock_socket):
        """Test _kippo_cr_probe with normal protocol mismatch."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = [
            b"SSH-2.0-OpenSSH_8.0p1\r\n",
            b"Protocol mismatch.",
        ]

        result = detector._kippo_cr_probe("192.168.1.100", 22)

        assert result is False


class TestSSHDetectorBadVersionProbe:
    """Tests for bad version string probe."""

    @pytest.fixture
    def detector(self):
        """Create SSH detector instance."""
        return SSHDetector()

    def test_bad_version_probe_method(self, detector, mock_socket):
        """Test _probe_bad_version method directly."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = [
            b"SSH-2.0-OpenSSH_6.0p1\r\n",
            b"bad version SSH-1337",
        ]

        result = detector._probe_bad_version("192.168.1.100", 22)

        assert result is True

    def test_bad_version_probe_normal_response(self, detector, mock_socket):
        """Test _probe_bad_version with normal response."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = [
            b"SSH-2.0-OpenSSH_8.0p1\r\n",
            b"Protocol mismatch.",
        ]

        result = detector._probe_bad_version("192.168.1.100", 22)

        assert result is False


class TestSSHDetectorSpacerProbe:
    """Tests for spacer packet probe."""

    @pytest.fixture
    def detector(self):
        """Create SSH detector instance."""
        return SSHDetector()

    def test_spacer_probe_corrupt_response(self, detector, mock_socket):
        """Test _probe_spacer_packet with corrupt response."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = [
            b"SSH-2.0-OpenSSH_6.0p1\r\n",
            b"packet corrupt",
        ]

        result = detector._probe_spacer_packet("192.168.1.100", 22)

        assert result is True

    def test_spacer_probe_mismatch_response(self, detector, mock_socket):
        """Test _probe_spacer_packet with mismatch response."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = [
            b"SSH-2.0-OpenSSH_6.0p1\r\n",
            b"Protocol mismatch.",
        ]

        result = detector._probe_spacer_packet("192.168.1.100", 22)

        assert result is True

    def test_spacer_probe_normal_response(self, detector, mock_socket):
        """Test _probe_spacer_packet with normal response."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = [
            b"SSH-2.0-OpenSSH_8.0p1\r\n",
            b"Some other error",
        ]

        result = detector._probe_spacer_packet("192.168.1.100", 22)

        assert result is False


class TestSSHDetectorDoubleBannerProbe:
    """Tests for double banner probe."""

    @pytest.fixture
    def detector(self):
        """Create SSH detector instance."""
        return SSHDetector()

    def test_double_banner_probe_corrupt(self, detector, mock_socket):
        """Test _probe_double_banner with corrupt response."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = [
            b"SSH-2.0-OpenSSH_6.0p1\r\n",
            b"packet corrupt",
        ]

        result = detector._probe_double_banner("192.168.1.100", 22)

        assert result is True

    def test_double_banner_probe_normal(self, detector, mock_socket):
        """Test _probe_double_banner with normal response."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = [
            b"SSH-2.0-OpenSSH_8.0p1\r\n",
            b"Some other response",
        ]

        result = detector._probe_double_banner("192.168.1.100", 22)

        assert result is False


class TestSSHDetectorCredentialProbe:
    """Tests for credential-based detection with mocked paramiko."""

    @pytest.fixture
    def detector(self):
        """Create SSH detector instance."""
        return SSHDetector()

    @patch("potsnitch.detectors.ssh.HAS_PARAMIKO", True)
    @patch("potsnitch.detectors.ssh.paramiko")
    def test_probe_auth_credentials_accepted(self, mock_paramiko, detector):
        """Test _probe_auth_credentials when credentials accepted."""
        mock_client = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_client
        mock_paramiko.AutoAddPolicy.return_value = MagicMock()

        # Simulate successful authentication
        mock_client.connect.return_value = None

        # Mock exec_command for post-auth probes
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b""
        mock_client.exec_command.return_value = (MagicMock(), mock_stdout, MagicMock())

        indicators = detector._probe_auth_credentials("192.168.1.100", 22)

        assert any(i.name == "default_credentials_accepted" for i in indicators)

    @patch("potsnitch.detectors.ssh.HAS_PARAMIKO", True)
    @patch("potsnitch.detectors.ssh.paramiko")
    def test_probe_auth_credentials_rejected(self, mock_paramiko, detector):
        """Test _probe_auth_credentials when all credentials rejected."""
        mock_client = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_client
        mock_paramiko.AuthenticationException = Exception

        # All auth attempts fail
        mock_client.connect.side_effect = mock_paramiko.AuthenticationException("Auth failed")

        indicators = detector._probe_auth_credentials("192.168.1.100", 22)

        assert not any(i.name == "default_credentials_accepted" for i in indicators)


class TestSSHDetectorPostAuthCommands:
    """Tests for post-authentication command detection."""

    @pytest.fixture
    def detector(self):
        """Create SSH detector instance."""
        return SSHDetector()

    def test_detect_proc_self_exe_missing(self, detector):
        """Test detection of missing /proc/self/exe."""
        mock_client = MagicMock()

        def exec_side_effect(cmd, timeout=None):
            stdin = MagicMock()
            stdout = MagicMock()
            stderr = MagicMock()

            if "/proc/self/exe" in cmd:
                stdout.read.return_value = b"No such file or directory"
            else:
                stdout.read.return_value = b""
            return stdin, stdout, stderr

        mock_client.exec_command.side_effect = exec_side_effect

        indicators = detector._probe_post_auth_commands(mock_client)

        assert any(i.name == "proc_self_exe_missing" for i in indicators)
        assert any(i.severity == Confidence.DEFINITE for i in indicators)

    def test_detect_static_zero_load(self, detector):
        """Test detection of static zero load average."""
        mock_client = MagicMock()

        def exec_side_effect(cmd, timeout=None):
            stdin = MagicMock()
            stdout = MagicMock()
            stderr = MagicMock()

            if "uptime" in cmd:
                stdout.read.return_value = b"12:00:00 up 1 day, load average: 0.00, 0.00, 0.00"
            else:
                stdout.read.return_value = b""
            return stdin, stdout, stderr

        mock_client.exec_command.side_effect = exec_side_effect

        indicators = detector._probe_post_auth_commands(mock_client)

        assert any(i.name == "static_zero_load" for i in indicators)

    def test_detect_default_users_in_passwd(self, detector):
        """Test detection of default Cowrie users in /etc/passwd."""
        mock_client = MagicMock()

        def exec_side_effect(cmd, timeout=None):
            stdin = MagicMock()
            stdout = MagicMock()
            stderr = MagicMock()

            if "cat /etc/passwd" in cmd:
                stdout.read.return_value = b"root:x:0:0:root:/root:/bin/bash\nphil:x:1000:1000::/home/phil:/bin/bash"
            else:
                stdout.read.return_value = b""
            return stdin, stdout, stderr

        mock_client.exec_command.side_effect = exec_side_effect

        indicators = detector._probe_post_auth_commands(mock_client)

        assert any(i.name == "default_user_phil" for i in indicators)

    def test_detect_cowrie_default_kernel(self, detector):
        """Test detection of default Cowrie kernel version."""
        mock_client = MagicMock()

        def exec_side_effect(cmd, timeout=None):
            stdin = MagicMock()
            stdout = MagicMock()
            stderr = MagicMock()

            if "uname -a" in cmd:
                stdout.read.return_value = b"Linux svr04 3.2.0-4-amd64 #1 SMP Debian 3.2.68-1+deb7u1 x86_64 GNU/Linux"
            else:
                stdout.read.return_value = b""
            return stdin, stdout, stderr

        mock_client.exec_command.side_effect = exec_side_effect

        indicators = detector._probe_post_auth_commands(mock_client)

        assert any(i.name == "cowrie_default_kernel" for i in indicators)

    def test_detect_which_returns_empty(self, detector):
        """Test detection when 'which' command returns empty."""
        mock_client = MagicMock()

        def exec_side_effect(cmd, timeout=None):
            stdin = MagicMock()
            stdout = MagicMock()
            stderr = MagicMock()

            if "which ls" in cmd:
                stdout.read.return_value = b""
            else:
                stdout.read.return_value = b"some output"
            return stdin, stdout, stderr

        mock_client.exec_command.side_effect = exec_side_effect

        indicators = detector._probe_post_auth_commands(mock_client)

        assert any(i.name == "which_returns_empty" for i in indicators)


class TestSSHDetectorInvalidPayloads:
    """Tests for invalid payload detection."""

    @pytest.fixture
    def detector(self):
        """Create SSH detector instance."""
        return SSHDetector()

    def test_detect_uniform_error_response(self, detector, mock_socket):
        """Test detection of uniform error responses."""
        socket_instance = mock_socket.return_value

        # All invalid payloads get the same response
        socket_instance.recv.side_effect = [
            b"SSH-2.0-OpenSSH_6.0p1\r\n",
            b"Protocol mismatch.",
            b"SSH-2.0-OpenSSH_6.0p1\r\n",
            b"Protocol mismatch.",
            b"SSH-2.0-OpenSSH_6.0p1\r\n",
            b"Protocol mismatch.",
            b"SSH-2.0-OpenSSH_6.0p1\r\n",
            b"Protocol mismatch.",
            b"SSH-2.0-OpenSSH_6.0p1\r\n",
            b"Protocol mismatch.",
            b"SSH-2.0-OpenSSH_6.0p1\r\n",
            b"Protocol mismatch.",
        ]

        indicators = detector._probe_invalid_payloads("192.168.1.100", 22)

        assert any(i.name == "uniform_error_response" for i in indicators)

    def test_no_detection_on_varied_responses(self, detector, mock_socket):
        """Test no detection when responses vary."""
        socket_instance = mock_socket.return_value

        # Different responses for different payloads
        socket_instance.recv.side_effect = [
            b"SSH-2.0-OpenSSH_8.0p1\r\n",
            b"Bad protocol version",
            b"SSH-2.0-OpenSSH_8.0p1\r\n",
            b"Invalid SSH packet",
            b"SSH-2.0-OpenSSH_8.0p1\r\n",
            b"Connection reset",
            b"SSH-2.0-OpenSSH_8.0p1\r\n",
            b"Protocol error",
            b"SSH-2.0-OpenSSH_8.0p1\r\n",
            b"Packet format error",
            b"SSH-2.0-OpenSSH_8.0p1\r\n",
            b"Unknown error",
        ]

        indicators = detector._probe_invalid_payloads("192.168.1.100", 22)

        assert not any(i.name == "uniform_error_response" for i in indicators)


class TestSSHDetectorIntegration:
    """Integration tests for SSH detector."""

    @pytest.fixture
    def detector(self):
        """Create SSH detector instance."""
        return SSHDetector()

    def test_honeypot_type_set_correctly(self, detector, mock_socket):
        """Test that honeypot_type is set to cowrie by default."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = COWRIE_DEFAULT_BANNERS[0].encode() + b"\r\n"

        result = detector.detect_passive("192.168.1.100", 22)

        assert result.is_honeypot
        assert result.honeypot_type == "cowrie"

    def test_detector_properties(self, detector):
        """Test detector class properties."""
        assert detector.name == "ssh"
        assert "cowrie" in detector.honeypot_types
        assert "kippo" in detector.honeypot_types
        assert 22 in detector.default_ports
        assert 2222 in detector.default_ports

    def test_detector_description(self, detector):
        """Test detector has description."""
        assert detector.description is not None
        assert len(detector.description) > 0


class TestSSHDetectorRecommendations:
    """Tests for SSH detector recommendations."""

    @pytest.fixture
    def detector(self):
        """Create SSH detector instance."""
        return SSHDetector()

    def test_recommendations_for_default_banner(self, detector, mock_socket):
        """Test recommendations when default banner is detected."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = COWRIE_DEFAULT_BANNERS[0].encode() + b"\r\n"

        result = detector.detect_passive("192.168.1.100", 22)
        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any("banner" in r.lower() for r in recommendations)

    def test_recommendations_for_kippo_indicator(self, detector):
        """Test recommendations when Kippo indicator is present."""
        from potsnitch.core.result import DetectionResult, Indicator

        result = DetectionResult(target="192.168.1.100", port=22)
        result.add_indicator(
            Indicator(
                name="kippo_cr_probe",
                description="Kippo detected via CR probe",
                severity=Confidence.DEFINITE,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert any("kippo" in r.lower() or "cowrie" in r.lower() for r in recommendations)

    def test_recommendations_for_cipher_indicator(self, detector):
        """Test recommendations for cipher-related indicators."""
        from potsnitch.core.result import DetectionResult, Indicator

        result = DetectionResult(target="192.168.1.100", port=22)
        result.add_indicator(
            Indicator(
                name="cowrie_ciphers",
                description="Cowrie cipher list detected",
                severity=Confidence.HIGH,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert any("twisted" in r.lower() or "openssh" in r.lower() for r in recommendations)


class TestSSHDetectorBannerCheck:
    """Tests for the _check_banner method."""

    @pytest.fixture
    def detector(self):
        """Create SSH detector instance."""
        return SSHDetector()

    @pytest.mark.parametrize("banner,expected_indicator", [
        ("SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2", "default_banner"),
        ("SSH-2.0-OpenSSH_5.1p1 Debian-5", "default_banner"),
        ("SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.4", "default_banner"),
    ])
    def test_check_banner_default_banners(self, detector, banner, expected_indicator):
        """Test _check_banner with known default banners."""
        from potsnitch.core.result import DetectionResult

        result = DetectionResult(target="192.168.1.100", port=22)
        detector._check_banner(banner, result)

        assert any(i.name == expected_indicator for i in result.indicators)

    @pytest.mark.parametrize("banner", [
        "SSH-2.0-OpenSSH_5.1p1 Custom",
        "SSH-2.0-OpenSSH_5.9p1 Custom",
        "SSH-2.0-OpenSSH_6.0p1 Custom",
    ])
    def test_check_banner_outdated_versions(self, detector, banner):
        """Test _check_banner flags outdated OpenSSH versions."""
        from potsnitch.core.result import DetectionResult

        result = DetectionResult(target="192.168.1.100", port=22)
        detector._check_banner(banner, result)

        assert any(i.name == "outdated_version" for i in result.indicators)

    def test_check_banner_debian7_signature(self, detector):
        """Test _check_banner flags Debian 7 signature."""
        from potsnitch.core.result import DetectionResult

        result = DetectionResult(target="192.168.1.100", port=22)
        detector._check_banner("SSH-2.0-OpenSSH_7.4p1 deb7-custom", result)

        assert any(i.name == "debian7_banner" for i in result.indicators)

    def test_check_banner_no_detection_modern(self, detector):
        """Test _check_banner does not flag modern versions."""
        from potsnitch.core.result import DetectionResult

        result = DetectionResult(target="192.168.1.100", port=22)
        detector._check_banner("SSH-2.0-OpenSSH_9.0p1 Ubuntu-1", result)

        assert len(result.indicators) == 0


class TestSSHDetectorCowrieSignatures:
    """Tests for Cowrie signature checking."""

    @pytest.fixture
    def detector(self):
        """Create SSH detector instance."""
        return SSHDetector()

    def test_check_cowrie_signatures_kernel(self, detector):
        """Test _check_cowrie_signatures with kernel match."""
        system_info = {
            "proc_version": "Linux version 3.2.0-4-amd64 (debian-kernel@lists.debian.org)",
            "uname": "",
            "hostname": "",
        }
        signatures = {"kernel_version": "3.2.0-4-amd64"}

        matches = detector._check_cowrie_signatures(system_info, signatures)

        assert any("kernel_version" in m[0] for m in matches)

    def test_check_cowrie_signatures_hostname(self, detector):
        """Test _check_cowrie_signatures with hostname match."""
        system_info = {
            "proc_version": "",
            "uname": "",
            "hostname": "svr04",
        }
        signatures = {"hostname": "svr04"}

        matches = detector._check_cowrie_signatures(system_info, signatures)

        assert any("hostname" in m[0] for m in matches)

    def test_check_cowrie_signatures_no_match(self, detector):
        """Test _check_cowrie_signatures with no matches."""
        system_info = {
            "proc_version": "Linux version 6.1.0",
            "uname": "Linux server 6.1.0",
            "hostname": "production-server",
        }
        signatures = {
            "kernel_version": "3.2.0-4-amd64",
            "hostname": "svr04",
        }

        matches = detector._check_cowrie_signatures(system_info, signatures)

        assert len(matches) == 0
