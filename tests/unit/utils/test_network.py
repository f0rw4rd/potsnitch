"""Unit tests for potsnitch.utils.network module."""

import socket
from unittest.mock import MagicMock, patch, call

import pytest

from potsnitch.utils.network import (
    is_port_open,
    scan_ports,
    resolve_hostname,
    get_banner,
)


class TestIsPortOpen:
    """Tests for is_port_open function."""

    def test_port_open_returns_true(self, mock_socket):
        """Test returns True when port is open (connect_ex returns 0)."""
        socket_instance = mock_socket.return_value
        socket_instance.connect_ex.return_value = 0

        result = is_port_open("192.168.1.1", 80)

        assert result is True
        mock_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        socket_instance.settimeout.assert_called_once_with(2.0)
        socket_instance.connect_ex.assert_called_once_with(("192.168.1.1", 80))
        socket_instance.close.assert_called_once()

    def test_port_closed_returns_false(self, mock_socket):
        """Test returns False when port is closed (connect_ex returns non-zero)."""
        socket_instance = mock_socket.return_value
        socket_instance.connect_ex.return_value = 111  # Connection refused

        result = is_port_open("192.168.1.1", 443)

        assert result is False

    @pytest.mark.parametrize("timeout", [0.5, 1.0, 5.0, 10.0])
    def test_custom_timeout(self, mock_socket, timeout):
        """Test custom timeout is applied."""
        socket_instance = mock_socket.return_value
        socket_instance.connect_ex.return_value = 0

        is_port_open("192.168.1.1", 22, timeout=timeout)

        socket_instance.settimeout.assert_called_once_with(timeout)

    @pytest.mark.parametrize("exception", [
        socket.error("Connection failed"),
        socket.timeout("Timed out"),
        OSError("Network unreachable"),
    ])
    def test_socket_exceptions_return_false(self, mock_socket, exception):
        """Test socket exceptions are caught and return False."""
        mock_socket.return_value.connect_ex.side_effect = exception

        result = is_port_open("192.168.1.1", 80)

        assert result is False


class TestScanPorts:
    """Tests for scan_ports function."""

    def test_returns_sorted_open_ports(self, mock_socket):
        """Test returns sorted list of open ports."""
        socket_instance = mock_socket.return_value

        # Mock: ports 80 and 443 open, 22 closed
        def connect_ex_side_effect(addr):
            return 0 if addr[1] in [80, 443] else 111

        socket_instance.connect_ex.side_effect = connect_ex_side_effect

        result = scan_ports("192.168.1.1", [443, 22, 80])

        assert result == [80, 443]

    def test_empty_ports_list(self, mock_socket):
        """Test with empty ports list."""
        result = scan_ports("192.168.1.1", [])

        assert result == []

    def test_all_ports_closed(self, mock_socket):
        """Test when all ports are closed."""
        socket_instance = mock_socket.return_value
        socket_instance.connect_ex.return_value = 111

        result = scan_ports("192.168.1.1", [22, 80, 443])

        assert result == []

    def test_all_ports_open(self, mock_socket):
        """Test when all ports are open."""
        socket_instance = mock_socket.return_value
        socket_instance.connect_ex.return_value = 0

        result = scan_ports("192.168.1.1", [22, 80, 443])

        assert result == [22, 80, 443]

    @pytest.mark.parametrize("max_workers", [1, 5, 10, 50])
    def test_max_workers_parameter(self, max_workers):
        """Test max_workers parameter is passed correctly."""
        with patch("potsnitch.utils.network.ThreadPoolExecutor") as mock_executor:
            mock_context = MagicMock()
            mock_executor.return_value.__enter__.return_value = mock_context
            mock_executor.return_value.__exit__.return_value = None

            # Mock the submit to return a completed future
            mock_future = MagicMock()
            mock_future.result.return_value = True
            mock_context.submit.return_value = mock_future

            # Make as_completed return the future immediately
            with patch("potsnitch.utils.network.as_completed") as mock_as_completed:
                mock_as_completed.return_value = iter([mock_future])

                scan_ports("192.168.1.1", [80], max_workers=max_workers)

                mock_executor.assert_called_once_with(max_workers=max_workers)


class TestResolveHostname:
    """Tests for resolve_hostname function."""

    def test_successful_resolution(self):
        """Test successful hostname resolution."""
        with patch("socket.gethostbyname") as mock_gethost:
            mock_gethost.return_value = "93.184.216.34"

            result = resolve_hostname("example.com")

            assert result == "93.184.216.34"
            mock_gethost.assert_called_once_with("example.com")

    def test_resolution_failure_returns_none(self):
        """Test failed resolution returns None."""
        with patch("socket.gethostbyname") as mock_gethost:
            mock_gethost.side_effect = socket.gaierror("Name resolution failed")

            result = resolve_hostname("invalid.nonexistent.domain")

            assert result is None

    @pytest.mark.parametrize("hostname,expected_ip", [
        ("localhost", "127.0.0.1"),
        ("google.com", "142.250.80.46"),
        ("cloudflare.com", "104.16.132.229"),
    ])
    def test_various_hostnames(self, hostname, expected_ip):
        """Test resolution of various hostnames."""
        with patch("socket.gethostbyname") as mock_gethost:
            mock_gethost.return_value = expected_ip

            result = resolve_hostname(hostname)

            assert result == expected_ip


class TestGetBanner:
    """Tests for get_banner function."""

    def test_banner_received_on_connect(self, mock_socket):
        """Test banner received immediately after connection."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"SSH-2.0-OpenSSH_8.2\r\n"

        result = get_banner("192.168.1.1", 22)

        assert result == "SSH-2.0-OpenSSH_8.2"
        socket_instance.connect.assert_called_once_with(("192.168.1.1", 22))

    def test_banner_after_nudge(self, mock_socket):
        """Test banner received after sending newline."""
        socket_instance = mock_socket.return_value
        # First recv times out, second succeeds
        socket_instance.recv.side_effect = [
            socket.timeout("timeout"),
            b"220 smtp.example.com ESMTP\r\n",
        ]

        result = get_banner("192.168.1.1", 25)

        assert result == "220 smtp.example.com ESMTP"
        socket_instance.send.assert_called_once_with(b"\r\n")

    def test_no_banner_returns_none(self, mock_socket):
        """Test returns None when no banner received."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.side_effect = socket.timeout("timeout")

        result = get_banner("192.168.1.1", 80)

        assert result is None

    def test_empty_banner_returns_none(self, mock_socket):
        """Test returns None when banner is empty."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b""

        result = get_banner("192.168.1.1", 22)

        assert result is None

    def test_custom_timeout(self, mock_socket):
        """Test custom timeout is applied."""
        socket_instance = mock_socket.return_value
        socket_instance.recv.return_value = b"Banner"

        get_banner("192.168.1.1", 22, timeout=10.0)

        # First settimeout is for connection, second for recv
        assert socket_instance.settimeout.call_args_list[0] == call(10.0)

    @pytest.mark.parametrize("exception", [
        socket.error("Connection refused"),
        socket.timeout("Timed out"),
        OSError("Network unreachable"),
    ])
    def test_connection_errors_return_none(self, mock_socket, exception):
        """Test connection errors return None."""
        mock_socket.return_value.connect.side_effect = exception

        result = get_banner("192.168.1.1", 22)

        assert result is None

    def test_banner_decoding_with_errors(self, mock_socket):
        """Test banner with invalid UTF-8 is decoded with errors ignored."""
        socket_instance = mock_socket.return_value
        # Invalid UTF-8 sequence
        socket_instance.recv.return_value = b"Banner\xff\xfe data\r\n"

        result = get_banner("192.168.1.1", 22)

        assert result == "Banner data"
