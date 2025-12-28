"""Unit tests for potsnitch.probes.credentials module."""

import pytest
from typing import List, Tuple

from potsnitch.probes.credentials import (
    # Credential lists
    SSH_HONEYPOT_CREDENTIALS,
    MYSQL_HONEYPOT_CREDENTIALS,
    REDIS_HONEYPOT_CREDENTIALS,
    MONGODB_HONEYPOT_CREDENTIALS,
    POSTGRESQL_HONEYPOT_CREDENTIALS,
    TELNET_HONEYPOT_CREDENTIALS,
    FTP_HONEYPOT_CREDENTIALS,
    SMTP_HONEYPOT_CREDENTIALS,
    RDP_HONEYPOT_CREDENTIALS,
    VNC_HONEYPOT_PASSWORDS,
    GARBAGE_CREDENTIALS,
    # Signature dicts
    COWRIE_SYSTEM_SIGNATURES,
    KIPPO_SYSTEM_SIGNATURES,
    # Invalid payload lists
    SSH_INVALID_PAYLOADS,
    HTTP_INVALID_PAYLOADS,
    MYSQL_INVALID_PAYLOADS,
    REDIS_INVALID_PAYLOADS,
    MODBUS_INVALID_PAYLOADS,
    FTP_INVALID_PAYLOADS,
    SMTP_INVALID_PAYLOADS,
    TELNET_INVALID_PAYLOADS,
    VNC_INVALID_PAYLOADS,
    POSTGRESQL_INVALID_PAYLOADS,
    # Functions
    get_credentials_for_service,
    generate_garbage_credentials,
    get_garbage_credentials,
    get_invalid_payloads,
)


class TestSSHCredentials:
    """Tests for SSH honeypot credentials."""

    def test_ssh_credentials_is_list(self):
        """SSH credentials should be a list."""
        assert isinstance(SSH_HONEYPOT_CREDENTIALS, list)

    def test_ssh_credentials_not_empty(self):
        """SSH credentials should not be empty."""
        assert len(SSH_HONEYPOT_CREDENTIALS) > 0

    def test_ssh_credentials_are_tuples(self):
        """Each SSH credential should be a tuple of (username, password)."""
        for cred in SSH_HONEYPOT_CREDENTIALS:
            assert isinstance(cred, tuple)
            assert len(cred) == 2

    def test_ssh_credentials_are_strings(self):
        """Both username and password should be strings."""
        for username, password in SSH_HONEYPOT_CREDENTIALS:
            assert isinstance(username, str)
            assert isinstance(password, str)

    def test_ssh_contains_common_defaults(self):
        """SSH credentials should contain common default credentials."""
        assert ("root", "root") in SSH_HONEYPOT_CREDENTIALS
        assert ("admin", "admin") in SSH_HONEYPOT_CREDENTIALS
        assert ("root", "123456") in SSH_HONEYPOT_CREDENTIALS

    def test_ssh_contains_cowrie_defaults(self):
        """SSH credentials should contain Cowrie-specific defaults."""
        assert ("phil", "phil") in SSH_HONEYPOT_CREDENTIALS
        assert ("richard", "richard") in SSH_HONEYPOT_CREDENTIALS


class TestMySQLCredentials:
    """Tests for MySQL honeypot credentials."""

    def test_mysql_credentials_is_list(self):
        """MySQL credentials should be a list."""
        assert isinstance(MYSQL_HONEYPOT_CREDENTIALS, list)

    def test_mysql_credentials_not_empty(self):
        """MySQL credentials should not be empty."""
        assert len(MYSQL_HONEYPOT_CREDENTIALS) > 0

    def test_mysql_credentials_are_tuples(self):
        """Each MySQL credential should be a tuple of (username, password)."""
        for cred in MYSQL_HONEYPOT_CREDENTIALS:
            assert isinstance(cred, tuple)
            assert len(cred) == 2

    def test_mysql_contains_default_root(self):
        """MySQL credentials should contain root with empty password."""
        assert ("root", "") in MYSQL_HONEYPOT_CREDENTIALS


class TestRedisCredentials:
    """Tests for Redis honeypot credentials."""

    def test_redis_credentials_is_list(self):
        """Redis credentials should be a list."""
        assert isinstance(REDIS_HONEYPOT_CREDENTIALS, list)

    def test_redis_credentials_not_empty(self):
        """Redis credentials should not be empty."""
        assert len(REDIS_HONEYPOT_CREDENTIALS) > 0

    def test_redis_credentials_are_tuples(self):
        """Each Redis credential should be a tuple of (username, password)."""
        for cred in REDIS_HONEYPOT_CREDENTIALS:
            assert isinstance(cred, tuple)
            assert len(cred) == 2

    def test_redis_contains_no_auth(self):
        """Redis credentials should contain no-auth default."""
        assert ("", "") in REDIS_HONEYPOT_CREDENTIALS


class TestMongoDBCredentials:
    """Tests for MongoDB honeypot credentials."""

    def test_mongodb_credentials_is_list(self):
        """MongoDB credentials should be a list."""
        assert isinstance(MONGODB_HONEYPOT_CREDENTIALS, list)

    def test_mongodb_credentials_not_empty(self):
        """MongoDB credentials should not be empty."""
        assert len(MONGODB_HONEYPOT_CREDENTIALS) > 0

    def test_mongodb_credentials_are_tuples(self):
        """Each MongoDB credential should be a tuple of (username, password)."""
        for cred in MONGODB_HONEYPOT_CREDENTIALS:
            assert isinstance(cred, tuple)
            assert len(cred) == 2

    def test_mongodb_contains_no_auth(self):
        """MongoDB credentials should contain no-auth default."""
        assert ("", "") in MONGODB_HONEYPOT_CREDENTIALS


class TestAllCredentialLists:
    """Tests for all credential list structures."""

    @pytest.mark.parametrize("cred_list,name", [
        (SSH_HONEYPOT_CREDENTIALS, "SSH"),
        (MYSQL_HONEYPOT_CREDENTIALS, "MySQL"),
        (REDIS_HONEYPOT_CREDENTIALS, "Redis"),
        (MONGODB_HONEYPOT_CREDENTIALS, "MongoDB"),
        (POSTGRESQL_HONEYPOT_CREDENTIALS, "PostgreSQL"),
        (TELNET_HONEYPOT_CREDENTIALS, "Telnet"),
        (FTP_HONEYPOT_CREDENTIALS, "FTP"),
        (SMTP_HONEYPOT_CREDENTIALS, "SMTP"),
        (RDP_HONEYPOT_CREDENTIALS, "RDP"),
    ])
    def test_credential_list_format(self, cred_list: List[Tuple[str, str]], name: str):
        """All credential lists should have correct format."""
        assert isinstance(cred_list, list), f"{name} credentials should be a list"
        assert len(cred_list) > 0, f"{name} credentials should not be empty"
        for cred in cred_list:
            assert isinstance(cred, tuple), f"{name} credential should be a tuple"
            assert len(cred) == 2, f"{name} credential tuple should have 2 elements"
            assert isinstance(cred[0], str), f"{name} username should be string"
            assert isinstance(cred[1], str), f"{name} password should be string"


class TestVNCPasswords:
    """Tests for VNC password list."""

    def test_vnc_passwords_is_list(self):
        """VNC passwords should be a list."""
        assert isinstance(VNC_HONEYPOT_PASSWORDS, list)

    def test_vnc_passwords_not_empty(self):
        """VNC passwords should not be empty."""
        assert len(VNC_HONEYPOT_PASSWORDS) > 0

    def test_vnc_passwords_are_strings(self):
        """VNC passwords should be strings (not tuples, no username)."""
        for pwd in VNC_HONEYPOT_PASSWORDS:
            assert isinstance(pwd, str)

    def test_vnc_contains_common_passwords(self):
        """VNC passwords should contain common defaults."""
        assert "password" in VNC_HONEYPOT_PASSWORDS
        assert "123456" in VNC_HONEYPOT_PASSWORDS


class TestGetCredentialsForService:
    """Tests for get_credentials_for_service function."""

    @pytest.mark.parametrize("service,expected_list", [
        ("ssh", SSH_HONEYPOT_CREDENTIALS),
        ("mysql", MYSQL_HONEYPOT_CREDENTIALS),
        ("redis", REDIS_HONEYPOT_CREDENTIALS),
        ("mongodb", MONGODB_HONEYPOT_CREDENTIALS),
        ("postgresql", POSTGRESQL_HONEYPOT_CREDENTIALS),
        ("telnet", TELNET_HONEYPOT_CREDENTIALS),
        ("ftp", FTP_HONEYPOT_CREDENTIALS),
        ("smtp", SMTP_HONEYPOT_CREDENTIALS),
        ("rdp", RDP_HONEYPOT_CREDENTIALS),
    ])
    def test_get_credentials_returns_correct_list(self, service: str, expected_list: list):
        """Should return correct credentials for each service."""
        result = get_credentials_for_service(service, limit=100)
        assert result == expected_list

    @pytest.mark.parametrize("service", [
        "SSH", "MySQL", "REDIS", "MongoDB", "PostgreSQL",
    ])
    def test_get_credentials_case_insensitive(self, service: str):
        """Service lookup should be case-insensitive."""
        result = get_credentials_for_service(service)
        assert len(result) > 0

    def test_get_credentials_with_limit(self):
        """Should respect limit parameter."""
        result = get_credentials_for_service("ssh", limit=3)
        assert len(result) == 3

    def test_get_credentials_unknown_service(self):
        """Should return empty list for unknown service."""
        result = get_credentials_for_service("unknown_service")
        assert result == []

    def test_get_credentials_default_limit(self):
        """Default limit should be 5."""
        result = get_credentials_for_service("ssh")
        assert len(result) == 5


class TestGenerateGarbageCredentials:
    """Tests for generate_garbage_credentials function."""

    def test_returns_list(self):
        """Should return a list."""
        result = generate_garbage_credentials()
        assert isinstance(result, list)

    def test_returns_correct_count(self):
        """Should return requested number of credentials."""
        result = generate_garbage_credentials(count=10)
        assert len(result) == 10

    def test_returns_tuples(self):
        """Should return list of tuples."""
        result = generate_garbage_credentials(count=3)
        for cred in result:
            assert isinstance(cred, tuple)
            assert len(cred) == 2

    def test_credentials_are_strings(self):
        """Generated credentials should be strings."""
        result = generate_garbage_credentials(count=3)
        for username, password in result:
            assert isinstance(username, str)
            assert isinstance(password, str)

    def test_username_length(self):
        """Username should be 8-12 characters."""
        result = generate_garbage_credentials(count=20)
        for username, _ in result:
            assert 8 <= len(username) <= 12

    def test_password_length(self):
        """Password should be 12-16 characters."""
        result = generate_garbage_credentials(count=20)
        for _, password in result:
            assert 12 <= len(password) <= 16

    def test_generates_unique_credentials(self):
        """Generated credentials should be unique."""
        result = generate_garbage_credentials(count=10)
        usernames = [u for u, _ in result]
        assert len(set(usernames)) == len(usernames)

    def test_default_count(self):
        """Default count should be 5."""
        result = generate_garbage_credentials()
        assert len(result) == 5


class TestGarbageCredentials:
    """Tests for static GARBAGE_CREDENTIALS list."""

    def test_garbage_credentials_is_list(self):
        """GARBAGE_CREDENTIALS should be a list."""
        assert isinstance(GARBAGE_CREDENTIALS, list)

    def test_garbage_credentials_not_empty(self):
        """GARBAGE_CREDENTIALS should not be empty."""
        assert len(GARBAGE_CREDENTIALS) > 0

    def test_garbage_credentials_are_tuples(self):
        """Each garbage credential should be a tuple."""
        for cred in GARBAGE_CREDENTIALS:
            assert isinstance(cred, tuple)
            assert len(cred) == 2

    def test_contains_long_credentials(self):
        """Should contain long credentials for length testing."""
        long_creds = [(u, p) for u, p in GARBAGE_CREDENTIALS if len(u) > 60 or len(p) > 60]
        assert len(long_creds) > 0


class TestGetGarbageCredentials:
    """Tests for get_garbage_credentials function."""

    def test_returns_list(self):
        """Should return a list."""
        result = get_garbage_credentials()
        assert isinstance(result, list)

    def test_includes_static_garbage(self):
        """Should include static GARBAGE_CREDENTIALS."""
        result = get_garbage_credentials()
        for cred in GARBAGE_CREDENTIALS:
            assert cred in result

    def test_includes_generated_garbage(self):
        """Should include generated credentials (more than static)."""
        result = get_garbage_credentials()
        assert len(result) > len(GARBAGE_CREDENTIALS)


class TestGetInvalidPayloads:
    """Tests for get_invalid_payloads function."""

    @pytest.mark.parametrize("protocol,expected_list", [
        ("ssh", SSH_INVALID_PAYLOADS),
        ("http", HTTP_INVALID_PAYLOADS),
        ("mysql", MYSQL_INVALID_PAYLOADS),
        ("redis", REDIS_INVALID_PAYLOADS),
        ("modbus", MODBUS_INVALID_PAYLOADS),
        ("ftp", FTP_INVALID_PAYLOADS),
        ("smtp", SMTP_INVALID_PAYLOADS),
        ("telnet", TELNET_INVALID_PAYLOADS),
        ("vnc", VNC_INVALID_PAYLOADS),
        ("postgresql", POSTGRESQL_INVALID_PAYLOADS),
    ])
    def test_get_invalid_payloads_returns_correct_list(self, protocol: str, expected_list: list):
        """Should return correct payloads for each protocol."""
        result = get_invalid_payloads(protocol)
        assert result == expected_list

    @pytest.mark.parametrize("protocol", [
        "SSH", "HTTP", "MySQL", "Redis", "Modbus",
    ])
    def test_get_invalid_payloads_case_insensitive(self, protocol: str):
        """Protocol lookup should be case-insensitive."""
        result = get_invalid_payloads(protocol)
        assert len(result) > 0

    def test_get_invalid_payloads_unknown_protocol(self):
        """Should return empty list for unknown protocol."""
        result = get_invalid_payloads("unknown_protocol")
        assert result == []


class TestInvalidPayloadLists:
    """Tests for invalid payload list structures."""

    @pytest.mark.parametrize("payload_list,name", [
        (SSH_INVALID_PAYLOADS, "SSH"),
        (HTTP_INVALID_PAYLOADS, "HTTP"),
        (MYSQL_INVALID_PAYLOADS, "MySQL"),
        (REDIS_INVALID_PAYLOADS, "Redis"),
        (MODBUS_INVALID_PAYLOADS, "Modbus"),
        (FTP_INVALID_PAYLOADS, "FTP"),
        (SMTP_INVALID_PAYLOADS, "SMTP"),
        (TELNET_INVALID_PAYLOADS, "Telnet"),
        (VNC_INVALID_PAYLOADS, "VNC"),
        (POSTGRESQL_INVALID_PAYLOADS, "PostgreSQL"),
    ])
    def test_payload_list_format(self, payload_list: List[bytes], name: str):
        """All payload lists should contain bytes."""
        assert isinstance(payload_list, list), f"{name} payloads should be a list"
        assert len(payload_list) > 0, f"{name} payloads should not be empty"
        for payload in payload_list:
            assert isinstance(payload, bytes), f"{name} payload should be bytes"


class TestSystemSignatures:
    """Tests for system signature dictionaries."""

    def test_cowrie_signatures_is_dict(self):
        """Cowrie signatures should be a dictionary."""
        assert isinstance(COWRIE_SYSTEM_SIGNATURES, dict)

    def test_cowrie_signatures_not_empty(self):
        """Cowrie signatures should not be empty."""
        assert len(COWRIE_SYSTEM_SIGNATURES) > 0

    def test_cowrie_contains_kernel_version(self):
        """Cowrie signatures should contain kernel version."""
        assert "kernel_version" in COWRIE_SYSTEM_SIGNATURES

    def test_cowrie_contains_hostname(self):
        """Cowrie signatures should contain hostname."""
        assert "hostname" in COWRIE_SYSTEM_SIGNATURES

    def test_kippo_signatures_is_dict(self):
        """Kippo signatures should be a dictionary."""
        assert isinstance(KIPPO_SYSTEM_SIGNATURES, dict)

    def test_kippo_signatures_not_empty(self):
        """Kippo signatures should not be empty."""
        assert len(KIPPO_SYSTEM_SIGNATURES) > 0
