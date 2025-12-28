"""Default honeypot credentials database.

Contains known default credentials for various honeypot implementations.
Used for credential-based honeypot detection.
"""

from typing import List, Tuple

# SSH Honeypot Credentials
# Cowrie, Kippo, and other SSH honeypots accept these by default
SSH_HONEYPOT_CREDENTIALS: List[Tuple[str, str]] = [
    # Cowrie defaults (from userdb.txt)
    ("root", ""),           # Empty password - often accepted
    ("root", "123456"),     # Most common password globally
    ("root", "password"),   # Generic default
    ("root", "root"),       # Root/root combination
    ("phil", "phil"),       # Cowrie default test user
    ("richard", "richard"), # Cowrie default test user
    ("richard", "fout"),    # Cowrie example config
    # IoT/Embedded device defaults (Mirai targets)
    ("root", "xc3511"),     # DVR/Camera default
    ("root", "vizxv"),      # DVR default
    ("root", "admin"),      # Generic embedded
    ("root", "7ujMko0admin"),  # DVR default
    ("root", "Zte521"),     # ZTE router
    ("root", "zlxx."),      # DVR default
    ("admin", "admin"),     # Generic admin
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", ""),
    ("ubnt", "ubnt"),       # Ubiquiti default
    ("user", "user"),
    ("guest", "guest"),
    ("test", "test"),
    # Service accounts
    ("oracle", "oracle"),
    ("mysql", "mysql"),
    ("postgres", "postgres"),
    ("tomcat", "tomcat"),
    ("ftp", "ftp"),
]

# MySQL Honeypot Credentials
MYSQL_HONEYPOT_CREDENTIALS: List[Tuple[str, str]] = [
    ("root", ""),           # Default MySQL with no password
    ("root", "root"),
    ("root", "123456"),
    ("root", "password"),
    ("root", "mysql"),
    ("root", "admin"),
    ("mysql", "mysql"),
    ("admin", "admin"),
    ("test", "test"),
]

# Redis Honeypot Credentials
# Note: Redis default has NO authentication
REDIS_HONEYPOT_CREDENTIALS: List[Tuple[str, str]] = [
    ("", ""),               # No auth (default Redis)
    ("default", ""),        # ACL default user
    ("", "password"),       # Common password-only auth
    ("", "123456"),
    ("", "redis"),
    ("", "foobared"),       # Redis default password example
]

# MongoDB Honeypot Credentials
# Note: MongoDB default has NO authentication
MONGODB_HONEYPOT_CREDENTIALS: List[Tuple[str, str]] = [
    ("", ""),               # No auth (default MongoDB)
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("mongodb", "mongodb"),
]

# PostgreSQL Honeypot Credentials
POSTGRESQL_HONEYPOT_CREDENTIALS: List[Tuple[str, str]] = [
    ("postgres", ""),       # Default with trust auth
    ("postgres", "postgres"),
    ("postgres", "password"),
    ("postgres", "123456"),
    ("admin", "admin"),
]

# Telnet Honeypot Credentials (IoT/BusyBox)
TELNET_HONEYPOT_CREDENTIALS: List[Tuple[str, str]] = [
    ("root", ""),
    ("root", "root"),
    ("root", "123456"),
    ("root", "12345"),
    ("root", "admin"),
    ("root", "xc3511"),
    ("root", "vizxv"),
    ("root", "7ujMko0admin"),
    ("admin", "admin"),
    ("admin", "1234"),
    ("admin", ""),
    ("user", "user"),
    ("support", "support"),
    ("guest", "guest"),
    # Specific device defaults
    ("root", "juantech"),   # Jauntech DVR
    ("root", "anko"),       # Anko devices
    ("root", "realtek"),    # Realtek-based devices
    ("root", "00000000"),   # Some DVRs
    ("supervisor", "supervisor"),
    ("service", "service"),
]

# FTP Honeypot Credentials
FTP_HONEYPOT_CREDENTIALS: List[Tuple[str, str]] = [
    ("anonymous", ""),      # Anonymous FTP
    ("anonymous", "anonymous@"),
    ("ftp", "ftp"),
    ("admin", "admin"),
    ("root", "root"),
    ("user", "user"),
    ("test", "test"),
]

# SMTP Honeypot Credentials
SMTP_HONEYPOT_CREDENTIALS: List[Tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("postmaster", "postmaster"),
    ("mail", "mail"),
    ("test", "test"),
]

# VNC Honeypot Credentials (password only, no username)
VNC_HONEYPOT_PASSWORDS: List[str] = [
    "",
    "password",
    "123456",
    "vnc",
    "admin",
    "1234",
]

# RDP Honeypot Credentials
RDP_HONEYPOT_CREDENTIALS: List[Tuple[str, str]] = [
    ("administrator", ""),
    ("administrator", "password"),
    ("administrator", "123456"),
    ("admin", "admin"),
    ("user", "user"),
    ("guest", ""),
]

# System info signatures that indicate honeypots
COWRIE_SYSTEM_SIGNATURES = {
    "kernel_version": "3.2.0-4-amd64",
    "kernel_full": "Linux version 3.2.0-4-amd64 (debian-kernel@lists.debian.org) (gcc version 4.6.3 (Debian 4.6.3-14) ) #1 SMP Debian 3.2.68-1+deb7u1",
    "hostname": "svr04",
    "default_user": "phil",
    "memfree": "MemFree:          997740 kB",
    "cpu_model": "Intel(R) Core(TM)2 Duo CPU",
    "debian_version": "7.8",
}

# Kippo-specific signatures
KIPPO_SYSTEM_SIGNATURES = {
    "kernel_version": "2.6.26-2-686",
    "hostname": "nas3",
}

# Invalid payload patterns for protocol fuzzing
SSH_INVALID_PAYLOADS = [
    b"SSH-9999-Invalid\r\n",           # Invalid protocol version
    b"\x00\x00\x00\x00",               # Zero-length packet
    b"SSH-2.0-Test\r\n" * 10,          # Repeated banners
    b"\xff" * 100,                      # Binary garbage
    b"SSH-1.99-Ancient\r\n",           # Very old protocol
    b"QUIT\r\n",                        # Wrong protocol command
]

HTTP_INVALID_PAYLOADS = [
    b"INVALID / HTTP/1.1\r\nHost: test\r\n\r\n",      # Invalid method
    b"GET /../../etc/passwd HTTP/1.1\r\nHost: test\r\n\r\n",  # Path traversal
    b"GET / HTTP/9.9\r\nHost: test\r\n\r\n",          # Invalid HTTP version
    b"GET / HTTP/1.1\r\n" + b"X-Header: " + b"A" * 10000 + b"\r\n\r\n",  # Long header
    b"\x00\x01\x02\x03",                               # Binary data
]

MYSQL_INVALID_PAYLOADS = [
    b"\x00\x00\x00\x00",               # Zero-length packet
    b"\xff" * 50,                       # Binary garbage
    b"SELECT 1;\n",                     # Raw SQL (no handshake)
]

REDIS_INVALID_PAYLOADS = [
    b"INVALID_COMMAND\r\n",
    b"*99\r\n",                         # Invalid RESP array
    b"\x00\x00\x00\x00",
]

MODBUS_INVALID_PAYLOADS = [
    b"\x00\x00\x00\x00\x00\x01\x01\xff",  # Invalid function code
    b"\x00" * 12,                          # All zeros
    b"\xff" * 12,                          # All ones
    b"\x00\x00\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01",  # Valid read, wrong unit
]

# FTP Invalid Payloads
FTP_INVALID_PAYLOADS = [
    b"INVALID\r\n",                        # Unknown command
    b"USER \x00\r\n",                      # Null byte in username
    b"PASV\r\n" * 10,                      # Repeated PASV
    b"CWD /../../../etc\r\n",              # Path traversal
    b"\xff\xff\xff\xff",                   # Binary garbage
]

# SMTP Invalid Payloads
SMTP_INVALID_PAYLOADS = [
    b"INVALID\r\n",                        # Unknown command
    b"HELO \x00\r\n",                      # Null byte
    b"MAIL FROM:<" + b"a" * 1000 + b">\r\n",  # Long address
    b"RCPT TO:<${jndi:ldap://x}>\r\n",    # Log4j attempt
    b"\xff\xff\xff\xff",                   # Binary garbage
]

# Telnet Invalid Payloads
TELNET_INVALID_PAYLOADS = [
    b"\xff\xfe\x00",                       # Invalid IAC sequence
    b"\x00" * 100,                         # Null bytes
    b"exit\r\n" * 20,                      # Repeated exit
    b"\xff\xff\xff\xff",                   # Binary garbage
]

# VNC Invalid Payloads (RFB Protocol)
VNC_INVALID_PAYLOADS = [
    b"RFB 999.999\n",                      # Invalid version
    b"\x00" * 12,                          # All zeros
    b"\xff\xff\xff\xff",                   # Invalid auth response
]

# PostgreSQL Invalid Payloads
POSTGRESQL_INVALID_PAYLOADS = [
    b"\x00\x00\x00\x08\x04\xd2\x16\x2f",   # Malformed startup
    b"X" * 100,                             # Binary garbage
    b"\x00\x00\x00\x00",                   # Zero-length message
]

# ============================================
# Garbage Credentials for Accept-All Detection
# ============================================
# These are intentionally random/malformed credentials
# that no real system should accept. If a service accepts
# these, it's almost certainly a honeypot.

import secrets
import string

def generate_garbage_credentials(count: int = 5) -> List[Tuple[str, str]]:
    """Generate random garbage credentials for accept-all detection.

    If a service accepts these random credentials, it's likely a honeypot
    that accepts any credentials to capture commands.

    Args:
        count: Number of credential pairs to generate

    Returns:
        List of (username, password) tuples
    """
    garbage = []
    for _ in range(count):
        # Random username (8-12 chars)
        username = ''.join(secrets.choice(string.ascii_lowercase) for _ in range(secrets.randbelow(5) + 8))
        # Random password (12-16 chars with special chars)
        chars = string.ascii_letters + string.digits + "!@#$%"
        password = ''.join(secrets.choice(chars) for _ in range(secrets.randbelow(5) + 12))
        garbage.append((username, password))
    return garbage


# Pre-generated garbage credentials (static for reproducibility in tests)
# Using purely random strings instead of attack patterns (SQLi, XSS, Log4J)
# to avoid triggering IDS/IPS alerts and leaving attack-like audit trails.
# Random strings still effectively detect accept-all honeypot behavior.
GARBAGE_CREDENTIALS: List[Tuple[str, str]] = [
    # Random alphanumeric strings - no real user would have these
    ("xkwqpzmt", "Hf7#nK2$pLmQ"),
    ("zjrnvlbx", "9Yx!mN4@wRtP"),
    ("qmfhvtpw", "Lk3@nP8#mXyZ"),
    ("bnrtycxs", "Wq5$hJ7&vRtK"),
    # Long random strings (tests input length handling)
    ("a" * 64, "b" * 64),
    # Unicode/special chars (real services may reject)
    ("tëst_üsér", "pàsswörd_tëst"),
    # Numeric-only (unusual for usernames)
    ("8472619035", "1938475620"),
]


def get_garbage_credentials() -> List[Tuple[str, str]]:
    """Get garbage credentials for accept-all detection.

    Returns both static garbage credentials and freshly generated random ones.

    Returns:
        List of (username, password) tuples
    """
    return GARBAGE_CREDENTIALS + generate_garbage_credentials(3)


def get_credentials_for_service(service: str, limit: int = 5) -> List[Tuple[str, str]]:
    """Get credential list for a specific service.

    Args:
        service: Service name (ssh, mysql, redis, mongodb, telnet, ftp, smtp, rdp)
        limit: Maximum number of credentials to return

    Returns:
        List of (username, password) tuples
    """
    credential_map = {
        "ssh": SSH_HONEYPOT_CREDENTIALS,
        "mysql": MYSQL_HONEYPOT_CREDENTIALS,
        "redis": REDIS_HONEYPOT_CREDENTIALS,
        "mongodb": MONGODB_HONEYPOT_CREDENTIALS,
        "postgresql": POSTGRESQL_HONEYPOT_CREDENTIALS,
        "telnet": TELNET_HONEYPOT_CREDENTIALS,
        "ftp": FTP_HONEYPOT_CREDENTIALS,
        "smtp": SMTP_HONEYPOT_CREDENTIALS,
        "rdp": RDP_HONEYPOT_CREDENTIALS,
    }

    creds = credential_map.get(service.lower(), [])
    return creds[:limit]


def get_invalid_payloads(protocol: str) -> List[bytes]:
    """Get invalid payload patterns for a protocol.

    Args:
        protocol: Protocol name (ssh, http, mysql, redis, modbus, ftp, smtp, telnet, vnc, postgresql)

    Returns:
        List of invalid payload byte strings
    """
    payload_map = {
        "ssh": SSH_INVALID_PAYLOADS,
        "http": HTTP_INVALID_PAYLOADS,
        "mysql": MYSQL_INVALID_PAYLOADS,
        "redis": REDIS_INVALID_PAYLOADS,
        "modbus": MODBUS_INVALID_PAYLOADS,
        "ftp": FTP_INVALID_PAYLOADS,
        "smtp": SMTP_INVALID_PAYLOADS,
        "telnet": TELNET_INVALID_PAYLOADS,
        "vnc": VNC_INVALID_PAYLOADS,
        "postgresql": POSTGRESQL_INVALID_PAYLOADS,
    }

    return payload_map.get(protocol.lower(), [])
