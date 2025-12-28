"""Honeypot probing utilities and credential databases."""

from .credentials import (
    SSH_HONEYPOT_CREDENTIALS,
    MYSQL_HONEYPOT_CREDENTIALS,
    REDIS_HONEYPOT_CREDENTIALS,
    MONGODB_HONEYPOT_CREDENTIALS,
    TELNET_HONEYPOT_CREDENTIALS,
    FTP_HONEYPOT_CREDENTIALS,
    SMTP_HONEYPOT_CREDENTIALS,
    VNC_HONEYPOT_PASSWORDS,
    RDP_HONEYPOT_CREDENTIALS,
    POSTGRESQL_HONEYPOT_CREDENTIALS,
    get_credentials_for_service,
    get_invalid_payloads,
    COWRIE_SYSTEM_SIGNATURES,
    SSH_INVALID_PAYLOADS,
    HTTP_INVALID_PAYLOADS,
    MYSQL_INVALID_PAYLOADS,
    REDIS_INVALID_PAYLOADS,
    MODBUS_INVALID_PAYLOADS,
)

from .timing import (
    TimingResult,
    TimingAnalysis,
    TimingProbe,
    measure_connection_time,
    measure_response_time,
    analyze_timing_samples,
    probe_auth_timing,
    probe_response_timing_variance,
    probe_error_timing_uniformity,
    probe_connection_timing_consistency,
)

__all__ = [
    # Credentials
    "SSH_HONEYPOT_CREDENTIALS",
    "MYSQL_HONEYPOT_CREDENTIALS",
    "REDIS_HONEYPOT_CREDENTIALS",
    "MONGODB_HONEYPOT_CREDENTIALS",
    "TELNET_HONEYPOT_CREDENTIALS",
    "FTP_HONEYPOT_CREDENTIALS",
    "SMTP_HONEYPOT_CREDENTIALS",
    "VNC_HONEYPOT_PASSWORDS",
    "RDP_HONEYPOT_CREDENTIALS",
    "POSTGRESQL_HONEYPOT_CREDENTIALS",
    "get_credentials_for_service",
    "get_invalid_payloads",
    # Signatures
    "COWRIE_SYSTEM_SIGNATURES",
    # Invalid payloads
    "SSH_INVALID_PAYLOADS",
    "HTTP_INVALID_PAYLOADS",
    "MYSQL_INVALID_PAYLOADS",
    "REDIS_INVALID_PAYLOADS",
    "MODBUS_INVALID_PAYLOADS",
    # Timing
    "TimingResult",
    "TimingAnalysis",
    "TimingProbe",
    "measure_connection_time",
    "measure_response_time",
    "analyze_timing_samples",
    "probe_auth_timing",
    "probe_response_timing_variance",
    "probe_error_timing_uniformity",
    "probe_connection_timing_consistency",
]
