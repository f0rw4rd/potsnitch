"""
Unit tests for honeypot version signatures.

Tests SSH version signatures, database version signatures, HTTP signatures,
ICS signatures, and validates all signature dictionaries have correct structure.
"""

import pytest

from potsnitch.signatures.versions import (
    # SSH Honeypots
    COWRIE_SIGNATURES,
    HERALDING_SSH_SIGNATURES,
    ENDLESSH_SIGNATURES,
    SSHESAME_SIGNATURES,
    BLACKNET_SIGNATURES,
    KOJONEY_SIGNATURES,
    # SMB/FTP Honeypots
    DIONAEA_SIGNATURES,
    # ICS/SCADA Honeypots
    CONPOT_SIGNATURES,
    GASPOT_SIGNATURES,
    GRIDPOT_SIGNATURES,
    HONEYPLC_SIGNATURES,
    # Elasticsearch Honeypots
    ELASTICPOT_SIGNATURES,
    # SMTP/Email Honeypots
    MAILONEY_SIGNATURES,
    HERALDING_MAIL_SIGNATURES,
    # Database Honeypots
    MONGODB_HONEYPOT_SIGNATURES,
    MYSQL_HONEYPOT_SIGNATURES,
    POSTGRESQL_HONEYPOT_SIGNATURES,
    REDIS_HONEYPOT_SIGNATURES,
    # Web/HTTP Honeypots
    HTTP_HONEYPOT_SIGNATURES,
    HELLPOT_SIGNATURES,
    WORDPOT_SIGNATURES,
    GLASTOPF_SIGNATURES,
    SHOCKPOT_SIGNATURES,
    # Telnet Honeypots
    TELNET_HONEYPOT_SIGNATURES,
    MTPOT_SIGNATURES,
    # RDP Honeypots
    RDP_HONEYPOT_SIGNATURES,
    # CVE-Specific Honeypots
    LOG4POT_SIGNATURES,
    CITRIX_HONEYPOT_SIGNATURES,
    CISCOASA_HONEYPOT_SIGNATURES,
    SPRING4SHELL_SIGNATURES,
    # Multi-Service Frameworks
    OPENCANARY_SIGNATURES,
    QEEQBOX_SIGNATURES,
    ARTILLERY_SIGNATURES,
    FAPRO_SIGNATURES,
    TPOT_SPECIFIC_SIGNATURES,
    TPOT_24_SIGNATURES,
    # Protocol-Specific
    VNC_HONEYPOT_SIGNATURES,
    SIP_HONEYPOT_SIGNATURES,
    # Fingerprinting
    HASSH_FINGERPRINTS,
    HONEYD_SIGNATURES,
)


class TestCowrieSignatures:
    """Tests for Cowrie SSH honeypot signatures."""

    def test_banners_structure(self):
        """Test Cowrie banners have correct structure."""
        assert "banners" in COWRIE_SIGNATURES
        assert isinstance(COWRIE_SIGNATURES["banners"], dict)

    @pytest.mark.parametrize("version_key", ["v2.5+", "tpot_24", "v1.x-2.4", "kippo", "alternatives"])
    def test_banner_versions_exist(self, version_key):
        """Test Cowrie banner version keys exist."""
        assert version_key in COWRIE_SIGNATURES["banners"]
        assert isinstance(COWRIE_SIGNATURES["banners"][version_key], list)
        assert len(COWRIE_SIGNATURES["banners"][version_key]) > 0

    @pytest.mark.parametrize("banner", [
        "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
        "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
        "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",
        "SSH-2.0-OpenSSH_5.1p1 Debian-5",
    ])
    def test_known_cowrie_banners(self, banner):
        """Test specific known Cowrie banners are present."""
        all_banners = []
        for banners in COWRIE_SIGNATURES["banners"].values():
            all_banners.extend(banners)
        assert banner in all_banners

    def test_hostnames_structure(self):
        """Test Cowrie hostnames have correct structure."""
        assert "hostnames" in COWRIE_SIGNATURES
        assert "cowrie" in COWRIE_SIGNATURES["hostnames"]
        assert "kippo" in COWRIE_SIGNATURES["hostnames"]
        assert "svr04" in COWRIE_SIGNATURES["hostnames"]["cowrie"]

    def test_kernels_structure(self):
        """Test Cowrie kernel versions are defined."""
        assert "kernels" in COWRIE_SIGNATURES
        assert isinstance(COWRIE_SIGNATURES["kernels"], list)
        assert "3.2.0-4-amd64" in COWRIE_SIGNATURES["kernels"]

    def test_users_structure(self):
        """Test Cowrie default users are defined."""
        assert "users" in COWRIE_SIGNATURES
        assert "phil" in COWRIE_SIGNATURES["users"]
        assert "richard" in COWRIE_SIGNATURES["users"]
        assert "root" in COWRIE_SIGNATURES["users"]


class TestHeraldingSSHSignatures:
    """Tests for Heralding SSH signatures."""

    def test_banners_structure(self):
        """Test Heralding SSH banners structure."""
        assert "banners" in HERALDING_SSH_SIGNATURES
        assert isinstance(HERALDING_SSH_SIGNATURES["banners"], list)

    def test_default_banner(self):
        """Test Heralding default SSH banner."""
        assert "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.8" in HERALDING_SSH_SIGNATURES["banners"]


class TestDionaeaSignatures:
    """Tests for Dionaea SMB/FTP honeypot signatures."""

    def test_smb_structure(self):
        """Test Dionaea SMB signatures structure."""
        assert "smb" in DIONAEA_SIGNATURES
        assert "domains" in DIONAEA_SIGNATURES["smb"]
        assert "servers" in DIONAEA_SIGNATURES["smb"]
        assert "native_os" in DIONAEA_SIGNATURES["smb"]
        assert "lan_manager" in DIONAEA_SIGNATURES["smb"]

    @pytest.mark.parametrize("domain", ["WORKGROUP", "MSHOME"])
    def test_smb_domains(self, domain):
        """Test Dionaea SMB domain signatures."""
        assert domain in DIONAEA_SIGNATURES["smb"]["domains"]

    def test_ftp_banners_structure(self):
        """Test Dionaea FTP banners structure."""
        assert "ftp_banners" in DIONAEA_SIGNATURES
        assert "current" in DIONAEA_SIGNATURES["ftp_banners"]
        assert "legacy" in DIONAEA_SIGNATURES["ftp_banners"]

    def test_ftp_current_banners(self):
        """Test Dionaea current FTP banners."""
        assert b"220 Welcome to the ftp service\r\n" in DIONAEA_SIGNATURES["ftp_banners"]["current"]

    def test_http_structure(self):
        """Test Dionaea HTTP signatures structure."""
        assert "http" in DIONAEA_SIGNATURES
        assert "default_page_hashes" in DIONAEA_SIGNATURES["http"]


class TestConpotSignatures:
    """Tests for Conpot ICS/SCADA honeypot signatures."""

    def test_s7comm_structure(self):
        """Test Conpot S7Comm signatures structure."""
        assert "s7comm" in CONPOT_SIGNATURES
        assert "system_names" in CONPOT_SIGNATURES["s7comm"]
        assert "facility_names" in CONPOT_SIGNATURES["s7comm"]
        assert "serials" in CONPOT_SIGNATURES["s7comm"]
        assert "locations" in CONPOT_SIGNATURES["s7comm"]
        assert "module_types" in CONPOT_SIGNATURES["s7comm"]

    @pytest.mark.parametrize("system_name", ["Technodrome", "S7-200", "SIMATIC"])
    def test_s7comm_system_names(self, system_name):
        """Test Conpot S7Comm system names."""
        assert system_name in CONPOT_SIGNATURES["s7comm"]["system_names"]

    def test_modbus_structure(self):
        """Test Conpot Modbus signatures structure."""
        assert "modbus" in CONPOT_SIGNATURES
        assert "vendor" in CONPOT_SIGNATURES["modbus"]
        assert CONPOT_SIGNATURES["modbus"]["vendor"] == "Siemens"

    def test_snmp_structure(self):
        """Test Conpot SNMP signatures structure."""
        assert "snmp" in CONPOT_SIGNATURES
        assert "sysName" in CONPOT_SIGNATURES["snmp"]
        assert "sysLocation" in CONPOT_SIGNATURES["snmp"]


class TestElasticpotSignatures:
    """Tests for Elasticpot Elasticsearch honeypot signatures."""

    def test_instance_names(self):
        """Test Elasticpot instance names."""
        assert "instance_names" in ELASTICPOT_SIGNATURES
        assert "default" in ELASTICPOT_SIGNATURES["instance_names"]
        assert "tpot" in ELASTICPOT_SIGNATURES["instance_names"]
        assert ELASTICPOT_SIGNATURES["instance_names"]["default"] == "Green Goblin"

    def test_cluster_names(self):
        """Test Elasticpot cluster names."""
        assert "cluster_names" in ELASTICPOT_SIGNATURES
        assert "elasticsearch" in ELASTICPOT_SIGNATURES["cluster_names"]

    def test_versions(self):
        """Test Elasticpot versions."""
        assert "versions" in ELASTICPOT_SIGNATURES
        assert "1.4.1" in ELASTICPOT_SIGNATURES["versions"]
        assert "2.4.6" in ELASTICPOT_SIGNATURES["versions"]


class TestDatabaseSignatures:
    """Tests for database honeypot signatures."""

    def test_mongodb_structure(self):
        """Test MongoDB honeypot signatures structure."""
        assert "versions" in MONGODB_HONEYPOT_SIGNATURES
        assert "git_hashes" in MONGODB_HONEYPOT_SIGNATURES
        assert "honeymongo" in MONGODB_HONEYPOT_SIGNATURES

    @pytest.mark.parametrize("version", ["3.4.4", "3.2.0", "2.6.0"])
    def test_mongodb_versions(self, version):
        """Test MongoDB honeypot versions."""
        assert version in MONGODB_HONEYPOT_SIGNATURES["versions"]

    def test_mysql_structure(self):
        """Test MySQL honeypot signatures structure."""
        assert "versions" in MYSQL_HONEYPOT_SIGNATURES
        assert "charsets" in MYSQL_HONEYPOT_SIGNATURES
        assert "protocol_version" in MYSQL_HONEYPOT_SIGNATURES
        assert "auth_plugin" in MYSQL_HONEYPOT_SIGNATURES

    @pytest.mark.parametrize("honeypot,version", [
        ("mysql-honeypotd", "5.7.16-MySQL-Community-Server"),
        ("qeeqbox", "5.7.30-MySQL-Community-Server"),
        ("opencanary", "5.5.30-MySQL-Community-Server"),
    ])
    def test_mysql_versions(self, honeypot, version):
        """Test MySQL honeypot versions."""
        assert MYSQL_HONEYPOT_SIGNATURES["versions"][honeypot] == version

    def test_postgresql_structure(self):
        """Test PostgreSQL honeypot signatures structure."""
        assert "error_codes" in POSTGRESQL_HONEYPOT_SIGNATURES
        assert "sticky_elephant" in POSTGRESQL_HONEYPOT_SIGNATURES

    def test_redis_structure(self):
        """Test Redis honeypot signatures structure."""
        assert "errors" in REDIS_HONEYPOT_SIGNATURES
        assert "limited_commands" in REDIS_HONEYPOT_SIGNATURES

    @pytest.mark.parametrize("error", [
        "-ERR unknown command",
        "-ERR wrong number of arguments",
    ])
    def test_redis_errors(self, error):
        """Test Redis honeypot error messages."""
        assert error in REDIS_HONEYPOT_SIGNATURES["errors"]


class TestHTTPSignatures:
    """Tests for HTTP honeypot signatures."""

    def test_glastopf_structure(self):
        """Test Glastopf signatures structure."""
        assert "glastopf" in HTTP_HONEYPOT_SIGNATURES
        assert "headers" in HTTP_HONEYPOT_SIGNATURES["glastopf"]
        assert "content_patterns" in HTTP_HONEYPOT_SIGNATURES["glastopf"]

    def test_wordpot_structure(self):
        """Test WordPot signatures structure."""
        assert "wordpot" in HTTP_HONEYPOT_SIGNATURES
        assert "paths" in HTTP_HONEYPOT_SIGNATURES["wordpot"]
        assert "/wp-admin/" in HTTP_HONEYPOT_SIGNATURES["wordpot"]["paths"]

    def test_shockpot_structure(self):
        """Test Shockpot signatures structure."""
        assert "shockpot" in HTTP_HONEYPOT_SIGNATURES
        assert "page_hashes" in HTTP_HONEYPOT_SIGNATURES["shockpot"]

    def test_hellpot_structure(self):
        """Test HellPot signatures structure."""
        assert "server_header" in HELLPOT_SIGNATURES
        assert "tarpit_paths" in HELLPOT_SIGNATURES
        assert "infinite_response" in HELLPOT_SIGNATURES
        assert HELLPOT_SIGNATURES["infinite_response"] is True

    @pytest.mark.parametrize("path", [
        "/wp-login.php",
        "/wp-admin/",
        "/.git/",
        "/.env",
        "/phpmyadmin/",
    ])
    def test_hellpot_tarpit_paths(self, path):
        """Test HellPot tarpit paths."""
        assert path in HELLPOT_SIGNATURES["tarpit_paths"]


class TestTelnetSignatures:
    """Tests for Telnet honeypot signatures."""

    def test_cowrie_telnet_structure(self):
        """Test Cowrie Telnet signatures structure."""
        assert "cowrie" in TELNET_HONEYPOT_SIGNATURES
        assert "banners" in TELNET_HONEYPOT_SIGNATURES["cowrie"]

    def test_mtpot_structure(self):
        """Test MTPot Telnet signatures structure."""
        assert "mtpot" in TELNET_HONEYPOT_SIGNATURES
        assert "banners" in TELNET_HONEYPOT_SIGNATURES["mtpot"]

    def test_mtpot_mirai_signatures(self):
        """Test MTPot Mirai-related signatures."""
        assert "mirai_telnet" in MTPOT_SIGNATURES
        assert "busybox_prompt" in MTPOT_SIGNATURES
        assert "limited_commands" in MTPOT_SIGNATURES


class TestICSSignatures:
    """Tests for ICS/SCADA honeypot signatures."""

    def test_gaspot_structure(self):
        """Test GasPot signatures structure."""
        assert "port" in GASPOT_SIGNATURES
        assert GASPOT_SIGNATURES["port"] == 10001
        assert "protocol" in GASPOT_SIGNATURES
        assert GASPOT_SIGNATURES["protocol"] == "ATG"

    def test_gridpot_structure(self):
        """Test GridPot signatures structure."""
        assert "ports" in GRIDPOT_SIGNATURES
        assert "dnp3" in GRIDPOT_SIGNATURES["ports"]
        assert "protocols" in GRIDPOT_SIGNATURES

    def test_honeyplc_structure(self):
        """Test HoneyPLC signatures structure."""
        assert "s7comm" in HONEYPLC_SIGNATURES
        assert HONEYPLC_SIGNATURES["s7comm"] is True


class TestSSHTarpitSignatures:
    """Tests for SSH tarpit and additional SSH honeypot signatures."""

    def test_endlessh_structure(self):
        """Test Endlessh signatures structure."""
        assert "delay_ms" in ENDLESSH_SIGNATURES
        assert ENDLESSH_SIGNATURES["delay_ms"] == 10000
        assert "detection_threshold_s" in ENDLESSH_SIGNATURES
        assert "ports" in ENDLESSH_SIGNATURES

    @pytest.mark.parametrize("port", [22, 2222, 22222])
    def test_endlessh_ports(self, port):
        """Test Endlessh common ports."""
        assert port in ENDLESSH_SIGNATURES["ports"]

    def test_sshesame_structure(self):
        """Test SSHesame signatures structure."""
        assert "banners" in SSHESAME_SIGNATURES
        assert "accepts_all_keys" in SSHESAME_SIGNATURES
        assert SSHESAME_SIGNATURES["accepts_all_keys"] is True

    @pytest.mark.parametrize("banner", ["SSH-2.0-sshesame", "SSH-2.0-Go"])
    def test_sshesame_banners(self, banner):
        """Test SSHesame known banners."""
        assert banner in SSHESAME_SIGNATURES["banners"]

    def test_blacknet_structure(self):
        """Test Blacknet signatures structure."""
        assert "hassh" in BLACKNET_SIGNATURES
        assert "library" in BLACKNET_SIGNATURES
        assert BLACKNET_SIGNATURES["library"] == "paramiko"

    def test_kojoney_structure(self):
        """Test Kojoney signatures structure."""
        assert "hassh" in KOJONEY_SIGNATURES
        assert "library" in KOJONEY_SIGNATURES
        assert "shell" in KOJONEY_SIGNATURES


class TestCVESpecificSignatures:
    """Tests for CVE-specific honeypot signatures."""

    def test_log4pot_structure(self):
        """Test Log4Pot signatures structure."""
        assert "sap_netweaver" in LOG4POT_SIGNATURES
        assert "title_patterns" in LOG4POT_SIGNATURES
        assert "response_patterns" in LOG4POT_SIGNATURES
        assert "ports" in LOG4POT_SIGNATURES

    def test_citrix_structure(self):
        """Test Citrix honeypot signatures structure."""
        assert "server_headers" in CITRIX_HONEYPOT_SIGNATURES
        assert "vulnerable_paths" in CITRIX_HONEYPOT_SIGNATURES
        assert "response_patterns" in CITRIX_HONEYPOT_SIGNATURES

    def test_ciscoasa_structure(self):
        """Test Cisco ASA honeypot signatures structure."""
        assert "http_patterns" in CISCOASA_HONEYPOT_SIGNATURES
        assert "ports" in CISCOASA_HONEYPOT_SIGNATURES

    def test_spring4shell_structure(self):
        """Test Spring4Shell honeypot signatures structure."""
        assert "actuator_endpoints" in SPRING4SHELL_SIGNATURES
        assert "error_patterns" in SPRING4SHELL_SIGNATURES

    @pytest.mark.parametrize("endpoint", [
        "/actuator/health",
        "/actuator/info",
        "/actuator/env",
    ])
    def test_spring4shell_endpoints(self, endpoint):
        """Test Spring4Shell actuator endpoints."""
        assert endpoint in SPRING4SHELL_SIGNATURES["actuator_endpoints"]


class TestMultiServiceFrameworkSignatures:
    """Tests for multi-service framework signatures."""

    def test_opencanary_structure(self):
        """Test OpenCanary signatures structure."""
        assert "ports" in OPENCANARY_SIGNATURES
        assert "detection_threshold" in OPENCANARY_SIGNATURES
        assert isinstance(OPENCANARY_SIGNATURES["ports"], dict)

    @pytest.mark.parametrize("port,service", [
        (21, "ftp"),
        (22, "ssh"),
        (3306, "mysql"),
        (6379, "redis"),
    ])
    def test_opencanary_ports(self, port, service):
        """Test OpenCanary port mappings."""
        assert OPENCANARY_SIGNATURES["ports"][port] == service

    def test_qeeqbox_structure(self):
        """Test Qeeqbox signatures structure."""
        assert "ports" in QEEQBOX_SIGNATURES
        assert "high_port_threshold" in QEEQBOX_SIGNATURES
        assert len(QEEQBOX_SIGNATURES["ports"]) > 10

    def test_artillery_structure(self):
        """Test Artillery signatures structure."""
        assert "ports" in ARTILLERY_SIGNATURES
        assert "silent_response" in ARTILLERY_SIGNATURES
        assert isinstance(ARTILLERY_SIGNATURES["ports"], list)

    def test_fapro_structure(self):
        """Test FaPro signatures structure."""
        assert "language" in FAPRO_SIGNATURES
        assert FAPRO_SIGNATURES["language"] == "go"


class TestTPotSpecificSignatures:
    """Tests for T-Pot specific honeypot signatures."""

    def test_tpot_specific_structure(self):
        """Test T-Pot specific signatures structure."""
        assert "adbhoney" in TPOT_SPECIFIC_SIGNATURES
        assert "log4pot" in TPOT_SPECIFIC_SIGNATURES
        assert "ddospot" in TPOT_SPECIFIC_SIGNATURES
        assert "medpot" in TPOT_SPECIFIC_SIGNATURES

    def test_tpot_24_structure(self):
        """Test T-Pot 24.x signatures structure."""
        assert "version" in TPOT_24_SIGNATURES
        assert "honeypots" in TPOT_24_SIGNATURES
        assert "elk_port" in TPOT_24_SIGNATURES
        assert TPOT_24_SIGNATURES["elk_port"] == 64297

    @pytest.mark.parametrize("honeypot", [
        "cowrie", "dionaea", "conpot", "elasticpot",
        "heralding", "log4pot", "mailoney", "medpot",
    ])
    def test_tpot_24_honeypots(self, honeypot):
        """Test T-Pot 24.x included honeypots."""
        assert honeypot in TPOT_24_SIGNATURES["honeypots"]


class TestHASSHFingerprints:
    """Tests for HASSH fingerprint signatures."""

    def test_hassh_structure(self):
        """Test HASSH fingerprints structure."""
        assert isinstance(HASSH_FINGERPRINTS, dict)
        for fingerprint, info in HASSH_FINGERPRINTS.items():
            assert "library" in info
            assert "honeypots" in info

    @pytest.mark.parametrize("fingerprint,library", [
        ("ec7378c1a92f5a8dde7e8b7a1ddf33d1", "TwistedConch"),
        ("b12d2871a1189eff20364cf5333619ee", "Paramiko"),
        ("92f20d5d0ed6c3f6e64d3e3b8f0e4a1c", "Go crypto/ssh"),
    ])
    def test_hassh_fingerprint_libraries(self, fingerprint, library):
        """Test HASSH fingerprint to library mapping."""
        assert HASSH_FINGERPRINTS[fingerprint]["library"] == library

    def test_twistedconch_honeypots(self):
        """Test TwistedConch-based honeypots."""
        fingerprint = "ec7378c1a92f5a8dde7e8b7a1ddf33d1"
        assert "cowrie" in HASSH_FINGERPRINTS[fingerprint]["honeypots"]
        assert "kippo" in HASSH_FINGERPRINTS[fingerprint]["honeypots"]


class TestHoneydSignatures:
    """Tests for Honeyd signatures."""

    def test_honeyd_structure(self):
        """Test Honeyd signatures structure."""
        assert "timing_threshold_ms" in HONEYD_SIGNATURES
        assert "fingerprint_deviation_threshold" in HONEYD_SIGNATURES

    def test_honeyd_thresholds(self):
        """Test Honeyd threshold values are reasonable."""
        assert HONEYD_SIGNATURES["timing_threshold_ms"] > 0
        assert 0 < HONEYD_SIGNATURES["fingerprint_deviation_threshold"] < 1


class TestSignatureDictionaryIntegrity:
    """Tests to validate all signature dictionaries are properly structured."""

    @pytest.mark.parametrize("signature_dict", [
        COWRIE_SIGNATURES,
        DIONAEA_SIGNATURES,
        CONPOT_SIGNATURES,
        ELASTICPOT_SIGNATURES,
        MONGODB_HONEYPOT_SIGNATURES,
        MYSQL_HONEYPOT_SIGNATURES,
        POSTGRESQL_HONEYPOT_SIGNATURES,
        REDIS_HONEYPOT_SIGNATURES,
        HTTP_HONEYPOT_SIGNATURES,
        TELNET_HONEYPOT_SIGNATURES,
        RDP_HONEYPOT_SIGNATURES,
        OPENCANARY_SIGNATURES,
        QEEQBOX_SIGNATURES,
        TPOT_SPECIFIC_SIGNATURES,
        TPOT_24_SIGNATURES,
        HASSH_FINGERPRINTS,
    ])
    def test_signature_is_dict(self, signature_dict):
        """Test all signature objects are dictionaries."""
        assert isinstance(signature_dict, dict)

    @pytest.mark.parametrize("signature_dict", [
        COWRIE_SIGNATURES,
        DIONAEA_SIGNATURES,
        CONPOT_SIGNATURES,
        ELASTICPOT_SIGNATURES,
        MONGODB_HONEYPOT_SIGNATURES,
        MYSQL_HONEYPOT_SIGNATURES,
        POSTGRESQL_HONEYPOT_SIGNATURES,
        REDIS_HONEYPOT_SIGNATURES,
        HTTP_HONEYPOT_SIGNATURES,
        TELNET_HONEYPOT_SIGNATURES,
        OPENCANARY_SIGNATURES,
        QEEQBOX_SIGNATURES,
        TPOT_SPECIFIC_SIGNATURES,
        TPOT_24_SIGNATURES,
        HASSH_FINGERPRINTS,
    ])
    def test_signature_not_empty(self, signature_dict):
        """Test all signature dictionaries are not empty."""
        assert len(signature_dict) > 0


class TestMailSignatures:
    """Tests for mail honeypot signatures."""

    def test_mailoney_structure(self):
        """Test Mailoney signatures structure."""
        assert "banners" in MAILONEY_SIGNATURES
        assert "modes" in MAILONEY_SIGNATURES

    @pytest.mark.parametrize("mode", ["schizo_open_relay", "postfix_creds", "open_relay"])
    def test_mailoney_modes(self, mode):
        """Test Mailoney operation modes."""
        assert mode in MAILONEY_SIGNATURES["modes"]

    def test_heralding_mail_structure(self):
        """Test Heralding mail signatures structure."""
        assert "smtp" in HERALDING_MAIL_SIGNATURES
        assert "pop3" in HERALDING_MAIL_SIGNATURES
        assert "imap" in HERALDING_MAIL_SIGNATURES
        assert "ftp" in HERALDING_MAIL_SIGNATURES


class TestVNCAndSIPSignatures:
    """Tests for VNC and SIP honeypot signatures."""

    def test_vnc_structure(self):
        """Test VNC honeypot signatures structure."""
        assert "vnclowpot" in VNC_HONEYPOT_SIGNATURES
        assert "security_types_limited" in VNC_HONEYPOT_SIGNATURES

    def test_sip_structure(self):
        """Test SIP honeypot signatures structure."""
        assert "sentrypeer" in SIP_HONEYPOT_SIGNATURES
        assert "port" in SIP_HONEYPOT_SIGNATURES["sentrypeer"]
        assert SIP_HONEYPOT_SIGNATURES["sentrypeer"]["port"] == 5060
