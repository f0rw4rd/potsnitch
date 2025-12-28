"""Version-specific honeypot signatures.

This module contains signatures for detecting honeypots across different versions.
Each honeypot has signatures categorized by version where known.
"""

# =============================================================================
# SSH HONEYPOTS (Cowrie, Kippo)
# =============================================================================

COWRIE_SIGNATURES = {
    # Version-specific SSH banners
    "banners": {
        # Cowrie v2.5+ (2023-2024)
        "v2.5+": [
            "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
        ],
        # T-Pot 24.x
        "tpot_24": [
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
        ],
        # Cowrie v1.0-2.4 (2016-2022)
        "v1.x-2.4": [
            "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",  # Classic default
        ],
        # Kippo (legacy, pre-2015)
        "kippo": [
            "SSH-2.0-OpenSSH_5.1p1 Debian-5",
        ],
        # Common alternatives
        "alternatives": [
            "SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.4",
            "SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1",
            "SSH-2.0-OpenSSH_5.9",
            "SSH-1.99-OpenSSH_4.3",
            "SSH-1.99-OpenSSH_4.7",
            "SSH-1.99-Sun_SSH_1.1",
        ],
    },
    # Default hostnames
    "hostnames": {
        "cowrie": ["svr04", "nas3"],
        "kippo": ["svr03"],
        "tpot": ["ubuntu"],
    },
    # Default kernel versions
    "kernels": [
        "3.2.0-4-amd64",           # Cowrie classic (Debian 7)
        "5.15.0-23-generic-amd64", # T-Pot 24.x
    ],
    # Default usernames
    "users": ["phil", "richard", "root"],
}

HERALDING_SSH_SIGNATURES = {
    "banners": [
        "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.8",  # All versions
    ],
}

# =============================================================================
# SMB/FTP HONEYPOTS (Dionaea)
# =============================================================================

DIONAEA_SIGNATURES = {
    # SMB signatures
    "smb": {
        "domains": ["WORKGROUP", "MSHOME"],
        "servers": ["HOMEUSER-3AF6FE", "VENUS", "COMPUTER"],
        "native_os": ["Windows 5.1", "Windows 6.1", "Windows Server 2003"],
        "lan_manager": ["Windows 2000 LAN Manager", "Windows Server 2003 5.2"],
    },
    # FTP banners across versions
    "ftp_banners": {
        "current": [
            b"220 Welcome to the ftp service\r\n",
            b"220 Service ready\r\n",
        ],
        "legacy": [
            b"220 DiskStation FTP server ready.\r\n",
        ],
    },
    # HTTP signatures
    "http": {
        "default_page_hashes": [
            "351190a71ddca564e471600c3d403fd8042e6888c8c6abe9cdfe536cef005e82",
        ],
    },
}

# =============================================================================
# ICS/SCADA HONEYPOTS (Conpot)
# =============================================================================

CONPOT_SIGNATURES = {
    # S7Comm defaults
    "s7comm": {
        "system_names": ["Technodrome", "S7-200", "SIMATIC"],
        "facility_names": ["Mouser", "Mouser Factory"],
        "serials": ["88111222"],
        "locations": ["Venus"],
        "module_types": ["IM151-8 PN/DP CPU", "CPU 315-2 PN/DP"],
        "contacts": ["Siemens AG"],
    },
    # Modbus defaults
    "modbus": {
        "vendor": "Siemens",
        "product_code": "SIMATIC",
        "revisions": ["S7-200", "S7-300", "S7-400"],
    },
    # SNMP defaults
    "snmp": {
        "sysName": ["CP 443-1 EX40"],
        "sysLocation": ["Venus"],
        "sysContact": ["Siemens AG"],
    },
}

# =============================================================================
# ELASTICSEARCH HONEYPOTS (Elasticpot, Elastichoney)
# =============================================================================

ELASTICPOT_SIGNATURES = {
    "instance_names": {
        "default": "Green Goblin",
        "tpot": "USNYES01",
    },
    "cluster_names": ["elasticsearch"],
    "host_names": {
        "default": "elk",
        "tpot": "usnyes01",
    },
    "versions": ["1.4.1", "1.4.2", "2.4.6"],
    "build_hashes": ["89d3241"],
}

# =============================================================================
# SMTP HONEYPOTS (Mailoney, Heralding)
# =============================================================================

MAILONEY_SIGNATURES = {
    "banners": [
        b"220 schizo-open-relay ESMTP Service Ready\r\n",
        b"220 localhost ESMTP Service Ready\r\n",
    ],
    "modes": ["schizo_open_relay", "postfix_creds", "open_relay"],
}

HERALDING_MAIL_SIGNATURES = {
    "smtp": [b"Microsoft ESMTP MAIL service ready"],
    "pop3": [b"+OK POP3 server ready"],
    "imap": [b"* OK IMAP4rev1 Server Ready"],
    "ftp": [b"Microsoft FTP Server"],
}

# =============================================================================
# REDIS HONEYPOTS (RedisHoneyPot)
# =============================================================================

REDIS_HONEYPOT_SIGNATURES = {
    "responses": {
        "ping": b"+PONG\r\n",
        "errors": [
            b"-ERR wrong number of arguments",
            b"-ERR Unknown subcommand or wrong number of arguments for 'get'. Try CONFIG HELP.\r\n",
            b"-ERR unknown command",
        ],
    },
}

# =============================================================================
# HTTP HONEYPOTS (Glastopf, SNARE, WordPot)
# =============================================================================

HTTP_HONEYPOT_SIGNATURES = {
    "glastopf": {
        "headers": {
            "Server": ["Apache/2.0.48", "Apache/2.2.22 (Ubuntu)"],
        },
        "content_patterns": [
            b"phpMyAdmin",
            b"phpmyadmin",
        ],
    },
    "snare": {
        "page_hashes": [],  # Dynamic - check against known hashes
    },
    "wordpot": {
        "paths": ["/wp-admin/", "/wp-content/", "/wp-login.php"],
    },
    "shockpot": {
        "page_hashes": [
            "c59e04f46e25c454e65544c236abd9d71705cc4e5c4b4b7dc3ff83fec0e9402f",
        ],
    },
}

# =============================================================================
# TELNET HONEYPOTS
# =============================================================================

TELNET_HONEYPOT_SIGNATURES = {
    "cowrie": {
        "banners": [
            b'\xff\xfd\x1flogin: ',
        ],
    },
    "mtpot": {
        "banners": [
            b'\xff\xfb\x01\xff\xfb\x03',
        ],
    },
    "telnetlogger": {
        "banners": [
            b'\xff\xfb\x03\xff\xfb\x01\xff\xfd\x1f\xff\xfd\x18\r\nlogin: ',
        ],
    },
    "honeypy": {
        "banners": [
            b'Debian GNU/Linux 7\r\nLogin: ',
        ],
    },
}

# =============================================================================
# RDP HONEYPOTS (RDPY, PyRDP, Heralding)
# =============================================================================

RDP_HONEYPOT_SIGNATURES = {
    "rdpy": {
        # RDPY uses Python TLS, detectable via JA3
        "tls_indicators": ["Python TLS stack"],
    },
    "pyrdp": {
        # PyRDP MITM patterns
        "patterns": [],
    },
    "heralding": {
        # Heralding RDP is minimal
        "patterns": [],
    },
}

# =============================================================================
# T-POT SPECIFIC HONEYPOTS
# =============================================================================

TPOT_SPECIFIC_SIGNATURES = {
    "adbhoney": {
        "device_id": "device::http://ro.product.name =starltexx;ro.product.model=SM-G960F",
    },
    "log4pot": {
        "responses": ["sap", "netweaver"],  # SAP NetWeaver HTML response
    },
    "ddospot": {
        "chargen": True,  # Responds to UDP on port 19
        "ssdp": True,     # Responds to SSDP on port 1900
    },
    "medpot": {
        "hl7": True,      # Responds to HL7 on port 2575
    },
    "dicompot": {
        "dicom": True,    # Responds to DICOM on port 11112
    },
    "miniprint": {
        "pjl": True,      # Responds to PJL on port 9100
    },
    "ipphoney": {
        "ipp": True,      # Responds to IPP on port 631
    },
    "sentrypeer": {
        "sip": True,      # Responds to SIP on port 5060
    },
}

# =============================================================================
# HONEYD SIGNATURES
# =============================================================================

HONEYD_SIGNATURES = {
    # Honeyd timing anomalies
    "timing_threshold_ms": 10,  # Response time variance threshold
    # OS fingerprint inconsistencies under load
    "fingerprint_deviation_threshold": 0.2,
}

# =============================================================================
# DATABASE HONEYPOTS
# =============================================================================

MONGODB_HONEYPOT_SIGNATURES = {
    "versions": ["3.4.4", "3.2.0", "2.6.0"],
    "git_hashes": ["e68e9a0"],  # HoneyMongo default
    "honeymongo": {
        "version": "3.4.4",
        "allocator": "static",
    },
}

MYSQL_HONEYPOT_SIGNATURES = {
    "versions": {
        "mysql-honeypotd": "5.7.16-MySQL-Community-Server",
        "qeeqbox": "5.7.30-MySQL-Community-Server",
        "opencanary": "5.5.30-MySQL-Community-Server",
    },
    "charsets": [33],  # utf8 default
    "protocol_version": 10,
    "auth_plugin": "mysql_native_password",
}

POSTGRESQL_HONEYPOT_SIGNATURES = {
    "error_codes": {
        "C28P01": "invalid_password",  # sticky_elephant
        "C28000": "invalid_authorization",
    },
    "sticky_elephant": {
        "auth_type": 5,  # MD5 password
        "version": "9.6.1",
    },
}

REDIS_HONEYPOT_SIGNATURES = {
    "errors": [
        "-ERR unknown command",
        "-ERR wrong number of arguments",
        "-ERR Unknown subcommand or wrong number of arguments for 'get'. Try CONFIG HELP.",
    ],
    "limited_commands": ["PING", "INFO", "QUIT"],
}

# =============================================================================
# SSH TARPITS AND ADDITIONAL SSH HONEYPOTS
# =============================================================================

ENDLESSH_SIGNATURES = {
    "delay_ms": 10000,  # 10 seconds between bytes
    "detection_threshold_s": 5,
    "banner_prefix": "SSH-2.0-",
    "ports": [22, 2222, 22222],
}

SSHESAME_SIGNATURES = {
    "banners": [
        "SSH-2.0-sshesame",
        "SSH-2.0-Go",
    ],
    "accepts_all_keys": True,
}

BLACKNET_SIGNATURES = {
    "hassh": "b12d2871a1189eff20364cf5333619ee",  # Paramiko
    "library": "paramiko",
}

KOJONEY_SIGNATURES = {
    "hassh": "ec7378c1a92f5a8dde7e8b7a1ddf33d1",  # TwistedConch
    "library": "twisted",
    "shell": "busybox",
}

# =============================================================================
# WEB/HTTP HONEYPOTS
# =============================================================================

HELLPOT_SIGNATURES = {
    "server_header": "nginx",
    "tarpit_paths": [
        "/wp-login.php",
        "/wp-admin/",
        "/wp-content/",
        "/.git/",
        "/.env",
        "/admin/",
        "/phpmyadmin/",
    ],
    "infinite_response": True,
}

WORDPOT_SIGNATURES = {
    "server_header": "Python/Flask",
    "wordpress_paths": ["/wp-content/", "/wp-admin/", "/wp-includes/"],
    "version": "4.9.8",
}

GLASTOPF_SIGNATURES = {
    "server_headers": ["Apache/2.0.48", "Apache/2.2.22 (Ubuntu)"],
    "content_patterns": [b"phpMyAdmin", b"phpmyadmin"],
}

SHOCKPOT_SIGNATURES = {
    "page_hash": "c59e04f46e25c454e65544c236abd9d71705cc4e5c4b4b7dc3ff83fec0e9402f",
    "cgi_paths": ["/cgi-bin/status", "/cgi-bin/test-cgi"],
}

# =============================================================================
# CVE-SPECIFIC HONEYPOTS
# =============================================================================

LOG4POT_SIGNATURES = {
    "sap_netweaver": True,
    "title_patterns": ["SAP NetWeaver", "Log4j"],
    "response_patterns": ["webdynpro", "sap/bc/"],
    "ports": [8080, 80],
}

CITRIX_HONEYPOT_SIGNATURES = {
    "server_headers": ["Citrix", "NetScaler"],
    "vulnerable_paths": [
        "/vpn/../vpns/cfg/smb.conf",
        "/vpn/../vpns/portal/scripts/",
    ],
    "response_patterns": ["Citrix Gateway", "NetScaler Gateway"],
}

CISCOASA_HONEYPOT_SIGNATURES = {
    "http_patterns": ["Cisco Adaptive Security Appliance", "ASDM"],
    "ports": {
        "https": [443, 8443],
        "snmp": 5000,
    },
}

SPRING4SHELL_SIGNATURES = {
    "actuator_endpoints": [
        "/actuator/health",
        "/actuator/info",
        "/actuator/env",
    ],
    "error_patterns": ["Whitelabel Error Page", "Spring Boot"],
    "ports": [8080, 80],
}

# =============================================================================
# MULTI-SERVICE FRAMEWORKS
# =============================================================================

OPENCANARY_SIGNATURES = {
    "ports": {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        80: "http",
        443: "https",
        445: "smb",
        1433: "mssql",
        3306: "mysql",
        3389: "rdp",
        5900: "vnc",
        6379: "redis",
        8080: "http-proxy",
    },
    "detection_threshold": 4,  # Minimum matching ports
}

QEEQBOX_SIGNATURES = {
    "ports": {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        80: "http",
        110: "pop3",
        143: "imap",
        389: "ldap",
        443: "https",
        445: "smb",
        1080: "socks5",
        1433: "mssql",
        1521: "oracle",
        3306: "mysql",
        3389: "rdp",
        5060: "sip",
        5432: "postgres",
        5900: "vnc",
        6379: "redis",
        8080: "http-proxy",
        9200: "elasticsearch",
        11211: "memcached",
        27017: "mongodb",
    },
    "high_port_threshold": 8,  # Suspicious if 8+ ports match
}

ARTILLERY_SIGNATURES = {
    "ports": [21, 22, 135, 445, 1433, 3306, 5900, 8080, 10000, 44443],
    "silent_response": True,  # Logs connections but minimal response
}

FAPRO_SIGNATURES = {
    "language": "go",
    "tls_fingerprint": "go-specific",  # Go TLS cipher order
}

# =============================================================================
# ICS/SCADA HONEYPOTS (Extended)
# =============================================================================

GASPOT_SIGNATURES = {
    "port": 10001,
    "protocol": "ATG",  # Automatic Tank Gauge
    "error_code": "9999FF1B",
    "commands": ["I20100"],  # Tank inventory query
}

GRIDPOT_SIGNATURES = {
    "ports": {
        "dnp3": 20000,
        "http": 80,
    },
    "protocols": ["DNP3", "IEC 61850"],
}

HONEYPLC_SIGNATURES = {
    "s7comm": True,
    "limited_cpu_functions": True,
    "static_memory": True,
}

# =============================================================================
# PROTOCOL-SPECIFIC HONEYPOTS
# =============================================================================

VNC_HONEYPOT_SIGNATURES = {
    "vnclowpot": {
        "rfb_versions": ["RFB 003.007", "RFB 003.008"],
        "default_size": "800x600",
    },
    "security_types_limited": True,
}

SIP_HONEYPOT_SIGNATURES = {
    "sentrypeer": {
        "port": 5060,
        "user_agent_static": True,
    },
}

MTPOT_SIGNATURES = {
    "mirai_telnet": True,
    "busybox_prompt": True,
    "limited_commands": True,
}

# =============================================================================
# HASSH FINGERPRINTS (SSH Server Fingerprinting)
# =============================================================================

HASSH_FINGERPRINTS = {
    # TwistedConch (Cowrie, Kippo, Kojoney)
    "ec7378c1a92f5a8dde7e8b7a1ddf33d1": {
        "library": "TwistedConch",
        "honeypots": ["cowrie", "kippo", "kojoney"],
    },
    # Paramiko (Blacknet, generic Python SSH)
    "b12d2871a1189eff20364cf5333619ee": {
        "library": "Paramiko",
        "honeypots": ["blacknet", "heralding"],
    },
    # Go crypto/ssh
    "92f20d5d0ed6c3f6e64d3e3b8f0e4a1c": {
        "library": "Go crypto/ssh",
        "honeypots": ["sshesame", "fapro"],
    },
}

# =============================================================================
# T-POT 24.x SPECIFIC SIGNATURES
# =============================================================================

TPOT_24_SIGNATURES = {
    "version": "24.x",
    "honeypots": [
        "adbhoney",
        "ciscoasa",
        "citrixhoneypot",
        "conpot",
        "cowrie",
        "ddospot",
        "dicompot",
        "dionaea",
        "elasticpot",
        "endlessh",
        "glutton",
        "heralding",
        "hellpot",
        "honeypots",
        "honeytrap",
        "ipphoney",
        "log4pot",
        "mailoney",
        "medpot",
        "miniprint",
        "redishoneypot",
        "sentrypeer",
        "snare",
        "tanner",
        "wordpot",
    ],
    "elk_port": 64297,
    "management_ports": [64294, 64295],
}
