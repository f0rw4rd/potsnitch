"""Database honeypot detectors for MongoDB, MySQL, PostgreSQL, and Redis.

Detection is split into:
- PASSIVE: Banners/handshakes received on connect (MySQL greeting, etc.)
- ACTIVE: Sending commands (INFO, buildInfo, CONFIG GET, etc.) and credential probing
"""

import socket
import struct
import hashlib
from typing import Optional, List, Tuple

from potsnitch.core.base import BaseDetector, DetectionMode, register_detector
from potsnitch.core.result import DetectionResult, Indicator, Confidence
from potsnitch.probes.credentials import (
    MYSQL_HONEYPOT_CREDENTIALS,
    REDIS_HONEYPOT_CREDENTIALS,
    MONGODB_HONEYPOT_CREDENTIALS,
    POSTGRESQL_HONEYPOT_CREDENTIALS,
    MYSQL_INVALID_PAYLOADS,
    REDIS_INVALID_PAYLOADS,
    POSTGRESQL_INVALID_PAYLOADS,
    GARBAGE_CREDENTIALS,
)


# MongoDB honeypot signatures
MONGODB_HONEYPOT_VERSIONS = [
    "3.4.4",  # Common honeypot default
    "3.2.0",
    "2.6.0",
]

MONGODB_HONEYPOT_GIT_HASHES = [
    "e68e9a0",  # HoneyMongo default
]

# MySQL honeypot signatures
MYSQL_HONEYPOT_VERSIONS = [
    "5.7.16-MySQL-Community-Server",  # mysql-honeypotd default
    "5.5.30-MySQL-Community-Server",
    "5.1.73-community",
]

# PostgreSQL honeypot signatures
POSTGRES_ERROR_CODES = {
    "C28P01": "invalid_password",  # sticky_elephant
    "C28000": "invalid_authorization",
}

# Redis honeypot signatures
REDIS_HONEYPOT_ERRORS = [
    b"-ERR unknown command",
    b"-ERR wrong number of arguments",
    b"-ERR Unknown subcommand or wrong number of arguments for 'get'. Try CONFIG HELP.",
]


@register_detector
class MongoDBDetector(BaseDetector):
    """Detector for MongoDB honeypots (HoneyMongo, MongoDB-HoneyProxy).

    Static (Passive) Detection:
    - isMaster command response analysis
    - Server version strings

    Dynamic (Active) Detection:
    - buildInfo command for honeypot signatures
    - Credential testing (MongoDB default has no auth)
    - Command support testing
    """

    name = "mongodb"
    description = "Detects MongoDB honeypots"
    honeypot_types = ["honeymongo", "mongodb-honeyproxy"]
    default_ports = [27017]

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive MongoDB detection.

        Checks server info via isMaster (minimally invasive).

        Args:
            target: IP address or hostname
            port: MongoDB port

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        # Try isMaster command to get server info
        server_info = self._get_server_info(target, port)
        if server_info:
            self._check_server_info(server_info, result)

        if result.is_honeypot:
            result.honeypot_type = "mongodb_honeypot"

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active MongoDB probing.

        Tests buildInfo, credential behavior, and command support.

        Args:
            target: IP address or hostname
            port: MongoDB port

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        # Check buildInfo for honeypot signatures
        build_info = self._get_build_info(target, port)
        if build_info:
            self._check_build_info(build_info, result)

        # Test authentication behavior
        auth_indicators = self._probe_mongodb_auth(target, port)
        for indicator in auth_indicators:
            result.add_indicator(indicator)

        # Test command support
        cmd_indicators = self._probe_mongodb_commands(target, port)
        for indicator in cmd_indicators:
            result.add_indicator(indicator)

        # Run comprehensive post-connect probes
        post_connect_indicators = self._probe_mongodb_post_connect(target, port)
        for indicator in post_connect_indicators:
            result.add_indicator(indicator)

        if result.is_honeypot:
            result.honeypot_type = "mongodb_honeypot"

        return result

    def _probe_mongodb_auth(self, target: str, port: int) -> List[Indicator]:
        """Test MongoDB authentication behavior.

        MongoDB honeypots often:
        - Accept any credentials
        - Don't require authentication at all
        - Have limited auth mechanism support

        Args:
            target: Target host
            port: MongoDB port

        Returns:
            List of indicators if honeypot behavior detected
        """
        indicators = []

        # Check if auth is required
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Try listDatabases without auth (should fail if auth enabled)
            list_dbs_cmd = self._build_query({"listDatabases": 1})
            if list_dbs_cmd:
                sock.send(list_dbs_cmd)
                response = sock.recv(4096)
                parsed = self._parse_response(response)

                if parsed:
                    # If we can list databases without auth, honeypot indicator
                    if "databases" in parsed and parsed.get("ok") == 1.0:
                        indicators.append(
                            Indicator(
                                name="mongodb_no_auth_required",
                                description="MongoDB allows listDatabases without authentication",
                                severity=Confidence.MEDIUM,
                                details="Production MongoDB should require authentication",
                            )
                        )

                    # Check for limited database list (honeypot indicator)
                    dbs = parsed.get("databases", [])
                    if len(dbs) <= 2:  # Only admin and local
                        indicators.append(
                            Indicator(
                                name="mongodb_minimal_databases",
                                description="Very few databases exist",
                                severity=Confidence.LOW,
                                details=f"Only {len(dbs)} databases found",
                            )
                        )

            sock.close()
        except (socket.error, socket.timeout, OSError):
            pass

        # Try authentication with default credentials
        for username, password in MONGODB_HONEYPOT_CREDENTIALS[:3]:
            if not username and not password:
                continue

            try:
                # Attempt SCRAM-SHA-1 auth
                auth_result = self._try_mongodb_auth(target, port, username, password)
                if auth_result:
                    indicators.append(
                        Indicator(
                            name="mongodb_default_cred_accepted",
                            description=f"Default credential {username}:{password or '(empty)'} accepted",
                            severity=Confidence.HIGH,
                            details="Honeypots often accept default MongoDB credentials",
                        )
                    )
                    break
            except Exception:
                continue

        return indicators

    def _try_mongodb_auth(self, target: str, port: int, username: str, password: str) -> bool:
        """Attempt MongoDB authentication.

        Simplified SCRAM-SHA-1 check - just checks if server accepts.

        Args:
            target: Target host
            port: MongoDB port
            username: Username to try
            password: Password to try

        Returns:
            True if authentication succeeds
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Send saslStart command
            import base64
            import os

            nonce = base64.b64encode(os.urandom(24)).decode()
            sasl_payload = f"n,,n={username},r={nonce}"
            sasl_b64 = base64.b64encode(sasl_payload.encode()).decode()

            sasl_start_cmd = self._build_query({
                "saslStart": 1,
                "mechanism": "SCRAM-SHA-1",
                "payload": sasl_b64,
            })

            if sasl_start_cmd:
                sock.send(sasl_start_cmd)
                response = sock.recv(4096)
                parsed = self._parse_response(response)

                sock.close()

                # If we get a conversation response, auth is at least partially working
                if parsed and parsed.get("ok") == 1.0:
                    # In real auth, this would continue the SCRAM exchange
                    # For honeypot detection, getting OK at this stage is suspicious
                    return True

            sock.close()
            return False
        except Exception:
            return False

    def _probe_mongodb_commands(self, target: str, port: int) -> List[Indicator]:
        """Test MongoDB command support.

        Honeypots often have limited command support.

        Args:
            target: Target host
            port: MongoDB port

        Returns:
            List of indicators if limited support detected
        """
        indicators = []
        unsupported_commands = 0

        # Commands that real MongoDB supports but honeypots might not
        test_commands = [
            {"serverStatus": 1},
            {"hostInfo": 1},
            {"getCmdLineOpts": 1},
            {"getLog": "global"},
        ]

        for cmd in test_commands:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((target, port))

                query = self._build_query(cmd)
                if query:
                    sock.send(query)
                    response = sock.recv(4096)
                    parsed = self._parse_response(response)

                    if parsed:
                        # Check for error or empty response
                        if parsed.get("ok") != 1.0 or "errmsg" in parsed:
                            unsupported_commands += 1

                sock.close()
            except (socket.error, socket.timeout, OSError):
                continue

        # If most commands are unsupported, likely honeypot
        if unsupported_commands >= 3:
            indicators.append(
                Indicator(
                    name="mongodb_limited_commands",
                    description=f"{unsupported_commands}/4 admin commands not supported",
                    severity=Confidence.HIGH,
                    details="Honeypots typically implement only basic commands",
                )
            )

        return indicators

    def _probe_mongodb_post_connect(self, target: str, port: int) -> List[Indicator]:
        """Run comprehensive MongoDB honeypot detection after connection.

        Tests advanced commands and checks for known honeypot signatures:
        - buildInfo for static version/git hash
        - serverStatus for detailed stats
        - aggregate pipeline support
        - collStats for collection info
        - replSetGetStatus for replication

        Args:
            target: Target host
            port: MongoDB port

        Returns:
            List of Indicator objects for detected honeypot signs
        """
        indicators: List[Indicator] = []

        # Test buildInfo - DEFINITE (check for static version and git hash)
        build_info = self._get_build_info(target, port)
        if build_info:
            version = build_info.get("version", "")
            git_version = build_info.get("gitVersion", "")

            # Check for known honeypot static version
            if version == "3.4.4":
                indicators.append(
                    Indicator(
                        name="mongodb_static_version_344",
                        description="Static MongoDB version 3.4.4 (honeypot default)",
                        severity=Confidence.DEFINITE,
                        details="HoneyMongo and similar honeypots use this version",
                    )
                )

            # Check for known honeypot git hashes
            known_hp_hashes = ["e68e9a0", "888390515874a9debd1b6c5d36559ca86b44babd"]
            for hp_hash in known_hp_hashes:
                if hp_hash in git_version:
                    indicators.append(
                        Indicator(
                            name="mongodb_known_hp_git_hash",
                            description=f"Known honeypot gitVersion hash: {hp_hash}",
                            severity=Confidence.DEFINITE,
                            details=f"Full gitVersion: {git_version}",
                        )
                    )
                    break

            # Check for minimal buildInfo (missing fields)
            expected_fields = ["allocator", "modules", "storageEngines", "buildEnvironment"]
            missing_fields = [f for f in expected_fields if f not in build_info]
            if len(missing_fields) >= 3:
                indicators.append(
                    Indicator(
                        name="mongodb_minimal_buildinfo",
                        description=f"buildInfo missing {len(missing_fields)} expected fields",
                        severity=Confidence.HIGH,
                        details=f"Missing: {', '.join(missing_fields)}",
                    )
                )

        # Test serverStatus - DEFINITE (often returns error or minimal data)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            server_status_cmd = self._build_query({"serverStatus": 1})
            if server_status_cmd:
                sock.send(server_status_cmd)
                response = sock.recv(8192)
                parsed = self._parse_response(response)

                if parsed:
                    if parsed.get("ok") != 1.0:
                        indicators.append(
                            Indicator(
                                name="mongodb_serverstatus_error",
                                description="serverStatus command failed",
                                severity=Confidence.HIGH,
                                details=str(parsed.get("errmsg", "unknown error")),
                            )
                        )
                    elif len(parsed) < 20:
                        # Real serverStatus has 50+ fields
                        indicators.append(
                            Indicator(
                                name="mongodb_serverstatus_minimal",
                                description=f"serverStatus returns only {len(parsed)} fields (expected 50+)",
                                severity=Confidence.HIGH,
                            )
                        )
                    else:
                        # Check for static/fake values
                        if parsed.get("connections", {}).get("current") == 1:
                            # Might be just us, but worth noting
                            pass
                        # Check for missing expected sections
                        expected_sections = ["opcounters", "network", "mem", "connections"]
                        missing = [s for s in expected_sections if s not in parsed]
                        if len(missing) >= 2:
                            indicators.append(
                                Indicator(
                                    name="mongodb_serverstatus_incomplete",
                                    description=f"serverStatus missing sections: {', '.join(missing)}",
                                    severity=Confidence.HIGH,
                                )
                            )

            sock.close()
        except (socket.error, socket.timeout, OSError):
            pass

        # Test aggregate pipeline - HIGH (not implemented in honeypots)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            aggregate_cmd = self._build_query({
                "aggregate": "test",
                "pipeline": [{"$match": {}}],
                "cursor": {},
            })
            if aggregate_cmd:
                sock.send(aggregate_cmd)
                response = sock.recv(4096)
                parsed = self._parse_response(response)

                if parsed:
                    if parsed.get("ok") != 1.0:
                        errmsg = str(parsed.get("errmsg", "")).lower()
                        if "not implemented" in errmsg or "unknown" in errmsg:
                            indicators.append(
                                Indicator(
                                    name="mongodb_no_aggregate",
                                    description="Aggregate pipeline not implemented",
                                    severity=Confidence.HIGH,
                                    details="Real MongoDB supports aggregation framework",
                                )
                            )

            sock.close()
        except (socket.error, socket.timeout, OSError):
            pass

        # Test collStats - HIGH (not implemented in honeypots)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            collstats_cmd = self._build_query({"collStats": "test"})
            if collstats_cmd:
                sock.send(collstats_cmd)
                response = sock.recv(4096)
                parsed = self._parse_response(response)

                if parsed:
                    if parsed.get("ok") != 1.0:
                        errmsg = str(parsed.get("errmsg", "")).lower()
                        if "not implemented" in errmsg or "unknown" in errmsg:
                            indicators.append(
                                Indicator(
                                    name="mongodb_no_collstats",
                                    description="collStats command not implemented",
                                    severity=Confidence.HIGH,
                                )
                            )

            sock.close()
        except (socket.error, socket.timeout, OSError):
            pass

        # Test currentOp - MEDIUM (often not implemented)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            currentop_cmd = self._build_query({"currentOp": 1})
            if currentop_cmd:
                sock.send(currentop_cmd)
                response = sock.recv(4096)
                parsed = self._parse_response(response)

                if parsed:
                    if parsed.get("ok") != 1.0:
                        errmsg = str(parsed.get("errmsg", "")).lower()
                        if "not implemented" in errmsg or "unknown" in errmsg:
                            indicators.append(
                                Indicator(
                                    name="mongodb_no_currentop",
                                    description="currentOp command not implemented",
                                    severity=Confidence.MEDIUM,
                                )
                            )

            sock.close()
        except (socket.error, socket.timeout, OSError):
            pass

        # Test getParameter - MEDIUM (useful for config detection)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            getparam_cmd = self._build_query({"getParameter": "*"})
            if getparam_cmd:
                sock.send(getparam_cmd)
                response = sock.recv(4096)
                parsed = self._parse_response(response)

                if parsed:
                    if parsed.get("ok") == 1.0:
                        # Check for minimal parameters
                        if len(parsed) < 10:
                            indicators.append(
                                Indicator(
                                    name="mongodb_few_parameters",
                                    description=f"getParameter returns only {len(parsed)} parameters",
                                    severity=Confidence.MEDIUM,
                                    details="Real MongoDB has 100+ configurable parameters",
                                )
                            )

            sock.close()
        except (socket.error, socket.timeout, OSError):
            pass

        return indicators

    def _get_server_info(self, target: str, port: int) -> Optional[dict]:
        """Get MongoDB server info via isMaster command."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # MongoDB Wire Protocol: isMaster command
            # This is a simplified query - real MongoDB clients use OP_MSG
            ismaster_cmd = self._build_query({"isMaster": 1})
            sock.send(ismaster_cmd)

            response = sock.recv(4096)
            sock.close()

            return self._parse_response(response)
        except (socket.error, socket.timeout, OSError):
            return None

    def _get_build_info(self, target: str, port: int) -> Optional[dict]:
        """Get MongoDB buildInfo."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            buildinfo_cmd = self._build_query({"buildInfo": 1})
            sock.send(buildinfo_cmd)

            response = sock.recv(4096)
            sock.close()

            return self._parse_response(response)
        except (socket.error, socket.timeout, OSError):
            return None

    def _build_query(self, doc: dict) -> bytes:
        """Build a simple MongoDB query packet."""
        # Simplified - uses OP_QUERY (deprecated but works for honeypot detection)
        import bson
        try:
            query_bson = bson.encode(doc)
            full_collection_name = b"admin.$cmd\x00"

            # OP_QUERY header
            flags = 0
            number_to_skip = 0
            number_to_return = 1

            message_body = (
                struct.pack("<I", flags) +
                full_collection_name +
                struct.pack("<I", number_to_skip) +
                struct.pack("<I", number_to_return) +
                query_bson
            )

            # Message header
            request_id = 1
            response_to = 0
            op_code = 2004  # OP_QUERY

            message_length = 16 + len(message_body)
            header = struct.pack("<IIII", message_length, request_id, response_to, op_code)

            return header + message_body
        except ImportError:
            # bson not available, return empty
            return b""

    def _parse_response(self, data: bytes) -> Optional[dict]:
        """Parse MongoDB response."""
        try:
            import bson
            if len(data) < 36:
                return None
            # Skip header (16 bytes) and OP_REPLY fields (20 bytes)
            doc_start = 36
            if doc_start < len(data):
                return bson.decode(data[doc_start:])
            return None
        except (ImportError, Exception):
            return None

    def _check_server_info(self, info: dict, result: DetectionResult) -> None:
        """Check server info for honeypot indicators."""
        version = info.get("version", "")
        for hp_version in MONGODB_HONEYPOT_VERSIONS:
            if version == hp_version:
                result.add_indicator(
                    Indicator(
                        name="mongodb_default_version",
                        description=f"Default honeypot MongoDB version: {version}",
                        severity=Confidence.MEDIUM,
                    )
                )
                break

        # Check for limited replica set info (honeypots often don't implement)
        if "hosts" not in info and info.get("ismaster"):
            result.add_indicator(
                Indicator(
                    name="mongodb_limited_replicaset",
                    description="Missing replica set info (common in honeypots)",
                    severity=Confidence.LOW,
                )
            )

    def _check_build_info(self, info: dict, result: DetectionResult) -> None:
        """Check build info for honeypot signatures."""
        git_version = info.get("gitVersion", "")
        for hp_hash in MONGODB_HONEYPOT_GIT_HASHES:
            if hp_hash in git_version:
                result.add_indicator(
                    Indicator(
                        name="mongodb_honeypot_git_hash",
                        description=f"Known honeypot git hash: {hp_hash}",
                        severity=Confidence.HIGH,
                        details=f"Full gitVersion: {git_version}",
                    )
                )
                break

        # Check for static/minimal build info
        if info.get("sysInfo") == "" or "static" in str(info.get("allocator", "")).lower():
            result.add_indicator(
                Indicator(
                    name="mongodb_static_buildinfo",
                    description="Static or minimal build info (honeypot indicator)",
                    severity=Confidence.MEDIUM,
                )
            )


@register_detector
class MySQLDetector(BaseDetector):
    """Detector for MySQL honeypots (mysql-honeypotd).

    Static (Passive) Detection:
    - Initial handshake packet analysis (server version, connection ID, charset)
    - Capability flags analysis

    Dynamic (Active) Detection:
    - None currently (authentication probing would be needed)
    """

    name = "mysql"
    description = "Detects MySQL honeypots"
    honeypot_types = ["mysql-honeypotd", "qeeqbox-mysql"]
    default_ports = [3306]

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive MySQL detection.

        Analyzes the initial handshake packet sent by the server
        on connection - no commands are sent.

        Args:
            target: IP address or hostname
            port: MySQL port

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        # Get initial handshake packet (sent by server on connect)
        handshake = self._get_handshake(target, port)
        if handshake:
            self._check_handshake(handshake, result)

        if result.is_honeypot:
            result.honeypot_type = "mysql_honeypot"

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active MySQL probing.

        Tests default credentials and invalid payloads to detect honeypots.
        Honeypots often accept any credentials or respond uniformly to errors.

        Args:
            target: IP address or hostname
            port: MySQL port

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        # Test default credentials and run post-connect probes if successful
        cred_indicators, auth_creds = self._probe_mysql_credentials_with_postauth(target, port)
        for indicator in cred_indicators:
            result.add_indicator(indicator)

        # Test invalid payloads
        payload_indicators = self._probe_mysql_invalid_payloads(target, port)
        for indicator in payload_indicators:
            result.add_indicator(indicator)

        if result.is_honeypot:
            result.honeypot_type = "mysql_honeypot"

        return result

    def _probe_mysql_credentials_with_postauth(
        self, target: str, port: int
    ) -> Tuple[List[Indicator], Optional[Tuple[str, str]]]:
        """Test default MySQL credentials and run post-auth probes if successful.

        Combines credential testing with post-authentication detection.
        When auth succeeds, runs comprehensive command detection.

        Args:
            target: Target host
            port: MySQL port

        Returns:
            Tuple of (indicators, successful_credentials or None)
        """
        indicators = []
        successful_creds = None

        # First try default credentials
        for username, password in MYSQL_HONEYPOT_CREDENTIALS[:5]:
            success = self._try_mysql_auth(target, port, username, password)
            if success:
                indicators.append(
                    Indicator(
                        name="mysql_default_cred_accepted",
                        description=f"Default credential {username}:{password or '(empty)'} accepted",
                        severity=Confidence.HIGH,
                        details="Honeypots accept default credentials to capture queries",
                    )
                )
                successful_creds = (username, password)
                break

        # If no default creds worked, try garbage credentials
        if not successful_creds:
            for username, password in GARBAGE_CREDENTIALS[:2]:
                success = self._try_mysql_auth(target, port, username, password)
                if success:
                    indicators.append(
                        Indicator(
                            name="mysql_accept_all",
                            description="MySQL accepts garbage/random credentials",
                            severity=Confidence.DEFINITE,
                            details=f"Accepted: {username}:{password}",
                        )
                    )
                    successful_creds = (username, password)
                    break

        # Run post-auth probes if we have working credentials
        if successful_creds:
            username, password = successful_creds
            post_auth_indicators = self._probe_mysql_post_connect(
                target, port, username, password
            )
            indicators.extend(post_auth_indicators)

        return indicators, successful_creds

    def _try_mysql_auth(self, target: str, port: int, username: str, password: str) -> bool:
        """Attempt MySQL authentication.

        Args:
            target: Target host
            port: MySQL port
            username: Username to try
            password: Password to try

        Returns:
            True if authentication succeeds
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Read handshake
            handshake_data = sock.recv(1024)
            handshake = self._parse_handshake(handshake_data)

            if not handshake:
                sock.close()
                return False

            # Extract auth data from handshake
            null_pos = handshake_data.find(b"\x00", 5)
            if null_pos == -1 or len(handshake_data) < null_pos + 13:
                sock.close()
                return False

            # Get salt (auth-plugin-data-part-1)
            salt1 = handshake_data[null_pos + 5:null_pos + 13]

            # Try to get salt2 if available (auth-plugin-data-part-2)
            salt2 = b""
            if len(handshake_data) > null_pos + 31:
                salt2_start = null_pos + 31
                salt2_end = handshake_data.find(b"\x00", salt2_start)
                if salt2_end > salt2_start:
                    salt2 = handshake_data[salt2_start:salt2_end]

            salt = salt1 + salt2

            # Build auth response packet
            auth_response = self._build_auth_packet(username, password, salt)
            sock.send(auth_response)

            # Read response
            response = sock.recv(1024)
            sock.close()

            if response and len(response) > 4:
                # Check for OK packet (0x00) or EOF packet (0xfe)
                packet_type = response[4]
                return packet_type == 0x00 or packet_type == 0xfe

            return False

        except (socket.error, socket.timeout, OSError, Exception):
            return False

    def _probe_mysql_credentials(self, target: str, port: int) -> List[Indicator]:
        """Test default MySQL credentials.

        Honeypots often accept any credentials to capture commands.
        Real MySQL servers reject unknown users/bad passwords.

        Args:
            target: Target host
            port: MySQL port

        Returns:
            List of indicators if honeypot behavior detected
        """
        indicators = []
        successful_auths = 0

        for username, password in MYSQL_HONEYPOT_CREDENTIALS[:5]:  # Limit attempts
            try:
                # Get handshake first
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((target, port))

                # Read handshake
                handshake_data = sock.recv(1024)
                handshake = self._parse_handshake(handshake_data)

                if not handshake:
                    sock.close()
                    continue

                # Extract auth data from handshake
                null_pos = handshake_data.find(b"\x00", 5)
                if null_pos == -1 or len(handshake_data) < null_pos + 13:
                    sock.close()
                    continue

                # Get salt (auth-plugin-data-part-1)
                salt1 = handshake_data[null_pos + 5:null_pos + 13]

                # Try to get salt2 if available (auth-plugin-data-part-2)
                salt2 = b""
                if len(handshake_data) > null_pos + 31:
                    # Find rest of salt after filler and capabilities
                    salt2_start = null_pos + 31
                    salt2_end = handshake_data.find(b"\x00", salt2_start)
                    if salt2_end > salt2_start:
                        salt2 = handshake_data[salt2_start:salt2_end]

                salt = salt1 + salt2

                # Build auth response packet
                auth_response = self._build_auth_packet(username, password, salt)
                sock.send(auth_response)

                # Read response
                response = sock.recv(1024)
                sock.close()

                if response and len(response) > 4:
                    # Check for OK packet (0x00) or EOF packet (0xfe)
                    packet_type = response[4]
                    if packet_type == 0x00 or packet_type == 0xfe:
                        successful_auths += 1
                        indicators.append(
                            Indicator(
                                name="mysql_default_cred_accepted",
                                description=f"Default credential {username}:{password or '(empty)'} accepted",
                                severity=Confidence.HIGH,
                                details="Honeypots accept default credentials to capture queries",
                            )
                        )
                        # One successful auth is enough to flag
                        break

            except (socket.error, socket.timeout, OSError):
                continue
            except Exception:
                continue

        return indicators

    def _build_auth_packet(self, username: str, password: str, salt: bytes) -> bytes:
        """Build MySQL authentication packet.

        Args:
            username: MySQL username
            password: MySQL password
            salt: Auth salt from handshake

        Returns:
            Authentication packet bytes
        """
        # Client capabilities (simplified)
        client_caps = 0x0003a685  # CLIENT_PROTOCOL_41 + others

        # Max packet size
        max_packet = 0x01000000

        # Charset (utf8)
        charset = 33

        # Build auth data
        if password:
            # SHA1(password) XOR SHA1(salt + SHA1(SHA1(password)))
            pass_sha1 = hashlib.sha1(password.encode()).digest()
            pass_sha1_sha1 = hashlib.sha1(pass_sha1).digest()
            combined = hashlib.sha1(salt[:20] + pass_sha1_sha1).digest()
            auth_data = bytes(a ^ b for a, b in zip(pass_sha1, combined))
        else:
            auth_data = b""

        # Build packet payload
        payload = (
            struct.pack("<I", client_caps) +
            struct.pack("<I", max_packet) +
            bytes([charset]) +
            b"\x00" * 23 +  # Reserved
            username.encode() + b"\x00" +
            bytes([len(auth_data)]) + auth_data
        )

        # Build packet header
        packet_len = len(payload)
        header = struct.pack("<I", packet_len)[:3] + b"\x01"  # Sequence number 1

        return header + payload

    def _probe_mysql_post_connect(self, target: str, port: int, username: str, password: str) -> List[Indicator]:
        """Run comprehensive MySQL honeypot detection after successful authentication.

        Tests stored procedures, InnoDB status, plugin count, and other
        advanced queries that honeypots typically don't implement.

        Args:
            target: Target host
            port: MySQL port
            username: Username for authentication
            password: Password for authentication

        Returns:
            List of Indicator objects for detected honeypot signs
        """
        indicators: List[Indicator] = []

        try:
            import mysql.connector

            conn = mysql.connector.connect(
                host=target,
                port=port,
                user=username,
                password=password,
                connection_timeout=self.timeout,
            )
            cursor = conn.cursor()

            # Test stored procedure creation - DEFINITE (honeypots don't implement)
            try:
                cursor.execute("CREATE PROCEDURE _hp_test_proc() BEGIN SELECT 1; END")
                cursor.execute("DROP PROCEDURE IF EXISTS _hp_test_proc")
            except Exception as e:
                error = str(e).lower()
                if "syntax" in error or "not implemented" in error or "denied" in error:
                    indicators.append(
                        Indicator(
                            name="mysql_no_stored_procs",
                            description="Stored procedures not supported (honeypot)",
                            severity=Confidence.DEFINITE,
                            details="Real MySQL supports stored procedures",
                        )
                    )

            # Test InnoDB status - DEFINITE (requires real InnoDB)
            try:
                cursor.execute("SHOW ENGINE INNODB STATUS")
                result = cursor.fetchone()
                if not result:
                    indicators.append(
                        Indicator(
                            name="mysql_no_innodb",
                            description="InnoDB status unavailable",
                            severity=Confidence.DEFINITE,
                        )
                    )
            except Exception as e:
                if "unknown storage engine" in str(e).lower() or "access denied" not in str(e).lower():
                    indicators.append(
                        Indicator(
                            name="mysql_no_innodb",
                            description="InnoDB not implemented",
                            severity=Confidence.DEFINITE,
                        )
                    )

            # Check plugin count - MEDIUM
            try:
                cursor.execute("SELECT COUNT(*) FROM information_schema.PLUGINS")
                plugin_count = cursor.fetchone()[0]
                if plugin_count < 5:
                    indicators.append(
                        Indicator(
                            name="mysql_few_plugins",
                            description=f"Only {plugin_count} plugins (expected 40+)",
                            severity=Confidence.MEDIUM,
                        )
                    )
            except Exception:
                pass

            # Check SHOW PROCESSLIST - HIGH
            try:
                cursor.execute("SHOW PROCESSLIST")
                processes = cursor.fetchall()
                if len(processes) <= 1:
                    indicators.append(
                        Indicator(
                            name="mysql_no_processes",
                            description="SHOW PROCESSLIST shows minimal processes",
                            severity=Confidence.HIGH,
                        )
                    )
            except Exception:
                pass

            # Check SHOW VARIABLES count - HIGH
            try:
                cursor.execute("SHOW VARIABLES")
                variables = cursor.fetchall()
                if len(variables) < 100:
                    indicators.append(
                        Indicator(
                            name="mysql_few_variables",
                            description=f"Only {len(variables)} variables (expected 400+)",
                            severity=Confidence.HIGH,
                        )
                    )
            except Exception:
                pass

            cursor.close()
            conn.close()

        except ImportError:
            # mysql.connector not available, skip these tests
            pass
        except Exception:
            pass

        return indicators

    def _probe_mysql_invalid_payloads(self, target: str, port: int) -> List[Indicator]:
        """Test MySQL response to invalid payloads.

        Honeypots often respond uniformly to all malformed data,
        while real MySQL has specific error handling.

        Args:
            target: Target host
            port: MySQL port

        Returns:
            List of indicators if uniform response detected
        """
        indicators = []
        responses = []

        for payload in MYSQL_INVALID_PAYLOADS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((target, port))

                # Read initial handshake
                sock.recv(1024)

                # Send invalid payload
                sock.send(payload)

                try:
                    response = sock.recv(1024)
                    responses.append(response)
                except socket.timeout:
                    responses.append(b"TIMEOUT")

                sock.close()
            except (socket.error, OSError):
                responses.append(b"ERROR")

        # Check for uniform responses
        if len(responses) >= 2:
            unique_responses = set(responses)
            if len(unique_responses) == 1 and responses[0] not in (b"TIMEOUT", b"ERROR"):
                indicators.append(
                    Indicator(
                        name="mysql_uniform_error",
                        description="Uniform response to different invalid payloads",
                        severity=Confidence.MEDIUM,
                        details="Honeypots often return identical errors for all malformed data",
                    )
                )

        return indicators

    def _get_handshake(self, target: str, port: int) -> Optional[dict]:
        """Get MySQL handshake packet."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # MySQL sends handshake on connect
            data = sock.recv(1024)
            sock.close()

            return self._parse_handshake(data)
        except (socket.error, socket.timeout, OSError):
            return None

    def _parse_handshake(self, data: bytes) -> Optional[dict]:
        """Parse MySQL initial handshake packet."""
        try:
            if len(data) < 5:
                return None

            # Packet header: 3 bytes length + 1 byte sequence
            payload_len = struct.unpack("<I", data[:3] + b"\x00")[0]
            sequence = data[3]
            payload = data[4:]

            if len(payload) < 1:
                return None

            protocol_version = payload[0]
            if protocol_version != 10:  # MySQL protocol version
                return None

            # Find null-terminated server version
            null_pos = payload.find(b"\x00", 1)
            if null_pos == -1:
                return None

            server_version = payload[1:null_pos].decode("utf-8", errors="ignore")

            # Connection ID (4 bytes after version)
            if len(payload) < null_pos + 5:
                return None
            conn_id = struct.unpack("<I", payload[null_pos + 1:null_pos + 5])[0]

            # Charset (at offset after various fields)
            charset = None
            if len(payload) > null_pos + 14:
                charset = payload[null_pos + 13]

            return {
                "protocol_version": protocol_version,
                "server_version": server_version,
                "connection_id": conn_id,
                "charset": charset,
            }
        except (struct.error, IndexError):
            return None

    def _check_handshake(self, handshake: dict, result: DetectionResult) -> None:
        """Check handshake for honeypot indicators."""
        version = handshake.get("server_version", "")

        # Check for known honeypot versions
        for hp_version in MYSQL_HONEYPOT_VERSIONS:
            if version == hp_version:
                result.add_indicator(
                    Indicator(
                        name="mysql_default_version",
                        description=f"Default honeypot MySQL version: {version}",
                        severity=Confidence.HIGH,
                        details="mysql-honeypotd default version",
                    )
                )
                break

        # Check for static connection ID patterns
        conn_id = handshake.get("connection_id", 0)
        if conn_id == 1 or conn_id == 0:
            result.add_indicator(
                Indicator(
                    name="mysql_static_connid",
                    description="Static or sequential connection ID",
                    severity=Confidence.LOW,
                    details=f"Connection ID: {conn_id}",
                )
            )

        # Check charset (33 = utf8 is common default for honeypots)
        charset = handshake.get("charset")
        if charset == 33:  # utf8
            result.add_indicator(
                Indicator(
                    name="mysql_utf8_charset",
                    description="UTF-8 charset (common honeypot default)",
                    severity=Confidence.LOW,
                )
            )


@register_detector
class PostgreSQLDetector(BaseDetector):
    """Detector for PostgreSQL honeypots (sticky_elephant, pgpot).

    Static (Passive) Detection:
    - SSL negotiation response
    - Initial connection behavior

    Dynamic (Active) Detection:
    - Credential testing with defaults
    - Error message analysis
    - Query capability testing
    """

    name = "postgresql"
    description = "Detects PostgreSQL honeypots"
    honeypot_types = ["sticky_elephant", "pgpot"]
    default_ports = [5432]

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive PostgreSQL detection.

        Checks SSL support and initial connection behavior.

        Args:
            target: IP address or hostname
            port: PostgreSQL port

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        # Try SSL negotiation
        ssl_response = self._check_ssl(target, port)
        if ssl_response is not None:
            self._analyze_ssl_response(ssl_response, result)

        if result.is_honeypot:
            result.honeypot_type = "postgresql_honeypot"

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active PostgreSQL probing.

        Tests credentials, error handling, and query capabilities.

        Args:
            target: IP address or hostname
            port: PostgreSQL port

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        # Test error response patterns
        error_response = self._probe_auth(target, port)
        if error_response:
            self._check_error_response(error_response, result)

        # Test default credentials
        cred_indicators = self._probe_credentials(target, port)
        for indicator in cred_indicators:
            result.add_indicator(indicator)

        # Test accept-all behavior and run post-connect probes if auth succeeds
        garbage_indicators, auth_creds = self._probe_accept_all_with_postauth(target, port)
        for indicator in garbage_indicators:
            result.add_indicator(indicator)

        # Test invalid payload responses
        payload_indicators = self._probe_invalid_payloads(target, port)
        for indicator in payload_indicators:
            result.add_indicator(indicator)

        if result.is_honeypot:
            result.honeypot_type = "postgresql_honeypot"

        return result

    def _probe_credentials(self, target: str, port: int) -> List[Indicator]:
        """Test PostgreSQL with default credentials."""
        indicators = []

        for username, password in POSTGRESQL_HONEYPOT_CREDENTIALS[:5]:
            success, timing = self._try_auth_full(target, port, username, password)

            if success:
                indicators.append(
                    Indicator(
                        name="postgres_default_cred_accepted",
                        description=f"Default credential {username}:{password or '(empty)'} accepted",
                        severity=Confidence.HIGH,
                        details="Honeypots often accept default PostgreSQL credentials",
                    )
                )
                break

            # Check for suspiciously fast rejection
            if timing > 0 and timing < 0.01:
                indicators.append(
                    Indicator(
                        name="postgres_instant_auth_failure",
                        description="Authentication rejected instantly (< 10ms)",
                        severity=Confidence.LOW,
                        details=f"Response time: {timing*1000:.2f}ms",
                    )
                )

        return indicators

    def _probe_accept_all(self, target: str, port: int) -> List[Indicator]:
        """Test if PostgreSQL accepts garbage credentials."""
        indicators = []

        for username, password in GARBAGE_CREDENTIALS[:3]:
            success, _ = self._try_auth_full(target, port, username, password)

            if success:
                indicators.append(
                    Indicator(
                        name="postgres_accept_all",
                        description="PostgreSQL accepts garbage/random credentials",
                        severity=Confidence.DEFINITE,
                        details=f"Accepted: {username}:{password}",
                    )
                )
                return indicators

        return indicators

    def _probe_accept_all_with_postauth(
        self, target: str, port: int
    ) -> Tuple[List[Indicator], Optional[Tuple[str, str]]]:
        """Test PostgreSQL for accept-all and run post-auth probes if successful.

        Combines garbage credential testing with post-authentication detection.

        Args:
            target: Target host
            port: PostgreSQL port

        Returns:
            Tuple of (indicators, successful_credentials or None)
        """
        indicators = []
        successful_creds = None

        # Try default credentials first
        for username, password in POSTGRESQL_HONEYPOT_CREDENTIALS[:5]:
            success, _ = self._try_auth_full(target, port, username, password)
            if success:
                indicators.append(
                    Indicator(
                        name="postgres_default_cred_accepted",
                        description=f"Default credential {username}:{password or '(empty)'} accepted",
                        severity=Confidence.HIGH,
                    )
                )
                successful_creds = (username, password)
                break

        # If no default creds, try garbage credentials
        if not successful_creds:
            for username, password in GARBAGE_CREDENTIALS[:3]:
                success, _ = self._try_auth_full(target, port, username, password)
                if success:
                    indicators.append(
                        Indicator(
                            name="postgres_accept_all",
                            description="PostgreSQL accepts garbage/random credentials",
                            severity=Confidence.DEFINITE,
                            details=f"Accepted: {username}:{password}",
                        )
                    )
                    successful_creds = (username, password)
                    break

        # Run post-auth probes if we have working credentials
        if successful_creds:
            username, password = successful_creds
            post_auth_indicators = self._probe_postgresql_post_connect(
                target, port, username, password
            )
            indicators.extend(post_auth_indicators)

        return indicators, successful_creds

    def _probe_postgresql_post_connect(
        self, target: str, port: int, username: str, password: str
    ) -> List[Indicator]:
        """Run comprehensive PostgreSQL honeypot detection after authentication.

        Tests advanced queries that honeypots typically don't implement:
        - EXPLAIN ANALYZE (query planning)
        - pg_proc function count
        - CREATE FUNCTION support
        - SHOW ALL parameter count
        - pg_stat_activity
        - pg_extension for installed extensions

        Args:
            target: Target host
            port: PostgreSQL port
            username: Username for authentication
            password: Password for authentication

        Returns:
            List of Indicator objects for detected honeypot signs
        """
        indicators: List[Indicator] = []

        try:
            import psycopg2
        except ImportError:
            # psycopg2 not available, try simple protocol approach
            return self._probe_postgresql_post_connect_raw(target, port, username, password)

        try:
            conn = psycopg2.connect(
                host=target,
                port=port,
                user=username,
                password=password,
                connect_timeout=int(self.timeout),
            )
            cursor = conn.cursor()

            # Test EXPLAIN ANALYZE - DEFINITE (requires query planner)
            try:
                cursor.execute("EXPLAIN ANALYZE SELECT 1")
                result = cursor.fetchall()
                if not result:
                    indicators.append(
                        Indicator(
                            name="postgres_no_explain",
                            description="EXPLAIN ANALYZE returns empty result",
                            severity=Confidence.DEFINITE,
                        )
                    )
            except Exception as e:
                error = str(e).lower()
                if "not implemented" in error or "syntax" in error:
                    indicators.append(
                        Indicator(
                            name="postgres_no_explain",
                            description="EXPLAIN ANALYZE not implemented",
                            severity=Confidence.DEFINITE,
                            details=str(e)[:100],
                        )
                    )

            # Test pg_proc function count - HIGH (real PostgreSQL has 3500+)
            try:
                cursor.execute("SELECT COUNT(*) FROM pg_proc")
                count = cursor.fetchone()[0]
                if count < 500:
                    indicators.append(
                        Indicator(
                            name="postgres_few_functions",
                            description=f"Only {count} functions in pg_proc (expected 3500+)",
                            severity=Confidence.HIGH,
                        )
                    )
            except Exception:
                indicators.append(
                    Indicator(
                        name="postgres_no_pg_proc",
                        description="Cannot query pg_proc system catalog",
                        severity=Confidence.HIGH,
                    )
                )

            # Test CREATE FUNCTION - DEFINITE (honeypots don't implement)
            try:
                cursor.execute(
                    "CREATE FUNCTION _hp_test_func() RETURNS int AS 'SELECT 1' LANGUAGE SQL"
                )
                cursor.execute("DROP FUNCTION IF EXISTS _hp_test_func()")
                conn.commit()
            except Exception as e:
                error = str(e).lower()
                if "not implemented" in error or "syntax" in error:
                    indicators.append(
                        Indicator(
                            name="postgres_no_functions",
                            description="Function creation not supported",
                            severity=Confidence.DEFINITE,
                        )
                    )
                # Rollback on error
                try:
                    conn.rollback()
                except Exception:
                    pass

            # Test SHOW ALL parameter count - HIGH (real PostgreSQL has 300+)
            try:
                cursor.execute("SHOW ALL")
                params = cursor.fetchall()
                if len(params) < 50:
                    indicators.append(
                        Indicator(
                            name="postgres_few_params",
                            description=f"Only {len(params)} parameters (expected 300+)",
                            severity=Confidence.HIGH,
                        )
                    )
            except Exception:
                pass

            # Test pg_stat_activity - HIGH (should show connections)
            try:
                cursor.execute("SELECT * FROM pg_stat_activity")
                activity = cursor.fetchall()
                if not activity:
                    indicators.append(
                        Indicator(
                            name="postgres_no_activity",
                            description="pg_stat_activity is empty",
                            severity=Confidence.HIGH,
                        )
                    )
            except Exception:
                indicators.append(
                    Indicator(
                        name="postgres_no_stat_activity",
                        description="Cannot query pg_stat_activity",
                        severity=Confidence.HIGH,
                    )
                )

            # Test pg_extension - MEDIUM (installed extensions)
            try:
                cursor.execute("SELECT * FROM pg_extension")
                extensions = cursor.fetchall()
                if len(extensions) < 2:  # At least plpgsql should be there
                    indicators.append(
                        Indicator(
                            name="postgres_no_extensions",
                            description=f"Only {len(extensions)} extensions installed",
                            severity=Confidence.MEDIUM,
                        )
                    )
            except Exception:
                pass

            # Test pg_class table count - MEDIUM
            try:
                cursor.execute("SELECT COUNT(*) FROM pg_class")
                count = cursor.fetchone()[0]
                if count < 100:  # Real PostgreSQL has 300+
                    indicators.append(
                        Indicator(
                            name="postgres_few_tables",
                            description=f"Only {count} entries in pg_class (expected 300+)",
                            severity=Confidence.MEDIUM,
                        )
                    )
            except Exception:
                pass

            cursor.close()
            conn.close()

        except ImportError:
            pass
        except Exception:
            pass

        return indicators

    def _probe_postgresql_post_connect_raw(
        self, target: str, port: int, username: str, password: str
    ) -> List[Indicator]:
        """Raw socket-based PostgreSQL post-connect probing (fallback).

        Used when psycopg2 is not available.

        Args:
            target: Target host
            port: PostgreSQL port
            username: Username for authentication
            password: Password for authentication

        Returns:
            List of Indicator objects
        """
        # This is a simplified fallback - just notes that advanced testing was skipped
        return []

    def _try_auth_full(self, target: str, port: int, username: str, password: str) -> Tuple[bool, float]:
        """Attempt PostgreSQL authentication with MD5.

        Returns:
            Tuple of (success, elapsed_time)
        """
        import time

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Send startup message
            startup_params = f"user\x00{username}\x00database\x00{username}\x00\x00".encode()
            startup_len = 4 + 4 + len(startup_params)
            startup_msg = struct.pack(">II", startup_len, 196608) + startup_params

            start = time.perf_counter()
            sock.send(startup_msg)

            # Read response
            response = sock.recv(4096)

            if not response:
                sock.close()
                return False, 0

            # Check message type
            msg_type = response[0:1]

            if msg_type == b"R":
                # Authentication request
                if len(response) >= 9:
                    auth_type = struct.unpack(">I", response[5:9])[0]

                    if auth_type == 0:
                        # AuthenticationOk - no password needed
                        elapsed = time.perf_counter() - start
                        sock.close()
                        return True, elapsed

                    elif auth_type == 5:
                        # MD5 password
                        if len(response) >= 13:
                            salt = response[9:13]
                            # Compute MD5 password
                            md5_password = self._compute_md5_password(username, password, salt)
                            # Send password message
                            pwd_msg = b"p" + struct.pack(">I", len(md5_password) + 5) + md5_password + b"\x00"
                            sock.send(pwd_msg)
                            # Read result
                            result = sock.recv(4096)
                            elapsed = time.perf_counter() - start

                            sock.close()

                            # Check for AuthenticationOk
                            if result and result[0:1] == b"R" and len(result) >= 9:
                                result_auth = struct.unpack(">I", result[5:9])[0]
                                return result_auth == 0, elapsed

                    elif auth_type == 3:
                        # Cleartext password
                        pwd_msg = b"p" + struct.pack(">I", len(password) + 5) + password.encode() + b"\x00"
                        sock.send(pwd_msg)
                        result = sock.recv(4096)
                        elapsed = time.perf_counter() - start
                        sock.close()

                        if result and result[0:1] == b"R" and len(result) >= 9:
                            result_auth = struct.unpack(">I", result[5:9])[0]
                            return result_auth == 0, elapsed

            elapsed = time.perf_counter() - start
            sock.close()
            return False, elapsed

        except (socket.error, socket.timeout, OSError):
            return False, 0

    def _compute_md5_password(self, username: str, password: str, salt: bytes) -> bytes:
        """Compute PostgreSQL MD5 password hash."""
        import hashlib

        # md5(md5(password + username) + salt)
        inner = hashlib.md5((password + username).encode()).hexdigest()
        outer = hashlib.md5((inner.encode() + salt)).hexdigest()
        return ("md5" + outer).encode()

    def _probe_invalid_payloads(self, target: str, port: int) -> List[Indicator]:
        """Test PostgreSQL response to invalid payloads."""
        indicators = []
        responses = []

        for payload in POSTGRESQL_INVALID_PAYLOADS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((target, port))

                sock.send(payload)

                try:
                    response = sock.recv(1024)
                    responses.append(response)
                except socket.timeout:
                    responses.append(b"TIMEOUT")

                sock.close()
            except (socket.error, OSError):
                responses.append(b"ERROR")

        if len(responses) >= 2:
            unique = set(responses)
            if len(unique) == 1 and responses[0] not in (b"TIMEOUT", b"ERROR"):
                indicators.append(
                    Indicator(
                        name="postgres_uniform_error",
                        description="Uniform response to different invalid payloads",
                        severity=Confidence.MEDIUM,
                    )
                )

        return indicators

    def _check_ssl(self, target: str, port: int) -> Optional[bytes]:
        """Check SSL negotiation response."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # PostgreSQL SSLRequest message
            # Length (4) + SSL request code (80877103)
            ssl_request = struct.pack(">II", 8, 80877103)
            sock.send(ssl_request)

            response = sock.recv(1)
            sock.close()
            return response
        except (socket.error, socket.timeout, OSError):
            return None

    def _probe_auth(self, target: str, port: int) -> Optional[bytes]:
        """Probe authentication and get error response."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # Startup message (protocol version 3.0)
            startup_params = b"user\x00test\x00database\x00test\x00\x00"
            startup_len = 4 + 4 + len(startup_params)
            startup_msg = struct.pack(">II", startup_len, 196608) + startup_params  # 196608 = 3.0

            sock.send(startup_msg)

            # Read response
            response = sock.recv(4096)
            sock.close()
            return response
        except (socket.error, socket.timeout, OSError):
            return None

    def _analyze_ssl_response(self, response: bytes, result: DetectionResult) -> None:
        """Analyze SSL negotiation response."""
        if response == b"N":
            # SSL not supported - normal for honeypots
            result.add_indicator(
                Indicator(
                    name="postgres_no_ssl",
                    description="SSL not supported (common in honeypots)",
                    severity=Confidence.LOW,
                )
            )

    def _check_error_response(self, response: bytes, result: DetectionResult) -> None:
        """Check error response for honeypot signatures."""
        if not response:
            return

        # Look for error message type 'E'
        if response[0:1] == b"E":
            try:
                # Parse error fields
                response_str = response.decode("utf-8", errors="ignore")

                # Check for known honeypot error codes
                for code, desc in POSTGRES_ERROR_CODES.items():
                    if code in response_str:
                        result.add_indicator(
                            Indicator(
                                name="postgres_honeypot_error",
                                description=f"Honeypot error code pattern: {desc}",
                                severity=Confidence.MEDIUM,
                                details=f"Error code: {code}",
                            )
                        )
                        break

                # Check for static error messages
                if "password authentication failed" in response_str.lower():
                    # This is expected, but timing can reveal honeypot
                    pass

            except UnicodeDecodeError:
                pass

        # Check for authentication request type
        if response[0:1] == b"R":
            auth_type = struct.unpack(">I", response[5:9])[0] if len(response) >= 9 else 0
            if auth_type == 5:  # MD5 password
                result.add_indicator(
                    Indicator(
                        name="postgres_md5_auth",
                        description="MD5 authentication (sticky_elephant default)",
                        severity=Confidence.LOW,
                    )
                )


@register_detector
class RedisDetector(BaseDetector):
    """Detector for Redis honeypots (RedisHoneyPot, redis-honeypot).

    Static (Passive) Detection:
    - PING response (basic connectivity check)

    Dynamic (Active) Detection:
    - INFO command (system info)
    - CONFIG GET (configuration access)
    - CLIENT LIST (client enumeration)
    """

    name = "redis"
    description = "Detects Redis honeypots"
    honeypot_types = ["redis-honeypot", "qeeqbox-redis"]
    default_ports = [6379]

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive Redis detection.

        Only sends PING which is the most basic Redis command
        and least likely to be logged as suspicious.

        Args:
            target: IP address or hostname
            port: Redis port

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        # PING is minimally invasive
        ping_response = self._send_command(target, port, "PING")
        if ping_response:
            self._check_ping(ping_response, result)

        if result.is_honeypot:
            result.honeypot_type = "redis_honeypot"

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active Redis probing.

        Sends commands that query server state and configuration,
        which are more likely to reveal honeypot limitations.
        Also tests default credentials and invalid payloads.

        Args:
            target: IP address or hostname
            port: Redis port

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        # INFO command - reveals system info or honeypot limitations
        info_response = self._send_command(target, port, "INFO")
        if info_response:
            self._check_info(info_response, result)

        # CONFIG GET - often not implemented in honeypots
        config_response = self._send_command(target, port, "CONFIG GET maxclients")
        if config_response:
            self._check_config(config_response, result)

        # CLIENT LIST - reveals connection handling
        client_response = self._send_command(target, port, "CLIENT LIST")
        if client_response:
            self._check_client_list(client_response, result)

        # Test default credentials via AUTH command
        cred_indicators = self._probe_redis_credentials(target, port)
        for indicator in cred_indicators:
            result.add_indicator(indicator)

        # Run comprehensive post-connect probes for advanced detection
        post_connect_indicators = self._probe_redis_post_connect(target, port)
        for indicator in post_connect_indicators:
            result.add_indicator(indicator)

        # Test invalid payloads
        payload_indicators = self._probe_redis_invalid_payloads(target, port)
        for indicator in payload_indicators:
            result.add_indicator(indicator)

        if result.is_honeypot:
            result.honeypot_type = "redis_honeypot"

        return result

    def _probe_redis_credentials(self, target: str, port: int) -> List[Indicator]:
        """Test Redis AUTH behavior with default credentials.

        Redis honeypots may:
        - Accept any AUTH credentials
        - Return inconsistent errors
        - Not require AUTH at all but claim to

        Args:
            target: Target host
            port: Redis port

        Returns:
            List of indicators if honeypot behavior detected
        """
        indicators = []

        # First check if AUTH is required
        ping_response = self._send_command(target, port, "PING")
        auth_required = ping_response and b"-NOAUTH" in ping_response

        if auth_required:
            # Try default passwords
            for _, password in REDIS_HONEYPOT_CREDENTIALS:
                if not password:
                    continue

                auth_response = self._send_command(target, port, f"AUTH {password}")
                if auth_response and auth_response.startswith(b"+OK"):
                    indicators.append(
                        Indicator(
                            name="redis_default_password_accepted",
                            description=f"Default password '{password}' accepted",
                            severity=Confidence.HIGH,
                            details="Redis honeypots often accept common default passwords",
                        )
                    )
                    break
        else:
            # No AUTH required - check if AUTH still works (accept-all behavior)
            for _, password in REDIS_HONEYPOT_CREDENTIALS[:3]:
                if not password:
                    continue

                auth_response = self._send_command(target, port, f"AUTH {password}")
                if auth_response:
                    # Real Redis without password: -ERR Client sent AUTH, but no password is set
                    # Honeypot might accept or return different error
                    if auth_response.startswith(b"+OK"):
                        indicators.append(
                            Indicator(
                                name="redis_auth_accept_all",
                                description="AUTH accepted without password being set",
                                severity=Confidence.DEFINITE,
                                details="Real Redis rejects AUTH when no password is configured",
                            )
                        )
                        break
                    elif b"-ERR" in auth_response and b"no password" not in auth_response.lower():
                        # Non-standard error response
                        indicators.append(
                            Indicator(
                                name="redis_auth_nonstandard_error",
                                description="Non-standard AUTH error response",
                                severity=Confidence.MEDIUM,
                                details=auth_response[:100].decode("utf-8", errors="ignore"),
                            )
                        )
                        break

        return indicators

    def _probe_redis_invalid_payloads(self, target: str, port: int) -> List[Indicator]:
        """Test Redis response to invalid payloads.

        Honeypots often respond uniformly to all malformed data.

        Args:
            target: Target host
            port: Redis port

        Returns:
            List of indicators if uniform response detected
        """
        indicators = []
        responses = []

        for payload in REDIS_INVALID_PAYLOADS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((target, port))

                sock.send(payload)

                try:
                    response = sock.recv(1024)
                    responses.append(response)
                except socket.timeout:
                    responses.append(b"TIMEOUT")

                sock.close()
            except (socket.error, OSError):
                responses.append(b"ERROR")

        # Check for uniform responses
        if len(responses) >= 2:
            unique_responses = set(responses)
            if len(unique_responses) == 1 and responses[0] not in (b"TIMEOUT", b"ERROR"):
                indicators.append(
                    Indicator(
                        name="redis_uniform_error",
                        description="Uniform response to different invalid payloads",
                        severity=Confidence.MEDIUM,
                        details="Honeypots often return identical errors for all malformed data",
                    )
                )

        return indicators

    def _probe_redis_post_connect(self, target: str, port: int) -> List[Indicator]:
        """Run comprehensive Redis honeypot detection commands.

        Tests advanced commands that honeypots typically don't implement:
        - CONFIG GET * (full config dump)
        - MODULE LIST (module support)
        - ACL LIST (ACL support)
        - DEBUG OBJECT (debug commands)
        - MEMORY DOCTOR (memory analysis)
        - SLOWLOG GET (slow query log)

        Args:
            target: Target host
            port: Redis port

        Returns:
            List of Indicator objects for detected honeypot signs
        """
        indicators: List[Indicator] = []
        unsupported_commands = 0

        # Test CONFIG GET * - HIGH (honeypots block this)
        config_response = self._send_command(target, port, "CONFIG GET *")
        if config_response:
            if b"-ERR" in config_response or b"unknown command" in config_response.lower():
                indicators.append(
                    Indicator(
                        name="redis_config_blocked",
                        description="CONFIG GET * command blocked or not implemented",
                        severity=Confidence.HIGH,
                        details="Real Redis allows CONFIG GET * for config inspection",
                    )
                )
                unsupported_commands += 1
            elif config_response.startswith(b"*"):
                # Parse array response and check item count
                try:
                    # Expected: 100+ config items in real Redis
                    # Format: *N\r\n where N is number of elements
                    count_end = config_response.find(b"\r\n")
                    if count_end > 1:
                        count = int(config_response[1:count_end])
                        if count < 20:  # Too few config items
                            indicators.append(
                                Indicator(
                                    name="redis_config_limited",
                                    description=f"CONFIG GET * returns only {count // 2} config items",
                                    severity=Confidence.HIGH,
                                    details="Real Redis has 100+ config parameters",
                                )
                            )
                except (ValueError, IndexError):
                    pass

        # Test MODULE LIST - DEFINITE (not implemented in honeypots)
        module_response = self._send_command(target, port, "MODULE LIST")
        if module_response:
            if b"unknown command" in module_response.lower():
                indicators.append(
                    Indicator(
                        name="redis_no_module_support",
                        description="MODULE LIST command not implemented",
                        severity=Confidence.DEFINITE,
                        details="Redis 4.0+ supports MODULE command",
                    )
                )
                unsupported_commands += 1

        # Test ACL LIST - DEFINITE (not implemented in honeypots)
        acl_response = self._send_command(target, port, "ACL LIST")
        if acl_response:
            if b"unknown command" in acl_response.lower():
                indicators.append(
                    Indicator(
                        name="redis_no_acl_support",
                        description="ACL LIST command not implemented",
                        severity=Confidence.DEFINITE,
                        details="Redis 6.0+ supports ACL commands",
                    )
                )
                unsupported_commands += 1

        # Test DEBUG OBJECT - HIGH (often disabled in honeypots)
        debug_response = self._send_command(target, port, "DEBUG OBJECT nonexistent")
        if debug_response:
            if b"unknown command" in debug_response.lower():
                indicators.append(
                    Indicator(
                        name="redis_no_debug",
                        description="DEBUG command not implemented",
                        severity=Confidence.HIGH,
                    )
                )
                unsupported_commands += 1

        # Test MEMORY DOCTOR - HIGH (not implemented in honeypots)
        memory_response = self._send_command(target, port, "MEMORY DOCTOR")
        if memory_response:
            if b"unknown command" in memory_response.lower():
                indicators.append(
                    Indicator(
                        name="redis_no_memory_cmds",
                        description="MEMORY DOCTOR command not implemented",
                        severity=Confidence.HIGH,
                    )
                )
                unsupported_commands += 1

        # Test SLOWLOG GET - MEDIUM
        slowlog_response = self._send_command(target, port, "SLOWLOG GET 10")
        if slowlog_response:
            if b"unknown command" in slowlog_response.lower():
                indicators.append(
                    Indicator(
                        name="redis_no_slowlog",
                        description="SLOWLOG command not implemented",
                        severity=Confidence.MEDIUM,
                    )
                )
                unsupported_commands += 1

        # Test DBSIZE - should return number of keys
        dbsize_response = self._send_command(target, port, "DBSIZE")
        if dbsize_response:
            if b"-ERR" in dbsize_response or b"unknown command" in dbsize_response.lower():
                indicators.append(
                    Indicator(
                        name="redis_no_dbsize",
                        description="DBSIZE command not implemented",
                        severity=Confidence.HIGH,
                    )
                )
                unsupported_commands += 1

        # Test COMMAND COUNT - returns number of available commands
        cmd_count_response = self._send_command(target, port, "COMMAND COUNT")
        if cmd_count_response:
            if cmd_count_response.startswith(b":"):
                try:
                    count = int(cmd_count_response[1:cmd_count_response.find(b"\r\n")])
                    # Real Redis has 200+ commands
                    if count < 50:
                        indicators.append(
                            Indicator(
                                name="redis_few_commands",
                                description=f"Only {count} commands available (expected 200+)",
                                severity=Confidence.DEFINITE,
                            )
                        )
                except (ValueError, IndexError):
                    pass
            elif b"unknown command" in cmd_count_response.lower():
                indicators.append(
                    Indicator(
                        name="redis_no_command_cmd",
                        description="COMMAND COUNT not implemented",
                        severity=Confidence.HIGH,
                    )
                )
                unsupported_commands += 1

        # Multiple unsupported commands = strong honeypot indicator
        if unsupported_commands >= 4:
            indicators.append(
                Indicator(
                    name="redis_limited_implementation",
                    description=f"{unsupported_commands} advanced commands not implemented",
                    severity=Confidence.DEFINITE,
                    details="Honeypots typically implement only basic Redis commands",
                )
            )

        return indicators

    def _send_command(self, target: str, port: int, command: str) -> Optional[bytes]:
        """Send Redis command and get response."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # RESP protocol: *1\r\n$4\r\nPING\r\n for simple commands
            parts = command.split()
            cmd = f"*{len(parts)}\r\n"
            for part in parts:
                cmd += f"${len(part)}\r\n{part}\r\n"

            sock.send(cmd.encode())
            response = sock.recv(4096)
            sock.close()
            return response
        except (socket.error, socket.timeout, OSError):
            return None

    def _check_ping(self, response: bytes, result: DetectionResult) -> None:
        """Check PING response."""
        if response == b"+PONG\r\n":
            # Normal response, but check timing/other factors
            pass
        elif b"-ERR" in response:
            result.add_indicator(
                Indicator(
                    name="redis_ping_error",
                    description="PING returns error (unexpected for Redis)",
                    severity=Confidence.MEDIUM,
                )
            )

    def _check_info(self, response: bytes, result: DetectionResult) -> None:
        """Check INFO response for honeypot indicators."""
        if b"-ERR" in response:
            # Check for known honeypot errors
            for error in REDIS_HONEYPOT_ERRORS:
                if error in response:
                    result.add_indicator(
                        Indicator(
                            name="redis_honeypot_error",
                            description="Known Redis honeypot error pattern",
                            severity=Confidence.HIGH,
                            details=response[:100].decode("utf-8", errors="ignore"),
                        )
                    )
                    return

        # Check for minimal/static INFO output
        try:
            info_str = response.decode("utf-8", errors="ignore")
            if info_str.startswith("$"):
                # Parse bulk string
                lines = info_str.split("\r\n")
                if len(lines) < 10:  # Real Redis has many more lines
                    result.add_indicator(
                        Indicator(
                            name="redis_minimal_info",
                            description="Minimal INFO response (honeypot indicator)",
                            severity=Confidence.MEDIUM,
                        )
                    )
        except UnicodeDecodeError:
            pass

    def _check_config(self, response: bytes, result: DetectionResult) -> None:
        """Check CONFIG GET response."""
        if b"-ERR" in response:
            for error in REDIS_HONEYPOT_ERRORS:
                if error in response:
                    result.add_indicator(
                        Indicator(
                            name="redis_config_error",
                            description="CONFIG GET returns honeypot error",
                            severity=Confidence.HIGH,
                        )
                    )
                    return

    def _check_client_list(self, response: bytes, result: DetectionResult) -> None:
        """Check CLIENT LIST response."""
        if b"-ERR" in response:
            result.add_indicator(
                Indicator(
                    name="redis_client_list_error",
                    description="CLIENT LIST not implemented (honeypot indicator)",
                    severity=Confidence.MEDIUM,
                )
            )
        elif response.startswith(b"$"):
            # Check if only one client (ourselves)
            try:
                content = response.split(b"\r\n", 1)[1] if b"\r\n" in response else b""
                if content.count(b"id=") <= 1:
                    result.add_indicator(
                        Indicator(
                            name="redis_single_client",
                            description="Only one client in CLIENT LIST",
                            severity=Confidence.LOW,
                        )
                    )
            except IndexError:
                pass

    def get_recommendations(self, result: DetectionResult) -> list[str]:
        """Get recommendations for Redis honeypot."""
        recommendations = []
        for indicator in result.indicators:
            if indicator.name == "redis_honeypot_error":
                recommendations.append(
                    "Implement proper Redis command handling to avoid detection"
                )
            elif indicator.name == "redis_minimal_info":
                recommendations.append(
                    "Return realistic INFO output with proper Redis statistics"
                )
        return recommendations
