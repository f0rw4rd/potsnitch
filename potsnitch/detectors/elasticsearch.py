"""Elasticsearch honeypot detector (Elastichoney, Elasticpot).

Detection is split into:
- PASSIVE: Default instance names, cluster names, build hashes, version strings
- ACTIVE: Endpoint enumeration, missing endpoint detection, response formatting
"""

import json
from typing import Optional

from potsnitch.core.base import BaseDetector, DetectionMode, register_detector
from potsnitch.core.result import DetectionResult, Indicator, Confidence

# Known Elasticpot default instance names (from T-Pot config)
ELASTICPOT_DEFAULT_NAMES = [
    "Green Goblin",  # Default from elasticpot
    "USNYES01",      # T-Pot default
    "usnyes01",      # T-Pot default hostname
    "elk",           # Common default
]

# Known Elasticpot default build hashes
ELASTICPOT_DEFAULT_BUILDS = [
    "89d3241",  # Default build number
]

# Known honeypot default cluster names
ELASTICPOT_DEFAULT_CLUSTERS = [
    "elasticsearch",
    "docker-cluster",
]

# Known honeypot version strings (very old versions)
ELASTICPOT_VERSIONS = [
    "1.4.1",
    "1.4.2",
    "2.4.6",
]


@register_detector
class ElasticsearchDetector(BaseDetector):
    """Detector for Elasticsearch honeypots.

    Static (Passive) Detection:
    - Default instance names: "Green Goblin", "USNYES01"
    - Default cluster name: "elasticsearch"
    - Default build hash: "89d3241"
    - Old version strings: 1.4.1, 1.4.2, 2.4.6

    Dynamic (Active) Detection:
    - Endpoint enumeration: /, /_search, /_nodes, /_cat/indices
    - Missing endpoint detection
    - Response formatting analysis (missing newlines, invalid JSON)
    """

    name = "elasticsearch"
    description = "Detects Elastichoney and Elasticpot via endpoint and response analysis"
    honeypot_types = ["elastichoney", "elasticpot"]
    default_ports = [9200]

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive/static Elasticsearch detection.

        Checks root endpoint for known default values without
        probing additional endpoints.

        Args:
            target: IP address or hostname
            port: Elasticsearch port

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        try:
            import requests

            base_url = f"http://{target}:{port}"

            # Check root endpoint for static signatures
            self._check_root_passive(base_url, result)

        except Exception:
            pass

        # Set honeypot type if detected
        if result.is_honeypot and not result.honeypot_type:
            result.honeypot_type = "elasticpot"

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active/dynamic Elasticsearch probing.

        Enumerates multiple endpoints to detect missing or
        incomplete API implementations.

        Args:
            target: IP address or hostname
            port: Elasticsearch port

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        try:
            import requests

            base_url = f"http://{target}:{port}"

            # Test search endpoint
            self._check_search(base_url, result)

            # Test nodes endpoint
            self._check_nodes(base_url, result)

            # Test indices endpoint
            self._check_indices(base_url, result)

            # Test for missing endpoints
            self._check_missing_endpoints(base_url, result)

        except Exception:
            pass

        # Set honeypot type if detected via active probes
        if result.is_honeypot and not result.honeypot_type:
            result.honeypot_type = "elastichoney"

        return result

    def _check_root_passive(self, base_url: str, result: DetectionResult) -> Optional[dict]:
        """Check root endpoint for static honeypot signatures."""
        try:
            import requests

            response = requests.get(f"{base_url}/", timeout=self.timeout)

            if response.status_code != 200:
                return None

            # Check for missing newline (Elastichoney signature)
            if not response.text.endswith("\n"):
                result.add_indicator(
                    Indicator(
                        name="missing_newline",
                        description="Response missing trailing newline",
                        severity=Confidence.MEDIUM,
                        details="Elastichoney doesn't add newline to responses",
                    )
                )

            try:
                data = response.json()

                # Check for default cluster name
                if "cluster_name" in data:
                    cluster = data["cluster_name"]
                    if cluster in ELASTICPOT_DEFAULT_CLUSTERS:
                        result.add_indicator(
                            Indicator(
                                name="default_cluster_name",
                                description=f"Default cluster name: {cluster}",
                                severity=Confidence.LOW,
                            )
                        )

                # Check version info
                if "version" in data:
                    version = data["version"].get("number", "")

                    # Check for known honeypot versions
                    if version in ELASTICPOT_VERSIONS:
                        result.add_indicator(
                            Indicator(
                                name="honeypot_version",
                                description=f"Known honeypot ES version: {version}",
                                severity=Confidence.HIGH,
                                details=f"Versions {', '.join(ELASTICPOT_VERSIONS)} are commonly used by honeypots",
                            )
                        )
                    # Very old versions might indicate honeypot
                    elif version.startswith("1.") or version.startswith("2."):
                        result.add_indicator(
                            Indicator(
                                name="old_version",
                                description=f"Very old ES version: {version}",
                                severity=Confidence.LOW,
                            )
                        )

                    # Check for default build hash (T-Pot/Elasticpot)
                    build = data["version"].get("build_hash", "")
                    if build in ELASTICPOT_DEFAULT_BUILDS:
                        result.add_indicator(
                            Indicator(
                                name="elasticpot_build",
                                description=f"Elasticpot default build hash: {build}",
                                severity=Confidence.HIGH,
                            )
                        )

                # Check for Elasticpot default instance name (T-Pot)
                if "name" in data:
                    name = data["name"]
                    if name in ELASTICPOT_DEFAULT_NAMES:
                        result.add_indicator(
                            Indicator(
                                name="elasticpot_default_name",
                                description=f"Elasticpot default instance name: {name}",
                                severity=Confidence.HIGH,
                                details="T-Pot uses USNYES01, default is 'Green Goblin'",
                            )
                        )

                return data

            except json.JSONDecodeError:
                result.add_indicator(
                    Indicator(
                        name="invalid_json",
                        description="Invalid JSON response from root endpoint",
                        severity=Confidence.HIGH,
                    )
                )

        except Exception:
            pass

        return None

    def _check_search(self, base_url: str, result: DetectionResult) -> None:
        """Check /_search endpoint (active probing)."""
        try:
            import requests

            response = requests.get(f"{base_url}/_search", timeout=self.timeout)

            if response.status_code == 200:
                try:
                    data = response.json()
                    # Real ES returns hits object
                    if "hits" not in data:
                        result.add_indicator(
                            Indicator(
                                name="missing_hits",
                                description="Search response missing 'hits' field",
                                severity=Confidence.MEDIUM,
                            )
                        )
                except json.JSONDecodeError:
                    pass

        except Exception:
            pass

    def _check_nodes(self, base_url: str, result: DetectionResult) -> None:
        """Check /_nodes endpoint (active probing)."""
        try:
            import requests

            response = requests.get(f"{base_url}/_nodes", timeout=self.timeout)

            if response.status_code == 200:
                try:
                    data = response.json()
                    # Check for realistic node info
                    if "nodes" in data:
                        nodes = data["nodes"]
                        if len(nodes) == 0:
                            result.add_indicator(
                                Indicator(
                                    name="empty_nodes",
                                    description="Empty nodes list in /_nodes response",
                                    severity=Confidence.HIGH,
                                )
                            )
                except json.JSONDecodeError:
                    pass

        except Exception:
            pass

    def _check_indices(self, base_url: str, result: DetectionResult) -> None:
        """Check /_cat/indices endpoint (active probing)."""
        try:
            import requests

            response = requests.get(f"{base_url}/_cat/indices", timeout=self.timeout)

            # Honeypots often don't implement this endpoint
            if response.status_code == 404:
                result.add_indicator(
                    Indicator(
                        name="missing_cat_indices",
                        description="/_cat/indices endpoint not implemented",
                        severity=Confidence.HIGH,
                        details="Elastichoney only implements limited endpoints",
                    )
                )
            elif "page not found" in response.text.lower():
                result.add_indicator(
                    Indicator(
                        name="page_not_found",
                        description="Non-standard 'page not found' response",
                        severity=Confidence.HIGH,
                    )
                )

        except Exception:
            pass

    def _check_missing_endpoints(self, base_url: str, result: DetectionResult) -> None:
        """Check for unimplemented endpoints typical of honeypots (active probing)."""
        try:
            import requests

            # These endpoints should exist in real ES
            endpoints = [
                "/_cluster/health",
                "/_cluster/stats",
                "/_cat/nodes",
            ]

            missing = 0
            for endpoint in endpoints:
                try:
                    response = requests.get(f"{base_url}{endpoint}", timeout=self.timeout)
                    if response.status_code in [404, 500] or "not found" in response.text.lower():
                        missing += 1
                except Exception:
                    missing += 1

            if missing >= 2:
                result.add_indicator(
                    Indicator(
                        name="limited_api",
                        description=f"{missing}/{len(endpoints)} standard endpoints missing",
                        severity=Confidence.HIGH,
                        details="Honeypots typically implement only exploit-targeted endpoints",
                    )
                )

        except Exception:
            pass

    def get_recommendations(self, result: DetectionResult) -> list[str]:
        """Get remediation recommendations for ES honeypots."""
        recommendations = []

        for indicator in result.indicators:
            if "newline" in indicator.name:
                recommendations.append("Add trailing newline to all JSON responses")
            elif "limited_api" in indicator.name or "missing" in indicator.name:
                recommendations.append(
                    "Implement more API endpoints or use a real ES instance as backend"
                )
            elif "cluster_name" in indicator.name:
                recommendations.append("Configure a realistic cluster name")
            elif "default_name" in indicator.name:
                recommendations.append("Configure a realistic instance name instead of defaults")
            elif "build" in indicator.name:
                recommendations.append("Use a realistic build hash value")
            elif "version" in indicator.name:
                recommendations.append("Use a more recent Elasticsearch version string")

        return list(set(recommendations))  # Remove duplicates
